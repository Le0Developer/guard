use super::*;
use crate::core::Core;
use toasty_core::driver::operation::TransactionMode;
use webauthn_rs::prelude::*;

pub(crate) enum Begin {
    Complete { token: String, redirect: String },
    Pending(String),
}
pub(crate) struct Complete {
    pub token: String,
    pub redirect: String,
}

pub(crate) async fn begin(core: &Core, verified: &User, login_id: i64) -> Result<Begin> {
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let current = user(&mut tx, verified.id).await?;
    if current.password != verified.password || current.email != verified.email {
        return Err(invalid("Account credentials changed. Sign in again."));
    }
    let login = LoginSession::get_by_id(&mut tx, login_id).await?;
    if login.created_at.as_second() + crate::session::LOGIN_LIFETIME_SECONDS <= now().as_second() {
        return Err(invalid("Your sign-in request expired. Start again."));
    }
    let redirect = login.redirect_uri.clone().unwrap_or_else(|| "/".into());
    LoginSession::filter_by_id(login.id)
        .delete()
        .exec(&mut tx)
        .await?;
    let result = if enabled(&mut tx, current.id).await? {
        not_throttled(&current)?;
        let ticket = ceremony(
            &mut tx,
            &current,
            current.id,
            None,
            Some(login.id),
            "login",
            json!({"redirect":redirect}),
        )
        .await?;
        Begin::Pending(ticket)
    } else {
        let token = crate::token::generate_token();
        toasty::create!(Session {
            user_id: current.id,
            token: &token
        })
        .exec(&mut tx)
        .await?;
        crate::audit::record(&mut tx, current.id, AuditLogEntry::UserLoggedIn).await?;
        Begin::Complete { token, redirect }
    };
    tx.commit().await?;
    Ok(result)
}

pub(crate) fn not_throttled(user: &User) -> Result<()> {
    if user.mfa_failures >= 5
        && user
            .mfa_window
            .is_some_and(|window| window.as_second() + 300 > now().as_second())
    {
        return Err(Error(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Wait five minutes before trying again.",
        ));
    }
    Ok(())
}
pub(crate) async fn failure(
    db: &mut dyn toasty::Executor,
    user: &User,
    ticket: &MfaCeremony,
    method: &str,
) -> Result<()> {
    let active = user
        .mfa_window
        .is_some_and(|window| window.as_second() + 300 > now().as_second());
    let failures = if active { user.mfa_failures + 1 } else { 1 };
    User::filter_by_id(user.id)
        .update()
        .mfa_failures(failures)
        .mfa_window(if active {
            user.mfa_window.expect("active window")
        } else {
            now()
        })
        .exec(&mut *db)
        .await?;
    MfaCeremony::filter_by_id(ticket.id)
        .update()
        .attempts(ticket.attempts + 1)
        .exec(&mut *db)
        .await?;
    event(
        db,
        ticket.actor_id,
        user.id,
        "MFA verification",
        method,
        Some(ticket.id),
        if failures >= 5 {
            "Throttled"
        } else {
            "Rejected"
        },
    )
    .await
}

pub(crate) async fn pending(
    db: &mut dyn toasty::Executor,
    raw: &str,
) -> Result<(MfaCeremony, User)> {
    let ticket = load_ceremony(&mut *db, raw, "login").await?;
    let user = user(&mut *db, ticket.user_id).await?;
    not_throttled(&user)?;
    if !enabled(db, user.id).await? {
        return Err(invalid("Security settings changed. Sign in again."));
    }
    Ok((ticket, user))
}
async fn finish(
    db: &mut dyn toasty::Executor,
    ticket: &MfaCeremony,
    user: &User,
    method: &str,
    record: Option<i64>,
) -> Result<Complete> {
    MfaCeremony::filter_by_id(ticket.id)
        .update()
        .consumed_at(now())
        .exec(&mut *db)
        .await?;
    User::filter_by_id(user.id)
        .update()
        .mfa_failures(0)
        .exec(&mut *db)
        .await?;
    let token = generate_token();
    toasty::create!(Session {
        user_id: user.id,
        token: &token
    })
    .exec(&mut *db)
    .await?;
    event(
        &mut *db,
        user.id,
        user.id,
        "MFA verification",
        method,
        record,
        "Succeeded",
    )
    .await?;
    crate::audit::record(db, user.id, AuditLogEntry::UserLoggedIn).await?;
    Ok(Complete {
        token,
        redirect: ticket.state.0["redirect"]
            .as_str()
            .unwrap_or("/")
            .to_owned(),
    })
}

async fn verify_code_inner(core: &Core, raw: &str, method: &str, code: &str) -> Result<Complete> {
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let (ticket, user) = pending(&mut tx, raw).await?;
    let mut accepted = None;
    match method {
        "totp" => {
            let factors =
                TotpAuthenticator::filter(TotpAuthenticator::fields().user_id().eq(user.id))
                    .exec(&mut tx)
                    .await?;
            if code.trim().len() == 6 && code.trim().bytes().all(|c| c.is_ascii_digit()) {
                for factor in factors {
                    let secret = unseal(user.id, &factor.secret)?;
                    if let Some(step) =
                        totp(&secret, &user.username)?.check(code.trim(), now().as_second() as u64)
                    {
                        if step as i64 > factor.last_step {
                            TotpAuthenticator::filter_by_id(factor.id)
                                .update()
                                .last_step(step as i64)
                                .last_used_at(now())
                                .exec(&mut tx)
                                .await?;
                            accepted = Some(factor.id);
                            break;
                        }
                    }
                }
            }
        }
        "backup" => {
            let hashed = manage::recovery_hash(user.id, code);
            match RecoveryCode::get_by_hash(&mut tx, hashed).await {
                Ok(record) if record.user_id == user.id && record.used_at.is_none() => {
                    RecoveryCode::filter_by_id(record.id)
                        .update()
                        .used_at(now())
                        .exec(&mut tx)
                        .await?;
                    accepted = Some(record.id);
                }
                Ok(_) => (),
                Err(e) if e.is_record_not_found() => (),
                Err(e) => return Err(e.into()),
            }
        }
        _ => return Err(invalid("Choose an authenticator code or backup code.")),
    }
    let Some(id) = accepted else {
        failure(&mut tx, &user, &ticket, method).await?;
        tx.commit().await?;
        return Err(invalid("Invalid or already used code."));
    };
    let result = finish(&mut tx, &ticket, &user, method, Some(id)).await?;
    tx.commit().await?;
    Ok(result)
}

async fn start_key_inner(core: &Core, raw: &str) -> Result<Value> {
    let webauthn = webauthn(core)?;
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let (ticket, user) = pending(&mut tx, raw).await?;
    let credentials =
        WebauthnCredential::filter(WebauthnCredential::fields().user_id().eq(user.id))
            .exec(&mut tx)
            .await?;
    let keys = credentials
        .into_iter()
        .map(|key| key.credential.0)
        .collect::<Vec<_>>();
    if keys.is_empty() {
        return Err(invalid("This account has no security keys."));
    }
    let (challenge, state) = webauthn
        .start_securitykey_authentication(&keys)
        .map_err(|_| invalid("Unable to start security-key verification."))?;
    let state =
        serde_json::to_value(state).map_err(|_| invalid("Unable to save security-key state."))?;
    let token = ceremony(
        &mut tx,
        &user,
        user.id,
        None,
        ticket.login_session_id,
        "key-auth",
        json!({"state":state,"pending_id":ticket.id}),
    )
    .await?;
    tx.commit().await?;
    let mut value = serde_json::to_value(challenge)
        .map_err(|_| invalid("Unable to create security-key challenge."))?;
    value["ceremony"] = token.into();
    Ok(value)
}

async fn finish_key_inner(
    core: &Core,
    raw: &str,
    token: &str,
    credential: PublicKeyCredential,
) -> Result<Complete> {
    let webauthn = webauthn(core)?;
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let (ticket, user) = pending(&mut tx, raw).await?;
    let ceremony = load_ceremony(&mut tx, token, "key-auth").await?;
    if ceremony.user_id != user.id || ceremony.state.0["pending_id"].as_i64() != Some(ticket.id) {
        return Err(invalid(
            "This security-key challenge belongs to another sign-in.",
        ));
    }
    MfaCeremony::filter_by_id(ceremony.id)
        .update()
        .consumed_at(now())
        .exec(&mut tx)
        .await?;
    let state: SecurityKeyAuthentication =
        serde_json::from_value(ceremony.state.0["state"].clone())
            .map_err(|_| invalid("Invalid security-key state."))?;
    let result = match webauthn.finish_securitykey_authentication(&credential, &state) {
        Ok(value) => value,
        Err(_) => {
            failure(&mut tx, &user, &ticket, "webauthn").await?;
            tx.commit().await?;
            return Err(invalid(
                "Security-key verification failed. Try again or use another method.",
            ));
        }
    };
    let id = URL_SAFE_NO_PAD.encode(result.cred_id().as_ref());
    let mut key = WebauthnCredential::get_by_credential_id(&mut tx, id).await?;
    if key.user_id != user.id
        || ((result.counter() != 0 || key.sign_count != 0) && result.counter() <= key.sign_count)
    {
        failure(&mut tx, &user, &ticket, "webauthn").await?;
        tx.commit().await?;
        return Err(invalid(
            "The security-key counter is invalid. Use another method.",
        ));
    }
    if key.credential.0.update_credential(&result).is_none() {
        return Err(invalid("Security-key identity mismatch."));
    }
    WebauthnCredential::filter_by_id(key.id)
        .update()
        .credential(key.credential)
        .sign_count(result.counter())
        .last_used_at(now())
        .exec(&mut tx)
        .await?;
    let complete = finish(&mut tx, &ticket, &user, "webauthn", Some(key.id)).await?;
    tx.commit().await?;
    Ok(complete)
}

pub(crate) async fn verify_code(
    core: &Core,
    raw: &str,
    method: &str,
    code: &str,
) -> Result<Complete> {
    let result = verify_code_inner(core, raw, method, code).await;
    if let Err(error) = &result {
        rejected(core, raw, error).await;
    }
    result
}
pub(crate) async fn start_key(core: &Core, raw: &str) -> Result<Value> {
    let result = start_key_inner(core, raw).await;
    if let Err(error) = &result {
        rejected(core, raw, error).await;
    }
    result
}
pub(crate) async fn finish_key(
    core: &Core,
    raw: &str,
    token: &str,
    credential: PublicKeyCredential,
) -> Result<Complete> {
    let result = finish_key_inner(core, raw, token, credential).await;
    if let Err(error) = &result {
        rejected(core, raw, error).await;
        rejected(core, token, error).await;
    }
    result
}
