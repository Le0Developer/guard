use super::*;
use crate::core::Core;
use toasty_core::driver::operation::TransactionMode;
use webauthn_rs::prelude::*;

pub(crate) struct Context {
    pub actor: i64,
    pub target: i64,
    pub session: i64,
}
impl Context {
    pub async fn authorize(&self, db: &mut dyn toasty::Executor) -> Result<User> {
        let (actor, session) = crate::session::by_id(&mut *db, self.session)
            .await?
            .filter(|(actor, _)| actor.id == self.actor)
            .ok_or(Error(
                axum::http::StatusCode::UNAUTHORIZED,
                "Sign in again before changing security settings.",
            ))?;
        if actor.id != self.target && !matches!(actor.role, Role::Admin) {
            return Err(Error(
                axum::http::StatusCode::FORBIDDEN,
                "You cannot manage another account's security.",
            ));
        }
        if session.user_id != actor.id || session.created_at.as_second() + 300 < now().as_second() {
            return Err(Error(
                axum::http::StatusCode::UNAUTHORIZED,
                "Sign in again before changing security settings.",
            ));
        }
        let target = User::get_by_id(db, self.target).await?;
        if target.deleted_at.is_some() {
            return Err(invalid("This account no longer exists."));
        }
        Ok(target)
    }
    fn keep(&self) -> Option<i64> {
        if self.actor == self.target {
            Some(self.session)
        } else {
            None
        }
    }
    fn bound(&self, value: &MfaCeremony) -> Result<()> {
        if value.user_id != self.target
            || value.actor_id != self.actor
            || value.session_id != Some(self.session)
        {
            return Err(invalid(
                "This enrollment belongs to another account or session.",
            ));
        }
        Ok(())
    }
}

pub(crate) struct TotpSetup {
    pub ticket: String,
    pub secret: String,
    pub qr: String,
}
pub(crate) async fn start_totp(core: &Core, ctx: &Context, label: &str) -> Result<TotpSetup> {
    let label = name(label)?;
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let target = ctx.authorize(&mut tx).await?;
    let secret = totp_rs::Secret::generate().to_base32();
    let otp = totp(&secret, &target.username)?;
    let qr = otp
        .to_qr_base64()
        .map_err(|_| invalid("Unable to generate the setup QR code."))?;
    let encrypted = seal(target.id, &secret)?;
    let ticket = ceremony(
        &mut tx,
        &target,
        ctx.actor,
        Some(ctx.session),
        None,
        "totp-enroll",
        json!({"secret":encrypted,"name":label}),
    )
    .await?;
    tx.commit().await?;
    Ok(TotpSetup { ticket, secret, qr })
}

async fn confirm_totp_inner(core: &Core, ctx: &Context, token: &str, code: &str) -> Result<()> {
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let target = ctx.authorize(&mut tx).await?;
    let setup = load_ceremony(&mut tx, token, "totp-enroll").await?;
    ctx.bound(&setup)?;
    auth::not_throttled(&target)?;
    let encrypted = setup.state.0["secret"]
        .as_str()
        .ok_or_else(|| invalid("Invalid enrollment state."))?;
    let secret = unseal(target.id, encrypted)?;
    let step = totp(&secret, &target.username)?.check(code.trim(), now().as_second() as u64);
    let Some(step) = step else {
        auth::failure(&mut tx, &target, &setup, "totp-enrollment").await?;
        tx.commit().await?;
        return Err(invalid("Invalid authenticator code."));
    };
    let label = setup.state.0["name"]
        .as_str()
        .ok_or_else(|| invalid("Invalid enrollment state."))?;
    let factor = toasty::create!(TotpAuthenticator {
        user_id: target.id,
        name: label,
        secret: encrypted,
        last_step: step as i64,
        last_used_at: now()
    })
    .exec(&mut tx)
    .await?;
    changed(
        &mut tx,
        &target,
        ctx.actor,
        ctx.keep(),
        "Enrolled authenticator",
        "totp",
        Some(factor.id),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn start_key(core: &Core, ctx: &Context, label: &str) -> Result<Value> {
    let label = name(label)?;
    let webauthn = webauthn(core)?;
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let mut target = ctx.authorize(&mut tx).await?;
    let uuid = match &target.webauthn_user_id {
        Some(id) => {
            Uuid::parse_str(id).map_err(|_| invalid("Invalid WebAuthn user identifier."))?
        }
        None => {
            let id = Uuid::new_v4();
            User::filter_by_id(target.id)
                .update()
                .webauthn_user_id(id.to_string())
                .exec(&mut tx)
                .await?;
            target.webauthn_user_id = Some(id.to_string());
            id
        }
    };
    let existing = WebauthnCredential::filter(WebauthnCredential::fields().user_id().eq(target.id))
        .exec(&mut tx)
        .await?;
    let excluded = existing
        .iter()
        .map(|key| key.credential.0.cred_id().clone())
        .collect();
    let (challenge, state) = webauthn
        .start_securitykey_registration(
            uuid,
            &target.username,
            &target.username,
            Some(excluded),
            None,
            Some(AuthenticatorAttachment::CrossPlatform),
        )
        .map_err(|_| invalid("Unable to start security-key registration."))?;
    let state =
        serde_json::to_value(state).map_err(|_| invalid("Unable to save registration state."))?;
    let ticket = ceremony(
        &mut tx,
        &target,
        ctx.actor,
        Some(ctx.session),
        None,
        "key-enroll",
        json!({"state":state,"name":label}),
    )
    .await?;
    tx.commit().await?;
    let mut value = serde_json::to_value(challenge)
        .map_err(|_| invalid("Unable to create security-key challenge."))?;
    value["ceremony"] = ticket.into();
    Ok(value)
}

async fn finish_key_inner(
    core: &Core,
    ctx: &Context,
    token: &str,
    credential: RegisterPublicKeyCredential,
) -> Result<()> {
    let webauthn = webauthn(core)?;
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let target = ctx.authorize(&mut tx).await?;
    let setup = load_ceremony(&mut tx, token, "key-enroll").await?;
    ctx.bound(&setup)?;
    auth::not_throttled(&target)?;
    MfaCeremony::filter_by_id(setup.id)
        .update()
        .consumed_at(now())
        .exec(&mut tx)
        .await?;
    let state: SecurityKeyRegistration = serde_json::from_value(setup.state.0["state"].clone())
        .map_err(|_| invalid("Invalid registration state."))?;
    let key = match webauthn.finish_securitykey_registration(&credential, &state) {
        Ok(key) => key,
        Err(_) => {
            auth::failure(&mut tx, &target, &setup, "security-key-enrollment").await?;
            tx.commit().await?;
            return Err(invalid("Security-key registration failed. Start again."));
        }
    };
    let credential_id = URL_SAFE_NO_PAD.encode(key.cred_id().as_ref());
    match WebauthnCredential::get_by_credential_id(&mut tx, &credential_id).await {
        Ok(_) => {
            event(
                &mut tx,
                ctx.actor,
                target.id,
                "Enroll security key",
                "webauthn",
                None,
                "Rejected duplicate credential",
            )
            .await?;
            tx.commit().await?;
            return Err(invalid(
                "This security key credential is already registered.",
            ));
        }
        Err(e) if e.is_record_not_found() => (),
        Err(e) => return Err(e.into()),
    }
    let label = setup.state.0["name"]
        .as_str()
        .ok_or_else(|| invalid("Invalid registration state."))?;
    let key = toasty::create!(WebauthnCredential {
        user_id: target.id,
        credential_id: credential_id,
        name: label,
        credential: toasty::Json(key)
    })
    .exec(&mut tx)
    .await?;
    changed(
        &mut tx,
        &target,
        ctx.actor,
        ctx.keep(),
        "Enrolled security key",
        "webauthn",
        Some(key.id),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn backup_codes(core: &Core, ctx: &Context) -> Result<Vec<String>> {
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let target = ctx.authorize(&mut tx).await?;
    if !enabled(&mut tx, target.id).await? {
        return Err(invalid(
            "Enroll an authenticator or security key before generating backup codes.",
        ));
    }
    RecoveryCode::filter(RecoveryCode::fields().user_id().eq(target.id))
        .delete()
        .exec(&mut tx)
        .await?;
    let mut codes = Vec::new();
    for _ in 0..10 {
        let raw = rand::random::<[u8; 16]>()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let code = raw
            .as_bytes()
            .chunks(8)
            .map(|c| std::str::from_utf8(c).expect("hex"))
            .collect::<Vec<_>>()
            .join("-");
        toasty::create!(RecoveryCode {
            user_id: target.id,
            hash: recovery_hash(target.id, &code)
        })
        .exec(&mut tx)
        .await?;
        codes.push(code);
    }
    changed(
        &mut tx,
        &target,
        ctx.actor,
        ctx.keep(),
        "Regenerated backup codes",
        "backup",
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(codes)
}
pub(crate) fn recovery_hash(user_id: i64, code: &str) -> String {
    let normalized = code
        .chars()
        .filter(|c| *c != '-' && !c.is_ascii_whitespace())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    hash(&format!("{user_id}:{normalized}"))
}

pub(crate) async fn remove(core: &Core, ctx: &Context, kind: &str, id: i64) -> Result<()> {
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let target = ctx.authorize(&mut tx).await?;
    let totps = TotpAuthenticator::filter(TotpAuthenticator::fields().user_id().eq(target.id))
        .exec(&mut tx)
        .await?;
    let keys = WebauthnCredential::filter(WebauthnCredential::fields().user_id().eq(target.id))
        .exec(&mut tx)
        .await?;
    if totps.len() + keys.len() <= 1 {
        return Err(invalid(
            "Use Disable MFA to remove the final method and its backup codes.",
        ));
    }
    match kind {
        "totp" if totps.iter().any(|r| r.id == id) => {
            TotpAuthenticator::filter_by_id(id)
                .delete()
                .exec(&mut tx)
                .await?;
        }
        "webauthn" if keys.iter().any(|r| r.id == id) => {
            WebauthnCredential::filter_by_id(id)
                .delete()
                .exec(&mut tx)
                .await?;
        }
        _ => {
            return Err(invalid(
                "This method does not belong to the selected account.",
            ));
        }
    }
    changed(
        &mut tx,
        &target,
        ctx.actor,
        ctx.keep(),
        "Removed MFA method",
        kind,
        Some(id),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
pub(crate) async fn rename(
    core: &Core,
    ctx: &Context,
    kind: &str,
    id: i64,
    label: &str,
) -> Result<()> {
    let label = name(label)?;
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let target = ctx.authorize(&mut tx).await?;
    match kind {
        "totp" => {
            let record = TotpAuthenticator::get_by_id(&mut tx, id).await?;
            if record.user_id != target.id {
                return Err(invalid("This method belongs to another account."));
            }
            TotpAuthenticator::filter_by_id(id)
                .update()
                .name(label)
                .exec(&mut tx)
                .await?;
        }
        "webauthn" => {
            let record = WebauthnCredential::get_by_id(&mut tx, id).await?;
            if record.user_id != target.id {
                return Err(invalid("This method belongs to another account."));
            }
            WebauthnCredential::filter_by_id(id)
                .update()
                .name(label)
                .exec(&mut tx)
                .await?;
        }
        _ => return Err(invalid("Unknown MFA method.")),
    }
    event(
        &mut tx,
        ctx.actor,
        target.id,
        "Renamed MFA method",
        kind,
        Some(id),
        "Succeeded",
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
pub(crate) async fn reset(core: &Core, ctx: &Context) -> Result<()> {
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let target = ctx.authorize(&mut tx).await?;
    TotpAuthenticator::filter(TotpAuthenticator::fields().user_id().eq(target.id))
        .delete()
        .exec(&mut tx)
        .await?;
    WebauthnCredential::filter(WebauthnCredential::fields().user_id().eq(target.id))
        .delete()
        .exec(&mut tx)
        .await?;
    RecoveryCode::filter(RecoveryCode::fields().user_id().eq(target.id))
        .delete()
        .exec(&mut tx)
        .await?;
    changed(&mut tx, &target, ctx.actor, None, "Reset MFA", "all", None).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn confirm_totp(
    core: &Core,
    ctx: &Context,
    token: &str,
    code: &str,
) -> Result<()> {
    let result = confirm_totp_inner(core, ctx, token, code).await;
    if let Err(error) = &result {
        rejected(core, token, error).await;
    }
    result
}
pub(crate) async fn finish_key(
    core: &Core,
    ctx: &Context,
    token: &str,
    credential: RegisterPublicKeyCredential,
) -> Result<()> {
    let result = finish_key_inner(core, ctx, token, credential).await;
    if let Err(error) = &result {
        rejected(core, token, error).await;
    }
    result
}
