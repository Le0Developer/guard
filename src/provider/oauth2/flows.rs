use super::*;
use crate::{
    models::{AuditLogEntry, ClientCryptographicKey, OAuthToken, Session, User},
    token::generate_token,
};
use serde::Serialize;
use serde_json::Value;
use toasty::stmt::IntoStatement;
use toasty_core::driver::operation::TransactionMode;

#[derive(Serialize)]
pub(crate) struct TokenResponse {
    #[serde(skip)]
    pub(crate) journal_subject: (i64, i64, i64),
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    refresh_token: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

pub(crate) async fn issue_code(
    db: &mut dyn toasty::Executor,
    client: &Client,
    user: &User,
    session: &Session,
    request: OAuth2AuthorizationRequest,
) -> Result<(String, i64)> {
    let code = generate_token();
    let expiry = timestamp(jiff::Timestamp::now().as_second() + CODE_LIFETIME)?;
    let issued = toasty::create!(ClientToken {
        client_id: client.id,
        user_id: user.id,
        token: hash_token(&code),
        redirect_uri: request.redirect_uri,
        pkce_challenge: request.challenge,
        scope: request.scope.join(" "),
        nonce: request.nonce,
        session_id: session.id,
        expires_at: expiry
    })
    .exec(&mut *db)
    .await?;
    crate::audit::record(
        db,
        user.id,
        AuditLogEntry::OAuthAuthorization {
            client_id: client.id,
            session_id: session.id,
        },
    )
    .await?;
    Ok((code, issued.id))
}

fn timestamp(second: i64) -> Result<jiff::Timestamp> {
    jiff::Timestamp::from_second(second)
        .map_err(|_| OAuthError::new("server_error", "Invalid token lifetime configuration."))
}

pub(crate) async fn redeem(
    core: &Core,
    client: &Client,
    request: OAuth2TokenRequest,
) -> Result<TokenResponse> {
    let mut db = core.db.clone();
    let signing_key = keys::ensure(&mut db, client).await?;
    // Claim the SQLite write lock before reading the grant. This avoids
    // two deferred transactions both reading an unconsumed code then deadlocking.
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let fresh = access::client(&mut tx, &client.slug).await?;
    if !secret_eq(&fresh.client_secret, &client.client_secret) {
        return Err(OAuthError::invalid_client());
    }
    let code = ClientToken::get_by_token(&mut tx, hash_token(&request.code))
        .await
        .map_err(|e| {
            if e.is_record_not_found() {
                OAuthError::invalid_grant()
            } else {
                e.into()
            }
        })?;
    request.valid(&fresh, &code)?;
    if code.consumed_at.is_some() {
        OAuthToken::filter(OAuthToken::fields().code_id().eq(code.id))
            .update()
            .revoked_at(jiff::Timestamp::now())
            .exec(&mut tx)
            .await?;
        crate::audit::record(
            &mut tx,
            code.user_id,
            AuditLogEntry::OAuthReplayDetected {
                client_id: fresh.id,
                session_id: code.session_id,
                grant: "authorization code".into(),
            },
        )
        .await?;
        tx.commit().await?;
        return Err(OAuthError::invalid_grant());
    }
    let now = jiff::Timestamp::now();
    if code.expires_at <= now {
        return Err(OAuthError::invalid_grant());
    }
    let (user, session) = access::user_session(&mut tx, code.session_id, code.user_id).await?;
    if !access::permitted(&mut tx, &fresh, &user).await? {
        return Err(OAuthError::invalid_grant());
    }
    let claim = ClientToken::filter(
        ClientToken::fields()
            .id()
            .eq(code.id)
            .and(ClientToken::fields().consumed_at().is_none()),
    )
    .update()
    .consumed_at(now);
    if !claim_rows(&mut tx, claim).await? {
        OAuthToken::filter(OAuthToken::fields().code_id().eq(code.id))
            .update()
            .revoked_at(jiff::Timestamp::now())
            .exec(&mut tx)
            .await?;
        crate::audit::record(
            &mut tx,
            code.user_id,
            AuditLogEntry::OAuthReplayDetected {
                client_id: fresh.id,
                session_id: code.session_id,
                grant: "authorization code".into(),
            },
        )
        .await?;
        tx.commit().await?;
        return Err(OAuthError::invalid_grant());
    }
    let expires = timestamp(
        (now.as_second() + i64::from(fresh.session_lifetime_s))
            .min(crate::session::expires_at(&session)),
    )?;
    let response = mint(
        core,
        &mut tx,
        &fresh,
        &user,
        session.id,
        code.id,
        generate_token(),
        code.scope,
        code.nonce,
        session.created_at.as_second(),
        expires,
        &signing_key,
    )
    .await?;
    crate::audit::record(
        &mut tx,
        user.id,
        AuditLogEntry::OAuthTokenIssued {
            client_id: fresh.id,
            session_id: session.id,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub(crate) async fn refresh(
    core: &Core,
    client: &Client,
    raw_refresh: &str,
    requested_scope: Option<&str>,
) -> Result<TokenResponse> {
    let mut db = core.db.clone();
    let signing_key = keys::ensure(&mut db, client).await?;
    // Claim the SQLite write lock before reading the grant. This avoids
    // two deferred transactions both reading an unconsumed code then deadlocking.
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let fresh = access::client(&mut tx, &client.slug).await?;
    if !secret_eq(&fresh.client_secret, &client.client_secret) {
        return Err(OAuthError::invalid_client());
    }
    let previous = OAuthToken::get_by_refresh_token(&mut tx, hash_token(raw_refresh))
        .await
        .map_err(|e| {
            if e.is_record_not_found() {
                OAuthError::invalid_grant()
            } else {
                e.into()
            }
        })?;
    if previous.client_id != fresh.id {
        return Err(OAuthError::invalid_grant());
    }
    if previous.revoked_at.is_some() {
        revoke_family(&mut tx, &previous.family).await?;
        crate::audit::record(
            &mut tx,
            previous.user_id,
            AuditLogEntry::OAuthReplayDetected {
                client_id: fresh.id,
                session_id: previous.session_id,
                grant: "refresh token".into(),
            },
        )
        .await?;
        tx.commit().await?;
        return Err(OAuthError::invalid_grant());
    }
    if previous.expires_at <= jiff::Timestamp::now() {
        return Err(OAuthError::invalid_grant());
    }
    let (user, session) =
        access::user_session(&mut tx, previous.session_id, previous.user_id).await?;
    if !access::permitted(&mut tx, &fresh, &user).await? {
        return Err(OAuthError::invalid_grant());
    }
    let scope = if let Some(requested) = requested_scope {
        if !requested
            .split_whitespace()
            .all(|s| previous.scope.split_whitespace().any(|old| old == s))
        {
            return Err(OAuthError::new(
                "invalid_scope",
                "Refresh cannot expand the authorized scopes.",
            ));
        }
        requested.split_whitespace().collect::<Vec<_>>().join(" ")
    } else {
        previous.scope.clone()
    };
    let claim = OAuthToken::filter(
        OAuthToken::fields()
            .id()
            .eq(previous.id)
            .and(OAuthToken::fields().revoked_at().is_none()),
    )
    .update()
    .revoked_at(jiff::Timestamp::now());
    if !claim_rows(&mut tx, claim).await? {
        revoke_family(&mut tx, &previous.family).await?;
        crate::audit::record(
            &mut tx,
            previous.user_id,
            AuditLogEntry::OAuthReplayDetected {
                client_id: fresh.id,
                session_id: previous.session_id,
                grant: "refresh token".into(),
            },
        )
        .await?;
        tx.commit().await?;
        return Err(OAuthError::invalid_grant());
    }
    let response = mint(
        core,
        &mut tx,
        &fresh,
        &user,
        previous.session_id,
        previous.code_id,
        previous.family,
        scope,
        previous.nonce,
        previous.auth_time,
        timestamp(
            previous
                .expires_at
                .as_second()
                .min(crate::session::expires_at(&session)),
        )?,
        &signing_key,
    )
    .await?;
    crate::audit::record(
        &mut tx,
        user.id,
        AuditLogEntry::OAuthTokenRefreshed {
            client_id: fresh.id,
            session_id: previous.session_id,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

async fn mint(
    core: &Core,
    db: &mut dyn toasty::Executor,
    client: &Client,
    user: &User,
    session_id: i64,
    code_id: i64,
    family: String,
    scope: String,
    nonce: Option<String>,
    auth_time: i64,
    expires_at: jiff::Timestamp,
    signing_key: &ClientCryptographicKey,
) -> Result<TokenResponse> {
    let now = jiff::Timestamp::now().as_second();
    let access_expires_at = timestamp((now + ACCESS_LIFETIME).min(expires_at.as_second()))?;
    if access_expires_at.as_second() <= now {
        return Err(OAuthError::invalid_grant());
    }
    let access_token = generate_token();
    let refresh_token = generate_token();
    let mut claims = identity(user, &scope);
    claims["iss"] = issuer(core, client)?.into();
    claims["aud"] = client.client_id.clone().into();
    claims["iat"] = now.into();
    claims["exp"] = access_expires_at.as_second().into();
    claims["auth_time"] = auth_time.into();
    if let Some(nonce) = &nonce {
        claims["nonce"] = nonce.clone().into();
    }
    let id_token = if scope.split_whitespace().any(|s| s == "openid") {
        Some(keys::sign(signing_key, claims).await?)
    } else {
        None
    };
    toasty::create!(OAuthToken {
        client_id: client.id,
        user_id: user.id,
        session_id: session_id,
        code_id: code_id,
        family: family,
        access_token: hash_token(&access_token),
        refresh_token: hash_token(&refresh_token),
        scope: &scope,
        nonce: nonce,
        auth_time: auth_time,
        access_expires_at: access_expires_at,
        expires_at: expires_at
    })
    .exec(db)
    .await?;
    Ok(TokenResponse {
        journal_subject: (user.id, session_id, code_id),
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in: access_expires_at.as_second() - now,
        scope,
        id_token,
    })
}

fn identity(user: &User, scope: &str) -> Value {
    let mut identity = json!({ "sub": user.id.to_string() });
    if scope.split_whitespace().any(|s| s == "profile") {
        identity["preferred_username"] = user.username.clone().into();
        identity["name"] = user.username.clone().into();
    }
    if scope.split_whitespace().any(|s| s == "email") {
        if let Some(email) = &user.email {
            identity["email"] = email.clone().into();
        }
    }
    identity
}

pub(crate) async fn userinfo(core: &Core, client: &Client, bearer: &str) -> Result<Value> {
    let mut db = core.db.clone();
    let token = OAuthToken::get_by_access_token(&mut db, hash_token(bearer))
        .await
        .map_err(|e| {
            if e.is_record_not_found() {
                OAuthError::invalid_token()
            } else {
                e.into()
            }
        })?;
    let now = jiff::Timestamp::now();
    if token.client_id != client.id
        || token.revoked_at.is_some()
        || token.access_expires_at <= now
        || token.expires_at <= now
    {
        return Err(OAuthError::invalid_token());
    }
    let (user, _) = access::user_session(&mut db, token.session_id, token.user_id)
        .await
        .map_err(|e| {
            if e.code == "invalid_grant" {
                OAuthError::invalid_token()
            } else {
                e
            }
        })?;
    if !access::permitted(&mut db, client, &user).await? {
        return Err(OAuthError::invalid_token());
    }
    if !token.scope.split_whitespace().any(|s| s == "openid") {
        return Err(OAuthError {
            status: StatusCode::FORBIDDEN,
            code: "insufficient_scope",
            description: "The openid scope is required for userinfo.".into(),
        });
    }
    Ok(identity(&user, &token.scope))
}

pub(crate) async fn revoke(
    core: &Core,
    client: &Client,
    raw: &str,
) -> Result<Option<(i64, i64, i64)>> {
    let hash = hash_token(raw);
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let matches = OAuthToken::filter(
        OAuthToken::fields().client_id().eq(client.id).and(
            OAuthToken::fields()
                .access_token()
                .eq(&hash)
                .or(OAuthToken::fields().refresh_token().eq(&hash)),
        ),
    )
    .exec(&mut tx)
    .await?;
    let subject = matches
        .first()
        .map(|token| (token.user_id, token.session_id, token.code_id));
    for token in matches {
        revoke_family(&mut tx, &token.family).await?;
        crate::audit::record(
            &mut tx,
            token.user_id,
            AuditLogEntry::OAuthTokenRevoked {
                client_id: client.id,
                session_id: token.session_id,
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(subject)
}

async fn revoke_family(db: &mut dyn toasty::Executor, family: &str) -> Result<()> {
    OAuthToken::filter(OAuthToken::fields().family().eq(family))
        .update()
        .revoked_at(jiff::Timestamp::now())
        .exec(db)
        .await?;
    Ok(())
}

// The generated update builder discards returned rows. Inspect the conditional
// update's result so a competing redemption cannot mint another token pair.
async fn claim_rows(
    db: &mut dyn toasty::Executor,
    update: impl IntoStatement<Returning = ()>,
) -> Result<bool> {
    use toasty::stmt::Value;
    let response = db
        .exec_untyped(update.into_statement().into_untyped())
        .await?;
    let value = response.values.collect_as_value().await?;
    match value {
        Value::List(rows) => Ok(!rows.is_empty()),
        Value::U64(count) => Ok(count > 0),
        Value::I64(count) => Ok(count > 0),
        _ => Err(OAuthError::new(
            "server_error",
            "Unable to claim the grant.",
        )),
    }
}
