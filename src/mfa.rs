use crate::{models::*, token::generate_token};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

pub(crate) mod auth;
pub(crate) mod manage;
pub(crate) const PENDING_COOKIE: &str = "mfa_pending";
pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub(crate) struct Error(pub axum::http::StatusCode, pub &'static str);
impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        (
            self.0,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            axum::Json(json!({"error":self.1})),
        )
            .into_response()
    }
}
impl From<toasty::Error> for Error {
    fn from(error: toasty::Error) -> Self {
        if error.is_record_not_found() {
            return invalid("This request has expired or is no longer available.");
        }
        eprintln!("MFA database operation failed: {error}");
        Self(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to save security changes.",
        )
    }
}
pub(crate) fn invalid(message: &'static str) -> Error {
    Error(axum::http::StatusCode::BAD_REQUEST, message)
}
pub(crate) fn now() -> jiff::Timestamp {
    jiff::Timestamp::now()
}
pub(crate) fn expiry() -> jiff::Timestamp {
    jiff::Timestamp::from_second(now().as_second() + 300).expect("five-minute expiry")
}
pub(crate) fn hash(value: &str) -> String {
    crate::provider::oauth2::hash_token(value)
}

fn cipher() -> Result<Aes256Gcm> {
    let raw = std::env::var("MFA_ENCRYPTION_KEY")
        .map_err(|_| invalid("Set MFA_ENCRYPTION_KEY before using authenticator apps."))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| invalid("MFA_ENCRYPTION_KEY must be a base64url-encoded 32-byte key."))?;
    Aes256Gcm::new_from_slice(&bytes)
        .map_err(|_| invalid("MFA_ENCRYPTION_KEY must be a base64url-encoded 32-byte key."))
}
fn seal(user_id: i64, secret: &str) -> Result<String> {
    let nonce = rand::random::<[u8; 12]>();
    let aad = format!("guard:totp:{user_id}");
    let encrypted = cipher()?
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: secret.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| invalid("Unable to protect the authenticator secret."))?;
    let mut value = nonce.to_vec();
    value.extend(encrypted);
    Ok(URL_SAFE_NO_PAD.encode(value))
}
fn unseal(user_id: i64, value: &str) -> Result<String> {
    let value = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("Unable to read this authenticator secret."))?;
    if value.len() < 28 {
        return Err(invalid("Unable to read this authenticator secret."));
    }
    let aad = format!("guard:totp:{user_id}");
    let bytes = cipher()?
        .decrypt(
            (&value[..12]).into(),
            Payload {
                msg: &value[12..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| invalid("Unable to decrypt this authenticator. Check MFA_ENCRYPTION_KEY."))?;
    String::from_utf8(bytes).map_err(|_| invalid("Unable to read this authenticator secret."))
}
fn totp(secret: &str, username: &str) -> Result<totp_rs::Totp> {
    let secret = totp_rs::Secret::try_from_base32(secret)
        .map_err(|_| invalid("Invalid authenticator configuration."))?;
    totp_rs::Builder::new()
        .with_secret(secret)
        .with_issuer(Some("Guard"))
        .with_account_name(username.replace(':', "_"))
        .build()
        .map_err(|_| invalid("Invalid authenticator configuration."))
}
pub(crate) fn webauthn(core: &crate::core::Core) -> Result<webauthn_rs::Webauthn> {
    let url = reqwest::Url::parse(&core.domain)
        .map_err(|_| invalid("DOMAIN is not a valid WebAuthn origin."))?;
    let host = url
        .host_str()
        .ok_or_else(|| invalid("DOMAIN needs a hostname for security keys."))?;
    if url.scheme() != "https" && !(url.scheme() == "http" && host == "localhost") {
        return Err(invalid(
            "Security keys require HTTPS, or http://localhost for development.",
        ));
    }
    let origin = reqwest::Url::parse(&url.origin().ascii_serialization())
        .map_err(|_| invalid("Invalid WebAuthn origin."))?;
    webauthn_rs::WebauthnBuilder::new(host, &origin)
        .map_err(|_| invalid("Invalid WebAuthn relying party configuration."))?
        .rp_name("Guard")
        .build()
        .map_err(|_| invalid("Unable to configure security keys."))
}
pub(crate) async fn enabled(db: &mut dyn toasty::Executor, user_id: i64) -> Result<bool> {
    Ok(
        !TotpAuthenticator::filter(TotpAuthenticator::fields().user_id().eq(user_id))
            .exec(&mut *db)
            .await?
            .is_empty()
            || !WebauthnCredential::filter(WebauthnCredential::fields().user_id().eq(user_id))
                .exec(db)
                .await?
                .is_empty(),
    )
}
pub(crate) async fn user(db: &mut dyn toasty::Executor, id: i64) -> Result<User> {
    let user = User::get_by_id(db, id).await?;
    if user.disabled || user.deleted_at.is_some() {
        return Err(invalid("This account is not available for sign-in."));
    }
    Ok(user)
}
pub(crate) async fn event(
    db: &mut dyn toasty::Executor,
    actor: i64,
    subject: i64,
    action: &str,
    method: &str,
    record: Option<i64>,
    outcome: &str,
) -> Result<()> {
    crate::audit::record(
        db,
        actor,
        AuditLogEntry::Mfa {
            action: action.into(),
            subject_id: subject,
            method: method.into(),
            record_id: record,
            outcome: outcome.into(),
        },
    )
    .await?;
    Ok(())
}
pub(crate) async fn ceremony(
    db: &mut dyn toasty::Executor,
    user: &User,
    actor: i64,
    session: Option<i64>,
    login_session: Option<i64>,
    purpose: &str,
    state: Value,
) -> Result<String> {
    let token = generate_token();
    toasty::create!(MfaCeremony {
        token_hash: hash(&token),
        user_id: user.id,
        actor_id: actor,
        session_id: session,
        login_session_id: login_session,
        revision: user.mfa_revision,
        purpose: purpose,
        state: toasty::Json(state),
        expires_at: expiry()
    })
    .exec(db)
    .await?;
    Ok(token)
}
pub(crate) async fn load_ceremony(
    db: &mut dyn toasty::Executor,
    token: &str,
    purpose: &str,
) -> Result<MfaCeremony> {
    let value = MfaCeremony::get_by_token_hash(&mut *db, hash(token)).await?;
    if value.purpose != purpose
        || value.consumed_at.is_some()
        || value.expires_at <= now()
        || value.attempts >= 5
    {
        return Err(invalid("This security request has expired. Start again."));
    }
    let user = user(db, value.user_id).await?;
    if user.mfa_revision != value.revision {
        return Err(invalid("Security settings have changed. Start again."));
    }
    Ok(value)
}
pub(crate) async fn changed(
    db: &mut dyn toasty::Executor,
    target: &User,
    actor: i64,
    keep_session: Option<i64>,
    action: &str,
    method: &str,
    record: Option<i64>,
) -> Result<()> {
    User::filter_by_id(target.id)
        .update()
        .mfa_revision(target.mfa_revision + 1)
        .exec(&mut *db)
        .await?;
    MfaCeremony::filter(MfaCeremony::fields().user_id().eq(target.id))
        .delete()
        .exec(&mut *db)
        .await?;
    // Preserve only the initiating, recently authenticated owner session. Other
    // sessions and all sessions after an administrator's reset are revoked.
    let sessions = Session::filter(Session::fields().user_id().eq(target.id))
        .exec(&mut *db)
        .await?;
    for session in sessions {
        if Some(session.id) != keep_session {
            Session::filter_by_id(session.id)
                .delete()
                .exec(&mut *db)
                .await?;
        }
    }
    event(db, actor, target.id, action, method, record, "Succeeded").await
}
pub(crate) fn name(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 100 || value.chars().any(char::is_control) {
        return Err(invalid("Enter a name of 1–100 characters."));
    }
    Ok(value.into())
}

pub(crate) async fn invalidate_logins(
    db: &mut dyn toasty::Executor,
    user_id: i64,
) -> toasty::Result<()> {
    let current = User::get_by_id(&mut *db, user_id).await?;
    User::filter_by_id(user_id)
        .update()
        .mfa_revision(current.mfa_revision + 1)
        .exec(&mut *db)
        .await?;
    MfaCeremony::filter(MfaCeremony::fields().user_id().eq(user_id))
        .delete()
        .exec(db)
        .await?;
    Ok(())
}

// Authentication transactions are dropped before this separate rejection write.
// Only persisted, known-account ceremonies can produce an event here.
pub(crate) async fn rejected(core: &crate::core::Core, token: &str, error: &Error) {
    if !matches!(
        error.1,
        "This security request has expired. Start again."
            | "Security settings have changed. Start again."
    ) {
        return;
    }
    if let Ok(ticket) = MfaCeremony::get_by_token_hash(&mut core.db.clone(), hash(token)).await {
        let revision_changed = User::get_by_id(&mut core.db.clone(), ticket.user_id)
            .await
            .is_ok_and(|user| user.mfa_revision != ticket.revision);
        if ticket.consumed_at.is_none()
            && ticket.expires_at > now()
            && ticket.attempts < 5
            && !revision_changed
        {
            return;
        }
        crate::audit::best_effort(
            core,
            ticket.actor_id,
            AuditLogEntry::Mfa {
                action: "Rejected MFA ceremony".into(),
                subject_id: ticket.user_id,
                method: ticket.purpose,
                record_id: Some(ticket.id),
                outcome: "Expired, consumed or invalidated".into(),
            },
        )
        .await;
    }
}
