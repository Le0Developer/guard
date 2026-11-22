use super::oauth2::{self, OAuthError, access};
use crate::{core::Core, models::*, token::generate_token};
use axum::http::StatusCode;
use reqwest::Url;
use std::collections::HashMap;
use toasty_core::driver::operation::TransactionMode;

pub(crate) type Result<T> = oauth2::Result<T>;
pub(crate) fn session_cookie(client_id: i64, origin: &str) -> String {
    format!(
        "{}guard_forwardauth_session_{client_id}_{}",
        cookie_prefix(origin),
        &hash(origin)[..16]
    )
}
pub(crate) const CALLBACK: &str = "/.guard/login";
pub(crate) fn hash(value: &str) -> String {
    oauth2::hash_token(value)
}
pub(crate) fn denied(message: &str) -> OAuthError {
    OAuthError {
        status: StatusCode::FORBIDDEN,
        code: "access_denied",
        description: message.into(),
    }
}
fn invalid(message: &str) -> OAuthError {
    OAuthError::new("invalid_request", message)
}
fn now() -> jiff::Timestamp {
    jiff::Timestamp::now()
}
fn at(seconds: i64) -> Result<jiff::Timestamp> {
    jiff::Timestamp::from_second(seconds).map_err(|_| invalid("Invalid session lifetime."))
}

pub(crate) fn parse_url(value: &str) -> Result<Url> {
    if value.len() > 16384
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
        || value.contains('\\')
    {
        return Err(invalid("Invalid application URL."));
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return Err(invalid("Use an absolute HTTP or HTTPS application URL."));
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https")
        || rest.split(['/', '?', '#']).next().is_none_or(str::is_empty)
    {
        return Err(invalid("Invalid application origin."));
    }
    let url = Url::parse(value).map_err(|_| invalid("Invalid application URL."))?;
    if url.host_str().is_none_or(|host| host.contains('*'))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid("Invalid application origin."));
    }
    Ok(url)
}
pub(crate) fn origin(value: &str) -> Result<String> {
    Ok(parse_url(value)?.origin().ascii_serialization())
}
fn validate_state(state: &str) -> Result<()> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(state)
        .map_err(|_| invalid("Invalid ForwardAuth state."))?;
    if bytes.len() != 32 {
        return Err(invalid("Invalid ForwardAuth state."));
    }
    Ok(())
}
fn cookie_prefix(origin: &str) -> &'static str {
    if origin.starts_with("https://") {
        "__Host-"
    } else {
        ""
    }
}
pub(crate) fn flow_cookie(state: &str, origin: &str) -> Result<String> {
    validate_state(state)?;
    Ok(format!(
        "{}guard_forwardauth_flow_{state}",
        cookie_prefix(origin)
    ))
}
pub(crate) async fn client(db: &mut dyn toasty::Executor, id: i64) -> Result<Client> {
    let client = Client::get_by_id(db, id).await?;
    if client.deleted_at.is_some() || !matches!(client.client_type, ClientType::ForwardAuth) {
        return Err(denied("This ForwardAuth client is not available."));
    }
    Ok(client)
}
pub(crate) async fn allowed(
    db: &mut dyn toasty::Executor,
    client: &Client,
    requested: &str,
) -> Result<bool> {
    let requested = origin(requested)?;
    Ok(
        ClientRedirect::filter(ClientRedirect::fields().client_id().eq(client.id))
            .exec(db)
            .await?
            .iter()
            .any(|entry| origin(&entry.redirect_uri).is_ok_and(|value| value == requested)),
    )
}
pub(crate) async fn for_origin(db: &mut dyn toasty::Executor, requested: &str) -> Result<Client> {
    let clients = Client::all().exec(&mut *db).await?;
    let mut found = None;
    for client in clients {
        if client.deleted_at.is_some() || !matches!(client.client_type, ClientType::ForwardAuth) {
            continue;
        }
        if allowed(&mut *db, &client, requested).await? {
            if found.is_some() {
                return Err(invalid(
                    "More than one ForwardAuth client allows this origin.",
                ));
            }
            found = Some(client);
        }
    }
    found.ok_or_else(|| denied("No ForwardAuth client allows this application origin."))
}

pub(crate) struct Start {
    pub state: String,
    pub browser: String,
    pub authorize_url: String,
}
pub(crate) async fn start(core: &Core, client: &Client, return_uri: &str) -> Result<Start> {
    let original = parse_url(return_uri)?;
    let origin = original.origin().ascii_serialization();
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let current = self::client(&mut tx, client.id).await?;
    if !allowed(&mut tx, &current, &origin).await? {
        return Err(denied("This application origin is no longer registered."));
    }
    let state = generate_token();
    let browser = generate_token();
    toasty::create!(ForwardAuthRequest {
        state_hash: hash(&state),
        browser_hash: hash(&browser),
        code_hash: hash(&generate_token()),
        client_id: current.id,
        origin: &origin,
        return_uri: return_uri,
        expires_at: at(now().as_second() + 300)?
    })
    .exec(&mut tx)
    .await?;
    tx.commit().await?;
    let query = serde_urlencoded::to_string([
        ("client_id", current.client_id.as_str()),
        ("client_type", "forwardauth"),
        ("redirect_uri", origin.as_str()),
        ("response_type", "code"),
        ("state", state.as_str()),
    ])
    .expect("string fields serialize");
    let authorize_url = format!(
        "{}/oauth2/authorize?{query}",
        core.domain.trim_end_matches('/')
    );
    Ok(Start {
        state,
        browser,
        authorize_url,
    })
}
pub(crate) async fn validate_authorization(
    db: &mut dyn toasty::Executor,
    client: &Client,
    fields: &HashMap<String, String>,
) -> Result<ForwardAuthRequest> {
    if fields.get("client_type").map(String::as_str) != Some("forwardauth")
        || fields.get("response_type").map(String::as_str) != Some("code")
    {
        return Err(invalid(
            "Use client_type=forwardauth and response_type=code.",
        ));
    }
    let state = oauth2::required(fields, "state")?;
    validate_state(&state)?;
    let request = ForwardAuthRequest::get_by_state_hash(&mut *db, hash(&state))
        .await
        .map_err(|e| {
            if e.is_record_not_found() {
                invalid("Unknown ForwardAuth request.")
            } else {
                e.into()
            }
        })?;
    let redirect = oauth2::required(fields, "redirect_uri")?;
    if request.client_id != client.id
        || request.origin != origin(&redirect)?
        || request.consumed_at.is_some()
        || request.expires_at <= now()
    {
        return Err(invalid(
            "This ForwardAuth authorization request has expired or does not match the client/origin.",
        ));
    }
    let parsed = parse_url(&redirect)?;
    if parsed.path() != "/" || parsed.query().is_some() {
        return Err(invalid(
            "ForwardAuth redirect_uri must be the application origin.",
        ));
    }
    if !allowed(db, client, &request.origin).await? {
        return Err(denied("This application origin is no longer allowed."));
    }
    Ok(request)
}
pub(crate) async fn authorize(
    core: &Core,
    client: &Client,
    user: &User,
    session: &Session,
    fields: &HashMap<String, String>,
) -> Result<String> {
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let client = self::client(&mut tx, client.id).await?;
    let request = validate_authorization(&mut tx, &client, fields).await?;
    let (user, session) = access::user_session(&mut tx, session.id, user.id).await?;
    if !access::permitted(&mut tx, &client, &user).await? {
        return Err(denied("This user cannot access this application."));
    }
    let code = generate_token();
    ForwardAuthRequest::filter_by_id(request.id)
        .update()
        .code_hash(hash(&code))
        .user_id(user.id)
        .session_id(session.id)
        .exec(&mut tx)
        .await?;
    crate::audit::record(
        &mut tx,
        user.id,
        AuditLogEntry::ForwardAuth {
            action: "ForwardAuth authorized".into(),
            client_id: client.id,
            session_id: session.id,
        },
    )
    .await?;
    tx.commit().await?;
    let query =
        serde_urlencoded::to_string([("code", code.as_str()), ("state", fields["state"].as_str())])
            .expect("string fields serialize");
    Ok(format!("{}{CALLBACK}?{query}", request.origin))
}
pub(crate) struct Complete {
    pub token: String,
    pub return_uri: String,
    pub lifetime: i64,
    pub client_id: i64,
    pub user_id: i64,
    pub guard_session_id: i64,
    pub forward_session_id: i64,
}
pub(crate) async fn finish(
    core: &Core,
    external_origin: &str,
    state: &str,
    code: &str,
    browser: &str,
) -> Result<Complete> {
    validate_state(state)?;
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let request = ForwardAuthRequest::get_by_state_hash(&mut tx, hash(state))
        .await
        .map_err(|e| {
            if e.is_record_not_found() {
                invalid("Unknown ForwardAuth request.")
            } else {
                e.into()
            }
        })?;
    if request.consumed_at.is_some()
        || request.expires_at <= now()
        || request.origin != external_origin
        || !oauth2::secret_eq(&request.code_hash, &hash(code))
        || !oauth2::secret_eq(&request.browser_hash, &hash(browser))
    {
        return Err(invalid("Invalid or expired ForwardAuth callback."));
    }
    let client = self::client(&mut tx, request.client_id).await?;
    if !allowed(&mut tx, &client, external_origin).await?
        || origin(&request.return_uri)? != external_origin
    {
        return Err(denied("This application origin is no longer allowed."));
    }
    let user_id = request
        .user_id
        .ok_or_else(|| invalid("ForwardAuth authorization is incomplete."))?;
    let session_id = request
        .session_id
        .ok_or_else(|| invalid("ForwardAuth authorization is incomplete."))?;
    let (user, session) = access::user_session(&mut tx, session_id, user_id).await?;
    if !access::permitted(&mut tx, &client, &user).await? {
        return Err(denied("This user cannot access this application."));
    }
    let expires = (now().as_second() + i64::from(client.session_lifetime_s))
        .min(crate::session::expires_at(&session));
    if expires <= now().as_second() {
        return Err(invalid("The Guard session has expired."));
    }
    let token = generate_token();
    ForwardAuthRequest::filter_by_id(request.id)
        .update()
        .consumed_at(now())
        .return_uri("")
        .exec(&mut tx)
        .await?;
    let issued = toasty::create!(ForwardAuthSession {
        token_hash: hash(&token),
        client_id: client.id,
        user_id: user.id,
        session_id: session.id,
        origin: external_origin,
        expires_at: at(expires)?
    })
    .exec(&mut tx)
    .await?;
    crate::audit::record(
        &mut tx,
        user.id,
        AuditLogEntry::ForwardAuth {
            action: "ForwardAuth session created".into(),
            client_id: client.id,
            session_id: session.id,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Complete {
        token,
        return_uri: request.return_uri,
        lifetime: expires - now().as_second(),
        client_id: client.id,
        user_id: user.id,
        guard_session_id: session.id,
        forward_session_id: issued.id,
    })
}
pub(crate) struct Identity {
    pub user: User,
    pub guard_session_id: i64,
    pub forward_session_id: i64,
}
pub(crate) async fn check(
    core: &Core,
    client: &Client,
    external_origin: &str,
    raw: &str,
) -> Result<Option<Identity>> {
    let mut db = core.db.clone();
    let session = match ForwardAuthSession::get_by_token_hash(&mut db, hash(raw)).await {
        Ok(value) => value,
        Err(e) if e.is_record_not_found() => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if session.client_id != client.id
        || session.origin != external_origin
        || session.expires_at <= now()
    {
        return Ok(None);
    }
    let (user, _) = match access::user_session(&mut db, session.session_id, session.user_id).await {
        Ok(value) => value,
        Err(e) if e.code == "invalid_grant" => return Ok(None),
        Err(e) => return Err(e),
    };
    if !access::permitted(&mut db, client, &user).await? {
        return Err(denied("This user cannot access this application."));
    }
    Ok(Some(Identity {
        user,
        guard_session_id: session.session_id,
        forward_session_id: session.id,
    }))
}
