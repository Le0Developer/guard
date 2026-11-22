use crate::{
    core::Core,
    journal::Capture,
    models::{Client, ClientRedirect, ClientType, OAuthToken},
    provider::oauth2::{
        self, OAuth2AuthorizationRequest, OAuth2TokenRequest, OAuthError, access, flows, keys,
    },
    server::cookies::LOGIN_COOKIE_NAME,
};
use axum::{
    Extension, Form, Json, Router,
    extract::{Path, RawQuery, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::CookieJar;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};

pub fn routes(core: Arc<Core>) -> Router<Arc<Core>> {
    Router::new()
        .route(
            "/oauth2/{slug}/.well-known/openid-configuration",
            get(discovery).options(preflight),
        )
        .route("/oauth2/authorize", get(authorize))
        .route("/oauth2/token", post(token).options(preflight))
        .route("/oauth2/{slug}/jwks", get(jwks).options(preflight))
        .route(
            "/oauth2/userinfo",
            get(userinfo).post(userinfo).options(preflight),
        )
        .route("/oauth2/revoke", post(revoke).options(preflight))
        .route(
            "/oauth2/event",
            post(event).layer(axum::extract::DefaultBodyLimit::max(8192)),
        )
        .layer(middleware::from_fn_with_state(core, crate::journal::oauth))
        .layer(middleware::from_fn(response_headers))
}

async fn response_headers(req: Request, next: Next) -> Response {
    let event_endpoint = req.uri().path() == "/oauth2/event";
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if !event_endpoint {
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
    }
    response
}

async fn preflight() -> impl IntoResponse {
    (
        StatusCode::NO_CONTENT,
        [
            (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
            (
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Authorization, Content-Type",
            ),
        ],
    )
}

async fn discovery(
    State(core): State<Arc<Core>>,
    Extension(trace): Extension<Capture>,
    Path(slug): Path<String>,
) -> oauth2::Result<Json<Value>> {
    let client = access::client(&mut core.db.clone(), &slug).await?;
    trace.client(&client);
    let issuer = oauth2::issuer(&core, &client)?;
    let base = format!("{}/oauth2", core.domain.trim_end_matches('/'));
    Ok(Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "userinfo_endpoint": format!("{base}/userinfo"),
        "revocation_endpoint": format!("{base}/revoke"),
        "event_endpoint": format!("{base}/event"),
        "response_types_supported": ["code"], "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "scopes_supported": oauth2::ALLOWED_SCOPES,
        "claims_supported": ["iss", "sub", "aud", "iat", "exp", "auth_time", "nonce", "name", "preferred_username", "email"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "request_parameter_supported": false, "request_uri_parameter_supported": false
    })))
}

async fn jwks(
    State(core): State<Arc<Core>>,
    Extension(trace): Extension<Capture>,
    Path(slug): Path<String>,
) -> oauth2::Result<Json<Value>> {
    let client = access::client(&mut core.db.clone(), &slug).await?;
    trace.client(&client);
    Ok(Json(keys::jwks(&core, &client).await?))
}

fn callback(uri: &str, pairs: Vec<(&str, String)>) -> Response {
    let query = serde_urlencoded::to_string(pairs).expect("string parameters serialize");
    let separator = if uri.ends_with('?') || uri.ends_with('&') {
        ""
    } else if uri.contains('?') {
        "&"
    } else {
        "?"
    };
    Redirect::to(&format!("{uri}{separator}{query}")).into_response()
}

fn authorization_error(uri: &str, state: Option<&String>, error: OAuthError) -> Response {
    let mut pairs = vec![
        ("error", error.code.to_string()),
        ("error_description", error.description),
    ];
    if let Some(state) = state {
        pairs.push(("state", state.clone()));
    }
    crate::journal::outcome(
        callback(uri, pairs),
        if error.code == "login_required" {
            "authentication_required"
        } else {
            "denied"
        },
        Some(error.code),
    )
}

fn authorization_failure(
    client: &Client,
    uri: &str,
    state: Option<&String>,
    mut error: OAuthError,
) -> Response {
    if matches!(client.client_type, ClientType::ForwardAuth) {
        if error.code == "access_denied" {
            error.status = StatusCode::FORBIDDEN;
        }
        error.into_response()
    } else {
        authorization_error(uri, state, error)
    }
}

async fn authorize(
    State(core): State<Arc<Core>>,
    Extension(trace): Extension<Capture>,
    RawQuery(raw): RawQuery,
    cookies: CookieJar,
) -> oauth2::Result<Response> {
    let pairs =
        serde_urlencoded::from_str::<Vec<(String, String)>>(raw.as_deref().unwrap_or_default())
            .map_err(|_| OAuthError::new("invalid_request", "Invalid query parameters."))?;
    let mut fields = oauth2::unique_fields(pairs)?;
    let mut db = core.db.clone();
    let client =
        access::registered_client(&mut db, &oauth2::required(&fields, "client_id")?).await?;
    trace.client(&client);
    let redirect_uri = oauth2::required(&fields, "redirect_uri")?;
    let state = fields.get("state").cloned();
    let request = if matches!(client.client_type, ClientType::ForwardAuth) {
        let flow =
            crate::provider::forwardauth::validate_authorization(&mut db, &client, &fields).await?;
        trace.target(&flow.origin, &flow.return_uri, None);
        None
    } else {
        if fields.get("client_type").is_some_and(|kind| kind != "oidc") {
            return Err(OAuthError::new("invalid_request", "Invalid client_type."));
        }
        let authority = redirect_uri
            .split_once("://")
            .is_some_and(|(scheme, rest)| {
                (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
                    && rest
                        .split(['/', '?', '#'])
                        .next()
                        .is_some_and(|host| !host.is_empty())
            });
        let valid_url = authority
            && reqwest::Url::parse(&redirect_uri).is_ok_and(|u| {
                matches!(u.scheme(), "https" | "http")
                    && u.host_str().is_some()
                    && u.fragment().is_none()
                    && u.username().is_empty()
                    && u.password().is_none()
            });
        if !valid_url
            || redirect_uri
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            || redirect_uri.contains('\\')
        {
            return Err(OAuthError::new("invalid_request", "Invalid redirect_uri."));
        }
        let redirects = ClientRedirect::filter(ClientRedirect::fields().client_id().eq(client.id))
            .exec(&mut db)
            .await?;
        if !redirects.iter().any(|r| r.redirect_uri == redirect_uri) {
            return Err(OAuthError::new(
                "invalid_request",
                "redirect_uri is not registered for this client.",
            ));
        }
        let request = match OAuth2AuthorizationRequest::try_from(fields.clone()) {
            Ok(request) => request,
            Err(error) => return Ok(authorization_error(&redirect_uri, state.as_ref(), error)),
        };
        if let Err(error) = request.valid(&client) {
            return Ok(authorization_error(&redirect_uri, state.as_ref(), error));
        }
        Some(request)
    };
    let state = request
        .as_ref()
        .and_then(|request| request.state.clone())
        .or(state);
    if fields.get("response_mode").is_some_and(|v| v != "query")
        || fields.contains_key("request")
        || fields.contains_key("request_uri")
    {
        return Ok(authorization_failure(
            &client,
            &redirect_uri,
            state.as_ref(),
            OAuthError::new(
                "invalid_request",
                "Only query responses and direct authorization parameters are supported.",
            ),
        ));
    }
    let prompt = fields.get("prompt").map(String::as_str).unwrap_or_default();
    if !matches!(prompt, "" | "none" | "login") {
        return Ok(authorization_failure(
            &client,
            &redirect_uri,
            state.as_ref(),
            OAuthError::new("invalid_request", "Supported prompts are none and login."),
        ));
    }
    let max_age = match fields.get("max_age").map(|v| v.parse::<u64>()).transpose() {
        Ok(value) => value,
        Err(_) => {
            return Ok(authorization_failure(
                &client,
                &redirect_uri,
                state.as_ref(),
                OAuthError::new("invalid_request", "max_age must be a nonnegative integer."),
            ));
        }
    };
    let identity = if let Some(cookie) = cookies.get(LOGIN_COOKIE_NAME) {
        crate::session::by_token(&mut db, cookie.value()).await?
    } else {
        None
    };
    if let Some((user, session)) = &identity {
        trace.subject(user.id, session.id, None, None, true);
    }
    let reauthenticate = prompt == "login"
        || identity.as_ref().is_some_and(|(_, s)| {
            max_age.is_some_and(|age| {
                age == 0
                    || jiff::Timestamp::now()
                        .as_second()
                        .saturating_sub(s.created_at.as_second()) as u64
                        > age
            })
        });
    if identity.is_none() || reauthenticate {
        if prompt == "none" {
            return Ok(authorization_failure(
                &client,
                &redirect_uri,
                state.as_ref(),
                OAuthError::new("login_required", "Sign-in is required."),
            ));
        }
        // The login page always authenticates. Remove forced-login parameters from
        // its continuation so a completed login does not start a redirect loop.
        fields.remove("prompt");
        fields.remove("max_age");
        let continuation = format!(
            "/oauth2/authorize?{}",
            serde_urlencoded::to_string(&fields).expect("string parameters serialize")
        );
        let query = serde_urlencoded::to_string([("r", continuation)])
            .expect("string parameters serialize");
        return Ok(crate::journal::outcome(
            Redirect::to(&format!("/login?{query}")).into_response(),
            "authentication_required",
            None,
        ));
    }
    let (user, session) = identity.expect("authenticated identity checked");
    if !access::permitted(&mut db, &client, &user).await? {
        return Ok(authorization_failure(
            &client,
            &redirect_uri,
            state.as_ref(),
            OAuthError::new("access_denied", "This user cannot access this client."),
        ));
    }
    if matches!(client.client_type, ClientType::ForwardAuth) {
        let callback =
            crate::provider::forwardauth::authorize(&core, &client, &user, &session, &fields)
                .await?;
        return Ok(crate::journal::outcome(
            Redirect::to(&callback).into_response(),
            "allowed",
            None,
        ));
    }
    let mut tx = db.transaction().await?;
    let (code, grant_id) = flows::issue_code(
        &mut tx,
        &client,
        &user,
        &session,
        request.expect("OIDC request validated"),
    )
    .await?;
    tx.commit().await?;
    trace.subject(user.id, session.id, Some(grant_id), None, true);
    let mut response = vec![("code", code)];
    if let Some(state) = state {
        response.push(("state", state));
    }
    Ok(crate::journal::outcome(
        callback(&redirect_uri, response),
        "allowed",
        None,
    ))
}

fn decode_basic_component(value: &str) -> oauth2::Result<String> {
    let fields: Vec<(String, String)> = serde_urlencoded::from_str(&format!("v={value}"))
        .map_err(|_| OAuthError::invalid_client())?;
    if fields.len() != 1 {
        return Err(OAuthError::invalid_client());
    }
    Ok(fields[0].1.clone())
}

async fn authenticate_registered(
    core: &Core,
    headers: &HeaderMap,
    fields: &HashMap<String, String>,
    trace: &Capture,
) -> oauth2::Result<Client> {
    let (id, secret) = if let Some(header) = headers.get(header::AUTHORIZATION) {
        if headers.get_all(header::AUTHORIZATION).iter().count() != 1
            || fields.contains_key("client_secret")
        {
            return Err(OAuthError::invalid_client());
        }
        let (method, encoded) = header
            .to_str()
            .map_err(|_| OAuthError::invalid_client())?
            .split_once(' ')
            .ok_or_else(OAuthError::invalid_client)?;
        if !method.eq_ignore_ascii_case("Basic") {
            return Err(OAuthError::invalid_client());
        }
        let decoded = String::from_utf8(
            STANDARD
                .decode(encoded)
                .map_err(|_| OAuthError::invalid_client())?,
        )
        .map_err(|_| OAuthError::invalid_client())?;
        let (id, secret) = decoded
            .split_once(':')
            .ok_or_else(OAuthError::invalid_client)?;
        let id = decode_basic_component(id)?;
        if fields
            .get("client_id")
            .is_some_and(|body_id| body_id != &id)
        {
            return Err(OAuthError::invalid_client());
        }
        (id, decode_basic_component(secret)?)
    } else {
        (
            fields
                .get("client_id")
                .cloned()
                .ok_or_else(OAuthError::invalid_client)?,
            fields
                .get("client_secret")
                .cloned()
                .ok_or_else(OAuthError::invalid_client)?,
        )
    };
    let client = access::registered_client(&mut core.db.clone(), &id).await?;
    trace.client(&client);
    if !oauth2::secret_eq(&id, &client.client_id)
        || !oauth2::secret_eq(&secret, &client.client_secret)
    {
        return Err(OAuthError::invalid_client());
    }
    trace.client_authenticated();
    Ok(client)
}

async fn authenticate(
    core: &Core,
    headers: &HeaderMap,
    fields: &HashMap<String, String>,
    trace: &Capture,
) -> oauth2::Result<Client> {
    let client = authenticate_registered(core, headers, fields, trace).await?;
    if !matches!(client.client_type, ClientType::Oidc) {
        return Err(OAuthError::invalid_client());
    }
    Ok(client)
}

async fn token(
    State(core): State<Arc<Core>>,
    Extension(trace): Extension<Capture>,
    headers: HeaderMap,
    body: std::result::Result<Form<Vec<(String, String)>>, axum::extract::rejection::FormRejection>,
) -> oauth2::Result<Json<flows::TokenResponse>> {
    let Form(pairs) = body.map_err(|_| {
        OAuthError::new(
            "invalid_request",
            "Use a valid application/x-www-form-urlencoded body.",
        )
    })?;
    crate::journal::claim_fields(&core, &trace, &pairs).await;
    let fields = oauth2::unique_fields(pairs)?;
    let client = authenticate(&core, &headers, &fields, &trace).await?;
    let mut journal_db = core.db.clone();
    match fields.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            if let Some(raw) = fields.get("code") {
                match crate::models::ClientToken::get_by_token(
                    &mut journal_db,
                    oauth2::hash_token(raw),
                )
                .await
                {
                    Ok(code) if code.client_id == client.id => {
                        trace.subject(code.user_id, code.session_id, Some(code.id), None, false)
                    }
                    Ok(_) => (),
                    Err(error) if error.is_record_not_found() => (),
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Some("refresh_token") => {
            if let Some(raw) = fields.get("refresh_token") {
                match OAuthToken::get_by_refresh_token(&mut journal_db, oauth2::hash_token(raw))
                    .await
                {
                    Ok(token) if token.client_id == client.id => trace.subject(
                        token.user_id,
                        token.session_id,
                        Some(token.code_id),
                        None,
                        false,
                    ),
                    Ok(_) => (),
                    Err(error) if error.is_record_not_found() => (),
                    Err(error) => return Err(error.into()),
                }
            }
        }
        _ => (),
    }
    let response = match fields.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            flows::redeem(&core, &client, OAuth2TokenRequest::try_from(fields)?).await?
        }
        Some("refresh_token") => {
            flows::refresh(
                &core,
                &client,
                &oauth2::required(&fields, "refresh_token")?,
                fields.get("scope").map(String::as_str),
            )
            .await?
        }
        Some(_) => {
            return Err(OAuthError::new(
                "unsupported_grant_type",
                "Supported grants are authorization_code and refresh_token.",
            ));
        }
        None => return Err(OAuthError::new("invalid_request", "Missing grant_type.")),
    };
    let (user, session, grant) = response.journal_subject;
    trace.subject(user, session, Some(grant), None, true);
    Ok(Json(response))
}

async fn userinfo(
    State(core): State<Arc<Core>>,
    Extension(trace): Extension<Capture>,
    headers: HeaderMap,
) -> oauth2::Result<Json<Value>> {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(OAuthError::invalid_token());
    }
    let (scheme, bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .ok_or_else(OAuthError::invalid_token)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || bearer.is_empty() {
        return Err(OAuthError::invalid_token());
    }
    let mut db = core.db.clone();
    let token = OAuthToken::get_by_access_token(&mut db, oauth2::hash_token(bearer))
        .await
        .map_err(|e| {
            if e.is_record_not_found() {
                OAuthError::invalid_token()
            } else {
                e.into()
            }
        })?;
    let client = Client::get_by_id(&mut db, token.client_id)
        .await
        .map_err(|e| {
            if e.is_record_not_found() {
                OAuthError::invalid_token()
            } else {
                e.into()
            }
        })?;
    if client.deleted_at.is_some() || !matches!(client.client_type, ClientType::Oidc) {
        return Err(OAuthError::invalid_token());
    }
    trace.client(&client);
    trace.subject(
        token.user_id,
        token.session_id,
        Some(token.code_id),
        None,
        false,
    );
    let value = flows::userinfo(&core, &client, bearer).await?;
    trace.verified();
    Ok(Json(value))
}

async fn revoke(
    State(core): State<Arc<Core>>,
    Extension(trace): Extension<Capture>,
    headers: HeaderMap,
    body: std::result::Result<Form<Vec<(String, String)>>, axum::extract::rejection::FormRejection>,
) -> oauth2::Result<StatusCode> {
    let Form(pairs) = body.map_err(|_| {
        OAuthError::new(
            "invalid_request",
            "Use a valid application/x-www-form-urlencoded body.",
        )
    })?;
    crate::journal::claim_fields(&core, &trace, &pairs).await;
    let fields = oauth2::unique_fields(pairs)?;
    let client = authenticate(&core, &headers, &fields, &trace).await?;
    let raw = oauth2::required(&fields, "token")?;
    if let Some((user, session, grant)) = flows::revoke(&core, &client, &raw).await? {
        trace.subject(user, session, Some(grant), None, false);
    }
    Ok(StatusCode::OK)
}

async fn event(
    State(core): State<Arc<Core>>,
    Extension(trace): Extension<Capture>,
    headers: HeaderMap,
    body: std::result::Result<
        Json<crate::journal::reports::Input>,
        axum::extract::rejection::JsonRejection,
    >,
) -> oauth2::Result<Response> {
    let client = authenticate_registered(&core, &headers, &HashMap::new(), &trace).await?;
    let Json(input) = body.map_err(|error| OAuthError {
        status: if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        },
        code: "invalid_request",
        description: "Use the documented event JSON schema (maximum 8 KiB).".into(),
    })?;
    let (created, value) = crate::journal::reports::submit(&core, &client, &trace, input).await?;
    Ok((
        if created {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        Json(value),
    )
        .into_response())
}
