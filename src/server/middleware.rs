use std::collections::HashMap;
use std::sync::Arc;

use axum::Extension;
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Redirect};

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::extract::CookieJar;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::header;
use sha2::Sha256;

use crate::core::Core;
use crate::models::{Role, User};
use crate::server::cookies::{CSRF_COOKIE_NAME, LOGIN_COOKIE_NAME};
use crate::views::ErrorPage;

#[derive(Debug, Clone)]
pub struct RemoteIP {
    pub ip: String,
}

#[derive(Debug, Clone)]
pub struct CsrfToken {
    pub token: String,
}

pub async fn remoteip(State(core): State<Arc<Core>>, mut req: Request, next: Next) -> Response {
    let ip = crate::journal::request_ip(&req, &core, false)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into());
    req.extensions_mut().insert(RemoteIP { ip });
    next.run(req).await
}

pub async fn csrf_token(
    State(core): State<Arc<Core>>,
    cookies: CookieJar,
    mut req: Request,
    next: Next,
) -> Response {
    let remoteip = req.extensions().get::<RemoteIP>().unwrap();

    let session_token = cookies
        .get(LOGIN_COOKIE_NAME)
        .map(|cookie| cookie.value())
        .unwrap_or_default();
    let csrf_token = derive_csrf_token(remoteip, session_token, &core.session_secret);
    req.extensions_mut().insert(CsrfToken {
        token: csrf_token.clone(),
    });

    let mut res = next.run(req).await;

    let is_cookie_okay = match cookies.get(CSRF_COOKIE_NAME) {
        Some(cookie) => cookie.value() == csrf_token,
        None => false,
    };

    if !is_cookie_okay {
        res.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "{}={}; {}",
                CSRF_COOKIE_NAME,
                csrf_token,
                crate::server::cookies::attributes(&core.domain)
            ))
            .unwrap(),
        );
    }

    res
}

fn derive_csrf_token(remoteip: &RemoteIP, session_token: &str, secret: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(remoteip.ip.as_bytes());
    mac.update(&[0]);
    mac.update(session_token.as_bytes());
    let raw_token = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(&raw_token)
}

pub async fn authentication(
    State(core): State<Arc<Core>>,
    cookies: CookieJar,
    mut req: Request,
    next: Next,
) -> Response {
    if let Some(cookie) = cookies.get(LOGIN_COOKIE_NAME) {
        match crate::session::by_token(&mut core.db.clone(), cookie.value()).await {
            Ok(Some((user, _))) => {
                req.extensions_mut().insert(Arc::new(user));
                return next.run(req).await;
            }
            Ok(None) => (),
            Err(error) => {
                eprintln!("Unable to validate Guard session: {error}");
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to validate session.",
                )
                    .into_response();
            }
        }
    }
    require_login(&req)
}

pub async fn login_rate_limit(State(core): State<Arc<Core>>, req: Request, next: Next) -> Response {
    let primary_login = req.method() == axum::http::Method::POST
        && req
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .is_some_and(|path| matches!(path.as_str(), "/login" | "/login/{login_method}"));
    if primary_login {
        if let Err(retry) = core
            .login_rate
            .check(crate::journal::request_ip(&req, &core, false))
        {
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                [
                    (header::RETRY_AFTER, retry.to_string()),
                    (header::CACHE_CONTROL, "no-store".into()),
                ],
                "Too many login attempts. Try again later.",
            )
                .into_response();
        }
    }
    next.run(req).await
}

pub async fn require_admin(
    Extension(user): Extension<Arc<User>>,
    req: Request,
    next: Next,
) -> Response {
    if !matches!(user.role, Role::Admin) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            ErrorPage {
                error: "You need an administrator account to view this page.".into(),
            }
            .into_response(),
        )
            .into_response();
    }

    next.run(req).await
}

fn require_login(req: &Request) -> Response {
    // retain the current url by putting it in ?r=
    let mut params = HashMap::<&str, String>::new();
    params.insert("r", req.uri().to_string());

    let query_string = serde_urlencoded::to_string(&params).unwrap();
    let login_url = format!("/login?{}", query_string);

    Redirect::to(&login_url).into_response()
}
