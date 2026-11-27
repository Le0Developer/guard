use crate::server::cookies::{LOGIN_COOKIE_NAME, LOGIN_SESSION_COOKIE_NAME};
use crate::{
    core::Core,
    models::{LoginSession, User},
    server::middleware::CsrfToken,
    token::generate_token,
    upstream_auth,
    views::{ErrorPage, LoginMethod, LoginPage},
};
use anyhow::bail;
use axum::{
    Extension, Form,
    body::Body,
    extract::{Path, Query, State},
    http::HeaderValue,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use reqwest::{StatusCode, header};
use std::collections::HashMap;
use std::sync::Arc;
use toasty::create;

pub async fn login(
    state: State<Arc<Core>>,
    Query(params): Query<HashMap<String, String>>,
    Extension(csrf_token): Extension<CsrfToken>,
    Path(path): Path<HashMap<String, String>>,
) -> Response {
    let login_method = path.get("login_method").cloned();

    let mut db = state.db.clone();

    let login_session = match create!(LoginSession {
        token: generate_token(),
        internal_token: generate_token(),
        redirect_uri: params
            .get("r")
            .filter(|s| s.starts_with('/')
                && !s.starts_with("//")
                && !s.contains('\\')
                && !s.chars().any(char::is_control))
            .cloned(),
    })
    .exec(&mut db)
    .await
    {
        Ok(session) => session,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("Error creating session: {}", e)))
                .unwrap();
        }
    };

    let upstream_authenticator = get_upstream_authenticator(&state, login_method.clone());
    let mut ctx = context_from_request(&state, upstream_authenticator, &login_session, csrf_token);
    let mut res = show_login_page(&mut ctx, None).await;

    res.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{}={}; {}; Max-Age={}",
            LOGIN_SESSION_COOKIE_NAME,
            login_session.token,
            crate::server::cookies::attributes(&state.domain),
            crate::session::LOGIN_LIFETIME_SECONDS
        ))
        .unwrap(),
    );

    res
}

pub async fn finish_login(
    state: State<Arc<Core>>,
    Extension(csrf_token): Extension<CsrfToken>,
    Path(path): Path<HashMap<String, String>>,
    cookie_jar: CookieJar,
    Form(data): Form<HashMap<String, String>>,
) -> Response {
    complete_primary(state.0, csrf_token, path, cookie_jar, data).await
}

pub async fn finish_callback(
    state: State<Arc<Core>>,
    Extension(csrf_token): Extension<CsrfToken>,
    Path(path): Path<HashMap<String, String>>,
    cookie_jar: CookieJar,
    Query(data): Query<HashMap<String, String>>,
) -> Response {
    if !get_upstream_authenticator(&state, path.get("login_method").cloned())
        .is_some_and(|auth| auth.supports_callback())
    {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::CACHE_CONTROL, "no-store")],
            "This login method does not accept callbacks.",
        )
            .into_response();
    }
    complete_primary(state.0, csrf_token, path, cookie_jar, data).await
}

async fn complete_primary(
    state: Arc<Core>,
    csrf_token: CsrfToken,
    path: HashMap<String, String>,
    cookie_jar: CookieJar,
    data: HashMap<String, String>,
) -> Response {
    let login_method = path.get("login_method");
    let login_session = match get_login_session(&state, &cookie_jar).await {
        Ok(session) => session,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("Error getting login session: {}", e)))
                .unwrap();
        }
    };
    let upstream_authenticator = get_upstream_authenticator(&state, login_method.cloned());
    let mut ctx = context_from_request(&state, upstream_authenticator, &login_session, csrf_token);

    match upstream_authenticator {
        Some(auth) => {
            handle_authorization_response(auth.finish_auth(&mut ctx, data).await, &mut ctx).await
        }
        None => show_login_page(&mut ctx, Some("No upstream authenticator found".into())).await,
    }
}

async fn get_login_session(core: &Core, cookie_jar: &CookieJar) -> anyhow::Result<LoginSession> {
    let login_token = cookie_jar
        .get(LOGIN_SESSION_COOKIE_NAME)
        .map(|c| c.value().to_string());
    match login_token {
        Some(token) => {
            let mut db = core.db.clone();
            match LoginSession::get_by_token(&mut db, token).await {
                Ok(session) => Ok(session),
                Err(e) => bail!("Failed to get login session: {}", e),
            }
        }
        None => bail!("No login session token found"),
    }
}

fn get_upstream_authenticator(
    state: &Core,
    login_method: Option<String>,
) -> Option<&dyn upstream_auth::UpstreamAuthenticator> {
    match login_method {
        Some(method) => state
            .upstream_authenticators
            .iter()
            .find(|auth| auth.id() == method)
            .map(|auth| auth.as_ref()),
        None if state.upstream_authenticators.len() == 1 => {
            Some(state.upstream_authenticators[0].as_ref())
        }
        None => None,
    }
}

async fn handle_authorization_response(
    response: anyhow::Result<upstream_auth::AuthorizeResponse>,
    ctx: &upstream_auth::Context<'_>,
) -> Response {
    match response {
        Ok(upstream_auth::AuthorizeResponse::HTMLFragment(fragment)) => LoginPage {
            authenticators: vec![],
            fragment: Some(fragment),
            error: None,
        }
        .into_response(),
        Ok(upstream_auth::AuthorizeResponse::Redirect(url)) => Redirect::to(&url).into_response(),
        Ok(upstream_auth::AuthorizeResponse::Done(user)) => do_login(user, ctx).await,
        Err(e) => show_error_page(&format!("Error: {}", e)),
    }
}

async fn show_login_page(ctx: &upstream_auth::Context<'_>, error: Option<String>) -> Response {
    if let Some(auth) = ctx.upstream_authenticator {
        return handle_authorization_response(auth.auth(ctx).await, ctx)
            .await
            .into_response();
    }

    LoginPage {
        authenticators: ctx
            .core
            .upstream_authenticators
            .iter()
            .map(|auth| LoginMethod {
                id: auth.id().into(),
                name: auth.name().into(),
            })
            .collect(),
        fragment: None,
        error,
    }
    .into_response()
}

fn show_error_page(error: &str) -> Response {
    ErrorPage {
        error: error.into(),
    }
    .into_response()
}

fn context_from_request<'a>(
    core: &'a Core,
    upstream_authenticator: Option<&'a dyn upstream_auth::UpstreamAuthenticator>,
    login_session: &'a LoginSession,
    csrf_token: CsrfToken,
) -> upstream_auth::Context<'a> {
    upstream_auth::Context::new(
        csrf_token.token,
        upstream_authenticator,
        login_session,
        core,
    )
}

async fn do_login(user: User, ctx: &upstream_auth::Context<'_>) -> Response {
    match crate::mfa::auth::begin(ctx.core, &user, ctx.login_session.id).await {
        Ok(crate::mfa::auth::Begin::Complete { token, redirect }) => {
            complete_response(ctx.core, &token, &redirect)
        }
        Ok(crate::mfa::auth::Begin::Pending(ticket)) => {
            let mut response = Redirect::to("/login/mfa").into_response();
            let attributes = crate::server::cookies::attributes(&ctx.core.domain);
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&format!(
                    "{}={ticket}; {attributes}; Max-Age=300",
                    crate::mfa::PENDING_COOKIE
                ))
                .unwrap(),
            );
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&format!(
                    "{LOGIN_SESSION_COOKIE_NAME}=; {attributes}; Max-Age=0"
                ))
                .unwrap(),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => (error.0, show_error_page(error.1)).into_response(),
    }
}

pub(crate) fn complete_response(core: &Core, token: &str, redirect: &str) -> Response {
    let mut response = Redirect::temporary(redirect).into_response();
    // Keep the existing 302 behavior after a successful primary-only login.
    *response.status_mut() = StatusCode::FOUND;
    let attributes = crate::server::cookies::attributes(&core.domain);
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{LOGIN_COOKIE_NAME}={token}; {attributes}; Max-Age={}",
            crate::session::LIFETIME_SECONDS
        ))
        .unwrap(),
    );
    for name in [LOGIN_SESSION_COOKIE_NAME, crate::mfa::PENDING_COOKIE] {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!("{name}=; {attributes}; Max-Age=0")).unwrap(),
        );
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
