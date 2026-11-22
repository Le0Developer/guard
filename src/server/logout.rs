use std::{collections::HashMap, sync::Arc};

use axum::{Extension, Form, extract::State, http::{header, HeaderValue, StatusCode}, response::{IntoResponse, Redirect, Response}};
use axum_extra::extract::CookieJar;
use crate::{core::Core, models::{Session, AuditLogEntry}, server::{cookies::{LOGIN_COOKIE_NAME, LOGIN_SESSION_COOKIE_NAME}, middleware::CsrfToken}, views::ErrorPage};

pub async fn logout(
    State(core): State<Arc<Core>>,
    Extension(csrf): Extension<CsrfToken>,
    cookies: CookieJar,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    if fields.get("csrf_token") != Some(&csrf.token) {
        return (StatusCode::FORBIDDEN, ErrorPage { error: "Reload the page and try logging out again.".into() }.into_response()).into_response();
    }
    if let Some(cookie) = cookies.get(LOGIN_COOKIE_NAME) {
        let mut db = core.db.clone();
        let result = async {
            let mut tx = db.transaction().await?;
            match Session::get_by_token(&mut tx, cookie.value()).await {
                Ok(session) => {
                    Session::filter_by_id(session.id).delete().exec(&mut tx).await?;
                    crate::audit::record(&mut tx, session.user_id, AuditLogEntry::UserLoggedOut { session_id: session.id }).await?;
                }
                Err(error) if error.is_record_not_found() => (),
                Err(error) => return Err(error),
            }
            tx.commit().await
        }.await;
        if let Err(error) = result {
            eprintln!("Unable to revoke session during logout: {error}");
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorPage { error: "Unable to log out. Please try again.".into() }.into_response()).into_response();
        }
    }
    let mut response = Redirect::to("/login").into_response();
    for name in [LOGIN_COOKIE_NAME, LOGIN_SESSION_COOKIE_NAME, crate::mfa::PENDING_COOKIE] {
        response.headers_mut().append(header::SET_COOKIE,
            HeaderValue::from_str(&format!("{name}=; {}; Max-Age=0", crate::server::cookies::attributes(&core.domain))).unwrap());
    }
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
