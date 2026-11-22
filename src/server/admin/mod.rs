use std::{collections::HashMap, sync::Arc};

use axum::{Extension, Router, extract::{FromRequest, Request, State}, http::StatusCode, response::{IntoResponse, Redirect, Response}, routing::{get, post}, Form};
use crate::{core::Core, models::{Client, Group, User}, server::middleware::CsrfToken, views::{ErrorPage, admin::*}};

mod users;
mod groups;
mod clients;
pub(super) mod audit;
mod access_log;

pub fn routes() -> Router<Arc<Core>> {
    Router::new()
        .route("/admin", get(home))
        .route("/admin/audit", get(audit::list))
        .route("/admin/access-log", get(access_log::list))
        .route("/admin/users", get(users::list).post(users::create))
        .route("/admin/users/new", get(users::new))
        .route("/admin/users/{id}", get(users::edit).post(users::save))
        .route("/admin/users/{id}/password", get(users::edit_password).post(users::reset_password))
        .route("/admin/users/{id}/role", get(users::edit_role).post(users::change_role))
        .route("/admin/users/{id}/delete", get(users::confirm_delete).post(users::delete))
        .route("/admin/users/{id}/sessions/delete", post(users::delete_sessions))
        .route("/admin/users/{id}/sessions/{session_id}/delete", post(users::delete_session))
        .route("/admin/groups", get(groups::list).post(groups::create))
        .route("/admin/groups/new", get(groups::new))
        .route("/admin/groups/{id}", get(groups::edit).post(groups::save))
        .route("/admin/groups/{id}/delete", get(groups::confirm_delete).post(groups::delete))
        .route("/admin/groups/{id}/members", post(groups::add_member))
        .route("/admin/groups/{id}/members/{user_id}/remove", post(groups::remove_member))
        .route("/admin/clients", get(clients::list).post(clients::create))
        .route("/admin/clients/new", get(clients::new))
        .route("/admin/clients/{id}", get(clients::edit).post(clients::save))
        .route("/admin/clients/{id}/delete", get(clients::confirm_delete).post(clients::delete))
        .route("/admin/clients/{id}/rotate-secret", post(clients::rotate_secret))
        .route("/admin/clients/{id}/redirects", post(clients::add_redirect))
        .route("/admin/clients/{id}/redirects/{redirect_id}", post(clients::save_redirect))
        .route("/admin/clients/{id}/redirects/{redirect_id}/remove", post(clients::remove_redirect))
        .route("/admin/clients/{id}/rules", post(clients::save_rule))
        .route("/admin/clients/{id}/rules/{group_id}/remove", post(clients::remove_rule))
}

pub(super) type Result<T = Response> = std::result::Result<T, AdminError>;

pub(super) struct AdminError(pub StatusCode, pub String);

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        (self.0, ErrorPage { error: self.1 }.into_response()).into_response()
    }
}

impl From<toasty::Error> for AdminError {
    fn from(error: toasty::Error) -> Self {
        if error.is_record_not_found() {
            Self(StatusCode::NOT_FOUND, "This record no longer exists.".into())
        } else {
            eprintln!("Administration database operation failed: {error}");
            Self(StatusCode::INTERNAL_SERVER_ERROR, "Unable to save the change. Please try again.".into())
        }
    }
}

// All admin writes go through this extractor, including destructive actions.
pub(super) struct AdminForm(pub HashMap<String, String>);

impl<S: Send + Sync> FromRequest<S> for AdminForm {
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> std::result::Result<Self, Response> {
        let token = req.extensions().get::<CsrfToken>().map(|value| value.token.clone());
        let Form(fields) = Form::<HashMap<String, String>>::from_request(req, state).await.map_err(IntoResponse::into_response)?;
        match (token, fields.get("csrf_token")) {
            (Some(expected), Some(actual)) if !expected.is_empty() && expected == *actual => Ok(Self(fields)),
            _ => Err(AdminError(StatusCode::FORBIDDEN, "Your form has expired. Reload the page and try again.".into()).into_response()),
        }
    }
}

pub(super) fn field(fields: &HashMap<String, String>, name: &str) -> String {
    fields.get(name).cloned().unwrap_or_default()
}

pub(super) fn required(value: &str, label: &str, max: usize) -> std::result::Result<(), String> {
    if value.trim().is_empty() { return Err(format!("{label} is required.")); }
    if value.chars().count() > max { return Err(format!("{label} must be {max} characters or fewer.")); }
    Ok(())
}

pub(super) fn bad_input(message: &str) -> AdminError {
    AdminError(StatusCode::UNPROCESSABLE_ENTITY, message.into())
}

pub(super) fn not_found() -> AdminError {
    AdminError(StatusCode::NOT_FOUND, "This record no longer exists.".into())
}

pub(super) fn saved(path: &str) -> Response { Redirect::to(path).into_response() }

pub(super) async fn password_hash(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || bcrypt::hash(password, bcrypt::DEFAULT_COST)).await
        .map_err(|_| AdminError(StatusCode::INTERNAL_SERVER_ERROR, "Unable to process the password.".into()))?
        .map_err(|_| AdminError(StatusCode::INTERNAL_SERVER_ERROR, "Unable to process the password.".into()))
}

async fn home(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>) -> Result {
    let mut db = core.db.clone();
    let users = User::all().exec(&mut db).await?.into_iter().filter(|u| u.deleted_at.is_none()).collect::<Vec<_>>();
    let groups = Group::all().exec(&mut db).await?.into_iter().filter(|g| g.deleted_at.is_none()).count();
    let clients = Client::all().exec(&mut db).await?.into_iter().filter(|c| c.deleted_at.is_none()).count();
    Ok(AdminHome { user: &user, csrf: &csrf.token, users: users.len(), groups, clients }.into_response())
}

pub(super) fn delete_page<'a>(user: &'a User, csrf: &'a str, section: &'a str, name: &'a str, action: &'a str, cancel: &'a str, consequence: &'a str) -> Response {
    DeletePage { user, csrf, section, name, action, cancel, consequence }.into_response()
}
