use axum::{Extension, response::{IntoResponse, Response}};

use std::sync::Arc;
use crate::{models::User, views::UserPage, server::middleware::CsrfToken};

pub async fn user(Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>) -> Response {
	UserPage {
		user: user.as_ref(),
        csrf: &csrf.token,
	}.into_response()
}
