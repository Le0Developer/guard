use std::sync::Arc;

use axum::{
    Router,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use reqwest::header;

use crate::{
    core::Core,
    server::{
        login::{finish_login, login},
        middleware::{authentication, csrf_token, remoteip, require_admin},
        user::user,
    },
};

pub fn create_router(core: Core) -> Router {
    let state = Arc::new(core);
    crate::cleanup::spawn(&state);
    crate::journal::spawn_exporter(Arc::clone(&state));
    main_router(state)
}

pub fn create_routers(core: Core) -> (Router, Router) {
    let state = Arc::new(core);
    crate::cleanup::spawn(&state);
    crate::journal::spawn_exporter(Arc::clone(&state));
    (
        main_router(Arc::clone(&state)),
        super::forwardauth::routes(state),
    )
}

fn main_router(state: Arc<Core>) -> Router {
    let api = Router::new().layer(from_fn_with_state(Arc::clone(&state), remoteip));

    let public_html = Router::new()
        .merge(super::mfa::public_routes())
        .route("/login", get(login).post(finish_login))
        .route("/logout", post(super::logout::logout))
        .route("/login/{login_method}", get(login).post(finish_login))
        .route(
            "/login/{login_method}/callback",
            get(super::login::finish_callback),
        )
        .route("/static/styles.css", get(get_styles))
        .layer(from_fn_with_state(
            Arc::clone(&state),
            super::middleware::login_rate_limit,
        ))
        .layer(from_fn_with_state(Arc::clone(&state), csrf_token))
        .layer(from_fn_with_state(Arc::clone(&state), remoteip));

    let authenticated = Router::new()
        .merge(super::mfa::management_routes())
        .route("/", get(user))
        .route_layer(from_fn_with_state(Arc::clone(&state), authentication))
        .layer(from_fn_with_state(Arc::clone(&state), csrf_token))
        .layer(from_fn_with_state(Arc::clone(&state), remoteip));

    let admin = super::admin::routes()
        .route_layer(from_fn_with_state(
            Arc::clone(&state),
            super::admin::audit::capture,
        ))
        .route_layer(from_fn_with_state(Arc::clone(&state), require_admin))
        .route_layer(from_fn_with_state(Arc::clone(&state), authentication))
        .layer(from_fn_with_state(Arc::clone(&state), csrf_token))
        .layer(from_fn_with_state(Arc::clone(&state), remoteip));

    Router::new()
        .merge(api)
        .merge(super::oauth2::routes(Arc::clone(&state)))
        .merge(public_html)
        .merge(authenticated)
        .merge(admin)
        .with_state(state)
}

async fn get_styles() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../views/style.css"),
    )
        .into_response()
}
