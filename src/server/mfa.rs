use crate::{
    core::Core,
    mfa::{self, manage::Context},
    models::*,
    server::{admin::AdminForm, cookies::LOGIN_COOKIE_NAME, middleware::CsrfToken},
    views::security::*,
};
use axum::{
    Extension, Form, Json, Router,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::CookieJar;
use std::{collections::HashMap, sync::Arc};

pub(crate) fn public_routes() -> Router<Arc<Core>> {
    Router::new()
        .route("/login/mfa", get(challenge).post(verify_code))
        .route("/login/mfa/key/start", post(auth_start))
        .route("/login/mfa/key/finish", post(auth_finish))
        .route("/static/security.js", get(script))
}
pub(crate) fn management_routes() -> Router<Arc<Core>> {
    let mut router = Router::new();
    for base in ["/account/security", "/admin/users/{id}/security"] {
        router = router
            .route(base, get(page))
            .route(&format!("{base}/totp"), post(totp_start))
            .route(&format!("{base}/totp/confirm"), post(totp_confirm))
            .route(&format!("{base}/keys/start"), post(key_start))
            .route(&format!("{base}/keys/finish"), post(key_finish))
            .route(&format!("{base}/backup-codes"), post(backup_codes))
            .route(
                &format!("{base}/methods/{{kind}}/{{method_id}}/remove"),
                post(remove),
            )
            .route(
                &format!("{base}/methods/{{kind}}/{{method_id}}/rename"),
                post(rename),
            )
            .route(&format!("{base}/reset"), post(reset));
    }
    router
}
async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../views/security.js"),
    )
}
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
fn field<'a>(data: &'a HashMap<String, String>, key: &str) -> &'a str {
    data.get(key).map(String::as_str).unwrap_or_default()
}
fn pending_cookie(cookies: &CookieJar) -> mfa::Result<&str> {
    cookies
        .get(mfa::PENDING_COOKIE)
        .map(|v| v.value())
        .ok_or_else(|| mfa::invalid("Your pending sign-in expired. Sign in again."))
}
fn csrf(fields: &HashMap<String, String>, token: &CsrfToken) -> mfa::Result<()> {
    if fields.get("csrf_token") != Some(&token.token) {
        return Err(mfa::Error(
            StatusCode::FORBIDDEN,
            "Reload the page and try again.",
        ));
    }
    Ok(())
}
async fn context(
    core: &Core,
    actor: &User,
    params: &HashMap<String, String>,
    cookies: &CookieJar,
) -> mfa::Result<Context> {
    let target = params
        .get("id")
        .map(|id| id.parse::<i64>())
        .transpose()
        .map_err(|_| mfa::invalid("Invalid user ID."))?
        .unwrap_or(actor.id);
    let cookie = cookies
        .get(LOGIN_COOKIE_NAME)
        .ok_or_else(|| mfa::invalid("Sign in before changing security settings."))?;
    let (_, session) = crate::session::by_token(&mut core.db.clone(), cookie.value())
        .await?
        .ok_or_else(|| mfa::invalid("Invalid security session."))?;
    if session.user_id != actor.id {
        return Err(mfa::invalid("Invalid security session."));
    }
    let ctx = Context {
        actor: actor.id,
        target,
        session: session.id,
    };
    ctx.authorize(&mut core.db.clone()).await?;
    Ok(ctx)
}
fn base(actor: i64, target: i64) -> String {
    if actor == target {
        "/account/security".into()
    } else {
        format!("/admin/users/{target}/security")
    }
}
fn management_error(error: mfa::Error, actor: i64, params: &HashMap<String, String>) -> Response {
    if error.0 == StatusCode::UNAUTHORIZED {
        let target = params
            .get("id")
            .and_then(|v| v.parse().ok())
            .unwrap_or(actor);
        let query =
            serde_urlencoded::to_string([("r", base(actor, target))]).expect("local continuation");
        return no_store(Redirect::to(&format!("/login?{query}")).into_response());
    }
    no_store(
        (
            error.0,
            crate::views::ErrorPage {
                error: error.1.into(),
            }
            .into_response(),
        )
            .into_response(),
    )
}
async fn render_challenge(
    core: &Core,
    cookies: &CookieJar,
    token: &CsrfToken,
    error: Option<String>,
) -> mfa::Result<Response> {
    let raw = pending_cookie(cookies)?;
    let mut db = core.db.clone();
    let (_, user) = match mfa::auth::pending(&mut db, raw).await {
        Ok(value) => value,
        Err(error) => {
            mfa::rejected(core, raw, &error).await;
            return Err(error);
        }
    };
    let has_totp = !TotpAuthenticator::filter(TotpAuthenticator::fields().user_id().eq(user.id))
        .exec(&mut db)
        .await?
        .is_empty();
    let has_keys = !WebauthnCredential::filter(WebauthnCredential::fields().user_id().eq(user.id))
        .exec(&mut db)
        .await?
        .is_empty();
    Ok(no_store(
        MfaPage {
            csrf: token.token.clone(),
            has_totp,
            has_keys,
            error,
        }
        .into_response(),
    ))
}
async fn challenge(
    State(core): State<Arc<Core>>,
    cookies: CookieJar,
    Extension(token): Extension<CsrfToken>,
) -> Response {
    match render_challenge(&core, &cookies, &token, None).await {
        Ok(res) => res,
        Err(error) => no_store(
            (
                error.0,
                crate::views::ErrorPage {
                    error: error.1.into(),
                }
                .into_response(),
            )
                .into_response(),
        ),
    }
}
async fn verify_code(
    State(core): State<Arc<Core>>,
    cookies: CookieJar,
    Extension(token): Extension<CsrfToken>,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    if let Err(error) = csrf(&fields, &token) {
        return no_store(error.into_response());
    }
    let raw = match pending_cookie(&cookies) {
        Ok(v) => v,
        Err(e) => return no_store(e.into_response()),
    };
    match mfa::auth::verify_code(&core, raw, field(&fields, "method"), field(&fields, "code")).await
    {
        Ok(done) => crate::server::login::complete_response(&core, &done.token, &done.redirect),
        Err(error) => match render_challenge(&core, &cookies, &token, Some(error.1.into())).await {
            Ok(mut res) => {
                *res.status_mut() = error.0;
                res
            }
            Err(e) => no_store(
                (
                    e.0,
                    crate::views::ErrorPage { error: e.1.into() }.into_response(),
                )
                    .into_response(),
            ),
        },
    }
}
async fn auth_start(
    State(core): State<Arc<Core>>,
    cookies: CookieJar,
    Extension(token): Extension<CsrfToken>,
    Form(fields): Form<HashMap<String, String>>,
) -> mfa::Result<Response> {
    csrf(&fields, &token)?;
    Ok(no_store(
        Json(mfa::auth::start_key(&core, pending_cookie(&cookies)?).await?).into_response(),
    ))
}
async fn auth_finish(
    State(core): State<Arc<Core>>,
    cookies: CookieJar,
    Extension(token): Extension<CsrfToken>,
    Form(fields): Form<HashMap<String, String>>,
) -> mfa::Result<Response> {
    csrf(&fields, &token)?;
    let credential = serde_json::from_str(field(&fields, "credential"))
        .map_err(|_| mfa::invalid("Invalid security-key response."))?;
    let done = mfa::auth::finish_key(
        &core,
        pending_cookie(&cookies)?,
        field(&fields, "ceremony"),
        credential,
    )
    .await?;
    let mut response = crate::server::login::complete_response(&core, &done.token, &done.redirect);
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    *response.body_mut() =
        axum::body::Body::from(serde_json::json!({"redirect":done.redirect}).to_string());
    Ok(response)
}
async fn page(
    State(core): State<Arc<Core>>,
    Extension(actor): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    Path(params): Path<HashMap<String, String>>,
    cookies: CookieJar,
) -> Response {
    let ctx = match context(&core, &actor, &params, &cookies).await {
        Ok(ctx) => ctx,
        Err(e) => return management_error(e, actor.id, &params),
    };
    let result = async {
        let mut db = core.db.clone();
        let target = User::get_by_id(&mut db, ctx.target).await?;
        let mut methods = Vec::new();
        for factor in TotpAuthenticator::filter(TotpAuthenticator::fields().user_id().eq(target.id))
            .exec(&mut db)
            .await?
        {
            methods.push(MethodRow {
                id: factor.id,
                kind: "totp".into(),
                name: factor.name,
                created_at: factor.created_at.strftime("%Y-%m-%d %H:%M").to_string(),
                last_used: factor
                    .last_used_at
                    .map(|t| t.strftime("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "Never".into()),
            });
        }
        for key in WebauthnCredential::filter(WebauthnCredential::fields().user_id().eq(target.id))
            .exec(&mut db)
            .await?
        {
            methods.push(MethodRow {
                id: key.id,
                kind: "webauthn".into(),
                name: key.name,
                created_at: key.created_at.strftime("%Y-%m-%d %H:%M").to_string(),
                last_used: key
                    .last_used_at
                    .map(|t| t.strftime("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "Never".into()),
            });
        }
        let backup_count = RecoveryCode::filter(
            RecoveryCode::fields()
                .user_id()
                .eq(target.id)
                .and(RecoveryCode::fields().used_at().is_none()),
        )
        .exec(&mut db)
        .await?
        .len();
        Ok::<_, mfa::Error>(no_store(
            SecurityPage {
                user: &actor,
                csrf: &csrf.token,
                target_id: target.id,
                target_name: target.username,
                base: base(actor.id, target.id),
                methods,
                backup_count,
            }
            .into_response(),
        ))
    }
    .await;
    result.unwrap_or_else(|e| management_error(e, actor.id, &params))
}
async fn totp_start(
    State(core): State<Arc<Core>>,
    Extension(actor): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    Path(params): Path<HashMap<String, String>>,
    cookies: CookieJar,
    AdminForm(fields): AdminForm,
) -> Response {
    let ctx = match context(&core, &actor, &params, &cookies).await {
        Ok(ctx) => ctx,
        Err(e) => return management_error(e, actor.id, &params),
    };
    match mfa::manage::start_totp(&core, &ctx, field(&fields, "name")).await {
        Ok(setup) => no_store(
            TotpSetupPage {
                user: &actor,
                csrf: &csrf.token,
                base: base(actor.id, ctx.target),
                target_id: ctx.target,
                secret: setup.secret,
                qr: setup.qr,
                ticket: setup.ticket,
            }
            .into_response(),
        ),
        Err(e) => management_error(e, actor.id, &params),
    }
}
async fn totp_confirm(
    State(core): State<Arc<Core>>,
    Extension(actor): Extension<Arc<User>>,
    Path(params): Path<HashMap<String, String>>,
    cookies: CookieJar,
    AdminForm(fields): AdminForm,
) -> Response {
    let ctx = match context(&core, &actor, &params, &cookies).await {
        Ok(ctx) => ctx,
        Err(e) => return management_error(e, actor.id, &params),
    };
    match mfa::manage::confirm_totp(
        &core,
        &ctx,
        field(&fields, "ceremony"),
        field(&fields, "code"),
    )
    .await
    {
        Ok(()) => no_store(Redirect::to(&base(actor.id, ctx.target)).into_response()),
        Err(e) => management_error(e, actor.id, &params),
    }
}
async fn key_start(
    State(core): State<Arc<Core>>,
    Extension(actor): Extension<Arc<User>>,
    Path(params): Path<HashMap<String, String>>,
    cookies: CookieJar,
    AdminForm(fields): AdminForm,
) -> mfa::Result<Response> {
    let ctx = context(&core, &actor, &params, &cookies).await?;
    Ok(no_store(
        Json(mfa::manage::start_key(&core, &ctx, field(&fields, "name")).await?).into_response(),
    ))
}
async fn key_finish(
    State(core): State<Arc<Core>>,
    Extension(actor): Extension<Arc<User>>,
    Path(params): Path<HashMap<String, String>>,
    cookies: CookieJar,
    AdminForm(fields): AdminForm,
) -> mfa::Result<Response> {
    let ctx = context(&core, &actor, &params, &cookies).await?;
    let credential = serde_json::from_str(field(&fields, "credential"))
        .map_err(|_| mfa::invalid("Invalid security-key registration response."))?;
    mfa::manage::finish_key(&core, &ctx, field(&fields, "ceremony"), credential).await?;
    Ok(no_store(
        Json(serde_json::json!({"redirect":base(actor.id,ctx.target)})).into_response(),
    ))
}
async fn backup_codes(
    State(core): State<Arc<Core>>,
    Extension(actor): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    Path(params): Path<HashMap<String, String>>,
    cookies: CookieJar,
    AdminForm(fields): AdminForm,
) -> Response {
    let ctx = match context(&core, &actor, &params, &cookies).await {
        Ok(ctx) => ctx,
        Err(e) => return management_error(e, actor.id, &params),
    };
    if field(&fields, "confirm") != "generate" {
        return management_error(
            mfa::invalid("Confirm replacement of your backup codes."),
            actor.id,
            &params,
        );
    }
    match mfa::manage::backup_codes(&core, &ctx).await {
        Ok(codes) => no_store(
            BackupCodesPage {
                user: &actor,
                csrf: &csrf.token,
                base: base(actor.id, ctx.target),
                codes,
                target_id: ctx.target,
            }
            .into_response(),
        ),
        Err(e) => management_error(e, actor.id, &params),
    }
}
async fn remove(
    State(core): State<Arc<Core>>,
    Extension(actor): Extension<Arc<User>>,
    Path(params): Path<HashMap<String, String>>,
    cookies: CookieJar,
    AdminForm(_): AdminForm,
) -> Response {
    mutation(core, actor, params, cookies, HashMap::new(), "remove").await
}
async fn rename(
    State(core): State<Arc<Core>>,
    Extension(actor): Extension<Arc<User>>,
    Path(params): Path<HashMap<String, String>>,
    cookies: CookieJar,
    AdminForm(fields): AdminForm,
) -> Response {
    mutation(core, actor, params, cookies, fields, "rename").await
}
async fn reset(
    State(core): State<Arc<Core>>,
    Extension(actor): Extension<Arc<User>>,
    Path(params): Path<HashMap<String, String>>,
    cookies: CookieJar,
    AdminForm(fields): AdminForm,
) -> Response {
    mutation(core, actor, params, cookies, fields, "reset").await
}
async fn mutation(
    core: Arc<Core>,
    actor: Arc<User>,
    params: HashMap<String, String>,
    cookies: CookieJar,
    fields: HashMap<String, String>,
    action: &str,
) -> Response {
    let ctx = match context(&core, &actor, &params, &cookies).await {
        Ok(ctx) => ctx,
        Err(e) => return management_error(e, actor.id, &params),
    };
    let result = if action == "reset" {
        if field(&fields, "confirm") != "reset" {
            Err(mfa::invalid(
                "Confirm that you want to disable all MFA methods.",
            ))
        } else {
            mfa::manage::reset(&core, &ctx).await
        }
    } else {
        match params.get("method_id").and_then(|id| id.parse().ok()) {
            Some(id) if action == "remove" => {
                mfa::manage::remove(&core, &ctx, field(&params, "kind"), id).await
            }
            Some(id) => {
                mfa::manage::rename(
                    &core,
                    &ctx,
                    field(&params, "kind"),
                    id,
                    field(&fields, "name"),
                )
                .await
            }
            None => Err(mfa::invalid("Invalid method ID.")),
        }
    };
    let destination = if action == "reset" && actor.id == ctx.target {
        "/login".into()
    } else {
        base(actor.id, ctx.target)
    };
    match result {
        Ok(()) => no_store(Redirect::to(&destination).into_response()),
        Err(e) => management_error(e, actor.id, &params),
    }
}
