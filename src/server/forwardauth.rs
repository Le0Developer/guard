use crate::{
    core::Core,
    provider::{
        forwardauth::{self as service, Result},
        oauth2::{self, OAuthError},
    },
};
use axum::{
    Extension, Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::CookieJar;
use std::sync::Arc;

pub(crate) fn routes(core: Arc<Core>) -> Router {
    Router::new()
        .route(service::CALLBACK, get(verify))
        .fallback(verify)
        .layer(middleware::from_fn(no_store))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&core),
            crate::journal::forwardauth,
        ))
        .with_state(core)
}
async fn no_store(req: Request, next: Next) -> Response {
    let auth_request = req.uri().path() == "/auth_request";
    let mut response = next.run(req).await;
    // auth_request-style subrequests accept only 2xx/401/403. Preserve Location
    // and the browser-binding cookie for the proxy's external 303 adapter.
    if auth_request && response.status().is_redirection() {
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        // auth_request_set exposes one Set-Cookie value. The first cookie is
        // always the new flow binding (or the app session on a callback); do not
        // let an extra expired-cookie cleanup be combined into that value.
        let cookie = response.headers().get(header::SET_COOKIE).cloned();
        response.headers_mut().remove(header::SET_COOKIE);
        if let Some(cookie) = cookie {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
        }
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let values = headers.get_all(name);
    let mut iter = values.iter();
    let value = iter.next().ok_or_else(|| {
        OAuthError::new("invalid_request", format!("Missing {name} proxy header."))
    })?;
    if iter.next().is_some() {
        return Err(OAuthError::new(
            "invalid_request",
            "Ambiguous proxy headers.",
        ));
    }
    value
        .to_str()
        .map_err(|_| OAuthError::new("invalid_request", "Invalid proxy header."))
}
struct Original {
    origin: String,
    url: String,
    parsed: reqwest::Url,
}
fn original(req: &Request) -> Result<Original> {
    let headers = req.headers();
    let proto = single(headers, "x-forwarded-proto")?;
    if !matches!(proto, "http" | "https") {
        return Err(OAuthError::new(
            "invalid_request",
            "X-Forwarded-Proto must be http or https.",
        ));
    }
    let host = single(headers, "x-forwarded-host")?;
    if host.contains([',', '/', '?', '#']) {
        return Err(OAuthError::new(
            "invalid_request",
            "Invalid forwarded host.",
        ));
    }
    let origin = service::origin(&format!("{proto}://{host}"))?;
    let uri = if req.uri().path() == service::CALLBACK {
        req.uri().path_and_query().expect("callback path").as_str()
    } else {
        single(headers, "x-forwarded-uri")?
    };
    if !uri.starts_with('/') || uri.starts_with("//") {
        return Err(OAuthError::new(
            "invalid_request",
            "X-Forwarded-Uri must be an absolute path and query.",
        ));
    }
    let url = format!("{origin}{uri}");
    let parsed = service::parse_url(&url)?;
    if parsed.origin().ascii_serialization() != origin {
        return Err(OAuthError::new(
            "invalid_request",
            "The forwarded URL changed origin.",
        ));
    }
    Ok(Original {
        origin,
        url,
        parsed,
    })
}
fn attributes(origin: &str, path: &str) -> String {
    format!(
        "HttpOnly; SameSite=Lax; Path={path}{}",
        if origin.starts_with("https://") {
            "; Secure"
        } else {
            ""
        }
    )
}
fn set_cookie(response: &mut Response, value: String) -> Result<()> {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&value)
            .map_err(|_| OAuthError::new("server_error", "Unable to set ForwardAuth cookie."))?,
    );
    Ok(())
}
async fn verify(
    State(core): State<Arc<Core>>,
    Extension(trace): Extension<crate::journal::Capture>,
    req: Request,
) -> Result<Response> {
    let original = original(&req)?;
    trace.target(
        &original.origin,
        &original.url,
        req.headers()
            .get("x-forwarded-method")
            .and_then(|v| v.to_str().ok()),
    );
    let cookies = CookieJar::from_headers(req.headers());
    if original.parsed.path() == service::CALLBACK {
        let fields = oauth2::unique_fields(
            original
                .parsed
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
        )?;
        let state = oauth2::required(&fields, "state")?;
        let code = oauth2::required(&fields, "code")?;
        let binding_name = service::flow_cookie(&state, &original.origin)?;
        let binding = cookies.get(&binding_name).ok_or_else(|| {
            OAuthError::new(
                "invalid_request",
                "The ForwardAuth browser binding is missing. Start again.",
            )
        })?;
        let done = service::finish(&core, &original.origin, &state, &code, binding.value()).await?;
        let client = service::client(&mut core.db.clone(), done.client_id).await?;
        trace.client(&client);
        trace.subject(
            done.user_id,
            done.guard_session_id,
            None,
            Some(done.forward_session_id),
            true,
        );
        let mut response = Redirect::to(&done.return_uri).into_response();
        set_cookie(
            &mut response,
            format!(
                "{}={}; {}; Max-Age={}",
                service::session_cookie(done.client_id, &original.origin),
                done.token,
                attributes(&original.origin, "/"),
                done.lifetime
            ),
        )?;
        set_cookie(
            &mut response,
            format!(
                "{binding_name}=; {}; Max-Age=0",
                attributes(
                    &original.origin,
                    if original.origin.starts_with("https://") {
                        "/"
                    } else {
                        service::CALLBACK
                    }
                )
            ),
        )?;
        return Ok(crate::journal::outcome(response, "allowed", None));
    }
    if req.uri().path() == service::CALLBACK {
        return Err(OAuthError::new(
            "invalid_request",
            "The original callback URL is missing from the proxy headers.",
        ));
    }
    let client = service::for_origin(&mut core.db.clone(), &original.origin).await?;
    trace.client(&client);
    let cookie_name = service::session_cookie(client.id, &original.origin);
    if let Some(cookie) = cookies.get(&cookie_name) {
        if let Some(identity) =
            service::check(&core, &client, &original.origin, cookie.value()).await?
        {
            trace.subject(
                identity.user.id,
                identity.guard_session_id,
                None,
                Some(identity.forward_session_id),
                true,
            );
            let user = identity.user;
            let mut response = StatusCode::OK.into_response();
            response.headers_mut().insert(
                "x-guard-user-id",
                HeaderValue::from_str(&user.id.to_string()).expect("numeric ID"),
            );
            if let Ok(value) = HeaderValue::from_str(&user.username) {
                response.headers_mut().insert("x-guard-username", value);
            }
            return Ok(response);
        }
    }
    let flow = service::start(&core, &client, &original.url).await?;
    let mut response = Redirect::to(&flow.authorize_url).into_response();
    set_cookie(
        &mut response,
        format!(
            "{}={}; {}; Max-Age=300",
            service::flow_cookie(&flow.state, &original.origin)?,
            flow.browser,
            attributes(
                &original.origin,
                if original.origin.starts_with("https://") {
                    "/"
                } else {
                    service::CALLBACK
                }
            )
        ),
    )?;
    if cookies.get(&cookie_name).is_some() {
        set_cookie(
            &mut response,
            format!(
                "{}=; {}; Max-Age=0",
                cookie_name,
                attributes(&original.origin, "/")
            ),
        )?;
    }
    Ok(crate::journal::outcome(
        response,
        "authentication_required",
        None,
    ))
}
