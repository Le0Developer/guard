use super::*;
use axum::{extract::{MatchedPath, Query}, http::{header, Method}, middleware::Next};
use crate::models::{AuditLog, AuditLogEntry};

#[derive(Clone)]
pub(super) struct Target(pub i64);

// Runs inside authentication/admin authorization. Use the route pattern and
// numeric path IDs only; raw URLs, query strings and form values are excluded.
pub(crate) async fn capture(State(core): State<Arc<Core>>, req: Request, next: Next) -> Response {
    if req.method() != Method::POST { return next.run(req).await; }
    let actor = req.extensions().get::<Arc<User>>().map(|user| user.id);
    let route = req.extensions().get::<MatchedPath>().map(|p| p.as_str().to_owned()).unwrap_or_default();
    let ids: Vec<i64> = req.uri().path().split('/').filter_map(|s| s.parse().ok()).collect();
    let mut response = next.run(req).await;
    if let Some(actor) = actor {
        let status = response.status().as_u16();
        let target_id = response.extensions().get::<Target>().map(|target| target.0).or_else(|| ids.first().copied()).or_else(|| {
            if response.status().is_redirection() {
                response.headers().get(header::LOCATION)?.to_str().ok()?.rsplit('/').next()?.parse().ok()
            } else { None }
        });
        let entry = AuditLogEntry::AdminAction { action: route, target_id, related_id: ids.get(1).copied(), status };
        crate::audit::best_effort(&core, actor, entry).await;
    }
    response.headers_mut().insert(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    response
}

fn description(entry: &AuditLogEntry) -> (String, String, String) {
    match entry {
        AuditLogEntry::UserCreated => ("User created".into(), String::new(), "Succeeded".into()),
        AuditLogEntry::UserLoggedIn => ("Signed in".into(), String::new(), "Succeeded".into()),
        AuditLogEntry::UserQuarantined => ("User disabled".into(), String::new(), "Succeeded".into()),
        AuditLogEntry::UserDeleted => ("User deleted".into(), String::new(), "Succeeded".into()),
        AuditLogEntry::Mfa { action, subject_id, method, record_id, outcome } => (
            action.clone(), format!("User {subject_id}, {method}{}", record_id.map(|id|format!(" #{id}")).unwrap_or_default()), outcome.clone()),
        AuditLogEntry::ForwardAuth { action, client_id, session_id } => (action.clone(), format!("Client {client_id}, session {session_id}"), "Succeeded".into()),
        AuditLogEntry::ClientLoggingChanged { client_id, detailed_logging, allow_event_reports } => ("Client logging settings changed".into(), format!("Client {client_id}: requests={detailed_logging}, reports={allow_event_reports}"), "Succeeded".into()),
        AuditLogEntry::ApplicationEvent { client_id, session_id, event_id, event, resource, outcome } => (format!("Application report: {event}"), format!("Client {client_id}, session {session_id}, event {event_id}{}", resource.as_ref().map(|r|format!(", {r}")).unwrap_or_default()), outcome.clone()),
        AuditLogEntry::LoginFailed => ("Sign-in failed".into(), String::new(), "Rejected".into()),
        AuditLogEntry::UserLoggedOut { session_id } => ("Signed out".into(), format!("Session {session_id}"), "Succeeded".into()),
        AuditLogEntry::AdminAction { action, target_id, related_id, status } => {
            let parts: Vec<_> = action.split('/').collect();
            let resource = parts.get(2).copied().unwrap_or("record");
            let operation = match parts.get(4).copied() {
                None if !action.contains("{id}") => "Create",
                None => "Save",
                Some("delete") => "Delete",
                Some("rotate-secret") => "Rotate secret",
                Some("sessions") => "Revoke sessions",
                Some("members") if action.ends_with("remove") => "Remove member",
                Some("members") => "Add member",
                Some("redirects") if action.ends_with("remove") => "Remove redirect URI",
                Some("redirects") => "Save redirect URI",
                Some("rules") if action.ends_with("remove") => "Remove access rule",
                Some("rules") => "Save access rule",
                _ => "Change",
            };
            let target = target_id.map(|id| format!("{resource} #{id}")).unwrap_or_else(|| resource.into());
            let target = if let Some(id) = related_id { format!("{target}, related #{id}") } else { target };
            (operation.into(), target, if *status < 400 { "Succeeded".into() } else { format!("Rejected ({status})") })
        }
        AuditLogEntry::OAuthAuthorization { client_id, session_id } => oauth_description("OAuth authorization", *client_id, *session_id),
        AuditLogEntry::OAuthTokenIssued { client_id, session_id } => oauth_description("OAuth tokens issued", *client_id, *session_id),
        AuditLogEntry::OAuthTokenRefreshed { client_id, session_id } => oauth_description("OAuth tokens refreshed", *client_id, *session_id),
        AuditLogEntry::OAuthTokenRevoked { client_id, session_id } => oauth_description("OAuth tokens revoked", *client_id, *session_id),
        AuditLogEntry::OAuthReplayDetected { client_id, session_id, grant } => (format!("OAuth {grant} replay"), format!("Client {client_id}, session {session_id}"), "Rejected; tokens revoked".into()),
    }
}

fn oauth_description(action: &str, client: i64, session: i64) -> (String, String, String) {
    (action.into(), format!("Client {client}, session {session}"), "Succeeded".into())
}

pub async fn list(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, Query(params): Query<HashMap<String, String>>) -> Result {
    let before = params.get("before").map(|v| v.parse::<i64>()).transpose().map_err(|_| bad_input("Invalid page cursor."))?.unwrap_or(i64::MAX);
    let mut db = core.db.clone();
    let logs = AuditLog::filter(AuditLog::fields().id().lt(before)).order_by(AuditLog::fields().id().desc()).limit(51).exec(&mut db).await?;
    let has_more = logs.len() > 50;
    let mut rows = Vec::new();
    let mut actors = HashMap::new();
    for log in logs.into_iter().take(50) {
        if !actors.contains_key(&log.user_id) {
            let name = match User::get_by_id(&mut db, log.user_id).await {
                Ok(actor) => actor.username,
                Err(e) if e.is_record_not_found() => "Deleted user".into(),
                Err(e) => return Err(e.into()),
            };
            actors.insert(log.user_id, name);
        }
        let (action, target, outcome) = description(&log.data.0);
        rows.push(AuditRow { id: log.id, created_at: log.created_at, actor: format!("{} (#{})", actors[&log.user_id], log.user_id), action, target, outcome });
    }
    let next = if has_more { rows.last().map(|row| row.id) } else { None };
    let mut response = AuditPage { user: &user, csrf: &csrf.token, rows, next }.into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    Ok(response)
}
