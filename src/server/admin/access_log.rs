use super::*;
use crate::models::{AccessLog, AccessLogDelivery};
use axum::extract::Query;

pub async fn list(
    State(core): State<Arc<Core>>,
    Extension(user): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    Query(params): Query<HashMap<String, String>>,
) -> Result {
    let before = params
        .get("before")
        .map(|v| v.parse::<i64>())
        .transpose()
        .map_err(|_| bad_input("Invalid page cursor."))?
        .unwrap_or(i64::MAX);
    let client_id = params
        .get("client_id")
        .filter(|v| !v.is_empty())
        .map(|v| v.parse::<i64>())
        .transpose()
        .map_err(|_| bad_input("Invalid client ID."))?;
    let session_id = params
        .get("session_id")
        .filter(|v| !v.is_empty())
        .map(|v| v.parse::<i64>())
        .transpose()
        .map_err(|_| bad_input("Invalid session ID."))?;
    let source = field(&params, "source");
    if !matches!(
        source.as_str(),
        "" | "request" | "application" | "configuration"
    ) {
        return Err(bad_input("Invalid event source."));
    }
    let mut predicate = AccessLog::fields().id().lt(before);
    if let Some(id) = client_id {
        predicate = predicate.and(AccessLog::fields().client_id().eq(id));
    }
    if let Some(id) = session_id {
        predicate = predicate.and(AccessLog::fields().session_id().eq(Some(id)));
    }
    if !source.is_empty() {
        predicate = predicate.and(AccessLog::fields().source().eq(&source));
    }
    let mut db = core.db.clone();
    let records = AccessLog::filter(predicate)
        .order_by(AccessLog::fields().id().desc())
        .limit(51)
        .exec(&mut db)
        .await?;
    let more = records.len() > 50;
    let mut rows = Vec::new();
    for log in records.into_iter().take(50) {
        let delivery = match AccessLogDelivery::get_by_log_id(&mut db, log.id).await {
            Ok(value) => Some(value),
            Err(e) if e.is_record_not_found() => None,
            Err(e) => return Err(e.into()),
        };
        let status = match delivery {
            Some(d) if d.delivered_at.is_some() => "Delivered".into(),
            Some(d) if d.last_error.is_some() => format!(
                "Retrying: {} ({} attempts)",
                d.last_error.unwrap_or_default(),
                d.attempts
            ),
            _ => {
                if core.journal_config.export_url.is_some() {
                    "Pending".into()
                } else {
                    "Stored locally".into()
                }
            }
        };
        let entry = &log.data.0;
        let action = entry
            .report
            .as_ref()
            .and_then(|v| v["event"].as_str())
            .unwrap_or(&entry.endpoint)
            .to_string();
        let detail = serde_json::to_string_pretty(&serde_json::json!({
            "event_id": log.event_id,
            "received_at": log.created_at,
            "client_id": log.client_id,
            "user_id": log.user_id,
            "session_id": log.session_id,
            "source": log.source,
            "data": entry,
        }))
        .map_err(|_| bad_input("Unable to render event details."))?;
        rows.push(AccessRow {
            id: log.id,
            time: log.created_at.strftime("%Y-%m-%d %H:%M:%S").to_string(),
            client: format!("{} (#{})", entry.client_name, log.client_id),
            subject: log
                .user_id
                .map(|id| format!("User {id}"))
                .unwrap_or_else(|| "Unauthenticated".into()),
            session: log
                .session_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "Unknown".into()),
            source: log.source,
            action,
            outcome: format!("{} ({})", entry.decision, entry.status),
            path: entry.path.clone(),
            ip: entry.source_ip.clone().unwrap_or_else(|| "Unknown".into()),
            delivery: status,
            details: detail,
        });
    }
    let next = if more {
        rows.last().map(|r| r.id)
    } else {
        None
    };
    let mut pairs = Vec::new();
    if let Some(id) = client_id {
        pairs.push(("client_id", id.to_string()));
    }
    if let Some(id) = session_id {
        pairs.push(("session_id", id.to_string()));
    }
    if !source.is_empty() {
        pairs.push(("source", source.clone()));
    }
    let next_url = next.map(|id| {
        pairs.push(("before", id.to_string()));
        format!(
            "/admin/access-log?{}",
            serde_urlencoded::to_string(&pairs).expect("numeric filters")
        )
    });
    let mut clients: Vec<Choice> = Client::all()
        .exec(&mut db)
        .await?
        .into_iter()
        .map(|client| Choice {
            id: client.id,
            name: format!(
                "{}{}",
                client.name,
                if client.deleted_at.is_some() {
                    " (deleted)"
                } else {
                    ""
                }
            ),
        })
        .collect();
    clients.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    let pending = AccessLogDelivery::filter(AccessLogDelivery::fields().delivered_at().is_none())
        .count()
        .exec(&mut db)
        .await?;
    let failed = AccessLogDelivery::filter(
        AccessLogDelivery::fields()
            .delivered_at()
            .is_none()
            .and(AccessLogDelivery::fields().last_error().is_some()),
    )
    .count()
    .exec(&mut db)
    .await?;
    let mut response = AccessLogPage {
        user: &user,
        csrf: &csrf.token,
        rows,
        next_url,
        client_filter: client_id.map(|v| v.to_string()).unwrap_or_default(),
        session_filter: session_id.map(|v| v.to_string()).unwrap_or_default(),
        source_filter: source,
        clients,
        pending,
        failed,
        export_enabled: core.journal_config.export_url.is_some(),
    }
    .into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}
