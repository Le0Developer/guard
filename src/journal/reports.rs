use super::*;
use crate::provider::{
    forwardauth,
    oauth2::{self, OAuthError, access},
};
use std::collections::BTreeMap;
use toasty_core::driver::operation::TransactionMode;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    #[serde(skip_serializing)]
    pub session_token: String,
    pub report_id: Uuid,
    pub event: String,
    pub outcome: Outcome,
    pub resource: Option<String>,
    pub occurred_at: Option<jiff::Timestamp>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Success,
    Failure,
    Denied,
    Started,
    Completed,
}
fn invalid(message: &str) -> OAuthError {
    OAuthError::new("invalid_request", message)
}
fn forbidden(message: &str) -> OAuthError {
    OAuthError {
        status: StatusCode::FORBIDDEN,
        code: "access_denied",
        description: message.into(),
    }
}
struct Subject {
    user: i64,
    session: i64,
    grant: Option<i64>,
    forward: Option<i64>,
    started_at: jiff::Timestamp,
    origin: Option<String>,
}
async fn subject(
    db: &mut dyn toasty::Executor,
    client: &Client,
    raw: &str,
) -> oauth2::Result<Subject> {
    if raw.is_empty() || raw.len() > 512 {
        return Err(OAuthError::invalid_token());
    }
    let now = jiff::Timestamp::now();
    let (user_id, session_id, grant, forward, started_at, origin) = match client.client_type {
        ClientType::Oidc => {
            let token = OAuthToken::get_by_access_token(&mut *db, oauth2::hash_token(raw))
                .await
                .map_err(|e| {
                    if e.is_record_not_found() {
                        OAuthError::invalid_token()
                    } else {
                        e.into()
                    }
                })?;
            if token.client_id != client.id
                || token.revoked_at.is_some()
                || token.access_expires_at <= now
                || token.expires_at <= now
            {
                return Err(OAuthError::invalid_token());
            }
            let code = ClientToken::get_by_id(&mut *db, token.code_id).await?;
            let origin = reqwest::Url::parse(&code.redirect_uri)
                .ok()
                .map(|url| url.origin().ascii_serialization());
            (
                token.user_id,
                token.session_id,
                Some(token.code_id),
                None,
                code.created_at,
                origin,
            )
        }
        ClientType::ForwardAuth => {
            let token = ForwardAuthSession::get_by_token_hash(&mut *db, oauth2::hash_token(raw))
                .await
                .map_err(|e| {
                    if e.is_record_not_found() {
                        OAuthError::invalid_token()
                    } else {
                        e.into()
                    }
                })?;
            if token.client_id != client.id
                || token.expires_at <= now
                || !forwardauth::allowed(&mut *db, client, &token.origin).await?
            {
                return Err(OAuthError::invalid_token());
            }
            (
                token.user_id,
                token.session_id,
                None,
                Some(token.id),
                token.created_at,
                Some(token.origin),
            )
        }
    };
    let (user, session) = access::user_session(&mut *db, session_id, user_id)
        .await
        .map_err(|e| {
            if e.code == "invalid_grant" {
                OAuthError::invalid_token()
            } else {
                e
            }
        })?;
    if !access::permitted(db, client, &user).await? {
        return Err(forbidden(
            "This session no longer has access to this client.",
        ));
    }
    Ok(Subject {
        user: user.id,
        session: session.id,
        grant,
        forward,
        started_at,
        origin,
    })
}
fn validate(input: &mut Input) -> oauth2::Result<()> {
    if input.report_id.is_nil() {
        return Err(invalid("report_id must be a non-nil UUID."));
    }
    if input.event.is_empty()
        || input.event.len() > 100
        || !input
            .event
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return Err(invalid(
            "event must contain 1–100 letters, digits, dots, underscores or hyphens.",
        ));
    }
    if let Some(resource) = &input.resource {
        if resource.len() > 2048 || resource.chars().any(char::is_control) {
            return Err(invalid(
                "resource must be at most 2048 bytes without control characters.",
            ));
        }
        input.resource = Some(if let Ok(url) = reqwest::Url::parse(resource) {
            if matches!(url.scheme(), "http" | "https") {
                if !url.username().is_empty() || url.password().is_some() {
                    return Err(invalid("Resource URLs must not contain credentials."));
                }
                format!("{}{}", url.origin().ascii_serialization(), url.path())
            } else {
                resource.split(['?', '#']).next().unwrap_or_default().into()
            }
        } else {
            resource.split(['?', '#']).next().unwrap_or_default().into()
        });
    }
    if input.metadata.len() > 24 {
        return Err(invalid("metadata supports at most 24 flat fields."));
    }
    for (key, value) in &mut input.metadata {
        let normalized = key
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>();
        if key.is_empty()
            || key.len() > 64
            || key.chars().any(char::is_control)
            || [
                "password",
                "passwd",
                "secret",
                "token",
                "cookie",
                "authorization",
                "credential",
                "apikey",
            ]
            .iter()
            .any(|word| normalized.contains(word))
            || matches!(
                normalized.as_str(),
                "code" | "userid" | "sessionid" | "clientid" | "actorid" | "subjectid"
            )
        {
            return Err(invalid("metadata must use bounded nonsecret field names."));
        }
        match value {
            Value::String(value) => {
                if value.len() > 256 || value.chars().any(char::is_control) {
                    return Err(invalid(
                        "Metadata strings must be at most 256 bytes without control characters.",
                    ));
                }
                if let Ok(url) = reqwest::Url::parse(value) {
                    if matches!(url.scheme(), "http" | "https") {
                        if !url.username().is_empty() || url.password().is_some() {
                            return Err(invalid("Metadata URLs must not contain credentials."));
                        }
                        *value = format!("{}{}", url.origin().ascii_serialization(), url.path());
                    }
                }
            }
            Value::Number(_) | Value::Bool(_) | Value::Null => (),
            _ => {
                return Err(invalid(
                    "metadata values must be strings, numbers, booleans or null.",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) async fn submit(
    core: &Core,
    authenticated: &Client,
    capture: &Capture,
    mut input: Input,
) -> oauth2::Result<(bool, Value)> {
    validate(&mut input)?;
    let public_payload = serde_json::to_string(&input).map_err(|_| invalid("Invalid report."))?;
    if (!input.session_token.is_empty() && public_payload.contains(&input.session_token))
        || public_payload.contains(&authenticated.client_secret)
    {
        return Err(invalid(
            "Reports must not include session tokens or client secrets in event data.",
        ));
    }
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let client = access::registered_client(&mut tx, &authenticated.client_id).await?;
    if !oauth2::secret_eq(&client.client_secret, &authenticated.client_secret) {
        return Err(OAuthError::invalid_client());
    }
    capture.client(&client);
    if !client.allow_event_reports {
        return Err(forbidden(
            "Session event reports are disabled for this client.",
        ));
    }
    let subject = subject(&mut tx, &client, &input.session_token).await?;
    capture.subject(
        subject.user,
        subject.session,
        subject.grant,
        subject.forward,
        true,
    );
    let now = jiff::Timestamp::now();
    if input
        .occurred_at
        .is_some_and(|time| time < subject.started_at || time.as_second() > now.as_second() + 300)
    {
        return Err(invalid(
            "occurred_at must be within this Guard session and no more than five minutes in the future.",
        ));
    }
    let fingerprint =
        oauth2::hash_token(&serde_json::to_string(&input).map_err(|_| invalid("Invalid report."))?);
    let dedupe = format!("report:{}:{}", client.id, input.report_id);
    match AccessLog::get_by_dedupe_key(&mut tx, &dedupe).await {
        Ok(log) => {
            if log.user_id != Some(subject.user)
                || log.session_id != Some(subject.session)
                || log.data.0.grant_id != subject.grant
                || log.data.0.forward_session_id != subject.forward
                || log
                    .data
                    .0
                    .report
                    .as_ref()
                    .and_then(|r| r["fingerprint"].as_str())
                    != Some(fingerprint.as_str())
            {
                return Err(OAuthError {
                    status: StatusCode::CONFLICT,
                    code: "report_conflict",
                    description: "This report_id is already bound to another report or session."
                        .into(),
                });
            }
            return Ok((
                false,
                json!({"event_id":log.event_id,"report_id":input.report_id,"received_at":log.created_at}),
            ));
        }
        Err(e) if e.is_record_not_found() => (),
        Err(e) => return Err(e.into()),
    }
    let window = now.as_second() / 60;
    match EventReportRate::get_by_client_id(&mut tx, client.id).await {
        Ok(rate) => {
            if rate.window == window && rate.count >= core.journal_config.report_limit {
                return Err(OAuthError {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    code: "rate_limited",
                    description: "Event report limit reached. Retry in the next minute.".into(),
                });
            }
            EventReportRate::filter_by_client_id(client.id)
                .update()
                .window(window)
                .count(if rate.window == window {
                    rate.count + 1
                } else {
                    1
                })
                .exec(&mut tx)
                .await?;
        }
        Err(e) if e.is_record_not_found() => {
            toasty::create!(EventReportRate {
                client_id: client.id,
                window: window,
                count: 1
            })
            .exec(&mut tx)
            .await?;
        }
        Err(e) => return Err(e.into()),
    }
    let mut entry = capture.snapshot();
    entry.request_id = Uuid::new_v4().to_string();
    entry.protocol = "application".into();
    entry.status = 202;
    entry.decision = serde_json::to_value(&input.outcome)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "reported".into());
    entry.origin = subject.origin;
    entry.path = input.resource.clone().unwrap_or_default();
    entry.report = Some(
        json!({"report_id":input.report_id,"event":input.event,"outcome":input.outcome,"resource":input.resource,"occurred_at":input.occurred_at.unwrap_or(now),"metadata":input.metadata,"fingerprint":fingerprint}),
    );
    let log = persist(
        &mut tx,
        client.id,
        Some(subject.user),
        Some(subject.session),
        "application",
        &dedupe,
        entry,
    )
    .await?;
    crate::audit::record(
        &mut tx,
        subject.user,
        AuditLogEntry::ApplicationEvent {
            client_id: client.id,
            session_id: subject.session,
            event_id: log.event_id.clone(),
            event: input.event,
            resource: input.resource,
            outcome: log.data.0.decision.clone(),
        },
    )
    .await?;
    tx.commit().await?;
    Ok((
        true,
        json!({"event_id":log.event_id,"report_id":input.report_id,"received_at":log.created_at}),
    ))
}
