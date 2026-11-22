use crate::{core::Core, models::*};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Instant,
};
use uuid::Uuid;

mod export;
pub(crate) mod reports;

pub(crate) struct Config {
    pub trusted_proxies: Vec<ipnet::IpNet>,
    pub report_limit: u32,
    pub export_url: Option<reqwest::Url>,
    export_token: Option<String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            report_limit: 600,
            export_url: None,
            export_token: None,
        }
    }
}
impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let mut config = Self::default();
        if let Ok(value) = std::env::var("AUDIT_TRUSTED_PROXIES") {
            for network in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                config.trusted_proxies.push(
                    network
                        .parse()
                        .map_err(|_| anyhow::anyhow!("Invalid AUDIT_TRUSTED_PROXIES CIDR."))?,
                );
            }
        }
        if let Ok(value) = std::env::var("AUDIT_EVENT_REPORTS_PER_MINUTE") {
            config.report_limit = value
                .parse()
                .ok()
                .filter(|n| *n > 0 && *n <= 1_000_000)
                .ok_or_else(|| {
                    anyhow::anyhow!("AUDIT_EVENT_REPORTS_PER_MINUTE must be 1–1000000.")
                })?;
        }
        if let Ok(value) = std::env::var("ACCESS_LOG_EXPORT_URL") {
            let url = reqwest::Url::parse(&value)
                .map_err(|_| anyhow::anyhow!("Invalid ACCESS_LOG_EXPORT_URL."))?;
            let local = url.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .trim_matches(['[', ']'])
                        .parse::<IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if (url.scheme() != "https" && !(url.scheme() == "http" && local))
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                anyhow::bail!(
                    "ACCESS_LOG_EXPORT_URL requires HTTPS (HTTP loopback is allowed for development), without URL credentials/fragments."
                );
            }
            config.export_url = Some(url);
            config.export_token = std::env::var("ACCESS_LOG_EXPORT_TOKEN").ok();
        }
        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub request_id: String,
    pub client_identifier: String,
    pub client_name: String,
    pub protocol: String,
    pub endpoint: String,
    pub method: String,
    pub origin: Option<String>,
    pub path: String,
    pub peer_ip: Option<String>,
    pub source_ip: Option<String>,
    pub ip_source: String,
    pub user_agent: Option<String>,
    pub status: u16,
    pub decision: String,
    #[serde(default)]
    pub error_code: Option<String>,
    pub duration_ms: u64,
    pub started_at: jiff::Timestamp,
    pub client_authenticated: bool,
    pub identity_verified: bool,
    pub grant_id: Option<i64>,
    pub forward_session_id: Option<i64>,
    pub report: Option<Value>,
    pub settings: Option<Value>,
}
impl Entry {
    pub fn new(protocol: &str, endpoint: &str, method: &str) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            client_identifier: String::new(),
            client_name: String::new(),
            protocol: protocol.into(),
            endpoint: endpoint.into(),
            method: method.into(),
            origin: None,
            path: safe_path(endpoint),
            peer_ip: None,
            source_ip: None,
            ip_source: "peer".into(),
            user_agent: None,
            status: 0,
            decision: String::new(),
            error_code: None,
            duration_ms: 0,
            started_at: jiff::Timestamp::now(),
            client_authenticated: false,
            identity_verified: false,
            grant_id: None,
            forward_session_id: None,
            report: None,
            settings: None,
        }
    }
}
#[derive(Clone)]
struct Target {
    id: i64,
    enabled: bool,
}
#[derive(Clone)]
struct Context {
    target: Option<Target>,
    user: Option<i64>,
    session: Option<i64>,
    entry: Entry,
}
#[derive(Clone)]
pub(crate) struct Capture(Arc<Mutex<Context>>);
impl Capture {
    pub fn new(protocol: &str, req: &Request, core: &Core, trusted_forward: bool) -> Self {
        let mut entry = Entry::new(protocol, req.uri().path(), req.method().as_str());
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|v| v.0.ip());
        if protocol == "oauth2" {
            entry.origin = reqwest::Url::parse(&core.domain)
                .ok()
                .map(|url| url.origin().ascii_serialization());
        }
        entry.peer_ip = peer.map(|ip| ip.to_string());
        entry.source_ip = entry.peer_ip.clone();
        if trusted_forward
            || peer.is_some_and(|ip| {
                core.journal_config
                    .trusted_proxies
                    .iter()
                    .any(|net| net.contains(&ip))
            })
        {
            if let Some(ip) = source_ip(req.headers(), &core.journal_config.trusted_proxies) {
                entry.source_ip = Some(ip.to_string());
                entry.ip_source = "trusted_forwarded_for".into();
            }
        }
        entry.user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|v| bounded(v, 512));
        Self(Arc::new(Mutex::new(Context {
            target: None,
            user: None,
            session: None,
            entry,
        })))
    }
    pub fn client(&self, client: &Client) {
        let mut ctx = self.0.lock().expect("request context");
        if ctx
            .target
            .as_ref()
            .is_some_and(|target| target.id != client.id)
        {
            ctx.user = None;
            ctx.session = None;
            ctx.entry.client_authenticated = false;
            ctx.entry.identity_verified = false;
            ctx.entry.grant_id = None;
            ctx.entry.forward_session_id = None;
        }
        let enabled = client.detailed_logging
            || ctx
                .target
                .as_ref()
                .is_some_and(|target| target.id == client.id && target.enabled);
        ctx.target = Some(Target {
            id: client.id,
            enabled,
        });
        ctx.entry.client_identifier = client.client_id.clone();
        ctx.entry.client_name = client.name.clone();
    }
    pub fn client_authenticated(&self) {
        self.0
            .lock()
            .expect("request context")
            .entry
            .client_authenticated = true;
    }
    pub fn subject(
        &self,
        user: i64,
        session: i64,
        grant: Option<i64>,
        forward: Option<i64>,
        verified: bool,
    ) {
        let mut c = self.0.lock().expect("request context");
        c.user = Some(user);
        c.session = Some(session);
        c.entry.grant_id = grant;
        c.entry.forward_session_id = forward;
        c.entry.identity_verified = verified;
    }
    pub fn verified(&self) {
        self.0
            .lock()
            .expect("request context")
            .entry
            .identity_verified = true;
    }
    pub fn target(&self, origin: &str, path: &str, method: Option<&str>) {
        let mut c = self.0.lock().expect("request context");
        c.entry.origin = Some(origin.into());
        c.entry.path = safe_path(path);
        if let Some(method) =
            method.filter(|m| m.len() <= 32 && axum::http::Method::from_bytes(m.as_bytes()).is_ok())
        {
            c.entry.method = method.into();
        }
    }
    pub fn snapshot(&self) -> Entry {
        self.0.lock().expect("request context").entry.clone()
    }
}
pub(crate) fn bounded(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect()
}
pub(crate) fn safe_path(value: &str) -> String {
    if let Ok(url) = reqwest::Url::parse(value) {
        if matches!(url.scheme(), "http" | "https") {
            return bounded(url.path(), 16384);
        }
    }
    bounded(value.split(['?', '#']).next().unwrap_or_default(), 16384)
}
/// Resolve client IPs only through the configured proxy trust boundary.
pub(crate) fn request_ip(req: &Request, core: &Core, trusted_forward: bool) -> Option<IpAddr> {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|v| v.0.ip().to_canonical());
    if trusted_forward
        || peer.is_some_and(|ip| {
            core.journal_config
                .trusted_proxies
                .iter()
                .any(|net| net.contains(&ip))
        })
    {
        if let Some(ip) = source_ip(req.headers(), &core.journal_config.trusted_proxies) {
            return Some(ip.to_canonical());
        }
    }
    peer
}

fn source_ip(headers: &HeaderMap, trusted: &[ipnet::IpNet]) -> Option<IpAddr> {
    if headers.get_all("x-forwarded-for").iter().count() != 1 {
        return None;
    }
    let chain = headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .split(',')
        .map(|v| v.trim().parse::<IpAddr>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    chain
        .iter()
        .rev()
        .find(|ip| !trusted.iter().any(|net| net.contains(*ip)))
        .copied()
        .or_else(|| chain.first().copied())
}

pub(crate) async fn persist(
    db: &mut dyn toasty::Executor,
    client_id: i64,
    user: Option<i64>,
    session: Option<i64>,
    source: &str,
    dedupe: &str,
    entry: Entry,
) -> toasty::Result<AccessLog> {
    let log = toasty::create!(AccessLog {
        event_id: entry.request_id.clone(),
        dedupe_key: dedupe,
        client_id: client_id,
        user_id: user,
        session_id: session,
        source: source,
        data: toasty::Json(entry)
    })
    .exec(&mut *db)
    .await?;
    toasty::create!(AccessLogDelivery {
        log_id: log.id,
        next_attempt_at: jiff::Timestamp::now()
    })
    .exec(db)
    .await?;
    Ok(log)
}
pub(crate) async fn configuration(
    db: &mut dyn toasty::Executor,
    actor: i64,
    client: &Client,
    old: Option<(bool, bool)>,
) -> toasty::Result<()> {
    if old == Some((client.detailed_logging, client.allow_event_reports))
        || old.is_none() && !client.detailed_logging && !client.allow_event_reports
    {
        return Ok(());
    }
    crate::audit::record(
        &mut *db,
        actor,
        AuditLogEntry::ClientLoggingChanged {
            client_id: client.id,
            detailed_logging: client.detailed_logging,
            allow_event_reports: client.allow_event_reports,
        },
    )
    .await?;
    let mut entry = Entry::new("administration", "/admin/clients", "POST");
    entry.client_name = client.name.clone();
    entry.client_identifier = client.client_id.clone();
    entry.identity_verified = true;
    entry.status = 200;
    entry.decision = "settings_changed".into();
    entry.settings = Some(
        json!({"previous":old.map(|(d,r)|json!({"detailed_logging":d,"allow_event_reports":r})),"detailed_logging":client.detailed_logging,"allow_event_reports":client.allow_event_reports}),
    );
    let dedupe = format!("configuration:{}", entry.request_id);
    persist(
        db,
        client.id,
        Some(actor),
        None,
        "configuration",
        &dedupe,
        entry,
    )
    .await?;
    Ok(())
}

#[derive(Clone)]
pub(crate) struct ResponseOutcome {
    pub decision: &'static str,
    pub error: Option<&'static str>,
}
pub(crate) fn outcome(
    mut response: Response,
    decision: &'static str,
    error: Option<&'static str>,
) -> Response {
    response
        .extensions_mut()
        .insert(ResponseOutcome { decision, error });
    response
}

pub(crate) async fn oauth(State(core): State<Arc<Core>>, req: Request, next: Next) -> Response {
    capture(core, req, next, "oauth2", false).await
}
pub(crate) async fn forwardauth(
    State(core): State<Arc<Core>>,
    req: Request,
    next: Next,
) -> Response {
    capture(core, req, next, "forwardauth", true).await
}
async fn capture(
    core: Arc<Core>,
    mut req: Request,
    next: Next,
    protocol: &str,
    trusted: bool,
) -> Response {
    let started = Instant::now();
    let journal = Capture::new(protocol, &req, &core, trusted);
    identify(
        &core,
        req.headers().clone(),
        req.uri().clone(),
        &journal,
        protocol,
    )
    .await;
    let id = journal.snapshot().request_id;
    req.extensions_mut().insert(journal.clone());
    let mut response = next.run(req).await;
    let context = journal.0.lock().expect("request context").clone();
    if let Some(target) = context.target.filter(|target| target.enabled) {
        let mut entry = context.entry;
        entry.status = response.status().as_u16();
        entry.duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        entry.decision = match response.status().as_u16() {
            200..=299 => "allowed",
            300..=399 => "redirected",
            400..=499 => "denied",
            _ => "error",
        }
        .into();
        if let Some(semantic) = response.extensions().get::<ResponseOutcome>() {
            entry.decision = semantic.decision.into();
            entry.error_code = semantic.error.map(str::to_owned);
        }
        let result = async {
            let mut db = core.db.clone();
            let mut tx = db.transaction().await?;
            persist(
                &mut tx,
                target.id,
                context.user,
                context.session,
                "request",
                &format!("request:{id}"),
                entry,
            )
            .await?;
            tx.commit().await
        }
        .await;
        if result.is_err() {
            eprintln!(
                "Access journal persistence failed: request={id} client={}",
                target.id
            );
            response = (
                StatusCode::SERVICE_UNAVAILABLE,
                [(axum::http::header::CACHE_CONTROL, "no-store")],
                axum::Json(json!({"error":"access_journal_unavailable","request_id":id})),
            )
                .into_response();
        }
    }
    response.headers_mut().insert(
        "x-guard-request-id",
        HeaderValue::from_str(&id).expect("UUID"),
    );
    response
}

async fn identify(
    core: &Core,
    headers: HeaderMap,
    uri: axum::http::Uri,
    capture: &Capture,
    protocol: &str,
) {
    let mut db = core.db.clone();
    let path = uri.path();
    if protocol == "oauth2" {
        if let Some(slug) = path
            .strip_prefix("/oauth2/")
            .and_then(|p| p.split_once('/'))
            .map(|(slug, _)| slug)
        {
            if let Ok(client) = Client::get_by_slug(&mut db, slug).await {
                capture.client(&client);
            }
        }
        if path == "/oauth2/authorize" {
            if let Ok(pairs) =
                serde_urlencoded::from_str::<Vec<(String, String)>>(uri.query().unwrap_or_default())
            {
                claim_fields(core, capture, &pairs).await;
            }
        }
        if matches!(path, "/oauth2/token" | "/oauth2/revoke" | "/oauth2/event") {
            if let Some(id) = basic_identifier(&headers) {
                if let Ok(client) = Client::get_by_client_id(&mut db, id).await {
                    capture.client(&client);
                }
            }
        }
        if path == "/oauth2/userinfo" {
            if let Some(raw) = bearer(&headers) {
                if let Ok(token) = OAuthToken::get_by_access_token(
                    &mut db,
                    crate::provider::oauth2::hash_token(raw),
                )
                .await
                {
                    if let Ok(client) = Client::get_by_id(&mut db, token.client_id).await {
                        capture.client(&client);
                        capture.subject(
                            token.user_id,
                            token.session_id,
                            Some(token.code_id),
                            None,
                            false,
                        );
                    }
                }
            }
        }
    } else {
        let cookies = axum_extra::extract::CookieJar::from_headers(&headers);
        for cookie in cookies
            .iter()
            .filter(|c| c.name().contains("guard_forwardauth_session_"))
            .take(32)
        {
            if let Ok(session) = ForwardAuthSession::get_by_token_hash(
                &mut db,
                crate::provider::oauth2::hash_token(cookie.value()),
            )
            .await
            {
                let request_origin = headers
                    .get("x-forwarded-proto")
                    .and_then(|v| v.to_str().ok())
                    .zip(
                        headers
                            .get("x-forwarded-host")
                            .and_then(|v| v.to_str().ok()),
                    )
                    .and_then(|(proto, host)| {
                        crate::provider::forwardauth::origin(&format!("{proto}://{host}")).ok()
                    });
                if cookie.name()
                    != crate::provider::forwardauth::session_cookie(
                        session.client_id,
                        &session.origin,
                    )
                    || request_origin.as_deref() != Some(session.origin.as_str())
                {
                    continue;
                }
                if let Ok(client) = Client::get_by_id(&mut db, session.client_id).await {
                    capture.client(&client);
                    capture.subject(
                        session.user_id,
                        session.session_id,
                        None,
                        Some(session.id),
                        false,
                    );
                    break;
                }
            }
        }
        let uri = if path == crate::provider::forwardauth::CALLBACK {
            uri.path_and_query().map(|v| v.as_str())
        } else {
            headers.get("x-forwarded-uri").and_then(|v| v.to_str().ok())
        };
        if let Some(uri) =
            uri.filter(|uri| uri.split('?').next() == Some(crate::provider::forwardauth::CALLBACK))
        {
            if let Some(query) = uri.split_once('?').map(|(_, q)| q) {
                if let Ok(pairs) = serde_urlencoded::from_str::<Vec<(String, String)>>(query) {
                    let states = pairs
                        .iter()
                        .filter(|(k, _)| k == "state")
                        .collect::<Vec<_>>();
                    if states.len() == 1 {
                        if let Ok(flow) = ForwardAuthRequest::get_by_state_hash(
                            &mut db,
                            crate::provider::oauth2::hash_token(&states[0].1),
                        )
                        .await
                        {
                            if let Ok(client) = Client::get_by_id(&mut db, flow.client_id).await {
                                capture.client(&client);
                                if let (Some(user), Some(session)) = (flow.user_id, flow.session_id)
                                {
                                    capture.subject(user, session, None, None, false);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
pub(crate) async fn claim_fields(core: &Core, capture: &Capture, pairs: &[(String, String)]) {
    if capture.0.lock().expect("request context").target.is_some() {
        return;
    }
    let values = pairs
        .iter()
        .filter(|(key, _)| key == "client_id")
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>();
    if let Some(id) = values
        .first()
        .filter(|id| values.iter().all(|other| other == *id))
    {
        if let Ok(client) = Client::get_by_client_id(&mut core.db.clone(), *id).await {
            capture.client(&client);
        }
    }
}
fn basic_identifier(headers: &HeaderMap) -> Option<String> {
    use base64::Engine as _;
    if headers
        .get_all(axum::http::header::AUTHORIZATION)
        .iter()
        .count()
        != 1
    {
        return None;
    }
    let (method, raw) = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .split_once(' ')?;
    if !method.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded =
        String::from_utf8(base64::engine::general_purpose::STANDARD.decode(raw).ok()?).ok()?;
    let (id, _) = decoded.split_once(':')?;
    let pairs: Vec<(String, String)> = serde_urlencoded::from_str(&format!("v={id}")).ok()?;
    if pairs.len() != 1 {
        return None;
    }
    Some(pairs[0].1.clone())
}
pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    if headers
        .get_all(axum::http::header::AUTHORIZATION)
        .iter()
        .count()
        != 1
    {
        return None;
    }
    let (method, value) = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .split_once(' ')?;
    if method.eq_ignore_ascii_case("Bearer") && !value.is_empty() {
        Some(value)
    } else {
        None
    }
}
pub(crate) fn spawn_exporter(core: Arc<Core>) {
    if core.journal_config.export_url.is_some() {
        tokio::spawn(export::run(core));
    }
}
