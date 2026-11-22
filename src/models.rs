use std::{str::FromStr};

use serde::{Deserialize, Serialize};
use toasty::{Deferred, Model, Json};
use make_public::make_public;

#[derive(Debug, Model)]
#[make_public]
pub struct User {
	#[key]
	#[auto]
	id: i64,

	#[unique]
	username: String,
	email: Option<String>,
	password: Option<String>,
    #[default(0)]
    mfa_revision: i64,
    #[default(0)]
    mfa_failures: u32,
    mfa_window: Option<jiff::Timestamp>,
    webauthn_user_id: Option<String>,
	#[default(false)]
	disabled: bool,

	#[default(Role::User)]
	role: Role,

	#[auto]
	created_at: jiff::Timestamp,
	#[auto]
	updated_at: jiff::Timestamp,
	deleted_at: Option<jiff::Timestamp>,
}

#[derive(Debug, toasty::Embed)]
pub enum Role {
	User,
	Admin,
}

impl FromStr for Role {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"User" => Ok(Role::User),
			"Admin" => Ok(Role::Admin),
			_ => Err(anyhow::anyhow!("Invalid role")),
		}
	}
}

#[derive(Debug, Model)]
#[make_public]
pub struct Session {
	#[key]
	#[auto]
	id: i64,
	user_id: i64,

	#[unique]
	token: String,

	#[auto]
    #[index]
	created_at: jiff::Timestamp,

	#[belongs_to]
	user: Deferred<User>,
}

#[derive(Debug, Model)]
#[make_public]
pub struct AuditLog {
	#[key]
	#[auto]
	id: i64,
	user_id: i64,

	#[column(type = text)]
	data: Json<AuditLogEntry>,

	#[auto]
	created_at: jiff::Timestamp,

	#[belongs_to]
	user: Deferred<User>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuditLogEntry {
	UserCreated,
	UserLoggedIn,
	UserQuarantined,
	UserDeleted,
    LoginFailed,
    ClientLoggingChanged { client_id: i64, detailed_logging: bool, allow_event_reports: bool },
    ApplicationEvent { client_id: i64, session_id: i64, event_id: String, event: String, resource: Option<String>, outcome: String },
    ForwardAuth { action: String, client_id: i64, session_id: i64 },
    Mfa { action: String, subject_id: i64, method: String, record_id: Option<i64>, outcome: String },
    UserLoggedOut { session_id: i64 },
    AdminAction { action: String, target_id: Option<i64>, related_id: Option<i64>, status: u16 },
    OAuthAuthorization { client_id: i64, session_id: i64 },
    OAuthTokenIssued { client_id: i64, session_id: i64 },
    OAuthTokenRefreshed { client_id: i64, session_id: i64 },
    OAuthTokenRevoked { client_id: i64, session_id: i64 },
    OAuthReplayDetected { client_id: i64, session_id: i64, grant: String },
}

#[derive(Debug, Model)]
#[make_public]
pub struct LoginSession {
	#[key]
	#[auto]
	id: i64,

	#[unique]
	token: String,
	internal_token: String,
	redirect_uri: Option<String>,

	#[auto]
    #[index]
	created_at: jiff::Timestamp,
}

#[derive(Debug, Model)]
#[make_public]
pub struct Group {
	#[key]
	#[auto]
	id: i64,

	name: String,

	#[auto]
	created_at: jiff::Timestamp,
	#[auto]
	updated_at: jiff::Timestamp,
	deleted_at: Option<jiff::Timestamp>,

	#[has_many]
	group_members: Deferred<Vec<GroupMember>>,
}

#[derive(Debug, Model)]
#[make_public]
#[key(group_id, user_id)]
pub struct GroupMember {
	group_id: i64,
	user_id: i64,

	#[auto]
	created_at: jiff::Timestamp,

	#[belongs_to]
	group: Deferred<Group>,

	#[belongs_to]
	user: Deferred<User>,
}

#[derive(Debug, Model)]
#[make_public]
pub struct Client {
	#[key]
	#[auto]
	id: i64,

	name: String,
	#[unique]
	slug: String,

	client_type: ClientType,
	#[unique]
	client_id: String,
	client_secret: String,

	#[default(18 * 3600)]
	session_lifetime_s: u32,
	#[default(true)]
	require_pkce: bool,
    #[default(false)]
    detailed_logging: bool,
    #[default(false)]
    allow_event_reports: bool,

	#[auto]
	created_at: jiff::Timestamp,
	#[auto]
	updated_at: jiff::Timestamp,
	deleted_at: Option<jiff::Timestamp>,

	#[has_many]
	client_redirects: Deferred<Vec<ClientRedirect>>,
	#[has_many]
	client_access_rules: Deferred<Vec<ClientAccessRule>>,
	#[has_many]
	client_tokens: Deferred<Vec<ClientToken>>,
}

#[derive(Debug, toasty::Embed)]
pub enum ClientType {
	Oidc,
	ForwardAuth,
}

impl FromStr for ClientType {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"Oidc" => Ok(ClientType::Oidc),
			"ForwardAuth" => Ok(ClientType::ForwardAuth),
			_ => Err(anyhow::anyhow!("Invalid client type")),
		}
	}
}

#[derive(Debug, Model)]
#[make_public]
pub struct ClientRedirect {
	#[key]
	#[auto]
	id: i64,

	#[index]
	client_id: i64,
	redirect_uri: String,

	#[auto]
	created_at: jiff::Timestamp,

	#[belongs_to]
	client: Deferred<Client>,
}


#[derive(Debug, Model)]
#[make_public]
#[key(client_id, group_id)]
pub struct ClientAccessRule {
	client_id: i64,
	group_id: i64,

	priority: i16,

	#[default(AllowType::Allow)]
	access_control: AllowType,

	#[auto]
	created_at: jiff::Timestamp,

	#[belongs_to]
	client: Deferred<Client>,
	#[belongs_to]
	group: Deferred<Group>,
}

#[derive(Debug, Model)]
#[make_public]
pub struct ClientToken {
	#[key]
	#[auto]
	id: i64,

	#[index]
	client_id: i64,
	user_id: i64,
	#[unique]
	token: String,

	redirect_uri: String,
	pkce_challenge: Option<PKCEChallenge>,
    scope: String,
    nonce: Option<String>,
    session_id: i64,
    #[index]
    expires_at: jiff::Timestamp,
    consumed_at: Option<jiff::Timestamp>,

	#[auto]
	created_at: jiff::Timestamp,

	#[belongs_to]
	client: Deferred<Client>,
	#[belongs_to]
	user: Deferred<User>,
}

#[derive(Debug, toasty::Embed)]
pub enum AllowType {
	Allow,
	Deny,
}

#[derive(Debug, Clone, toasty::Embed)]
#[make_public]
pub struct PKCEChallenge {
	code: String,
	method: PKCEChallengeMethod,
}

#[derive(Debug, Clone, toasty::Embed)]
pub enum PKCEChallengeMethod {
	Plain,
	S256,
}
impl FromStr for PKCEChallengeMethod {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"plain" => Ok(PKCEChallengeMethod::Plain),
			"S256" => Ok(PKCEChallengeMethod::S256),
			_ => Err(anyhow::anyhow!("Invalid PKCE challenge method")),
		}
	}
}

#[derive(Debug, Model)]
#[make_public]
pub struct ClientCryptographicKey {
	#[key]
	#[auto]
	id: i64,

	#[index]
	client_id: i64,

	#[column(type = text)]
	key: Json<serde_json::Value>, // JWT

	#[auto]
	created_at: jiff::Timestamp,
    #[index]
	expires_at: jiff::Timestamp,

	#[belongs_to]
	client: Deferred<Client>,
}

#[derive(Debug, Model)]
#[make_public]
pub struct OAuthToken {
    #[key]
    #[auto]
    id: i64,
    #[index]
    client_id: i64,
    user_id: i64,
    session_id: i64,
    #[index]
    code_id: i64,
    #[index]
    family: String,
    #[unique]
    access_token: String,
    #[unique]
    refresh_token: String,
    scope: String,
    nonce: Option<String>,
    auth_time: i64,
    access_expires_at: jiff::Timestamp,
    #[index]
    expires_at: jiff::Timestamp,
    revoked_at: Option<jiff::Timestamp>,
    #[auto]
    created_at: jiff::Timestamp,
}

#[derive(Debug, Model)]
#[make_public]
pub struct TotpAuthenticator {
    #[key]
    #[auto]
    id: i64,
    #[index]
    user_id: i64,
    name: String,
    secret: String,
    #[default(-1)]
    last_step: i64,
    last_used_at: Option<jiff::Timestamp>,
    #[auto]
    created_at: jiff::Timestamp,
}

#[derive(Debug, Model)]
#[make_public]
pub struct WebauthnCredential {
    #[key]
    #[auto]
    id: i64,
    #[index]
    user_id: i64,
    #[unique]
    credential_id: String,
    name: String,
    #[column(type = text)]
    credential: Json<webauthn_rs::prelude::SecurityKey>,
    #[default(0)]
    sign_count: u32,
    last_used_at: Option<jiff::Timestamp>,
    #[auto]
    created_at: jiff::Timestamp,
}

#[derive(Debug, Model)]
#[make_public]
pub struct RecoveryCode {
    #[key]
    #[auto]
    id: i64,
    #[index]
    user_id: i64,
    #[unique]
    hash: String,
    #[index]
    used_at: Option<jiff::Timestamp>,
    #[auto]
    created_at: jiff::Timestamp,
}

#[derive(Debug, Model)]
#[make_public]
pub struct MfaCeremony {
    #[key]
    #[auto]
    id: i64,
    #[unique]
    token_hash: String,
    #[index]
    user_id: i64,
    actor_id: i64,
    session_id: Option<i64>,
    login_session_id: Option<i64>,
    revision: i64,
    purpose: String,
    #[column(type = text)]
    state: Json<serde_json::Value>,
    #[index]
    expires_at: jiff::Timestamp,
    consumed_at: Option<jiff::Timestamp>,
    #[default(0)]
    attempts: u32,
    #[auto]
    created_at: jiff::Timestamp,
}

#[derive(Debug, Model)]
#[make_public]
pub struct ForwardAuthRequest {
    #[key]
    #[auto]
    id: i64,
    #[unique]
    state_hash: String,
    browser_hash: String,
    #[unique]
    code_hash: String,
    #[index]
    client_id: i64,
    origin: String,
    return_uri: String,
    user_id: Option<i64>,
    session_id: Option<i64>,
    #[index]
    expires_at: jiff::Timestamp,
    consumed_at: Option<jiff::Timestamp>,
    #[auto]
    created_at: jiff::Timestamp,
}

#[derive(Debug, Model)]
#[make_public]
pub struct ForwardAuthSession {
    #[key]
    #[auto]
    id: i64,
    #[unique]
    token_hash: String,
    #[index]
    client_id: i64,
    user_id: i64,
    #[index]
    session_id: i64,
    origin: String,
    #[index]
    expires_at: jiff::Timestamp,
    #[auto]
    created_at: jiff::Timestamp,
}

#[derive(Debug, Model)]
#[make_public]
pub struct AccessLog {
    #[key]
    #[auto]
    id: i64,
    #[unique]
    event_id: String,
    #[unique]
    dedupe_key: String,
    #[index]
    client_id: i64,
    #[index]
    user_id: Option<i64>,
    #[index]
    session_id: Option<i64>,
    #[index]
    source: String,
    #[column(type = text)]
    data: Json<crate::journal::Entry>,
    #[auto]
    created_at: jiff::Timestamp,
}

#[derive(Debug, Model)]
#[make_public]
pub struct AccessLogDelivery {
    #[key]
    log_id: i64,
    #[default(0)]
    attempts: u32,
    #[index]
    next_attempt_at: jiff::Timestamp,
    delivered_at: Option<jiff::Timestamp>,
    last_error: Option<String>,
}

#[derive(Debug, Model)]
#[make_public]
pub struct EventReportRate {
    #[key]
    client_id: i64,
    #[index]
    window: i64,
    count: u32,
}
