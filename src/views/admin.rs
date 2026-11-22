use crate::models::{Role, User};
use rshtml::View;

pub struct SessionRow {
    pub id: i64,
    pub created_at: jiff::Timestamp,
}

pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub disabled: bool,
    pub local_password: bool,
}
pub struct GroupRow {
    pub id: i64,
    pub name: String,
    pub members: usize,
}
pub struct ClientRow {
    pub id: i64,
    pub name: String,
    pub identifier: String,
    pub kind: String,
    pub rules: usize,
}
pub struct Choice {
    pub id: i64,
    pub name: String,
}
#[derive(Default)]
pub struct RedirectFields {
    pub id: Option<i64>,
    pub uri: String,
}

pub struct RedirectRow {
    pub id: i64,
    pub uri: String,
}

pub struct RuleRow {
    pub group_id: i64,
    pub group_name: String,
    pub priority: i16,
    pub allow: bool,
}

#[derive(Default)]
pub struct UserFields {
    pub username: String,
    pub email: String,
    pub role: String,
    pub disabled: bool,
}
pub struct RuleFields {
    pub group_id: String,
    pub priority: String,
    pub access_control: String,
}
impl Default for RuleFields {
    fn default() -> Self {
        Self {
            group_id: String::new(),
            priority: "0".into(),
            access_control: "allow".into(),
        }
    }
}

#[derive(Default)]
pub struct ClientFields {
    pub name: String,
    pub kind: String,
    pub lifetime: String,
    pub require_pkce: bool,
    pub detailed_logging: bool,
    pub allow_event_reports: bool,
}

#[derive(View)]
#[view(path = "views/pages/admin/home.rs.html", extract = false)]
pub struct AdminHome<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub users: usize,
    pub groups: usize,
    pub clients: usize,
}

#[derive(View)]
#[view(path = "views/pages/admin/users.rs.html", extract = false)]
pub struct UsersPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub users: Vec<UserRow>,
    pub query: String,
}

#[derive(View)]
#[view(path = "views/pages/admin/user_form.rs.html", extract = false)]
pub struct UserFormPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub id: Option<i64>,
    pub fields: UserFields,
    pub sessions: Vec<SessionRow>,
    pub error: Option<String>,
}

#[derive(View)]
#[view(path = "views/pages/admin/groups.rs.html", extract = false)]
pub struct GroupsPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub groups: Vec<GroupRow>,
    pub query: String,
}

#[derive(View)]
#[view(path = "views/pages/admin/group_form.rs.html", extract = false)]
pub struct GroupFormPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub id: Option<i64>,
    pub name: String,
    pub members: Vec<Choice>,
    pub available: Vec<Choice>,
    pub error: Option<String>,
}

#[derive(View)]
#[view(path = "views/pages/admin/clients.rs.html", extract = false)]
pub struct ClientsPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub clients: Vec<ClientRow>,
    pub query: String,
}

pub struct ClientEndpoint {
    pub name: String,
    pub url: String,
    pub id: String,
}

#[derive(View)]
#[view(path = "views/pages/admin/client_form.rs.html", extract = false)]
pub struct ClientFormPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub id: Option<i64>,
    pub fields: ClientFields,
    pub identifier: Option<String>,
    pub endpoints: Vec<ClientEndpoint>,
    pub secret: Option<String>,
    pub rules: Vec<RuleRow>,
    pub groups: Vec<Choice>,
    pub rule_fields: RuleFields,
    pub redirects: Vec<RedirectRow>,
    pub redirect_fields: RedirectFields,
    pub error: Option<String>,
}

#[derive(View)]
#[view(path = "views/pages/admin/delete.rs.html", extract = false)]
pub struct DeletePage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub section: &'a str,
    pub name: &'a str,
    pub action: &'a str,
    pub cancel: &'a str,
    pub consequence: &'a str,
}

pub struct AuditRow {
    pub id: i64,
    pub created_at: jiff::Timestamp,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
}

#[derive(View)]
#[view(path = "views/pages/admin/audit.rs.html", extract = false)]
pub struct AuditPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub rows: Vec<AuditRow>,
    pub next: Option<i64>,
}

pub struct AccessRow {
    pub id: i64,
    pub time: String,
    pub client: String,
    pub subject: String,
    pub session: String,
    pub source: String,
    pub action: String,
    pub outcome: String,
    pub path: String,
    pub ip: String,
    pub delivery: String,
    pub details: String,
}
#[derive(View)]
#[view(path = "views/pages/admin/access_log.rs.html", extract = false)]
pub struct AccessLogPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub rows: Vec<AccessRow>,
    pub next_url: Option<String>,
    pub client_filter: String,
    pub session_filter: String,
    pub source_filter: String,
    pub clients: Vec<Choice>,
    pub pending: u64,
    pub failed: u64,
    pub export_enabled: bool,
}

#[derive(View)]
#[view(path = "views/pages/admin/user_password.rs.html", extract = false)]
pub struct UserPasswordPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub target_id: i64,
    pub target_name: &'a str,
    pub error: Option<String>,
}

#[derive(View)]
#[view(path = "views/pages/admin/user_role.rs.html", extract = false)]
pub struct UserRolePage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub target_id: i64,
    pub target_name: &'a str,
    pub current_role: &'a str,
    pub grant_admin: bool,
    pub error: Option<String>,
}
