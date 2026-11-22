use crate::models::{Role, User};
use rshtml::View;

pub struct MethodRow {
    pub id: i64,
    pub kind: String,
    pub name: String,
    pub created_at: String,
    pub last_used: String,
}
#[derive(View)]
#[view(path = "views/pages/security.rs.html", extract = false)]
pub struct SecurityPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub target_id: i64,
    pub target_name: String,
    pub base: String,
    pub methods: Vec<MethodRow>,
    pub backup_count: usize,
}
#[derive(View)]
#[view(path = "views/pages/totp_setup.rs.html", extract = false)]
pub struct TotpSetupPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub base: String,
    pub target_id: i64,
    pub secret: String,
    pub qr: String,
    pub ticket: String,
}
#[derive(View)]
#[view(path = "views/pages/backup_codes.rs.html", extract = false)]
pub struct BackupCodesPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
    pub base: String,
    pub target_id: i64,
    pub codes: Vec<String>,
}
#[derive(View)]
#[view(path = "views/pages/mfa.rs.html", extract = false)]
pub struct MfaPage {
    pub csrf: String,
    pub has_totp: bool,
    pub has_keys: bool,
    pub error: Option<String>,
}
