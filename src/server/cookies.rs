pub const LOGIN_COOKIE_NAME: &str = "session";
pub const LOGIN_SESSION_COOKIE_NAME: &str = "login_session";
pub const CSRF_COOKIE_NAME: &str = "csrf_token";
pub fn attributes(domain: &str) -> &'static str {
    if domain.get(..8).is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://")) {
        "HttpOnly; Path=/; SameSite=Lax; Secure"
    } else {
        "HttpOnly; Path=/; SameSite=Lax"
    }
}
