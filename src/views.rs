use make_public::make_public;
use rshtml::View;

use crate::models::{Role, User};

pub struct LoginMethod {
    pub id: String,
    pub name: String,
}

#[derive(View)]
#[view(path = "views/pages/login.rs.html", extract = false)]
#[make_public]
pub struct LoginPage {
    authenticators: Vec<LoginMethod>,
    fragment: Option<String>,
    error: Option<String>,
}

#[derive(View)]
#[view(path = "views/pages/error.rs.html", extract = false)]
#[make_public]
pub struct ErrorPage {
    error: String,
}

#[derive(View)]
#[view(path = "views/pages/user.rs.html", extract = false)]
pub struct UserPage<'a> {
    pub user: &'a User,
    pub csrf: &'a str,
}

pub mod admin;

pub mod security;
