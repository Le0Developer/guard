use async_trait::async_trait;
use rshtml::View;
use std::collections::HashMap;

use crate::{
    core::Core,
    models::{LoginSession, User},
};

pub mod oidc;
pub mod password;

#[async_trait]
pub trait UpstreamAuthenticator: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn supports_callback(&self) -> bool {
        false
    }

    async fn auth(&self, ctx: &Context) -> anyhow::Result<AuthorizeResponse>;
    async fn finish_auth(
        &self,
        ctx: &Context,
        data: HashMap<String, String>,
    ) -> anyhow::Result<AuthorizeResponse>;
}

pub struct Context<'a> {
    pub csrf_token: String,
    pub upstream_authenticator: Option<&'a dyn UpstreamAuthenticator>,
    pub login_session: &'a LoginSession,
    pub core: &'a Core,
}

impl Context<'_> {
    pub fn new<'a>(
        csrf_token: String,
        upstream_authenticator: Option<&'a dyn UpstreamAuthenticator>,
        login_session: &'a LoginSession,
        core: &'a Core,
    ) -> Context<'a> {
        Context {
            csrf_token,
            upstream_authenticator,
            login_session,
            core,
        }
    }
}

pub enum AuthorizeResponse {
    HTMLFragment(String),
    Redirect(String),
    Done(User),
}
