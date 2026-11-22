use crate::upstream_auth::*;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub struct Oidc {
    // these should be gotten from the OIDC provider configuration
    authorize_url: String,
    token_url: String,
    userinfo_url: String,

    provider_name: String,
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    supports_pkce: bool,

    http_client: reqwest::Client,
}

impl Oidc {
    pub fn new(
        provider_name: String,
        authorize_url: String,
        userinfo_url: String,
        token_url: String,
        client_id: String,
        client_secret: String,
        scopes: Vec<String>,
        supports_pkce: bool,
    ) -> Self {
        let http_client = reqwest::Client::new();
        Self {
            authorize_url,
            token_url,
            userinfo_url,
            provider_name,
            client_id,
            client_secret,
            scopes,
            supports_pkce,
            http_client,
        }
    }

    pub fn from_env() -> anyhow::Result<Vec<Self>> {
        const FIELDS: &[&str] = &[
            "AUTHORIZE_URL",
            "TOKEN_URL",
            "USERINFO_URL",
            "CLIENT_ID",
            "CLIENT_SECRET",
            "SCOPES",
            "SUPPORTS_PKCE",
        ];
        // Read once so discovery and loading see the same configuration.
        let env: BTreeMap<String, String> = std::env::vars_os()
            .filter_map(|(key, value)| {
                let key = key.into_string().ok()?;
                key.starts_with("OIDC_").then_some((key, value))
            })
            .map(|(key, value)| {
                value
                    .into_string()
                    .map(|value| (key.clone(), value))
                    .map_err(|_| anyhow::anyhow!("{key} must contain UTF-8 text"))
            })
            .collect::<anyhow::Result<_>>()?;
        let mut groups = BTreeSet::new();
        for key in env.keys() {
            let remainder = key.strip_prefix("OIDC_").expect("OIDC variable");
            for field in FIELDS {
                if let Some(name) = remainder.strip_suffix(&format!("_{field}")) {
                    if name.is_empty()
                        || !name
                            .bytes()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
                    {
                        anyhow::bail!(
                            "Invalid provider name in {key}; use uppercase letters, digits and underscores"
                        );
                    }
                    groups.insert(name.to_owned());
                }
            }
        }
        let required = |key: &str| -> anyhow::Result<String> {
            env.get(key)
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Missing required environment variable {key}"))
        };
        let mut configs = Vec::new();
        // Preserve existing deployments while allowing named providers alongside them.
        if env.contains_key("OIDC_PROVIDER_NAME")
            || FIELDS
                .iter()
                .any(|field| env.contains_key(&format!("OIDC_{field}")))
        {
            configs.push((required("OIDC_PROVIDER_NAME")?, "OIDC_".to_owned()));
        }
        configs.extend(
            groups
                .into_iter()
                .map(|name| (name.to_ascii_lowercase(), format!("OIDC_{name}_"))),
        );
        let mut providers = Vec::new();
        let mut names = BTreeSet::new();
        for (name, prefix) in configs {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
                || matches!(name.to_ascii_lowercase().as_str(), "form" | "mfa")
            {
                anyhow::bail!(
                    "Invalid OIDC provider name for {prefix}; use a URL name other than form or mfa"
                );
            }
            if !names.insert(name.to_ascii_lowercase()) {
                anyhow::bail!("Duplicate OIDC provider name {name}");
            }
            let authorize_url = required(&format!("{prefix}AUTHORIZE_URL"))?;
            let token_url = required(&format!("{prefix}TOKEN_URL"))?;
            let userinfo_url = required(&format!("{prefix}USERINFO_URL"))?;
            for (field, value) in [
                ("AUTHORIZE_URL", &authorize_url),
                ("TOKEN_URL", &token_url),
                ("USERINFO_URL", &userinfo_url),
            ] {
                let url = reqwest::Url::parse(value).map_err(|_| {
                    anyhow::anyhow!("{prefix}{field} must be an absolute HTTP or HTTPS URL")
                })?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                {
                    anyhow::bail!(
                        "{prefix}{field} must be an absolute HTTP or HTTPS URL without credentials or fragments"
                    );
                }
            }
            let client_id = required(&format!("{prefix}CLIENT_ID"))?;
            let client_secret = required(&format!("{prefix}CLIENT_SECRET"))?;
            let scopes = env
                .get(&format!("{prefix}SCOPES"))
                .map(String::as_str)
                .unwrap_or("openid profile email")
                .split_whitespace()
                .map(str::to_owned)
                .collect();
            let supports_pkce = match env
                .get(&format!("{prefix}SUPPORTS_PKCE"))
                .map(String::as_str)
            {
                None | Some("false") => false,
                Some("true") => true,
                _ => anyhow::bail!("{prefix}SUPPORTS_PKCE must be true or false"),
            };
            let provider = Self::new(
                name,
                authorize_url,
                userinfo_url,
                token_url,
                client_id,
                client_secret,
                scopes,
                supports_pkce,
            );
            providers.push(provider);
        }
        Ok(providers)
    }

    fn state_mac(&self, ctx: &Context<'_>) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(ctx.login_session.internal_token.as_bytes())
            .expect("HMAC accepts the login secret");
        mac.update(b"guard-upstream-oidc-state\0");
        mac.update(self.provider_name.as_bytes());
        mac
    }

    fn construct_authorize_url(&self, ctx: &Context) -> anyhow::Result<String> {
        let mut url = reqwest::Url::parse(&self.authorize_url)?;
        let mut pairs = url.query_pairs_mut();
        pairs
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.construct_redirect_url(ctx)?)
            .append_pair("response_type", "code")
            .append_pair("scope", &self.scopes.join(" "))
            .append_pair(
                "state",
                &URL_SAFE_NO_PAD.encode(self.state_mac(ctx).finalize().into_bytes()),
            );
        if self.supports_pkce {
            pairs
                .append_pair(
                    "code_challenge",
                    &derive_pkce_state(&ctx.login_session.internal_token),
                )
                .append_pair("code_challenge_method", "S256");
        }
        drop(pairs);
        Ok(url.into())
    }

    fn construct_redirect_url(&self, ctx: &Context) -> anyhow::Result<String> {
        let mut url = reqwest::Url::parse(&ctx.core.domain)?;
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("DOMAIN must be an HTTP URL"))?
            .pop_if_empty()
            .extend(["login", self.name(), "callback"]);
        Ok(url.into())
    }

    async fn fetch_token(&self, code: &str, ctx: &Context<'_>) -> anyhow::Result<String> {
        let client = &self.http_client;
        let redirect_uri = self.construct_redirect_url(ctx)?;
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];
        if self.supports_pkce {
            params.push(("code_verifier", &ctx.login_session.internal_token));
        }

        let res = client.post(&self.token_url).form(&params).send().await;

        let access_token = res?
            .error_for_status()?
            .json::<OidcTokenResponse>()
            .await?
            .access_token
            .ok_or_else(|| anyhow::anyhow!("No access token in response"))?;

        Ok(access_token)
    }

    async fn fetch_userinfo(&self, access_token: &str) -> anyhow::Result<OidcUserinfo> {
        let client = &self.http_client;
        let res = client
            .get(&self.userinfo_url)
            .bearer_auth(access_token)
            .send()
            .await;

        let json = res?.error_for_status()?.json::<OidcUserinfo>().await?;
        Ok(json)
    }
}

#[async_trait]
impl UpstreamAuthenticator for Oidc {
    fn supports_callback(&self) -> bool {
        true
    }
    fn name(&self) -> &str {
        &self.provider_name
    }

    async fn auth(&self, ctx: &Context) -> anyhow::Result<AuthorizeResponse> {
        Ok(AuthorizeResponse::Redirect(
            self.construct_authorize_url(ctx)?,
        ))
    }

    async fn finish_auth(
        &self,
        ctx: &Context,
        data: HashMap<String, String>,
    ) -> anyhow::Result<AuthorizeResponse> {
        {
            let state = data
                .get("state")
                .ok_or_else(|| anyhow::anyhow!("Missing state"))?;
            let decoded = URL_SAFE_NO_PAD
                .decode(state)
                .map_err(|_| anyhow::anyhow!("Invalid state"))?;
            self.state_mac(ctx)
                .verify_slice(&decoded)
                .map_err(|_| anyhow::anyhow!("Invalid state"))?;
        }

        let code = data
            .get("code")
            .ok_or_else(|| anyhow::anyhow!("Missing code"))?;
        let access_token = self.fetch_token(code, ctx).await?;
        let userinfo = self.fetch_userinfo(&access_token).await?;

        let email = userinfo
            .email
            .as_deref()
            .filter(|email| {
                !email.is_empty()
                    && email.len() <= 254
                    && !email.chars().any(char::is_whitespace)
                    && !email.chars().any(char::is_control)
                    && email.split('@').count() == 2
                    && !email.starts_with('@')
                    && !email.ends_with('@')
            })
            .ok_or_else(|| {
                anyhow::anyhow!("The upstream provider did not return a valid email address")
            })?;
        if userinfo.email_verified != Some(true) {
            anyhow::bail!("The upstream provider must verify the email address before signing in");
        }
        // SQLite LIKE matches ASCII without case sensitivity. Escape every
        // pattern metacharacter so an email is always an exact address match.
        let pattern = email
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let mut db = ctx.core.db.clone();
        let mut matches = User::filter(
            User::fields()
                .email()
                .like_with_escape(pattern, '\\')
                .and(User::fields().disabled().eq(false))
                .and(User::fields().deleted_at().is_none()),
        )
        .limit(2)
        .exec(&mut db)
        .await?;
        if matches.len() != 1
            || !matches[0]
                .email
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(email))
        {
            anyhow::bail!("No unique active account matches the upstream email address");
        }
        let user = matches.remove(0);
        Ok(AuthorizeResponse::Done(user))
    }
}

fn derive_pkce_state(code_verifier: &str) -> String {
    let hash = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

#[derive(Deserialize)]
struct OidcTokenResponse {
    access_token: Option<String>,
}

#[derive(Deserialize)]
struct OidcUserinfo {
    email: Option<String>,
    email_verified: Option<bool>,
}
