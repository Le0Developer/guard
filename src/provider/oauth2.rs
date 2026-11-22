use std::collections::HashMap;

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    core::Core,
    models::{Client, ClientToken, PKCEChallenge, PKCEChallengeMethod},
};

pub(crate) mod access;
pub(crate) mod flows;
pub(crate) mod keys;

pub(crate) const ALLOWED_SCOPES: &[&str] = &["openid", "profile", "email"];
pub(crate) const CODE_LIFETIME: i64 = 300;
pub(crate) const ACCESS_LIFETIME: i64 = 900;

pub(crate) type Result<T> = std::result::Result<T, OAuthError>;

#[derive(Debug)]
pub(crate) struct OAuthError {
    pub status: StatusCode,
    pub code: &'static str,
    pub description: String,
}

impl OAuthError {
    pub fn new(code: &'static str, description: impl Into<String>) -> Self {
        Self {
            status: if code == "server_error" {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_REQUEST
            },
            code,
            description: description.into(),
        }
    }
    pub fn invalid_grant() -> Self {
        Self::new(
            "invalid_grant",
            "The grant is invalid, expired or already used.",
        )
    }
    pub fn invalid_client() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_client",
            description: "Client authentication failed.".into(),
        }
    }
    pub fn invalid_token() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_token",
            description: "The access token is invalid or expired.".into(),
        }
    }
}

impl From<toasty::Error> for OAuthError {
    fn from(error: toasty::Error) -> Self {
        eprintln!("OAuth database operation failed: {error}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "server_error",
            description: "Unable to complete this request.".into(),
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(json!({ "error": self.code, "error_description": self.description })),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self.status == StatusCode::UNAUTHORIZED {
            let challenge = if self.code == "invalid_client" {
                "Basic realm=\"Guard\""
            } else {
                "Bearer error=\"invalid_token\""
            };
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(challenge),
            );
        }
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            let wait = 60 - jiff::Timestamp::now().as_second().rem_euclid(60);
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_str(&wait.to_string()).expect("numeric retry delay"),
            );
        }
        crate::journal::outcome(
            response,
            if self.code == "server_error" {
                "error"
            } else if self.code == "login_required" {
                "authentication_required"
            } else {
                "denied"
            },
            Some(self.code),
        )
    }
}

pub(crate) fn unique_fields(pairs: Vec<(String, String)>) -> Result<HashMap<String, String>> {
    let mut fields = HashMap::new();
    for (key, value) in pairs {
        if fields.insert(key, value).is_some() {
            return Err(OAuthError::new(
                "invalid_request",
                "Parameters must not be repeated.",
            ));
        }
    }
    Ok(fields)
}

pub(crate) fn required(fields: &HashMap<String, String>, key: &str) -> Result<String> {
    fields
        .get(key)
        .filter(|s| !s.is_empty())
        .cloned()
        .ok_or_else(|| OAuthError::new("invalid_request", format!("Missing {key}.")))
}

pub(crate) fn hash_token(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

pub(crate) fn secret_eq(left: &str, right: &str) -> bool {
    let mut a = Hmac::<Sha256>::new_from_slice(b"Guard constant-time credential comparison")
        .expect("valid HMAC key");
    let mut b = a.clone();
    a.update(left.as_bytes());
    b.update(right.as_bytes());
    a.verify_slice(&b.finalize().into_bytes()).is_ok()
}

pub(crate) fn issuer(core: &Core, client: &Client) -> Result<String> {
    let base = core.domain.trim_end_matches('/');
    let url = reqwest::Url::parse(base)
        .map_err(|_| OAuthError::new("server_error", "DOMAIN must be an absolute HTTPS URL."))?;
    let authority = base
        .split_once("://")
        .map(|(_, rest)| rest.split('/').next().unwrap_or_default())
        .unwrap_or_default();
    if authority.is_empty()
        || base.contains('\\')
        || base.chars().any(char::is_whitespace)
        || base.chars().any(char::is_control)
    {
        return Err(OAuthError::new(
            "server_error",
            "DOMAIN must be an absolute HTTPS URL.",
        ));
    }
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(OAuthError::new(
            "server_error",
            "DOMAIN must be HTTPS, or HTTP on loopback for development.",
        ));
    }
    Ok(format!("{base}/oauth2/{}", client.slug))
}

pub(crate) struct OAuth2AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub response_type: String,
    pub challenge: Option<PKCEChallenge>,
    pub state: Option<String>,
    pub nonce: Option<String>,
}

impl OAuth2AuthorizationRequest {
    pub fn valid(&self, client: &Client) -> Result<()> {
        if client.client_id != self.client_id {
            return Err(OAuthError::new("invalid_request", "Invalid client_id."));
        }
        if !self
            .scope
            .iter()
            .all(|s| ALLOWED_SCOPES.contains(&s.as_str()))
        {
            return Err(OAuthError::new("invalid_scope", "Unsupported scope."));
        }
        if self.response_type != "code" {
            return Err(OAuthError::new(
                "unsupported_response_type",
                "Only the code response type is supported.",
            ));
        }
        if client.require_pkce && self.challenge.is_none() {
            return Err(OAuthError::new(
                "invalid_request",
                "PKCE challenge required.",
            ));
        }
        if let Some(challenge) = &self.challenge {
            let valid = match challenge.method {
                PKCEChallengeMethod::Plain => verifier_valid(&challenge.code),
                PKCEChallengeMethod::S256 => {
                    challenge.code.len() == 43
                        && URL_SAFE_NO_PAD
                            .decode(&challenge.code)
                            .is_ok_and(|b| b.len() == 32)
                }
            };
            if !valid {
                return Err(OAuthError::new(
                    "invalid_request",
                    "Invalid PKCE challenge.",
                ));
            }
        }
        Ok(())
    }
}

impl TryFrom<HashMap<String, String>> for OAuth2AuthorizationRequest {
    type Error = OAuthError;
    fn try_from(value: HashMap<String, String>) -> Result<Self> {
        let challenge = if let Some(code) = value.get("code_challenge") {
            let method = value
                .get("code_challenge_method")
                .map(String::as_str)
                .unwrap_or("plain")
                .parse()
                .map_err(|_| {
                    OAuthError::new("invalid_request", "Unsupported PKCE challenge method.")
                })?;
            Some(PKCEChallenge {
                code: code.clone(),
                method,
            })
        } else {
            if value.contains_key("code_challenge_method") {
                return Err(OAuthError::new(
                    "invalid_request",
                    "code_challenge is required with its method.",
                ));
            }
            None
        };
        Ok(Self {
            client_id: required(&value, "client_id")?,
            redirect_uri: required(&value, "redirect_uri")?,
            scope: value
                .get("scope")
                .map(String::as_str)
                .unwrap_or_default()
                .split_whitespace()
                .map(String::from)
                .collect(),
            response_type: required(&value, "response_type")?,
            challenge,
            state: value.get("state").cloned(),
            nonce: value.get("nonce").cloned(),
        })
    }
}

pub(crate) struct OAuth2TokenRequest {
    pub code: String,
    pub redirect_uri: String,
    pub challenge_verifier: Option<String>,
}

impl TryFrom<HashMap<String, String>> for OAuth2TokenRequest {
    type Error = OAuthError;
    fn try_from(value: HashMap<String, String>) -> Result<Self> {
        Ok(Self {
            code: required(&value, "code")?,
            redirect_uri: required(&value, "redirect_uri")?,
            challenge_verifier: value.get("code_verifier").cloned(),
        })
    }
}

impl OAuth2TokenRequest {
    pub fn valid(&self, client: &Client, token: &ClientToken) -> Result<()> {
        if token.client_id != client.id || self.redirect_uri != token.redirect_uri {
            return Err(OAuthError::invalid_grant());
        }
        if let Some(challenge) = &token.pkce_challenge {
            if !self
                .challenge_verifier
                .as_deref()
                .is_some_and(|v| challenge.verify(v))
            {
                return Err(OAuthError::invalid_grant());
            }
        }
        Ok(())
    }
}

fn verifier_valid(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

impl PKCEChallenge {
    fn verify(&self, verifier: &str) -> bool {
        if !verifier_valid(verifier) {
            return false;
        }
        match self.method {
            PKCEChallengeMethod::Plain => secret_eq(&self.code, verifier),
            PKCEChallengeMethod::S256 => secret_eq(&self.code, &hash_token(verifier)),
        }
    }
}
