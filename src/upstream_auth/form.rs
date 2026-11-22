use crate::models::{AuditLogEntry, User};
use crate::upstream_auth::*;
use anyhow::bail;
use async_trait::async_trait;

pub struct Form {
    bcrypt_cost: u32,
}

impl Form {
    fn new(bcrypt_cost: u32) -> Self {
        Self { bcrypt_cost }
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let disabled =
            std::env::var("PASSWORD_DISABLED").unwrap_or_else(|_| "false".into()) == "true";
        if disabled {
            bail!("Password authentication is disabled");
        }

        let bcrypt_cost = std::env::var("PASSWORD_BCRYPT_COST")
            .unwrap_or_else(|_| "12".into())
            .parse()
            .unwrap_or(12);
        Ok(Self::new(bcrypt_cost))
    }
}

#[derive(View)]
#[view(path = "views/components/form.rs.html")]
struct FormView {
    csrf_token: String,
    login_token: String,
}

#[async_trait]
impl UpstreamAuthenticator for Form {
    fn name(&self) -> &str {
        "form"
    }

    async fn auth(&self, ctx: &Context) -> anyhow::Result<AuthorizeResponse> {
        let form_view = FormView {
            csrf_token: ctx.csrf_token.clone(),
            login_token: ctx.login_session.internal_token.clone(),
        };

        let mut out = String::with_capacity(form_view.text_size());
        form_view.render(&mut out)?;

        Ok(AuthorizeResponse::HTMLFragment(out))
    }

    async fn finish_auth(
        &self,
        ctx: &Context,
        data: HashMap<String, String>,
    ) -> anyhow::Result<AuthorizeResponse> {
        let login_request = LoginRequest::try_from(data)?;

        if login_request.csrf_token != ctx.csrf_token {
            bail!("CSRF token mismatch");
        } else if login_request.login_token != ctx.login_session.internal_token {
            bail!("Login token mismatch");
        }

        let mut db = ctx.core.db.clone();
        let user = match User::get_by_username(&mut db, &login_request.email).await {
            Ok(user) => Some(user),
            Err(error) if error.is_record_not_found() => None,
            Err(error) => return Err(error.into()),
        };
        let hash = user
            .as_ref()
            .filter(|user| !user.disabled && user.deleted_at.is_none())
            .and_then(|user| user.password.clone());
        let accepted = verify_password(login_request.password, hash, self.bcrypt_cost).await?;
        if let Some(user) = user {
            if accepted {
                return Ok(AuthorizeResponse::Done(user));
            }
            crate::audit::best_effort(ctx.core, user.id, AuditLogEntry::LoginFailed).await;
        }

        bail!("Invalid email or password");
    }
}

struct LoginRequest {
    email: String,
    password: String,
    csrf_token: String,
    login_token: String,
}

impl TryFrom<HashMap<String, String>> for LoginRequest {
    type Error = anyhow::Error;

    fn try_from(data: HashMap<String, String>) -> Result<Self, Self::Error> {
        Ok(LoginRequest {
            email: data
                .get("email")
                .ok_or_else(|| anyhow::anyhow!("Missing email"))?
                .to_string(),
            password: data
                .get("password")
                .ok_or_else(|| anyhow::anyhow!("Missing password"))?
                .to_string(),
            csrf_token: data
                .get("csrf_token")
                .ok_or_else(|| anyhow::anyhow!("Missing csrf_token"))?
                .to_string(),
            login_token: data
                .get("login_token")
                .ok_or_else(|| anyhow::anyhow!("Missing login_token"))?
                .to_string(),
        })
    }
}

async fn verify_password(
    password: String,
    hash: Option<String>,
    cost: u32,
) -> anyhow::Result<bool> {
    // Bound CPU work before scheduling it on Tokio's blocking thread pool.
    static WORKERS: std::sync::LazyLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| {
            let count = std::thread::available_parallelism()
                .map_or(1, |n| n.get())
                .min(8);
            std::sync::Arc::new(tokio::sync::Semaphore::new(count))
        });
    let permit = WORKERS.clone().acquire_owned().await?;
    tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        let _permit = permit;
        match hash {
            Some(hash) => Ok(bcrypt::verify(password, &hash).unwrap_or(false)),
            None => {
                // Perform comparable work for unknown/disabled/passwordless accounts.
                bcrypt::hash("password", cost)?;
                Ok(false)
            }
        }
    })
    .await?
}
