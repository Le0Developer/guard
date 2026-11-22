use crate::{db::build_db, upstream_auth};
use rand;

pub struct Core {
    pub domain: String,

    pub upstream_authenticators: Vec<Box<dyn upstream_auth::UpstreamAuthenticator>>,

    pub db: toasty::Db,
    pub session_secret: [u8; 32],
    pub(crate) login_rate: crate::login_rate::LoginRate,
    pub(crate) journal_config: crate::journal::Config,
}

impl Core {
    pub fn new(
        domain: String,
        upstream_authenticators: Vec<Box<dyn upstream_auth::UpstreamAuthenticator>>,
        db: toasty::Db,
    ) -> Self {
        let session_secret = rand::random::<[u8; 32]>();
        Self {
            domain: domain.to_string(),
            upstream_authenticators,
            session_secret,
            db,
            journal_config: crate::journal::Config::default(),
            login_rate: crate::login_rate::LoginRate::default(),
        }
    }

    pub async fn from_env() -> anyhow::Result<Self> {
        let domain = std::env::var("DOMAIN")?;

        let mut upstream_authenticators =
            Vec::<Box<dyn upstream_auth::UpstreamAuthenticator>>::new();
        for upstream in upstream_auth::oidc::Oidc::from_env()? {
            upstream_authenticators.push(Box::new(upstream));
        }
        if let Ok(upstream) = upstream_auth::form::Form::from_env() {
            upstream_authenticators.push(Box::new(upstream));
        }

        let db = build_db(&std::env::var("DATABASE_URL")?).await?;

        let mut core = Self::new(domain, upstream_authenticators, db);
        core.journal_config = crate::journal::Config::from_env()?;
        Ok(core)
    }
}
