use toasty_cli::{Config, ToastyCli};
use guard::db::build_db;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load()?;

    let db = build_db("sqlite::memory:").await?;

    let cli = ToastyCli::with_config(db, config);
    cli.parse_and_run().await?;

    Ok(())
}
