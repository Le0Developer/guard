use anyhow::bail;
use toasty::create;

use crate::{models::{Role, User}, token::generate_token};


static MIGRATIONS: toasty::migration::MigrationSet = toasty::embed_migrations!();

pub async fn build_db(url: &str) -> anyhow::Result<toasty::Db> {
	let db = toasty::Db::builder()
		.models(toasty::models!(crate::*))
		.connect(url)
		.await?;

	let report = MIGRATIONS.apply(&db).await?;
	println!("Applied migrations: {:?}", report);

	Ok(db)
}

const ROOT_USER_ID: i64 = 0;
const ROOT_USERNAME: &str = "system";

pub async fn setup_wizard(db: &mut toasty::Db) -> anyhow::Result<()> {
	match User::get_by_id(db, ROOT_USER_ID).await {
		Ok(_) => return Ok(()),
		Err(e) if e.is_record_not_found() => (),
		Err(e) => bail!("Error checking for root user: {}", e)
	}

	let root_password = generate_token();
	let hashed_password = bcrypt::hash(&root_password, bcrypt::DEFAULT_COST).unwrap();

	create!(User {
		id: ROOT_USER_ID,
		username: ROOT_USERNAME,
		password: hashed_password,
		role: Role::Admin,
	}).exec(db).await?;

	println!("Created initial user {} with password: {}", ROOT_USERNAME, root_password);

	Ok(())
}