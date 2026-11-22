use crate::models::{AuditLog, AuditLogEntry};

/// Only structured, explicitly selected metadata belongs here. Never pass request
/// bodies, query strings, credentials, token values or raw authentication errors.
pub(crate) async fn record(db: &mut dyn toasty::Executor, actor: i64, entry: AuditLogEntry) -> toasty::Result<()> {
    toasty::create!(AuditLog { user_id: actor, data: toasty::Json(entry) }).exec(db).await?;
    Ok(())
}

pub(crate) async fn best_effort(core: &crate::core::Core, actor: i64, entry: AuditLogEntry) {
    if let Err(error) = record(&mut core.db.clone(), actor, entry).await {
        // Do not turn a completed action into an apparent failure and encourage
        // a retry. Transactional callers use record() before committing instead.
        eprintln!("Unable to persist audit record for user {actor}: {error}");
    }
}
