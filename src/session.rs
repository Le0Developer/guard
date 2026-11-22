use crate::models::{Session, User};

pub(crate) const LOGIN_LIFETIME_SECONDS: i64 = 3600;

pub(crate) const LIFETIME_SECONDS: i64 = 18 * 3600;

pub(crate) fn expires_at(session: &Session) -> i64 {
    session.created_at.as_second() + LIFETIME_SECONDS
}

async fn validate(
    db: &mut dyn toasty::Executor,
    session: toasty::Result<Session>,
) -> toasty::Result<Option<(User, Session)>> {
    let session = match session {
        Ok(session) => session,
        Err(error) if error.is_record_not_found() => return Ok(None),
        Err(error) => return Err(error),
    };
    if expires_at(&session) <= jiff::Timestamp::now().as_second() {
        return Ok(None);
    }
    let user = match User::get_by_id(db, session.user_id).await {
        Ok(user) => user,
        Err(error) if error.is_record_not_found() => return Ok(None),
        Err(error) => return Err(error),
    };
    if user.disabled || user.deleted_at.is_some() {
        return Ok(None);
    }
    Ok(Some((user, session)))
}

pub(crate) async fn by_token(
    db: &mut dyn toasty::Executor,
    token: &str,
) -> toasty::Result<Option<(User, Session)>> {
    let session = Session::get_by_token(&mut *db, token).await;
    validate(db, session).await
}

pub(crate) async fn by_id(
    db: &mut dyn toasty::Executor,
    id: i64,
) -> toasty::Result<Option<(User, Session)>> {
    let session = Session::get_by_id(&mut *db, id).await;
    validate(db, session).await
}
