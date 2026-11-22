use super::*;
use crate::models::{AllowType, ClientAccessRule, ClientType, Group, GroupMember, User};
use std::collections::HashSet;

pub(crate) async fn client(db: &mut dyn toasty::Executor, slug: &str) -> Result<Client> {
    let client = Client::get_by_slug(db, slug).await.map_err(|e| {
        if e.is_record_not_found() {
            OAuthError {
                status: StatusCode::NOT_FOUND,
                code: "invalid_client",
                description: "Unknown client.".into(),
            }
        } else {
            e.into()
        }
    })?;
    if client.deleted_at.is_some() || !matches!(client.client_type, ClientType::Oidc) {
        return Err(OAuthError {
            status: StatusCode::NOT_FOUND,
            code: "invalid_client",
            description: "Unknown client.".into(),
        });
    }
    Ok(client)
}

pub(crate) async fn registered_client(
    db: &mut dyn toasty::Executor,
    identifier: &str,
) -> Result<Client> {
    let client = Client::get_by_client_id(db, identifier)
        .await
        .map_err(|e| {
            if e.is_record_not_found() {
                OAuthError::invalid_client()
            } else {
                e.into()
            }
        })?;
    if client.deleted_at.is_some() {
        return Err(OAuthError::invalid_client());
    }
    Ok(client)
}

pub(crate) async fn user_session(
    db: &mut dyn toasty::Executor,
    session_id: i64,
    user_id: i64,
) -> Result<(User, crate::models::Session)> {
    let (user, session) = crate::session::by_id(db, session_id)
        .await?
        .ok_or_else(OAuthError::invalid_grant)?;
    if user.id != user_id {
        return Err(OAuthError::invalid_grant());
    }
    Ok((user, session))
}

pub(crate) async fn permitted(
    db: &mut dyn toasty::Executor,
    client: &Client,
    user: &User,
) -> Result<bool> {
    let mut rules = ClientAccessRule::filter(ClientAccessRule::fields().client_id().eq(client.id))
        .exec(db)
        .await?;
    if rules.is_empty() {
        return Ok(true);
    }
    rules.sort_by_key(|r| (r.priority, matches!(r.access_control, AllowType::Allow)));
    let groups: HashSet<_> = Group::all()
        .exec(db)
        .await?
        .into_iter()
        .filter(|g| g.deleted_at.is_none())
        .map(|g| g.id)
        .collect();
    let memberships: HashSet<_> = GroupMember::filter(GroupMember::fields().user_id().eq(user.id))
        .exec(db)
        .await?
        .into_iter()
        .map(|m| m.group_id)
        .collect();
    Ok(rules
        .iter()
        .find(|r| groups.contains(&r.group_id) && memberships.contains(&r.group_id))
        .is_some_and(|r| matches!(r.access_control, AllowType::Allow)))
}
