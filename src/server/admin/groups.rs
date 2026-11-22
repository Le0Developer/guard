use super::*;
use axum::extract::{Path, Query};
use crate::models::{GroupMember, ClientAccessRule};
use std::collections::HashSet;

pub async fn load(db: &mut dyn toasty::Executor, id: i64) -> Result<Group> {
    let group = Group::get_by_id(db, id).await?;
    if group.deleted_at.is_some() { return Err(not_found()); }
    Ok(group)
}

pub async fn list(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, Query(params): Query<HashMap<String, String>>) -> Result {
    let query = field(&params, "q");
    let mut db = core.db.clone();
    let members = GroupMember::all().exec(&mut db).await?;
    let mut groups: Vec<_> = Group::all().exec(&mut db).await?.into_iter()
        .filter(|g| g.deleted_at.is_none() && g.name.to_lowercase().contains(&query.to_lowercase()))
        .map(|g| GroupRow { id: g.id, members: members.iter().filter(|m| m.group_id == g.id).count(), name: g.name }).collect();
    groups.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(GroupsPage { user: &user, csrf: &csrf.token, groups, query }.into_response())
}

pub async fn new(Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>) -> Response {
    GroupFormPage { user: &user, csrf: &csrf.token, id: None, name: String::new(), members: vec![], available: vec![], error: None }.into_response()
}

async fn form(core: &Core, user: &User, csrf: &str, id: Option<i64>, name: String, error: Option<String>) -> Result {
    let mut db = core.db.clone();
    let ids: HashSet<i64> = if let Some(id) = id { GroupMember::filter(GroupMember::fields().group_id().eq(id)).exec(&mut db).await?.into_iter().map(|m| m.user_id).collect() } else { HashSet::new() };
    let mut users = User::all().exec(&mut db).await?;
    users.sort_by(|a, b| a.username.to_lowercase().cmp(&b.username.to_lowercase()));
    let (members, available): (Vec<_>, Vec<_>) = users.into_iter().filter(|u| u.deleted_at.is_none()).map(|u| Choice { id: u.id, name: u.username }).partition(|u| ids.contains(&u.id));
    let status = if error.is_some() { StatusCode::UNPROCESSABLE_ENTITY } else { StatusCode::OK };
    Ok((status, GroupFormPage { user, csrf, id, name, members, available, error }.into_response()).into_response())
}

pub async fn edit(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, Path(id): Path<i64>) -> Result {
    let group = load(&mut core.db.clone(), id).await?;
    form(&core, &user, &csrf.token, Some(id), group.name, None).await
}

pub async fn create(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, AdminForm(data): AdminForm) -> Result {
    write(&core, &user, &csrf.token, None, data).await
}

pub async fn save(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, Path(id): Path<i64>, AdminForm(data): AdminForm) -> Result {
    write(&core, &user, &csrf.token, Some(id), data).await
}

async fn write(core: &Core, user: &User, csrf: &str, id: Option<i64>, data: HashMap<String, String>) -> Result {
    let name = field(&data, "name").trim().to_owned();
    let mut db = core.db.clone();
    if let Some(id) = id { load(&mut db, id).await?; }
    let invalid = required(&name, "Group name", 200).err();
    if invalid.is_some() { return form(core, user, csrf, id, name, invalid).await; }
    if Group::all().exec(&mut db).await?.iter().any(|g| g.deleted_at.is_none() && g.name.to_lowercase() == name.to_lowercase() && Some(g.id) != id) {
        return form(core, user, csrf, id, name, Some("A group with this name already exists.".into())).await;
    }
    let group_id = if let Some(id) = id {
        Group::filter_by_id(id).update().name(&name).updated_at(jiff::Timestamp::now()).exec(&mut db).await?;
        id
    } else {
        toasty::create!(Group { name: name }).exec(&mut db).await?.id
    };
    Ok(saved(&format!("/admin/groups/{group_id}")))
}

pub async fn add_member(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, Path(id): Path<i64>, AdminForm(data): AdminForm) -> Result {
    let mut db = core.db.clone();
    let group = load(&mut db, id).await?;
    let user_id = field(&data, "user_id").parse::<i64>().map_err(|_| bad_input("Choose a user to add."))?;
    users::load(&mut db, user_id).await?;
    let members = GroupMember::filter(GroupMember::fields().group_id().eq(id)).exec(&mut db).await?;
    if members.iter().any(|m| m.user_id == user_id) { return form(&core, &user, &csrf.token, Some(id), group.name, Some("This user is already a member.".into())).await; }
    toasty::create!(GroupMember { group_id: id, user_id: user_id }).exec(&mut db).await?;
    Ok(saved(&format!("/admin/groups/{id}")))
}

pub async fn remove_member(State(core): State<Arc<Core>>, Path((id, user_id)): Path<(i64, i64)>, AdminForm(_): AdminForm) -> Result {
    let mut db = core.db.clone();
    load(&mut db, id).await?;
    GroupMember::filter(GroupMember::fields().group_id().eq(id).and(GroupMember::fields().user_id().eq(user_id))).delete().exec(&mut db).await?;
    Ok(saved(&format!("/admin/groups/{id}")))
}

pub async fn confirm_delete(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, Path(id): Path<i64>) -> Result {
    let group = load(&mut core.db.clone(), id).await?;
    Ok(delete_page(&user, &csrf.token, "groups", &group.name, &format!("/admin/groups/{id}/delete"), &format!("/admin/groups/{id}"), "All memberships and client access rules for this group will be removed. The group record will be retained."))
}

pub async fn delete(State(core): State<Arc<Core>>, Path(id): Path<i64>, AdminForm(_): AdminForm) -> Result {
    let mut db = core.db.clone();
    let mut tx = db.transaction().await?;
    load(&mut tx, id).await?;
    GroupMember::filter(GroupMember::fields().group_id().eq(id)).delete().exec(&mut tx).await?;
    ClientAccessRule::filter(ClientAccessRule::fields().group_id().eq(id)).delete().exec(&mut tx).await?;
    Group::filter_by_id(id).update().deleted_at(jiff::Timestamp::now()).updated_at(jiff::Timestamp::now()).exec(&mut tx).await?;
    tx.commit().await?;
    Ok(saved("/admin/groups"))
}
