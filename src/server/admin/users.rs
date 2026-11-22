use super::*;
use axum::extract::{Path, Query};
use crate::models::{GroupMember, Role, Session};

pub async fn load(db: &mut dyn toasty::Executor, id: i64) -> Result<User> {
    let user = User::get_by_id(db, id).await?;
    if user.deleted_at.is_some() { return Err(not_found()); }
    Ok(user)
}

pub async fn list(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, Query(params): Query<HashMap<String, String>>) -> Result {
    let query = field(&params, "q");
    let mut db = core.db.clone();
    let mut users: Vec<_> = User::all().exec(&mut db).await?.into_iter()
        .filter(|u| u.deleted_at.is_none() && u.username.to_lowercase().contains(&query.to_lowercase()))
        .map(|u| UserRow { id: u.id, username: u.username, role: if matches!(u.role, Role::Admin) { "Admin" } else { "User" }.into(), disabled: u.disabled, local_password: u.password.is_some() }).collect();
    users.sort_by(|a, b| a.username.to_lowercase().cmp(&b.username.to_lowercase()));
    Ok(UsersPage { user: &user, csrf: &csrf.token, users, query }.into_response())
}

pub async fn new(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>) -> Result {
    form(&core, &user, &csrf.token, None, UserFields { role: "User".into(), ..Default::default() }, None).await
}

async fn form(core: &Core, user: &User, csrf: &str, id: Option<i64>, fields: UserFields, error: Option<String>) -> Result {
    let sessions = if let Some(id) = id {
        let mut rows: Vec<_> = Session::filter(Session::fields().user_id().eq(id))
            .exec(&mut core.db.clone()).await?.into_iter()
            .map(|session| SessionRow { id: session.id, created_at: session.created_at }).collect();
        rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        rows
    } else { vec![] };
    let status = if error.is_some() { StatusCode::UNPROCESSABLE_ENTITY } else { StatusCode::OK };
    Ok((status, UserFormPage { user, csrf, id, fields, sessions, error }.into_response()).into_response())
}

pub async fn edit(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, Path(id): Path<i64>) -> Result {
    let target = load(&mut core.db.clone(), id).await?;
    form(&core, &user, &csrf.token, Some(id), UserFields { username: target.username, email: target.email.unwrap_or_default(), role: if matches!(target.role, Role::Admin) { "Admin" } else { "User" }.into(), disabled: target.disabled }, None).await
}

pub async fn create(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, AdminForm(data): AdminForm) -> Result {
    write(&core, &user, &csrf.token, None, data).await
}

pub async fn save(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, Path(id): Path<i64>, AdminForm(data): AdminForm) -> Result {
    write(&core, &user, &csrf.token, Some(id), data).await
}

async fn write(core: &Core, user: &User, csrf: &str, id: Option<i64>, data: HashMap<String, String>) -> Result {
    let fields = UserFields { username: field(&data, "username").trim().into(), email: field(&data, "email").trim().into(), role: field(&data, "role"), disabled: data.contains_key("disabled") };
    let role = match fields.role.parse::<Role>() {
        Ok(role) => role,
        Err(error) => return form(core, user, csrf, id, fields, Some(error.to_string())).await,
    };
    let password = field(&data, "password");
    let invalid = required(&fields.username, "Username", 128).err()
        .or_else(|| (!fields.email.is_empty() && (fields.email.len() > 254 || fields.email.chars().any(char::is_whitespace) || fields.email.split('@').count() != 2 || fields.email.starts_with('@') || fields.email.ends_with('@'))).then(|| "Enter a valid email address.".into()))
        .or_else(|| (!password.is_empty() && !(8..=72).contains(&password.len())).then(|| "Passwords must be between 8 and 72 bytes.".into()))
        .or_else(|| (id == Some(user.id) && (fields.disabled || !matches!(role, Role::Admin))).then(|| "You cannot disable your own account or remove your own admin role.".into()));
    if let Some(error) = invalid { return form(core, user, csrf, id, fields, Some(error)).await; }
    let mut db = core.db.clone();
    if let Some(id) = id { load(&mut db, id).await?; }
    if User::all().exec(&mut db).await?.iter().any(|u| u.username == fields.username && Some(u.id) != id) {
        return form(core, user, csrf, id, fields, Some("This username is already in use, including by a deleted account.".into())).await;
    }
    let email = if fields.email.is_empty() { None } else { Some(fields.email.clone()) };
    let hash = if password.is_empty() { None } else { Some(password_hash(password).await?) };
    let mut tx = db.transaction().await?;
    let result: std::result::Result<i64, toasty::Error> = async {
        if let Some(id) = id {
            User::filter_by_id(id).update().username(&fields.username).email(email.clone()).role(role).disabled(fields.disabled).updated_at(jiff::Timestamp::now()).exec(&mut tx).await?;
            if hash.is_some() || fields.disabled {
                crate::mfa::invalidate_logins(&mut tx, id).await?;
            }
            if let Some(hash) = hash {
                User::filter_by_id(id).update().password(hash).exec(&mut tx).await?;
                Session::filter(Session::fields().user_id().eq(id)).delete().exec(&mut tx).await?;
            } else if fields.disabled {
                Session::filter(Session::fields().user_id().eq(id)).delete().exec(&mut tx).await?;
            }
            Ok(id)
        } else {
            let created = toasty::create!(User { username: &fields.username, email: email, password: hash, role: role, disabled: fields.disabled }).exec(&mut tx).await?;
            Ok(created.id)
        }
    }.await;
    let target_id = match result {
        Ok(id) => id,
        Err(error) => {
            eprintln!("Unable to save user: {error}");
            tx.rollback().await?;
            return form(core, user, csrf, id, fields, Some("Unable to save this user. Check the username and try again.".into())).await;
        }
    };
    tx.commit().await?;
    let mut response = saved("/admin/users");
    response.extensions_mut().insert(super::audit::Target(target_id));
    Ok(response)
}

pub async fn confirm_delete(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Extension(csrf): Extension<CsrfToken>, Path(id): Path<i64>) -> Result {
    let target = load(&mut core.db.clone(), id).await?;
    if id == user.id { return Err(bad_input("You cannot delete your own account.")); }
    Ok(delete_page(&user, &csrf.token, "users", &target.username, &format!("/admin/users/{id}/delete"), &format!("/admin/users/{id}"), "This user will lose access immediately. Their sessions and group memberships will be removed. The account record will be retained."))
}

pub async fn delete(State(core): State<Arc<Core>>, Extension(user): Extension<Arc<User>>, Path(id): Path<i64>, AdminForm(_): AdminForm) -> Result {
    if id == user.id { return Err(bad_input("You cannot delete your own account.")); }
    let mut db = core.db.clone();
    let mut tx = db.transaction().await?;
    load(&mut tx, id).await?;
    crate::mfa::invalidate_logins(&mut tx, id).await?;
    Session::filter(Session::fields().user_id().eq(id)).delete().exec(&mut tx).await?;
    GroupMember::filter(GroupMember::fields().user_id().eq(id)).delete().exec(&mut tx).await?;
    User::filter_by_id(id).update().disabled(true).deleted_at(jiff::Timestamp::now()).updated_at(jiff::Timestamp::now()).exec(&mut tx).await?;
    tx.commit().await?;
    Ok(saved("/admin/users"))
}


pub async fn delete_session(
    State(core): State<Arc<Core>>,
    cookies: axum_extra::extract::CookieJar,
    Path((id, session_id)): Path<(i64, i64)>,
    AdminForm(_): AdminForm,
) -> Result {
    let mut db = core.db.clone();
    load(&mut db, id).await?;
    let session = Session::get_by_id(&mut db, session_id).await?;
    if session.user_id != id { return Err(not_found()); }
    let current = cookies.get(crate::server::cookies::LOGIN_COOKIE_NAME)
        .is_some_and(|cookie| cookie.value() == session.token);
    Session::filter(Session::fields().id().eq(session_id).and(Session::fields().user_id().eq(id)))
        .delete().exec(&mut db).await?;
    if current { Ok(saved("/login")) } else { Ok(saved(&format!("/admin/users/{id}"))) }
}

pub async fn delete_sessions(
    State(core): State<Arc<Core>>,
    Extension(user): Extension<Arc<User>>,
    Path(id): Path<i64>,
    AdminForm(_): AdminForm,
) -> Result {
    let mut db = core.db.clone();
    let mut tx = db.transaction().await?;
    load(&mut tx, id).await?;
    crate::mfa::invalidate_logins(&mut tx, id).await?;
    Session::filter(Session::fields().user_id().eq(id)).delete().exec(&mut tx).await?;
    tx.commit().await?;
    if id == user.id { Ok(saved("/login")) } else { Ok(saved(&format!("/admin/users/{id}"))) }
}
