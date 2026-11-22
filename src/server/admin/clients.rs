use super::*;
use crate::{
    models::{
        AllowType, ClientAccessRule, ClientRedirect, ClientToken, ClientType, ForwardAuthRequest,
        ForwardAuthSession, OAuthToken,
    },
    token::generate_token,
};
use axum::extract::{Path, Query};

async fn load(db: &mut dyn toasty::Executor, id: i64) -> Result<Client> {
    let client = Client::get_by_id(db, id).await?;
    if client.deleted_at.is_some() {
        return Err(not_found());
    }
    Ok(client)
}

fn fields_for(client: &Client) -> ClientFields {
    ClientFields {
        name: client.name.clone(),
        kind: kind(&client.client_type),
        lifetime: client.session_lifetime_s.to_string(),
        require_pkce: client.require_pkce,
        detailed_logging: client.detailed_logging,
        allow_event_reports: client.allow_event_reports,
    }
}

fn kind(client_type: &ClientType) -> String {
    match client_type {
        ClientType::Oidc => "Oidc",
        ClientType::ForwardAuth => "ForwardAuth",
    }
    .into()
}

pub async fn list(
    State(core): State<Arc<Core>>,
    Extension(user): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    Query(params): Query<HashMap<String, String>>,
) -> Result {
    let query = field(&params, "q");
    let mut db = core.db.clone();
    let rules = ClientAccessRule::all().exec(&mut db).await?;
    let mut clients: Vec<_> = Client::all()
        .exec(&mut db)
        .await?
        .into_iter()
        .filter(|c| {
            c.deleted_at.is_none()
                && (c.name.to_lowercase().contains(&query.to_lowercase())
                    || c.client_id.to_lowercase().contains(&query.to_lowercase()))
        })
        .map(|c| ClientRow {
            id: c.id,
            name: c.name,
            identifier: c.client_id,
            kind: kind(&c.client_type),
            rules: rules.iter().filter(|r| r.client_id == c.id).count(),
        })
        .collect();
    clients.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(ClientsPage {
        user: &user,
        csrf: &csrf.token,
        clients,
        query,
    }
    .into_response())
}

pub async fn new(
    Extension(user): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
) -> Response {
    ClientFormPage {
        user: &user,
        csrf: &csrf.token,
        id: None,
        fields: ClientFields {
            kind: "Oidc".into(),
            lifetime: "64800".into(),
            require_pkce: true,
            ..Default::default()
        },
        identifier: None,
        endpoints: vec![],
        secret: None,
        rules: vec![],
        groups: vec![],
        rule_fields: RuleFields::default(),
        redirects: vec![],
        redirect_fields: RedirectFields::default(),
        error: None,
    }
    .into_response()
}

async fn form(
    core: &Core,
    user: &User,
    csrf: &str,
    id: Option<i64>,
    fields: ClientFields,
    error: Option<String>,
) -> Result {
    render_form(
        core,
        user,
        csrf,
        id,
        fields,
        RuleFields::default(),
        RedirectFields::default(),
        error,
    )
    .await
}

async fn render_form(
    core: &Core,
    user: &User,
    csrf: &str,
    id: Option<i64>,
    fields: ClientFields,
    rule_fields: RuleFields,
    redirect_fields: RedirectFields,
    error: Option<String>,
) -> Result {
    let mut db = core.db.clone();
    let client = if let Some(id) = id {
        Some(load(&mut db, id).await?)
    } else {
        None
    };
    let endpoints: Vec<ClientEndpoint> = client
        .as_ref()
        .filter(|c| matches!(c.client_type, ClientType::Oidc))
        .and_then(|c| crate::provider::oauth2::issuer(core, c).ok())
        .map(|issuer| {
            [
                (
                    "discovery",
                    "OpenID configuration",
                    "/.well-known/openid-configuration",
                ),
                ("authorize", "Authorization endpoint", "/authorize"),
                ("token", "Token endpoint", "/token"),
                ("jwks", "JWKS endpoint", "/jwks"),
                ("userinfo", "Userinfo endpoint", "/userinfo"),
                ("revoke", "Revocation endpoint", "/revoke"),
                ("event", "Application events endpoint", "/event"),
            ]
            .into_iter()
            .map(|(id, name, path)| ClientEndpoint {
                id: format!("client-{id}"),
                name: name.into(),
                url: if matches!(id, "discovery" | "jwks") {
                    format!("{issuer}{path}")
                } else {
                    format!("{}/oauth2{path}", core.domain.trim_end_matches('/'))
                },
            })
            .collect()
        })
        .unwrap_or_default();
    let mut endpoints = endpoints;
    if client
        .as_ref()
        .is_some_and(|c| matches!(c.client_type, ClientType::ForwardAuth))
    {
        endpoints.push(ClientEndpoint {
            id: "client-event".into(),
            name: "Application events endpoint".into(),
            url: format!("{}/oauth2/event", core.domain.trim_end_matches('/')),
        });
    }
    let identifier = client.as_ref().map(|c| c.client_id.clone());
    let secret = client.map(|c| c.client_secret);
    let mut groups: Vec<_> = Group::all()
        .exec(&mut db)
        .await?
        .into_iter()
        .filter(|g| g.deleted_at.is_none())
        .map(|g| Choice {
            id: g.id,
            name: g.name,
        })
        .collect();
    groups.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    let mut rules = vec![];
    let mut redirects = vec![];
    if let Some(id) = id {
        redirects = ClientRedirect::filter(ClientRedirect::fields().client_id().eq(id))
            .exec(&mut db)
            .await?
            .into_iter()
            .map(|redirect| RedirectRow {
                id: redirect.id,
                uri: redirect.redirect_uri,
            })
            .collect();
        redirects.sort_by(|a, b| a.uri.cmp(&b.uri));
        for rule in ClientAccessRule::filter(ClientAccessRule::fields().client_id().eq(id))
            .exec(&mut db)
            .await?
        {
            if let Some(group) = groups.iter().find(|g| g.id == rule.group_id) {
                rules.push(RuleRow {
                    group_id: rule.group_id,
                    group_name: group.name.clone(),
                    priority: rule.priority,
                    allow: matches!(rule.access_control, AllowType::Allow),
                });
            }
        }
        rules.sort_by_key(|r| (r.priority, r.group_id));
    }
    let status = if error.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    let mut response = (
        status,
        ClientFormPage {
            user,
            csrf,
            id,
            fields,
            identifier,
            endpoints,
            secret,
            rules,
            groups,
            rule_fields,
            redirects,
            redirect_fields,
            error,
        }
        .into_response(),
    )
        .into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

pub async fn edit(
    State(core): State<Arc<Core>>,
    Extension(user): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    Path(id): Path<i64>,
) -> Result {
    let client = load(&mut core.db.clone(), id).await?;
    form(
        &core,
        &user,
        &csrf.token,
        Some(id),
        fields_for(&client),
        None,
    )
    .await
}

pub async fn create(
    State(core): State<Arc<Core>>,
    Extension(user): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    AdminForm(data): AdminForm,
) -> Result {
    write(&core, &user, &csrf.token, None, data).await
}

pub async fn save(
    State(core): State<Arc<Core>>,
    Extension(user): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    Path(id): Path<i64>,
    AdminForm(data): AdminForm,
) -> Result {
    write(&core, &user, &csrf.token, Some(id), data).await
}

async fn write(
    core: &Core,
    user: &User,
    csrf: &str,
    id: Option<i64>,
    data: HashMap<String, String>,
) -> Result {
    let fields = ClientFields {
        name: field(&data, "name").trim().into(),
        kind: field(&data, "client_type"),
        lifetime: field(&data, "session_lifetime_s"),
        require_pkce: data.contains_key("require_pkce"),
        detailed_logging: data.contains_key("detailed_logging"),
        allow_event_reports: data.contains_key("allow_event_reports"),
    };
    let client_type = match fields.kind.parse::<ClientType>() {
        Ok(value) => value,
        Err(error) => return form(core, user, csrf, id, fields, Some(error.to_string())).await,
    };
    let lifetime = fields.lifetime.parse::<u32>();
    let invalid = required(&fields.name, "Client name", 200)
        .err()
        .or_else(|| {
            (!lifetime.as_ref().is_ok_and(|v| (300..=2592000).contains(v)))
                .then(|| "Session lifetime must be 300–2592000 seconds.".into())
        });
    if invalid.is_some() {
        return form(core, user, csrf, id, fields, invalid).await;
    }
    let lifetime = lifetime.map_err(|_| bad_input("Invalid session lifetime."))?;
    let mut db = core.db.clone();
    let mut tx = db
        .transaction_builder()
        .mode(toasty_core::driver::operation::TransactionMode::Immediate)
        .begin()
        .await?;
    let old = if let Some(id) = id {
        let client = load(&mut tx, id).await?;
        Some((client.detailed_logging, client.allow_event_reports))
    } else {
        None
    };
    let result = if let Some(id) = id {
        Client::filter_by_id(id)
            .update()
            .name(&fields.name)
            .client_type(client_type)
            .session_lifetime_s(lifetime)
            .require_pkce(fields.require_pkce)
            .detailed_logging(fields.detailed_logging)
            .allow_event_reports(fields.allow_event_reports)
            .updated_at(jiff::Timestamp::now())
            .exec(&mut tx)
            .await
            .map(|_| id)
    } else {
        toasty::create!(Client {
            name: &fields.name,
            slug: generate_token(),
            session_lifetime_s: lifetime,
            require_pkce: fields.require_pkce,
            detailed_logging: fields.detailed_logging,
            allow_event_reports: fields.allow_event_reports,
            client_id: generate_token(),
            client_type: client_type,
            client_secret: generate_token()
        })
        .exec(&mut tx)
        .await
        .map(|c| c.id)
    };
    let saved_id = match result {
        Ok(id) => id,
        Err(_) => {
            tx.rollback().await?;
            return form(
                core,
                user,
                csrf,
                id,
                fields,
                Some("Unable to save this client. Please try again.".into()),
            )
            .await;
        }
    };
    let client = Client::get_by_id(&mut tx, saved_id).await?;
    crate::journal::configuration(&mut tx, user.id, &client, old).await?;
    tx.commit().await?;
    Ok(saved(&format!("/admin/clients/{saved_id}")))
}

pub async fn rotate_secret(
    State(core): State<Arc<Core>>,
    Path(id): Path<i64>,
    AdminForm(data): AdminForm,
) -> Result {
    if field(&data, "confirm") != "rotate" {
        return Err(bad_input("Confirm that you want to rotate the secret."));
    }
    let mut db = core.db.clone();
    load(&mut db, id).await?;
    Client::filter_by_id(id)
        .update()
        .client_secret(generate_token())
        .updated_at(jiff::Timestamp::now())
        .exec(&mut db)
        .await?;
    Ok(saved(&format!("/admin/clients/{id}")))
}

pub async fn save_rule(
    State(core): State<Arc<Core>>,
    Extension(user): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    Path(id): Path<i64>,
    AdminForm(data): AdminForm,
) -> Result {
    let rule_fields = RuleFields {
        group_id: field(&data, "group_id"),
        priority: field(&data, "priority"),
        access_control: field(&data, "access_control"),
    };
    let group_id = rule_fields.group_id.parse::<i64>();
    let priority = rule_fields.priority.parse::<i16>();
    let error = if group_id.is_err() {
        Some("Choose a group.")
    } else if priority.is_err() {
        Some("Priority must be a whole number between -32768 and 32767.")
    } else if !matches!(rule_fields.access_control.as_str(), "allow" | "deny") {
        Some("Choose Allow or Deny.")
    } else {
        None
    };
    if let Some(error) = error {
        let client = load(&mut core.db.clone(), id).await?;
        return render_form(
            &core,
            &user,
            &csrf.token,
            Some(id),
            fields_for(&client),
            rule_fields,
            RedirectFields::default(),
            Some(error.into()),
        )
        .await;
    }
    let group_id = group_id.map_err(|_| bad_input("Choose a group."))?;
    let priority = priority.map_err(|_| bad_input("Choose a valid priority."))?;
    let access = if rule_fields.access_control == "allow" {
        AllowType::Allow
    } else {
        AllowType::Deny
    };
    let mut db = core.db.clone();
    let mut tx = db.transaction().await?;
    load(&mut tx, id).await?;
    groups::load(&mut tx, group_id).await?;
    ClientAccessRule::filter(
        ClientAccessRule::fields()
            .client_id()
            .eq(id)
            .and(ClientAccessRule::fields().group_id().eq(group_id)),
    )
    .delete()
    .exec(&mut tx)
    .await?;
    toasty::create!(ClientAccessRule {
        client_id: id,
        group_id: group_id,
        priority: priority,
        access_control: access
    })
    .exec(&mut tx)
    .await?;
    tx.commit().await?;
    Ok(saved(&format!("/admin/clients/{id}")))
}

pub async fn remove_rule(
    State(core): State<Arc<Core>>,
    Path((id, group_id)): Path<(i64, i64)>,
    AdminForm(_): AdminForm,
) -> Result {
    let mut db = core.db.clone();
    load(&mut db, id).await?;
    ClientAccessRule::filter(
        ClientAccessRule::fields()
            .client_id()
            .eq(id)
            .and(ClientAccessRule::fields().group_id().eq(group_id)),
    )
    .delete()
    .exec(&mut db)
    .await?;
    Ok(saved(&format!("/admin/clients/{id}")))
}

pub async fn confirm_delete(
    State(core): State<Arc<Core>>,
    Extension(user): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    Path(id): Path<i64>,
) -> Result {
    let client = load(&mut core.db.clone(), id).await?;
    Ok(delete_page(
        &user,
        &csrf.token,
        "clients",
        &client.name,
        &format!("/admin/clients/{id}/delete"),
        &format!("/admin/clients/{id}"),
        "This client and its group access rules will be removed from administration. The client record will be retained.",
    ))
}

pub async fn delete(
    State(core): State<Arc<Core>>,
    Path(id): Path<i64>,
    AdminForm(_): AdminForm,
) -> Result {
    let mut db = core.db.clone();
    let mut tx = db.transaction().await?;
    load(&mut tx, id).await?;
    ClientAccessRule::filter(ClientAccessRule::fields().client_id().eq(id))
        .delete()
        .exec(&mut tx)
        .await?;
    ClientRedirect::filter(ClientRedirect::fields().client_id().eq(id))
        .delete()
        .exec(&mut tx)
        .await?;
    ClientToken::filter(ClientToken::fields().client_id().eq(id))
        .delete()
        .exec(&mut tx)
        .await?;
    OAuthToken::filter(OAuthToken::fields().client_id().eq(id))
        .delete()
        .exec(&mut tx)
        .await?;
    ForwardAuthRequest::filter(ForwardAuthRequest::fields().client_id().eq(id))
        .delete()
        .exec(&mut tx)
        .await?;
    ForwardAuthSession::filter(ForwardAuthSession::fields().client_id().eq(id))
        .delete()
        .exec(&mut tx)
        .await?;
    Client::filter_by_id(id)
        .update()
        .deleted_at(jiff::Timestamp::now())
        .updated_at(jiff::Timestamp::now())
        .exec(&mut tx)
        .await?;
    tx.commit().await?;
    Ok(saved("/admin/clients"))
}

fn redirect_error(uri: &str) -> Option<&'static str> {
    if uri.is_empty() {
        return Some("Enter a redirect URI.");
    }
    if uri.len() > 2048 {
        return Some("Redirect URIs must be 2048 bytes or fewer.");
    }
    if uri.chars().any(char::is_whitespace) || uri.chars().any(char::is_control) {
        return Some("Redirect URIs cannot contain spaces or control characters.");
    }
    if uri.contains('*') {
        return Some("Enter an exact redirect URI without wildcards.");
    }
    // The URL parser repairs missing slashes and backslashes; reject those spellings
    // rather than storing a different string from the URI it validated.
    let Some((scheme, authority)) = uri.split_once("://") else {
        return Some("Enter an absolute HTTP or HTTPS redirect URI.");
    };
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
        || authority
            .split(['/', '?', '#'])
            .next()
            .is_none_or(str::is_empty)
        || uri.contains('\\')
    {
        return Some("Enter an absolute HTTP or HTTPS redirect URI.");
    }
    let url = match reqwest::Url::parse(uri) {
        Ok(url) => url,
        Err(_) => return Some("Enter an absolute HTTP or HTTPS redirect URI."),
    };
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Some("Enter an absolute HTTP or HTTPS redirect URI.");
    }
    if url.fragment().is_some() {
        return Some("Redirect URIs cannot contain a fragment (#).");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Some("Redirect URIs cannot contain a username or password.");
    }
    None
}

async fn redirect_form_error(
    core: &Core,
    user: &User,
    csrf: &str,
    id: i64,
    redirect_id: Option<i64>,
    uri: String,
    message: &str,
) -> Result {
    let client = load(&mut core.db.clone(), id).await?;
    render_form(
        core,
        user,
        csrf,
        Some(id),
        fields_for(&client),
        RuleFields::default(),
        RedirectFields {
            id: redirect_id,
            uri,
        },
        Some(message.into()),
    )
    .await
}

pub async fn add_redirect(
    State(core): State<Arc<Core>>,
    Extension(user): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    Path(id): Path<i64>,
    AdminForm(data): AdminForm,
) -> Result {
    write_redirect(&core, &user, &csrf.token, id, None, data).await
}

pub async fn save_redirect(
    State(core): State<Arc<Core>>,
    Extension(user): Extension<Arc<User>>,
    Extension(csrf): Extension<CsrfToken>,
    Path((id, redirect_id)): Path<(i64, i64)>,
    AdminForm(data): AdminForm,
) -> Result {
    write_redirect(&core, &user, &csrf.token, id, Some(redirect_id), data).await
}

async fn write_redirect(
    core: &Core,
    user: &User,
    csrf: &str,
    id: i64,
    redirect_id: Option<i64>,
    data: HashMap<String, String>,
) -> Result {
    // Preserve the exact URI. URL parsing validates it without normalizing the stored value.
    let mut uri = field(&data, "redirect_uri");
    let mut db = core.db.clone();
    let mut tx = db.transaction().await?;
    let client = load(&mut tx, id).await?;
    if let Some(redirect_id) = redirect_id {
        let redirect = ClientRedirect::get_by_id(&mut tx, redirect_id).await?;
        if redirect.client_id != id {
            return Err(not_found());
        }
    }
    if let Some(error) = redirect_error(&uri) {
        tx.rollback().await?;
        return redirect_form_error(core, user, csrf, id, redirect_id, uri, error).await;
    }
    if matches!(client.client_type, ClientType::ForwardAuth) {
        uri = crate::provider::forwardauth::origin(&uri)
            .map_err(|_| bad_input("Invalid application origin."))?;
    }
    let duplicates = ClientRedirect::filter(ClientRedirect::fields().client_id().eq(id))
        .exec(&mut tx)
        .await?;
    if duplicates.iter().any(|r| {
        Some(r.id) != redirect_id
            && (r.redirect_uri == uri
                || matches!(client.client_type, ClientType::ForwardAuth)
                    && crate::provider::forwardauth::origin(&r.redirect_uri)
                        .is_ok_and(|origin| origin == uri))
    }) {
        tx.rollback().await?;
        return redirect_form_error(
            core,
            user,
            csrf,
            id,
            redirect_id,
            uri,
            "This redirect URI is already whitelisted for this client.",
        )
        .await;
    }
    if let Some(redirect_id) = redirect_id {
        ClientRedirect::filter(
            ClientRedirect::fields()
                .id()
                .eq(redirect_id)
                .and(ClientRedirect::fields().client_id().eq(id)),
        )
        .update()
        .redirect_uri(&uri)
        .exec(&mut tx)
        .await?;
    } else {
        toasty::create!(ClientRedirect {
            client_id: id,
            redirect_uri: uri
        })
        .exec(&mut tx)
        .await?;
    }
    Client::filter_by_id(id)
        .update()
        .updated_at(jiff::Timestamp::now())
        .exec(&mut tx)
        .await?;
    tx.commit().await?;
    Ok(saved(&format!("/admin/clients/{id}#redirect-uris")))
}

pub async fn remove_redirect(
    State(core): State<Arc<Core>>,
    Path((id, redirect_id)): Path<(i64, i64)>,
    AdminForm(_): AdminForm,
) -> Result {
    let mut db = core.db.clone();
    let mut tx = db.transaction().await?;
    load(&mut tx, id).await?;
    let redirect = ClientRedirect::get_by_id(&mut tx, redirect_id).await?;
    if redirect.client_id != id {
        return Err(not_found());
    }
    ClientRedirect::filter(
        ClientRedirect::fields()
            .id()
            .eq(redirect_id)
            .and(ClientRedirect::fields().client_id().eq(id)),
    )
    .delete()
    .exec(&mut tx)
    .await?;
    Client::filter_by_id(id)
        .update()
        .updated_at(jiff::Timestamp::now())
        .exec(&mut tx)
        .await?;
    tx.commit().await?;
    Ok(saved(&format!("/admin/clients/{id}#redirect-uris")))
}
