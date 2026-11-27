//! The admin view's side of agent authorization: the consent page's
//! requests (they need the admin session, whose cookie lives under
//! `/admin`), the agents panel, and the avatar files.

use super::*;
use crate::{
    avatars,
    db::Approval,
    oauth::{self, CODE_TTL_SECS},
};

/// Longest note kept for an agent.
const NOTE_MAX_CHARS: usize = 300;

/// `GET /admin/avatars/<id>.svg`: one built-in avatar, cached for a year
/// (the files never change under an id).
pub(super) async fn avatar(Path(file): Path<String>) -> Response {
    let Some(svg) = file.strip_suffix(".svg").and_then(avatars::svg) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        svg,
    )
        .into_response()
}

fn expired() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "This authorization request has expired or was already answered. \
                      Start again from the application.",
        })),
    )
        .into_response()
}

fn stale_page() -> Response {
    forbidden(
        "This consent page is out of date or belongs to another sign-in. Reload it and try again.",
    )
}

/// What the consent page shows once the user is signed in: who asks, where
/// the answer goes, what approval grants, and the choices to make. Hands
/// out the page's one-time token, bound to this sign-in.
pub(super) async fn consent_request(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(oauth) = admin.oauth.clone() else {
        return expired();
    };
    let Some(request) = oauth.pending_request(&id) else {
        return expired();
    };
    let Some(session) = cookie(&headers, COOKIE) else {
        return stale_page();
    };
    let Some(csrf) = oauth.issue_csrf(&id, &session) else {
        return expired();
    };
    if !me.perms.contains(Perm::Agents) {
        // A clear refusal; the page may still send the application back
        // with a denial, which needs the one-time token.
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!(
                    "You are signed in as {}, who does not hold the agents permission. Only a \
                     user with it can authorize an agent; ask one, or sign in as one.",
                    me.username
                ),
                "permission": false,
                "csrf": csrf,
            })),
        )
            .into_response();
    }
    let state = admin.clone();
    let reserved = oauth.reserved_names();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let vault = state.db.vault_status()?;
        // Every configured service, by name: an approved agent reaches each
        // at the default level until someone lowers it.
        let services: Vec<&str> = ops::ALL
            .iter()
            .zip(vault.iter())
            .filter(|(_, row)| row.configured)
            .map(|(provider, _)| provider.label)
            .collect();
        let existing: Vec<serde_json::Value> = state
            .db
            .oauth_agents()?
            .into_iter()
            .map(|agent| {
                json!({
                    "name": agent.name,
                    "avatar": avatars::effective(&agent.name, &agent.avatar),
                    "disabled": agent.disabled,
                    "note": agent.note,
                })
            })
            .collect();
        let mut taken: Vec<String> = state
            .db
            .agent_records(&state.configured_agents)?
            .into_iter()
            .map(|agent| agent.name)
            .collect();
        taken.extend(reserved);
        let suggested = oauth::suggest_agent_name(&request.client_name, &taken);
        Ok(json!({
            "client_id": request.client_id,
            "client_name": request.client_name,
            "redirect_uri": request.redirect_uri,
            "csrf": csrf,
            "username": me.username,
            "services": services,
            "services_enabled": state.db.ops_enabled()?,
            // Without `integrations` the approver cannot hand out service
            // access: the agent gets level off on every service.
            "services_off": !me.perms.contains(Perm::Integrations),
            // The mailbox is not among them: it is off for a new agent
            // until someone with `integrations` grants it.
            "mailbox": state.db.mail_vault()?.is_some(),
            "existing": existing,
            "avatars": avatars::ids(),
            "suggested_name": suggested,
            "suggested_avatar": avatars::default_for(&suggested),
        }))
    })
    .await;
    respond(result)
}

#[derive(Deserialize)]
pub(super) struct ApproveForm {
    #[serde(default)]
    csrf: String,
    /// `new` or `existing`.
    #[serde(default)]
    mode: String,
    #[serde(default)]
    name: String,
    /// An avatar id; empty keeps (or derives) it.
    #[serde(default)]
    avatar: String,
}

impl std::fmt::Debug for ApproveForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApproveForm")
            .field("csrf", &"[redacted]")
            .field("mode", &self.mode)
            .field("name", &self.name)
            .field("avatar", &self.avatar)
            .finish()
    }
}

/// Approves a consent request: creates or re-authorizes the agent, issues
/// the authorization code and answers with the redirect the page follows.
pub(super) async fn consent_approve(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(form): Json<ApproveForm>,
) -> Response {
    let Some(oauth) = admin.oauth.clone() else {
        return expired();
    };
    let Some(session) = cookie(&headers, COOKIE) else {
        return stale_page();
    };
    if oauth.pending_request(&id).is_none() {
        return expired();
    }
    let Some(request) = oauth.check_csrf(&id, &session, &form.csrf) else {
        return stale_page();
    };
    let new_agent = match form.mode.as_str() {
        "new" => true,
        "existing" => false,
        _ => return bad_request("mode must be new or existing"),
    };
    let reserved = oauth.reserved_names();
    let name = match oauth::normalize_agent_name(&form.name, &reserved) {
        Ok(name) => name,
        Err(message) => return bad_request(&message),
    };
    let avatar = form.avatar.trim().to_string();
    if !avatar.is_empty() && !avatars::is_known(&avatar) {
        return bad_request("pick one of the avatars shown");
    }
    let Ok(code) = oauth::random_token() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let approval = Approval {
        agent: name.clone(),
        new_agent,
        avatar,
        client_id: request.client_id.clone(),
        client_name: request.client_name.clone(),
        redirect_uri: request.redirect_uri.clone(),
        authorized_by: me.username.clone(),
        reserved,
        services_off: !me.perms.contains(Perm::Integrations),
        code_hash: oauth::token_hash(&code),
        code_challenge: request.code_challenge.clone(),
        code_expires_at: db::unix_now() + CODE_TTL_SECS,
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || state.db.approve(&approval)).await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => return bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "the approval task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    oauth.finish(&id);
    let client = if request.client_name.is_empty() {
        "an unnamed client".to_string()
    } else {
        request.client_name.clone()
    };
    let verb = if new_agent {
        "authorized the new agent"
    } else {
        "re-authorized"
    };
    note_activity(
        &admin,
        "authorize",
        &format!("{} {verb} {name} for {client}", me.username),
    );
    tracing::info!(user = %me.username, agent = %name, "an agent was authorized");
    let mut pairs = vec![("code", code.as_str())];
    if let Some(state) = request.state.as_deref() {
        pairs.push(("state", state));
    }
    match oauth::redirect_with(&request.redirect_uri, &pairs) {
        Some(redirect) => Json(json!({ "redirect": redirect, "agent": name })).into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
pub(super) struct DenyForm {
    #[serde(default)]
    csrf: String,
}

/// Denies a consent request: the application is told `access_denied`.
pub(super) async fn consent_deny(
    State(admin): State<Arc<Admin>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(form): Json<DenyForm>,
) -> Response {
    let Some(oauth) = admin.oauth.clone() else {
        return expired();
    };
    let Some(session) = cookie(&headers, COOKIE) else {
        return stale_page();
    };
    if oauth.pending_request(&id).is_none() {
        return expired();
    }
    let Some(request) = oauth.check_csrf(&id, &session, &form.csrf) else {
        return stale_page();
    };
    oauth.finish(&id);
    let mut pairs = vec![
        ("error", "access_denied"),
        ("error_description", "the user denied the request"),
    ];
    if let Some(state) = request.state.as_deref() {
        pairs.push(("state", state));
    }
    match oauth::redirect_with(&request.redirect_uri, &pairs) {
        Some(redirect) => Json(json!({ "redirect": redirect })).into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Every agent with how it is connected and what it did. Any signed-in
/// user reads it; changes need `agents`.
pub(super) async fn list_agents(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
) -> Response {
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        Ok(json!({
            "agents": state.db.agent_records(&state.configured_agents)?,
            "avatars": avatars::ids(),
            "manage": me.perms.contains(Perm::Agents),
        }))
    })
    .await;
    respond(result)
}

/// An agent name from a path: lowercase, and something lore could know.
fn agent_name(name: &str) -> Option<String> {
    let name = name.trim().to_lowercase();
    let plain = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    plain.then_some(name)
}

/// Whether lore knows an agent by this name at all.
fn known_agent(admin: &Admin, name: &str) -> anyhow::Result<bool> {
    Ok(admin
        .db
        .agent_records(&admin.configured_agents)?
        .iter()
        .any(|agent| agent.name == name))
}

#[derive(Deserialize)]
pub(super) struct AgentForm {
    /// An avatar id, or empty for the one derived from the name.
    #[serde(default)]
    avatar: Option<String>,
    #[serde(default)]
    note: Option<String>,
    /// The name the page shows; empty clears it.
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    disabled: Option<bool>,
}

/// Changes an agent's avatar, note, display name, or whether it is
/// disabled. Disabling closes its open sessions; its tokens are refused
/// from then on. The technical name never changes.
pub(super) async fn update_agent(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(name): Path<String>,
    Json(form): Json<AgentForm>,
) -> Response {
    let Some(name) = agent_name(&name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let avatar = form.avatar.map(|avatar| avatar.trim().to_string());
    if let Some(avatar) = &avatar
        && !avatar.is_empty()
        && !avatars::is_known(avatar)
    {
        return bad_request("pick one of the built-in avatars");
    }
    let note = form.note.map(|note| {
        note.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect::<String>()
            .trim()
            .to_string()
    });
    if note
        .as_ref()
        .is_some_and(|note| note.chars().count() > NOTE_MAX_CHARS)
    {
        return bad_request(&format!(
            "the note must be at most {NOTE_MAX_CHARS} characters"
        ));
    }
    let display_name = match form
        .display_name
        .as_deref()
        .map(crate::db::clean_display_name)
    {
        None => None,
        Some(Ok(cleaned)) => Some(cleaned),
        Some(Err(why)) => return bad_request(&why),
    };
    let state = admin.clone();
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<serde_json::Value>> {
            if !known_agent(&state, &name)? {
                return Ok(None);
            }
            if let Some(display) = &display_name {
                state
                    .db
                    .set_agent_display_name(&name, display.as_deref(), &me.username)?;
            }
            if avatar.is_some() || note.is_some() {
                state.db.set_agent_details(
                    &name,
                    avatar.as_deref(),
                    note.as_deref(),
                    &me.username,
                )?;
            }
            if let Some(disabled) = form.disabled {
                let was = state
                    .db
                    .registry_agent(&name)?
                    .is_some_and(|agent| agent.disabled);
                if was != disabled {
                    let closed = state.db.set_agent_disabled(&name, disabled, &me.username)?;
                    let summary = if disabled {
                        format!(
                            "{} disabled the agent {name} ({closed} open session{} closed)",
                            me.username,
                            if closed == 1 { "" } else { "s" }
                        )
                    } else {
                        format!("{} enabled the agent {name}", me.username)
                    };
                    note_activity(
                        &state,
                        if disabled { "disable" } else { "enable" },
                        &summary,
                    );
                }
            }
            Ok(Some(json!({ "ok": true })))
        })
        .await;
    match result {
        Ok(Ok(Some(value))) => Json(value).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "changing an agent failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Revokes every authorization of an agent: all its OAuth tokens stop
/// working and it has to be authorized again.
pub(super) async fn revoke_agent(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(name): Path<String>,
) -> Response {
    let Some(name) = agent_name(&name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let revoked = state.db.revoke_agent(&name)?;
        note_activity(
            &state,
            "revoke",
            &format!(
                "{} revoked the authorization of {name} ({revoked} active)",
                me.username
            ),
        );
        Ok(json!({ "ok": true, "revoked": revoked }))
    })
    .await;
    respond(result)
}

/// Deletes an OAuth agent's authorization entirely: its grants, tokens
/// and registry row. What it wrote stays.
pub(super) async fn delete_agent(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(name): Path<String>,
) -> Response {
    let Some(name) = agent_name(&name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        let deleted = state.db.delete_oauth_agent(&name)?;
        if deleted {
            note_activity(
                &state,
                "revoke",
                &format!(
                    "{} deleted the authorization of {name}; what it wrote stays",
                    me.username
                ),
            );
        }
        Ok(deleted)
    })
    .await;
    match result {
        Ok(Ok(true)) => Json(json!({ "ok": true })).into_response(),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "deleting an agent failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
