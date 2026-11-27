//! Signing-in security of the admin view: changing passwords (stored and
//! built-in users), the second step of a sign-in, passkeys, the
//! authenticator app, recovery codes and re-authentication.

use super::*;

#[derive(Deserialize)]
pub(super) struct PasswordForm {
    #[serde(default)]
    current: String,
    #[serde(default)]
    password: String,
}

impl std::fmt::Debug for PasswordForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordForm { [redacted] }")
    }
}

#[derive(Deserialize)]
pub(super) struct NewPasswordForm {
    #[serde(default)]
    password: String,
}

impl std::fmt::Debug for NewPasswordForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewPasswordForm { [redacted] }")
    }
}

/// The environment password of a built-in user, when it exists.
fn env_password<'a>(admin: &'a Admin, name: &str) -> Option<&'a str> {
    match name {
        ADMIN_USER => Some(admin.password.as_str()),
        VIEWER_USER => admin.viewer_password.as_deref(),
        _ => None,
    }
}

/// Whether `password` signs in as the built-in user `name` right now: its
/// page password when one was set, else its environment password.
/// Argon2 when a page password exists: call it off the executor, holding a
/// slot.
fn builtin_password_matches(admin: &Admin, name: &str, password: &str) -> anyhow::Result<bool> {
    Ok(match admin.db.builtin_password(name)? {
        Some(row) => users::verify_password(password, &row.password_hash),
        None => env_password(admin, name)
            .is_some_and(|env| bool::from(password.as_bytes().ct_eq(env.as_bytes()))),
    })
}

/// Whether `password` is either password (environment or page) of the
/// other built-in user. An empty user name tries `admin` first, so a
/// viewer password that is also admin's would grant admin, and the other
/// way round would make the viewer unreachable.
fn matches_other_builtin(admin: &Admin, name: &str, password: &str) -> anyhow::Result<bool> {
    let other = if name == ADMIN_USER {
        VIEWER_USER
    } else {
        ADMIN_USER
    };
    if other == VIEWER_USER && admin.viewer_password.is_none() {
        return Ok(false);
    }
    let env = env_password(admin, other)
        .is_some_and(|env| bool::from(password.as_bytes().ct_eq(env.as_bytes())));
    let page = admin
        .db
        .builtin_password(other)?
        .is_some_and(|row| users::verify_password(password, &row.password_hash));
    Ok(env || page)
}

/// Why a password change was refused, or that it was done.
enum PasswordChange {
    Done,
    Refused(String),
}

/// `PUT /admin/api/password`: any signed-in user changes their own
/// password; the current one is required (that is the re-authentication).
/// Their other sessions end; this one moves to a new token.
pub(super) async fn change_own_password(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(form): Json<PasswordForm>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let builtin = me.user_id.is_none();
    if let Err(message) = users::check_password(&form.password) {
        return bad_request(&message);
    }
    if builtin
        && let Err(message) = users::check_new_password(&me.username, None, &form.password, true)
    {
        return bad_request(&message);
    }
    // Like a sign-in: the attempt counts before the current password is
    // checked, and the check needs a free Argon2 slot.
    if let Some(retry_after) = admin.logins.hit(&ip) {
        return too_many_requests(retry_after);
    }
    let Ok(permit) = admin.argon.clone().try_acquire_owned() else {
        return too_many_requests(2);
    };
    let keep = cookie(&headers, COOKIE);
    let state = admin.clone();
    let event_ip = ip.clone();
    let result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<(PasswordChange, Option<String>)> {
            let _permit = permit;
            let refused = |message: &str| Ok((PasswordChange::Refused(message.into()), None));
            let account = me.account();
            match me.user_id {
                Some(id) => {
                    let (Some(user), Some(hash)) =
                        (state.db.user(id)?, state.db.user_password_hash(id)?)
                    else {
                        return refused("your user no longer exists");
                    };
                    if let Err(message) = users::check_new_password(
                        &user.username,
                        user.email.as_deref(),
                        &form.password,
                        false,
                    ) {
                        return refused(&message);
                    }
                    if !users::verify_password(&form.current, &hash) {
                        return refused("the current password is wrong");
                    }
                    if users::verify_password(&form.password, &hash) {
                        return refused("the new password is the current one");
                    }
                    let patch = UserPatch {
                        password_hash: Some(users::hash_password(&form.password)?),
                        ..UserPatch::default()
                    };
                    state.db.update_user(id, &patch)?;
                }
                None => {
                    if !builtin_password_matches(&state, &me.username, &form.current)? {
                        return refused("the current password is wrong");
                    }
                    if builtin_password_matches(&state, &me.username, &form.password)? {
                        return refused("the new password is the current one");
                    }
                    if matches_other_builtin(&state, &me.username, &form.password)? {
                        return refused("the new password is the other built-in user's password");
                    }
                    let hash = users::hash_password(&form.password)?;
                    state
                        .db
                        .set_builtin_password(&me.username, &hash, &me.username)?;
                }
            }
            state.end_sessions_of_account(&account, keep.as_deref(), None);
            let rotated = keep.and_then(|keep| state.rotate_session(&keep, true));
            auth_event(
                &state,
                &account,
                &me.username,
                "password.changed",
                &event_ip,
                "",
            );
            let summary = format!("{} changed their password", me.username);
            note_activity(&state, "users", &summary);
            Ok((PasswordChange::Done, rotated))
        },
    )
    .await;
    match result {
        Ok(Ok((PasswordChange::Done, rotated))) => {
            admin.logins.reset(&ip);
            ok_with_cookie(rotated)
        }
        Ok(Ok((PasswordChange::Refused(message), _))) => bad_request(&message),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "changing a password failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `{"ok": true}`, with the rotated session cookie when there is one.
fn ok_with_cookie(token: Option<String>) -> Response {
    ok_body_with_cookie(json!({ "ok": true }), token)
}

fn ok_body_with_cookie(body: serde_json::Value, token: Option<String>) -> Response {
    match token {
        Some(token) => ([(header::SET_COOKIE, session_cookie(&token))], Json(body)).into_response(),
        None => Json(body).into_response(),
    }
}

/// `DELETE /admin/api/password` (fresh): a built-in user drops the
/// password set on the page, so the environment password signs in again.
pub(super) async fn restore_env_password(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if me.user_id.is_some() {
        return bad_request("only the built-in users have an environment password");
    }
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let keep = cookie(&headers, COOKIE);
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Option<String>>> {
        if !state.db.clear_builtin_password(&me.username)? {
            return Ok(None);
        }
        let account = me.account();
        state.end_sessions_of_account(&account, keep.as_deref(), None);
        let rotated = keep.and_then(|keep| state.rotate_session(&keep, false));
        auth_event(
            &state,
            &account,
            &me.username,
            "password.env_restored",
            &ip,
            "",
        );
        let summary = format!(
            "{} went back to the password set in the server environment",
            me.username
        );
        note_activity(&state, "users", &summary);
        Ok(Some(rotated))
    })
    .await;
    match result {
        Ok(Ok(Some(rotated))) => ok_with_cookie(rotated),
        Ok(Ok(None)) => bad_request("the environment password already signs in"),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "restoring the environment password failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Who may change a built-in user's password or reset its second factors:
/// the viewer's needs `users` (and a configured viewer); admin's only the
/// built-in admin itself, recovery being `LORE_ADMIN_BREAK_GLASS`.
fn may_manage_builtin(
    admin: &Admin,
    me: &SignedIn,
    name: &str,
) -> Result<(), (StatusCode, &'static str)> {
    match name {
        VIEWER_USER if admin.viewer_password.is_none() => {
            Err((StatusCode::NOT_FOUND, "there is no viewer"))
        }
        VIEWER_USER if !me.perms.contains(Perm::Users) => {
            Err((StatusCode::FORBIDDEN, "this needs the users permission"))
        }
        VIEWER_USER => Ok(()),
        ADMIN_USER if me.user_id.is_none() && me.username == ADMIN_USER => Ok(()),
        ADMIN_USER => Err((
            StatusCode::FORBIDDEN,
            "only admin changes admin's password or second steps; recovery is \
             LORE_ADMIN_BREAK_GLASS",
        )),
        _ => Err((StatusCode::NOT_FOUND, "there is no such built-in user")),
    }
}

/// The answer to a refused built-in change.
fn builtin_refusal((status, message): (StatusCode, &'static str)) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// `PUT /admin/api/builtin-users/{name}/password` (fresh): sets a built-in
/// user's password on the page. It then replaces the environment password.
/// That user's sessions end (the caller's own moves to a new token).
pub(super) async fn set_builtin_password(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(form): Json<NewPasswordForm>,
) -> Response {
    if let Err(refusal) = may_manage_builtin(&admin, &me, &name) {
        return builtin_refusal(refusal);
    }
    if let Err(message) = users::check_new_password(&name, None, &form.password, true) {
        return bad_request(&message);
    }
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let Ok(permit) = admin.argon.clone().try_acquire_owned() else {
        return too_many_requests(2);
    };
    let keep = cookie(&headers, COOKIE);
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<(PasswordChange, Option<String>)> {
            let _permit = permit;
            let myself = me.user_id.is_none() && me.username == name;
            if myself && builtin_password_matches(&state, &name, &form.password)? {
                return Ok((
                    PasswordChange::Refused("the new password is the current one".into()),
                    None,
                ));
            }
            if matches_other_builtin(&state, &name, &form.password)? {
                return Ok((
                    PasswordChange::Refused(
                        "the new password is the other built-in user's password".into(),
                    ),
                    None,
                ));
            }
            let hash = users::hash_password(&form.password)?;
            state.db.set_builtin_password(&name, &hash, &me.username)?;
            let keep = keep.filter(|_| myself);
            state.end_sessions_of_account(&name, keep.as_deref(), None);
            let rotated = keep.and_then(|keep| state.rotate_session(&keep, false));
            let event = if myself {
                "password.changed"
            } else {
                "password.set_by_other"
            };
            auth_event(&state, &name, &me.username, event, &ip, "");
            let summary = format!(
                "{} set the password of the built-in user {name}",
                me.username
            );
            note_activity(&state, "users", &summary);
            Ok((PasswordChange::Done, rotated))
        },
    )
    .await;
    match result {
        Ok(Ok((PasswordChange::Done, rotated))) => ok_with_cookie(rotated),
        Ok(Ok((PasswordChange::Refused(message), _))) => bad_request(&message),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "setting a built-in password failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
