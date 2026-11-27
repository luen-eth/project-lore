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
pub(super) fn builtin_password_matches(
    admin: &Admin,
    name: &str,
    password: &str,
) -> anyhow::Result<bool> {
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
pub(super) fn ok_with_cookie(token: Option<String>) -> Response {
    ok_body_with_cookie(json!({ "ok": true }), token)
}

pub(super) fn ok_body_with_cookie(body: serde_json::Value, token: Option<String>) -> Response {
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
pub(super) fn may_manage_builtin(
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
pub(super) fn builtin_refusal((status, message): (StatusCode, &'static str)) -> Response {
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

// ---------------------------------------------------------------------
// The second step of a sign-in, passkey sign-in, and the WebAuthn
// challenges both use.
// ---------------------------------------------------------------------

/// The cookie that carries a sign-in waiting for its second factor.
const PENDING_COOKIE: &str = "lore_pending";
/// The cookie that binds a passwordless passkey challenge to its browser.
const WEBAUTHN_COOKIE: &str = "lore_webauthn";
/// How long a right password waits for the second factor.
const PENDING_TTL: Duration = Duration::from_secs(5 * 60);
/// Wrong second-factor attempts one pending sign-in may make.
const PENDING_FAILURES: u8 = 5;
/// Pending sign-ins and WebAuthn challenges kept at most.
const MAP_CAP: usize = 1000;
/// How long the browser may show a passkey prompt for a sign-in.
const ASSERTION_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the browser may show a passkey prompt for a registration.
pub(super) const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(300);
/// The answer to every failed passkey step: the reason goes to the log.
pub(super) const PASSKEY_REFUSED: &str = "This passkey is not known here or could not be verified.";

/// Which second factors a pending sign-in may use.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SecondFactors {
    /// The account has a second factor at all (even an unusable one).
    pub(super) any: bool,
    pub(super) passkey: bool,
    pub(super) totp: bool,
    pub(super) recovery: bool,
}

impl SecondFactors {
    fn methods(self) -> Vec<&'static str> {
        let mut methods = Vec::new();
        if self.passkey {
            methods.push("passkey");
        }
        if self.totp {
            methods.push("totp");
        }
        if self.recovery {
            methods.push("recovery");
        }
        methods
    }
}

/// A sign-in whose password was right, waiting for its second factor.
pub(super) struct PendingSignIn {
    user: SignedIn,
    pub(super) account: String,
    expires: Instant,
    failures: u8,
    factors: SecondFactors,
}

/// What a WebAuthn challenge is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CeremonyKind {
    /// Adding a passkey with this name to the signed-in account.
    Register { name: String },
    /// Signing in with a passkey alone.
    Passwordless,
    /// The second step after a right password.
    SecondFactor,
    /// Confirming it is you, for a change that needs a fresh sign-in.
    Reauth,
}

/// A WebAuthn challenge handed out and not yet answered. Single use, and
/// bound to the session, pending sign-in or browser it was made for.
pub(super) struct Ceremony {
    pub(super) challenge: [u8; 32],
    pub(super) kind: CeremonyKind,
    /// The session token, pending token or `lore_webauthn` cookie value.
    pub(super) bound_to: String,
    /// The account it was made for; `None` for a passwordless sign-in.
    pub(super) account: Option<String>,
    pub(super) rp: RelyingParty,
    pub(super) user_verification: bool,
    /// The credential ids offered; empty for a passwordless sign-in.
    pub(super) allowed: Vec<Vec<u8>>,
    pub(super) expires: Instant,
}

/// Which second factors the account has, and which of them work at this
/// address: passkeys made for this relying party, an authenticator app
/// the vault can read, unused recovery codes. An account with a factor
/// none of which works still gets the second step (fail closed).
pub(super) fn second_factors(
    admin: &Admin,
    account: &str,
    rp: Option<&RelyingParty>,
) -> anyhow::Result<SecondFactors> {
    let passkey = rp.is_some_and(|rp| {
        admin
            .db
            .credentials(account)
            .is_ok_and(|list| list.iter().any(|credential| credential.rp_id == rp.id))
    });
    let totp_row = admin.db.totp(account)?;
    let totp = totp_row
        .as_ref()
        .is_some_and(|row| totp_key(admin, account, row).is_some());
    let recovery = admin.db.recovery_remaining(account)?.0 > 0;
    Ok(SecondFactors {
        any: passkey || totp_row.is_some() || recovery,
        passkey,
        totp,
        recovery,
    })
}

/// The decrypted authenticator-app key of an account, when the vault can
/// read it.
fn totp_key(admin: &Admin, account: &str, row: &db::TotpRow) -> Option<Vec<u8>> {
    let vault = admin.vault.as_ref()?;
    let secret = vault
        .decrypt("totp", account, &row.nonce, &row.secret)
        .ok()?;
    crate::totp::decode_secret(secret.expose())
}

/// A pending-sign-in cookie.
fn pending_cookie(token: &str) -> String {
    format!(
        "{PENDING_COOKIE}={token}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        PENDING_TTL.as_secs()
    )
}

/// Answers a right password for an account with a second factor: the
/// sign-in waits (5 minutes) under a `lore_pending` cookie.
pub(super) fn start_pending(
    admin: &Arc<Admin>,
    ip: &str,
    user: SignedIn,
    factors: SecondFactors,
) -> Response {
    let Ok(token) = random_token() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let account = user.account();
    let username = user.username.clone();
    {
        let mut pending = admin.pending_map();
        let now = Instant::now();
        pending.retain(|_, entry| entry.expires > now);
        if pending.len() >= MAP_CAP
            && let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(token, _)| token.clone())
        {
            pending.remove(&oldest);
        }
        pending.insert(
            token.clone(),
            PendingSignIn {
                user,
                account: account.clone(),
                expires: now + PENDING_TTL,
                failures: 0,
                factors,
            },
        );
    }
    let methods = factors.methods();
    auth_event(
        admin,
        &account,
        &username,
        "signin.pending",
        ip,
        &methods.join("+"),
    );
    tracing::info!(%ip, user = %username, "password right; waiting for the second factor");
    (
        [(header::SET_COOKIE, pending_cookie(&token))],
        Json(json!({
            "ok": false,
            "second_factor": { "methods": methods, "username": username },
        })),
    )
        .into_response()
}

/// The pending sign-in of a request, for the session JSON.
pub(super) fn pending_summary(admin: &Admin, headers: &HeaderMap) -> serde_json::Value {
    let Some(token) = cookie(headers, PENDING_COOKIE) else {
        return serde_json::Value::Null;
    };
    let mut pending = admin.pending_map();
    let now = Instant::now();
    pending.retain(|_, entry| entry.expires > now);
    pending.get(&token).map_or(
        serde_json::Value::Null,
        |entry| json!({ "methods": entry.factors.methods(), "username": entry.user.username }),
    )
}

/// `401 {"restart": true}`: the pending sign-in is gone; start again with
/// the password.
fn restart(message: &str) -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": message, "restart": true })),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&expired_cookie(PENDING_COOKIE)) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// Stores a new challenge; `None` when the map is full of passwordless
/// challenges and this one is passwordless too.
pub(super) fn insert_ceremony(admin: &Admin, ceremony: Ceremony) -> Option<String> {
    let mut id = [0u8; 32];
    getrandom::fill(&mut id).ok()?;
    let id = crate::webauthn::b64url_encode(&id);
    let mut map = admin.ceremony_map();
    let now = Instant::now();
    map.retain(|_, entry| entry.expires > now);
    if map.len() >= MAP_CAP {
        if ceremony.kind == CeremonyKind::Passwordless {
            return None;
        }
        let oldest = map
            .iter()
            .filter(|(_, entry)| entry.kind == CeremonyKind::Passwordless)
            .min_by_key(|(_, entry)| entry.expires)
            .map(|(id, _)| id.clone())?;
        map.remove(&oldest);
    }
    map.insert(id.clone(), ceremony);
    Some(id)
}

/// Takes a challenge out of the map (single use, whatever happens next):
/// it must exist, be unexpired, be of `kind`'s sort and bound to `bound`.
pub(super) fn take_ceremony(
    admin: &Admin,
    id: &str,
    bound: Option<&str>,
    matches: impl Fn(&CeremonyKind) -> bool,
) -> Option<Ceremony> {
    let ceremony = admin.ceremony_map().remove(id)?;
    let bound_ok =
        bound.is_some_and(|bound| bool::from(bound.as_bytes().ct_eq(ceremony.bound_to.as_bytes())));
    (ceremony.expires > Instant::now() && bound_ok && matches(&ceremony.kind)).then_some(ceremony)
}

pub(super) fn new_challenge() -> Option<[u8; 32]> {
    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge).ok()?;
    Some(challenge)
}

/// `PublicKeyCredentialRequestOptionsJSON` for a challenge.
fn request_options(ceremony: &Ceremony, credentials: &[db::Credential]) -> serde_json::Value {
    let allow: Vec<serde_json::Value> = credentials
        .iter()
        .filter(|credential| ceremony.allowed.contains(&credential.credential_id))
        .map(|credential| {
            json!({
                "type": "public-key",
                "id": crate::webauthn::b64url_encode(&credential.credential_id),
                "transports": credential.transports,
            })
        })
        .collect();
    json!({
        "challenge": crate::webauthn::b64url_encode(&ceremony.challenge),
        "rpId": ceremony.rp.id,
        "allowCredentials": allow,
        "userVerification": if ceremony.user_verification { "required" } else { "preferred" },
        "timeout": ASSERTION_TIMEOUT.as_millis() as u64,
    })
}

fn unknown_host() -> Response {
    bad_request("passkeys need a known host name")
}

/// Makes an assertion challenge for `account`'s passkeys at this relying
/// party: the second step (UV preferred) or a re-authentication (UV
/// required). `Ok(None)` when the account has no passkey here.
pub(super) fn account_assertion_options(
    admin: &Admin,
    account: &str,
    rp: RelyingParty,
    kind: CeremonyKind,
    bound_to: String,
) -> anyhow::Result<Option<serde_json::Value>> {
    let credentials: Vec<db::Credential> = admin
        .db
        .credentials(account)?
        .into_iter()
        .filter(|credential| credential.rp_id == rp.id)
        .collect();
    if credentials.is_empty() {
        return Ok(None);
    }
    let challenge = new_challenge().ok_or_else(|| anyhow::anyhow!("no randomness"))?;
    let ceremony = Ceremony {
        challenge,
        user_verification: kind == CeremonyKind::Reauth,
        kind,
        bound_to,
        account: Some(account.to_string()),
        rp,
        allowed: credentials
            .iter()
            .map(|credential| credential.credential_id.clone())
            .collect(),
        expires: Instant::now() + ASSERTION_TIMEOUT + Duration::from_secs(30),
    };
    let options = request_options(&ceremony, &credentials);
    let id =
        insert_ceremony(admin, ceremony).ok_or_else(|| anyhow::anyhow!("too many challenges"))?;
    Ok(Some(json!({ "ceremony": id, "publicKey": options })))
}

/// `POST /admin/api/login/second-factor/passkey-options`: a challenge for
/// the pending account's passkeys at this address.
pub(super) async fn second_factor_passkey_options(
    State(admin): State<Arc<Admin>>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = cookie(&headers, PENDING_COOKIE) else {
        return restart("The sign-in expired. Enter the password again.");
    };
    let account = {
        let mut pending = admin.pending_map();
        let now = Instant::now();
        pending.retain(|_, entry| entry.expires > now);
        match pending.get(&token) {
            Some(entry) => entry.account.clone(),
            None => return restart("The sign-in expired. Enter the password again."),
        }
    };
    let Some(rp) = admin.relying_party(&headers) else {
        return unknown_host();
    };
    let state = admin.clone();
    let made = tokio::task::spawn_blocking(move || {
        account_assertion_options(&state, &account, rp, CeremonyKind::SecondFactor, token)
    })
    .await;
    match made {
        Ok(Ok(Some(options))) => Json(options).into_response(),
        Ok(Ok(None)) => bad_request("there is no passkey for this account at this address"),
        Ok(Err(error)) => {
            tracing::warn!(%error, "making second-factor passkey options failed");
            too_many_requests(5)
        }
        Err(error) => {
            tracing::error!(%error, "the passkey options task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub(super) struct SecondFactorForm {
    #[serde(default)]
    method: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    ceremony: String,
    #[serde(default)]
    credential: Option<serde_json::Value>,
}

impl std::fmt::Debug for SecondFactorForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecondFactorForm")
            .field("method", &self.method)
            .field("code", &"[redacted]")
            .finish()
    }
}

/// How checking one second factor went.
pub(super) enum FactorCheck {
    /// Right; `Some(n)` recovery codes are left after a recovery code.
    Ok(Option<i64>),
    /// Wrong, with the reason for the log.
    Wrong(String),
}

/// Checks an authenticator-app code for `account` at `now`; a right code
/// is accepted once (its step must be later than every step used before).
pub(super) fn check_totp(
    admin: &Admin,
    account: &str,
    code: &str,
    now: u64,
) -> anyhow::Result<FactorCheck> {
    let Some(row) = admin.db.totp(account)? else {
        return Ok(FactorCheck::Wrong("no authenticator app".into()));
    };
    let Some(key) = totp_key(admin, account, &row) else {
        return Ok(FactorCheck::Wrong(
            "the authenticator app secret cannot be read".into(),
        ));
    };
    let Some(step) = crate::totp::matching_step(&key, code, now) else {
        return Ok(FactorCheck::Wrong("wrong code".into()));
    };
    if admin.db.advance_totp_step(account, step)? {
        Ok(FactorCheck::Ok(None))
    } else {
        Ok(FactorCheck::Wrong("code already used".into()))
    }
}

/// Spends a recovery code of `account`.
pub(super) fn check_recovery(
    admin: &Admin,
    account: &str,
    code: &str,
) -> anyhow::Result<FactorCheck> {
    let Some(normalized) = crate::totp::normalize_recovery(code) else {
        return Ok(FactorCheck::Wrong("malformed recovery code".into()));
    };
    let hash = crate::totp::recovery_hash(account, &normalized);
    Ok(match admin.db.use_recovery_code(account, &hash)? {
        Some(left) => FactorCheck::Ok(Some(left)),
        None => FactorCheck::Wrong("unknown or used recovery code".into()),
    })
}

/// A verified passkey assertion: the account it signed in.
pub(super) struct VerifiedPasskey {
    pub(super) account: String,
}

/// Verifies a passkey answer to a challenge already taken out of the map.
/// For a second step or a re-authentication the credential must be one
/// offered to that account; for a passwordless sign-in the user handle
/// names the account. Updates the record (counter, backup state, last
/// use) on success; logs a counter regression.
pub(super) fn verify_passkey(
    admin: &Admin,
    ceremony: &Ceremony,
    credential: &serde_json::Value,
    ip: &str,
) -> Result<VerifiedPasskey, String> {
    let response: crate::webauthn::AssertionJson =
        serde_json::from_value(credential.clone()).map_err(|_| "malformed answer".to_string())?;
    let raw = crate::webauthn::raw_id(&response.id, &response.raw_id, &response.kind)
        .map_err(|error| error.to_string())?;
    let handle = crate::webauthn::user_handle(&response).map_err(|error| error.to_string())?;
    let stored = admin
        .db
        .credential_by_id(&raw)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "unknown credential".to_string())?;
    match &ceremony.account {
        Some(account) => {
            if !ceremony.allowed.contains(&raw) || &stored.account != account {
                return Err("credential not offered to this account".into());
            }
            if let Some(handle) = &handle {
                let own = admin
                    .db
                    .existing_user_handle(account)
                    .map_err(|error| error.to_string())?;
                if own.as_deref() != Some(handle.as_slice()) {
                    return Err("user handle mismatch".into());
                }
            }
        }
        None => {
            let handle = handle.ok_or_else(|| "no user handle".to_string())?;
            let owner = admin
                .db
                .account_by_user_handle(&handle)
                .map_err(|error| error.to_string())?;
            if owner.as_deref() != Some(stored.account.as_str()) {
                return Err("user handle mismatch".into());
            }
        }
    }
    if stored.rp_id != ceremony.rp.id {
        return Err("credential made for another host".into());
    }
    let expected = crate::webauthn::Expected {
        challenge: &ceremony.challenge,
        origin: &ceremony.rp.origin,
        rp_id: &ceremony.rp.id,
        user_verification: ceremony.user_verification,
    };
    let checked = crate::webauthn::verify_assertion(
        &response,
        &expected,
        &crate::webauthn::StoredCredential {
            public_key: &stored.public_key,
            sign_count: stored.sign_count,
            backup_eligible: stored.backup_eligible,
        },
    );
    match checked {
        Ok(assertion) => {
            admin
                .db
                .touch_credential(
                    stored.id,
                    assertion.sign_count,
                    assertion.backup_state,
                    assertion.user_verified && ceremony.user_verification,
                )
                .map_err(|error| error.to_string())?;
            Ok(VerifiedPasskey {
                account: stored.account,
            })
        }
        Err(crate::webauthn::Error::CounterRegression) => {
            tracing::warn!(%ip, account = %stored.account, passkey = %stored.name, "a passkey's signature counter went backwards: refused");
            auth_event(
                admin,
                &stored.account,
                "",
                "passkey.counter_regression",
                ip,
                &stored.name,
            );
            Err("signature counter went backwards".into())
        }
        Err(error) => Err(error.to_string()),
    }
}

/// `POST /admin/api/login/second-factor`: finishes a pending sign-in with
/// an authenticator-app code, a recovery code or a passkey.
pub(super) async fn second_factor(
    State(admin): State<Arc<Admin>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(form): Json<SecondFactorForm>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let Some(token) = cookie(&headers, PENDING_COOKIE) else {
        return restart("The sign-in expired. Enter the password again.");
    };
    let (user, account, factors) = {
        let mut pending = admin.pending_map();
        let now = Instant::now();
        pending.retain(|_, entry| entry.expires > now);
        match pending.get(&token) {
            Some(entry) => (entry.user.clone(), entry.account.clone(), entry.factors),
            None => return restart("The sign-in expired. Enter the password again."),
        }
    };
    if let Some(retry_after) = admin.second_factor_failures.blocked(&account) {
        auth_event(
            &admin,
            &account,
            &user.username,
            "signin.limited",
            &ip,
            "second factor",
        );
        return too_many_requests(retry_after);
    }
    let method: &'static str = match form.method.as_str() {
        "totp" if factors.totp => "totp",
        "recovery" if factors.recovery => "recovery",
        "passkey" if factors.passkey => "passkey",
        _ => return bad_request("this way of confirming is not available for this sign-in"),
    };
    let state = admin.clone();
    let check_account = account.clone();
    let check_ip = ip.clone();
    let checked = tokio::task::spawn_blocking(move || -> anyhow::Result<FactorCheck> {
        match method {
            "totp" => check_totp(&state, &check_account, &form.code, crate::totp::now()),
            "recovery" => check_recovery(&state, &check_account, &form.code),
            _ => {
                let Some(ceremony) = take_ceremony(&state, &form.ceremony, Some(&token), |kind| {
                    *kind == CeremonyKind::SecondFactor
                }) else {
                    return Ok(FactorCheck::Wrong("unknown or used challenge".into()));
                };
                let credential = form.credential.unwrap_or_default();
                Ok(
                    match verify_passkey(&state, &ceremony, &credential, &check_ip) {
                        Ok(_) => FactorCheck::Ok(None),
                        Err(reason) => FactorCheck::Wrong(reason),
                    },
                )
            }
        }
    })
    .await;
    let checked = match checked {
        Ok(Ok(checked)) => checked,
        Ok(Err(error)) => {
            tracing::error!(%error, "checking a second factor failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(error) => {
            tracing::error!(%error, "the second-factor task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let pending_token = cookie(&headers, PENDING_COOKIE).unwrap_or_default();
    match checked {
        FactorCheck::Wrong(reason) => {
            tracing::warn!(%ip, user = %user.username, method, %reason, "a second factor was refused");
            auth_event(
                &admin,
                &account,
                &user.username,
                "signin.fail.second_factor",
                &ip,
                &format!("{method}: {reason}"),
            );
            admin.second_factor_failures.hit(&account);
            let gone = {
                let mut pending = admin.pending_map();
                match pending.get_mut(&pending_token) {
                    Some(entry) => {
                        entry.failures += 1;
                        if entry.failures >= PENDING_FAILURES {
                            pending.remove(&pending_token);
                            true
                        } else {
                            false
                        }
                    }
                    None => true,
                }
            };
            if gone {
                return restart("Too many wrong attempts. Enter the password again.");
            }
            let message = if method == "passkey" {
                PASSKEY_REFUSED
            } else {
                "Wrong code."
            };
            (StatusCode::UNAUTHORIZED, Json(json!({ "error": message }))).into_response()
        }
        FactorCheck::Ok(recovery_left) => {
            // Single use: a second request with the same cookie finds
            // nothing.
            if admin.pending_map().remove(&pending_token).is_none() {
                return restart("The sign-in expired. Enter the password again.");
            }
            admin.second_factor_failures.reset(&account);
            if let Some(left) = recovery_left {
                auth_event(
                    &admin,
                    &account,
                    &user.username,
                    "recovery.used",
                    &ip,
                    &format!("{left} left"),
                );
            }
            let extras = SignInExtras {
                body: recovery_left.map(|left| ("recovery_left", json!(left))),
                clear_cookies: vec![PENDING_COOKIE],
            };
            finish_sign_in(&admin, &ip, user, vec!["password", method], false, extras).await
        }
    }
}

/// `POST /admin/api/login/cancel`: drops the pending sign-in.
pub(super) async fn cancel_pending(
    State(admin): State<Arc<Admin>>,
    headers: HeaderMap,
) -> Response {
    if let Some(token) = cookie(&headers, PENDING_COOKIE) {
        admin.pending_map().remove(&token);
    }
    (
        [(header::SET_COOKIE, expired_cookie(PENDING_COOKIE))],
        Json(json!({ "ok": true })),
    )
        .into_response()
}

/// `POST /admin/api/login/passkey/options`: a challenge for signing in
/// with a passkey alone (discoverable credential, user verification
/// required), bound to this browser by a `lore_webauthn` cookie. The same
/// for everyone: no user name is asked.
pub(super) async fn passkey_options(
    State(admin): State<Arc<Admin>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    if let Some(retry_after) = admin.passkey_options.hit(&ip) {
        return too_many_requests(retry_after);
    }
    let Some(rp) = admin.relying_party(&headers) else {
        return unknown_host();
    };
    let (Some(challenge), Ok(binding)) = (new_challenge(), random_token()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let ceremony = Ceremony {
        challenge,
        kind: CeremonyKind::Passwordless,
        bound_to: binding.clone(),
        account: None,
        rp,
        user_verification: true,
        allowed: Vec::new(),
        expires: Instant::now() + ASSERTION_TIMEOUT + Duration::from_secs(30),
    };
    let options = request_options(&ceremony, &[]);
    let Some(id) = insert_ceremony(&admin, ceremony) else {
        return too_many_requests(30);
    };
    let bind_cookie = format!(
        "{WEBAUTHN_COOKIE}={binding}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=180"
    );
    (
        [(header::SET_COOKIE, bind_cookie)],
        Json(json!({ "ceremony": id, "publicKey": options })),
    )
        .into_response()
}

#[derive(Deserialize, Debug)]
pub(super) struct PasskeyForm {
    #[serde(default)]
    ceremony: String,
    #[serde(default)]
    credential: Option<serde_json::Value>,
}

/// The signed-in user an account key names now, if it may sign in: a
/// stored user that exists and is enabled (`Err` when disabled), or a
/// built-in user whose environment variable is set.
fn user_of_account(admin: &Admin, account: &str) -> anyhow::Result<Result<Option<SignedIn>, ()>> {
    match account {
        ADMIN_USER => Ok(Ok(Some(SignedIn::builtin_admin()))),
        VIEWER_USER if admin.viewer_password.is_some() => Ok(Ok(Some(SignedIn::builtin_viewer()))),
        VIEWER_USER => Ok(Ok(None)),
        _ => {
            let Some(id) = account
                .strip_prefix("user:")
                .and_then(|id| id.parse::<i64>().ok())
            else {
                return Ok(Ok(None));
            };
            match admin.db.user(id)? {
                Some(user) if user.disabled => Ok(Err(())),
                Some(user) => Ok(Ok(Some(SignedIn {
                    perms: user.perms(),
                    username: user.username,
                    user_id: Some(id),
                }))),
                None => Ok(Ok(None)),
            }
        }
    }
}

/// `POST /admin/api/login/passkey`: signs in with a passkey alone. The
/// passkey must verify the user (PIN, fingerprint, face): that is two
/// factors in one.
pub(super) async fn passkey_sign_in(
    State(admin): State<Arc<Admin>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(form): Json<PasskeyForm>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    if let Some(retry_after) = admin.logins.hit(&ip) {
        auth_event(&admin, "", "", "signin.limited", &ip, "passkey");
        return too_many_requests(retry_after);
    }
    let binding = cookie(&headers, WEBAUTHN_COOKIE);
    let state = admin.clone();
    let check_ip = ip.clone();
    let checked = tokio::task::spawn_blocking(
        move || -> anyhow::Result<Result<SignedIn, (StatusCode, String, String)>> {
            let refused = |reason: &str| {
                Ok(Err((
                    StatusCode::UNAUTHORIZED,
                    String::new(),
                    reason.to_string(),
                )))
            };
            let Some(ceremony) =
                take_ceremony(&state, &form.ceremony, binding.as_deref(), |kind| {
                    *kind == CeremonyKind::Passwordless
                })
            else {
                return refused("unknown, used or unbound challenge");
            };
            let credential = form.credential.unwrap_or_default();
            let verified = match verify_passkey(&state, &ceremony, &credential, &check_ip) {
                Ok(verified) => verified,
                Err(reason) => return refused(&reason),
            };
            match user_of_account(&state, &verified.account)? {
                Ok(Some(user)) => Ok(Ok(user)),
                Ok(None) => Ok(Err((
                    StatusCode::UNAUTHORIZED,
                    verified.account,
                    "account gone".into(),
                ))),
                Err(()) => Ok(Err((
                    StatusCode::FORBIDDEN,
                    verified.account,
                    "user disabled".into(),
                ))),
            }
        },
    )
    .await;
    let outcome = match checked {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) => {
            tracing::error!(%error, "checking a passkey sign-in failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(error) => {
            tracing::error!(%error, "the passkey sign-in task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    match outcome {
        Ok(user) => {
            let extras = SignInExtras {
                body: None,
                clear_cookies: vec![WEBAUTHN_COOKIE],
            };
            finish_sign_in(&admin, &ip, user, vec!["passkey-uv"], false, extras).await
        }
        Err((status, account, reason)) => {
            tracing::warn!(%ip, %reason, "a passkey sign-in was refused");
            auth_event(&admin, &account, "", "signin.fail.passkey", &ip, &reason);
            if status == StatusCode::FORBIDDEN {
                return forbidden("This user is disabled.");
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": PASSKEY_REFUSED })),
            )
                .into_response()
        }
    }
}
