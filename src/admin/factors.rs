//! Profile → Security: a signed-in user's own passkeys, authenticator app
//! and recovery codes, re-authentication, the sign-in log, and what an
//! administrator may reset for others.

use super::security::{
    Ceremony, CeremonyKind, FactorCheck, REGISTRATION_TIMEOUT, account_assertion_options,
    check_recovery, check_totp, insert_ceremony, new_challenge, ok_body_with_cookie,
    ok_with_cookie, take_ceremony, verify_passkey,
};
use super::*;

/// Passkeys one account may hold.
const MAX_PASSKEYS: usize = 20;
/// Longest passkey name.
const MAX_PASSKEY_NAME: usize = 60;
/// How long an authenticator-app setup waits for its confirming code.
const TOTP_SETUP_TTL: Duration = Duration::from_secs(10 * 60);
/// Wrong confirming codes before a setup is discarded.
const TOTP_SETUP_FAILURES: u8 = 5;
/// Own sign-in events the Security section shows.
const OWN_EVENTS: i64 = 20;

/// An authenticator-app secret waiting for its confirming code; kept in
/// the session only, never stored.
pub(super) struct TotpSetup {
    secret: String,
    expires: Instant,
    failures: u8,
}

/// The session token of a request, which every handler here acts on.
fn session_token(headers: &HeaderMap) -> Option<String> {
    cookie(headers, COOKIE)
}

/// Seconds of freshness the session has, and whether it is break-glass.
fn session_state(admin: &Admin, token: &str) -> (u64, bool) {
    admin.sessions().get(token).map_or((0, false), |session| {
        (session.fresh_for(), session.break_glass)
    })
}

/// The JSON of one passkey for the Security list.
fn passkey_json(credential: &db::Credential, rp: Option<&RelyingParty>) -> serde_json::Value {
    json!({
        "id": credential.id,
        "name": credential.name,
        "created_at": credential.created_at,
        "last_used_at": credential.last_used_at,
        "rp_id": credential.rp_id,
        "usable_here": rp.is_some_and(|rp| rp.id == credential.rp_id),
        "synced": credential.backup_state,
        "passwordless": credential.discoverable,
        "transports": credential.transports,
        "alg": credential.alg,
    })
}

/// `GET /admin/api/security`: the signed-in user's own sign-in settings.
pub(super) async fn security(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    headers: HeaderMap,
) -> Response {
    let rp = admin.relying_party(&headers);
    let (fresh_for, break_glass) = session_token(&headers)
        .map(|token| session_state(&admin, &token))
        .unwrap_or_default();
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let account = me.account();
        let password = match me.user_id {
            Some(_) => json!({ "source": "stored", "changed_at": null }),
            None => match state.db.builtin_password(&me.username)? {
                Some(row) => json!({ "source": "page", "changed_at": row.changed_at }),
                None => json!({ "source": "environment", "changed_at": null }),
            },
        };
        let passkeys: Vec<serde_json::Value> = state
            .db
            .credentials(&account)?
            .iter()
            .map(|credential| passkey_json(credential, rp.as_ref()))
            .collect();
        let totp = match state.db.totp(&account)? {
            Some(row) => {
                let readable = state
                    .vault
                    .as_ref()
                    .and_then(|vault| vault.decrypt("totp", &account, &row.nonce, &row.secret).ok())
                    .is_some();
                json!({ "enabled": true, "confirmed_at": row.confirmed_at, "readable": readable })
            }
            None => json!({ "enabled": false, "confirmed_at": null, "readable": false }),
        };
        let (left, total) = state.db.recovery_remaining(&account)?;
        let summary = state.db.second_factor_summary(&account)?;
        let events: Vec<serde_json::Value> = state
            .db
            .auth_events(Some(&account), OWN_EVENTS)?
            .into_iter()
            .map(|event| {
                json!({
                    "created_at": event.created_at,
                    "event": event.event,
                    "ip": event.ip,
                    "detail": event.detail,
                })
            })
            .collect();
        Ok(json!({
            "account": account,
            "username": me.username,
            "builtin": me.user_id.is_none(),
            "password": password,
            "passkeys": passkeys,
            "totp": totp,
            "recovery": if total > 0 { json!({ "left": left, "total": total }) } else { serde_json::Value::Null },
            "second_factor_required": summary.any(),
            "fresh_for": fresh_for,
            "vault": state.vault.is_some(),
            "rp_id": rp.as_ref().map(|rp| rp.id.clone()),
            "break_glass": break_glass,
            "events": events,
        }))
    })
    .await;
    respond(result)
}

/// `POST /admin/api/security/reauth/options`: a challenge for confirming
/// it is you with one of your passkeys (user verification required).
pub(super) async fn reauth_options(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(rp) = admin.relying_party(&headers) else {
        return bad_request("passkeys need a known host name");
    };
    let state = admin.clone();
    let made = tokio::task::spawn_blocking(move || {
        account_assertion_options(&state, &me.account(), rp, CeremonyKind::Reauth, token)
    })
    .await;
    match made {
        Ok(Ok(Some(options))) => Json(options).into_response(),
        Ok(Ok(None)) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "you have no passkey at this address" })),
        )
            .into_response(),
        Ok(Err(error)) => {
            tracing::warn!(%error, "making re-authentication options failed");
            too_many_requests(5)
        }
        Err(error) => {
            tracing::error!(%error, "the options task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub(super) struct ReauthForm {
    #[serde(default)]
    password: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    recovery_code: String,
    #[serde(default)]
    ceremony: String,
    #[serde(default)]
    credential: Option<serde_json::Value>,
}

impl std::fmt::Debug for ReauthForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReauthForm { [redacted] }")
    }
}

/// `POST /admin/api/security/reauth`: confirms it is you, making the
/// session fresh for ten minutes. With a passkey (user verification), or
/// with the password plus, when the account has a second factor, an
/// authenticator-app code or a recovery code. A break-glass admin session
/// confirms with the environment password alone.
pub(super) async fn reauth(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(form): Json<ReauthForm>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let Some(token) = session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if let Some(retry_after) = admin.logins.hit(&ip) {
        auth_event(
            &admin,
            &me.account(),
            &me.username,
            "signin.limited",
            &ip,
            "reauth",
        );
        return too_many_requests(retry_after);
    }
    let with_passkey = form.credential.is_some();
    let permit = if with_passkey {
        None
    } else {
        match admin.argon.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => return too_many_requests(2),
        }
    };
    let (_, break_glass) = session_state(&admin, &token);
    let state = admin.clone();
    let check_ip = ip.clone();
    let check_token = token.clone();
    let checked =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Result<&'static str, String>> {
            let _permit = permit;
            let account = me.account();
            if let Some(credential) = &form.credential {
                let Some(ceremony) =
                    take_ceremony(&state, &form.ceremony, Some(&check_token), |kind| {
                        *kind == CeremonyKind::Reauth
                    })
                else {
                    return Ok(Err("unknown or used challenge".into()));
                };
                if ceremony.account.as_deref() != Some(account.as_str()) {
                    return Ok(Err("challenge of another account".into()));
                }
                return Ok(
                    verify_passkey(&state, &ceremony, credential, &check_ip).map(|_| "passkey-uv")
                );
            }
            let password_ok = match me.user_id {
                Some(id) => state
                    .db
                    .user_password_hash(id)?
                    .is_some_and(|hash| users::verify_password(&form.password, &hash)),
                None => {
                    super::security::builtin_password_matches(&state, &me.username, &form.password)?
                }
            };
            let env_break_glass = break_glass
                && me.user_id.is_none()
                && me.username == ADMIN_USER
                && bool::from(form.password.as_bytes().ct_eq(state.password.as_bytes()));
            if env_break_glass {
                return Ok(Ok("password-env-break-glass"));
            }
            if !password_ok {
                return Ok(Err("wrong password".into()));
            }
            if !state.db.second_factor_summary(&account)?.any() {
                return Ok(Ok("password"));
            }
            let second = if !form.code.trim().is_empty() {
                check_totp(&state, &account, &form.code, crate::totp::now())?
            } else if !form.recovery_code.trim().is_empty() {
                check_recovery(&state, &account, &form.recovery_code)?
            } else {
                return Ok(Err("the second step is missing".into()));
            };
            Ok(match second {
                FactorCheck::Ok(_) => Ok("password+factor"),
                FactorCheck::Wrong(reason) => Err(reason),
            })
        })
        .await;
    let account = me_account(&admin, &token);
    match checked {
        Ok(Ok(Ok(how))) => {
            admin.logins.reset(&ip);
            let Some(rotated) = admin.rotate_session(&token, true) else {
                return StatusCode::UNAUTHORIZED.into_response();
            };
            auth_event(
                &admin,
                &account,
                &me_name(&admin, &rotated),
                "reauth.ok",
                &ip,
                how,
            );
            ok_body_with_cookie(
                json!({ "ok": true, "fresh_for": FRESH_FOR.as_secs() }),
                Some(rotated),
            )
        }
        Ok(Ok(Err(reason))) => {
            tracing::warn!(%ip, %reason, "a re-authentication was refused");
            auth_event(&admin, &account, "", "reauth.fail", &ip, &reason);
            let message = if with_passkey {
                super::security::PASSKEY_REFUSED
            } else {
                "That did not confirm it: check the password and the code."
            };
            bad_request(message)
        }
        Ok(Err(error)) => {
            tracing::error!(%error, "a re-authentication failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(error) => {
            tracing::error!(%error, "the re-authentication task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The account of a session, for the log.
fn me_account(admin: &Admin, token: &str) -> String {
    admin
        .sessions()
        .get(token)
        .map(|session| session.account.clone())
        .unwrap_or_default()
}

fn me_name(admin: &Admin, token: &str) -> String {
    admin
        .sessions()
        .get(token)
        .map(|session| session.user.username.clone())
        .unwrap_or_default()
}

/// After a change to how an account signs in: the account's other
/// sessions end, this one moves to a new token.
fn settle_sessions(admin: &Admin, account: &str, token: &str) -> Option<String> {
    admin.end_sessions_of_account(account, Some(token), None);
    admin.rotate_session(token, false)
}

/// New recovery codes when `account` just got its first second factor.
fn codes_for_first_factor(
    admin: &Admin,
    account: &str,
    had_factor: bool,
    ip: &str,
    actor: &str,
) -> anyhow::Result<Option<Vec<String>>> {
    if had_factor {
        return Ok(None);
    }
    let (codes, hashes) = crate::totp::new_recovery_codes(account)?;
    admin.db.replace_recovery_codes(account, &hashes)?;
    auth_event(
        admin,
        account,
        actor,
        "recovery.generated",
        ip,
        "with the first second factor",
    );
    Ok(Some(codes))
}

#[derive(Deserialize, Debug)]
pub(super) struct PasskeyNameForm {
    #[serde(default)]
    name: String,
}

fn check_passkey_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    let count = name.chars().count();
    if count == 0 || count > MAX_PASSKEY_NAME || name.chars().any(char::is_control) {
        return Err(format!(
            "a passkey name has 1 to {MAX_PASSKEY_NAME} characters, without control characters"
        ));
    }
    Ok(name.to_string())
}

/// `POST /admin/api/security/passkeys/options` (fresh): creation options
/// for a new passkey of the signed-in account.
pub(super) async fn passkey_create_options(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    headers: HeaderMap,
    Json(form): Json<PasskeyNameForm>,
) -> Response {
    let name = match check_passkey_name(&form.name) {
        Ok(name) => name,
        Err(message) => return bad_request(&message),
    };
    let Some(token) = session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(rp) = admin.relying_party(&headers) else {
        return bad_request("passkeys need a known host name");
    };
    let state = admin.clone();
    let made = tokio::task::spawn_blocking(
        move || -> anyhow::Result<Result<serde_json::Value, String>> {
            let account = me.account();
            let existing = state.db.credentials(&account)?;
            if existing.len() >= MAX_PASSKEYS {
                return Ok(Err(format!(
                    "an account holds at most {MAX_PASSKEYS} passkeys"
                )));
            }
            let handle = state.db.webauthn_user_handle(&account)?;
            let challenge = new_challenge().ok_or_else(|| anyhow::anyhow!("no randomness"))?;
            let exclude: Vec<serde_json::Value> = existing
                .iter()
                .filter(|credential| credential.rp_id == rp.id)
                .map(|credential| {
                    json!({
                        "type": "public-key",
                        "id": crate::webauthn::b64url_encode(&credential.credential_id),
                        "transports": credential.transports,
                    })
                })
                .collect();
            let params: Vec<serde_json::Value> = crate::webauthn::ALGORITHMS
                .iter()
                .map(|alg| json!({ "type": "public-key", "alg": alg }))
                .collect();
            let options = json!({
                "rp": { "id": rp.id, "name": "project-lore" },
                "user": {
                    "id": crate::webauthn::b64url_encode(&handle),
                    "name": me.username,
                    "displayName": format!("{} (lore)", me.username),
                },
                "challenge": crate::webauthn::b64url_encode(&challenge),
                "pubKeyCredParams": params,
                "timeout": REGISTRATION_TIMEOUT.as_millis() as u64,
                "excludeCredentials": exclude,
                "authenticatorSelection": {
                    "residentKey": "preferred",
                    "requireResidentKey": false,
                    "userVerification": "preferred",
                },
                "attestation": "none",
                "extensions": { "credProps": true },
            });
            let ceremony = Ceremony {
                challenge,
                kind: CeremonyKind::Register { name },
                bound_to: token,
                account: Some(account),
                rp,
                user_verification: false,
                allowed: Vec::new(),
                expires: Instant::now() + REGISTRATION_TIMEOUT + Duration::from_secs(30),
            };
            let id = insert_ceremony(&state, ceremony)
                .ok_or_else(|| anyhow::anyhow!("too many challenges"))?;
            Ok(Ok(json!({ "ceremony": id, "publicKey": options })))
        },
    )
    .await;
    match made {
        Ok(Ok(Ok(options))) => Json(options).into_response(),
        Ok(Ok(Err(message))) => bad_request(&message),
        Ok(Err(error)) => {
            tracing::warn!(%error, "making passkey creation options failed");
            too_many_requests(5)
        }
        Err(error) => {
            tracing::error!(%error, "the options task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// A body and the rotated session token to answer with.
type Answered = (serde_json::Value, Option<String>);

#[derive(Deserialize, Debug)]
pub(super) struct NewPasskeyForm {
    #[serde(default)]
    ceremony: String,
    #[serde(default)]
    credential: Option<serde_json::Value>,
}

/// `POST /admin/api/security/passkeys` (fresh): verifies and stores a new
/// passkey. The first second factor of an account comes with recovery
/// codes, shown once.
pub(super) async fn passkey_create(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(form): Json<NewPasskeyForm>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let Some(token) = session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<Result<Answered, (StatusCode, String)>> {
            let account = me.account();
            let Some(ceremony) = take_ceremony(&state, &form.ceremony, Some(&token), |kind| {
                matches!(kind, CeremonyKind::Register { .. })
            }) else {
                return Ok(Err((
                    StatusCode::BAD_REQUEST,
                    "the passkey request expired; try again".into(),
                )));
            };
            let CeremonyKind::Register { name } = &ceremony.kind else {
                return Ok(Err((
                    StatusCode::BAD_REQUEST,
                    "the passkey request expired; try again".into(),
                )));
            };
            if ceremony.account.as_deref() != Some(account.as_str()) {
                return Ok(Err((
                    StatusCode::BAD_REQUEST,
                    "the passkey request expired; try again".into(),
                )));
            }
            let Ok(response) = serde_json::from_value::<crate::webauthn::RegistrationJson>(
                form.credential.unwrap_or_default(),
            ) else {
                return Ok(Err((
                    StatusCode::BAD_REQUEST,
                    "the answer from the authenticator is malformed".into(),
                )));
            };
            let expected = crate::webauthn::Expected {
                challenge: &ceremony.challenge,
                origin: &ceremony.rp.origin,
                rp_id: &ceremony.rp.id,
                user_verification: false,
            };
            let registration = match crate::webauthn::verify_registration(&response, &expected) {
                Ok(registration) => registration,
                Err(crate::webauthn::Error::UnsupportedAlgorithm) => {
                    return Ok(Err((
                        StatusCode::BAD_REQUEST,
                        "this authenticator offers an algorithm lore does not accept".into(),
                    )));
                }
                Err(error) => {
                    tracing::warn!(%error, "a passkey registration was refused");
                    return Ok(Err((
                        StatusCode::BAD_REQUEST,
                        format!("the passkey could not be verified ({error})"),
                    )));
                }
            };
            if state.db.credential_id_taken(&registration.credential_id)? {
                return Ok(Err((
                    StatusCode::CONFLICT,
                    "this passkey is already registered".into(),
                )));
            }
            if state.db.credentials(&account)?.len() >= MAX_PASSKEYS {
                return Ok(Err((
                    StatusCode::BAD_REQUEST,
                    format!("an account holds at most {MAX_PASSKEYS} passkeys"),
                )));
            }
            let had_factor = state.db.second_factor_summary(&account)?.any();
            let stored = state.db.add_credential(&db::NewCredential {
                account: account.clone(),
                credential_id: registration.credential_id,
                rp_id: ceremony.rp.id.clone(),
                public_key: registration.public_key,
                alg: registration.alg,
                sign_count: registration.sign_count,
                uv_initialized: registration.user_verified,
                backup_eligible: registration.backup_eligible,
                backup_state: registration.backup_state,
                discoverable: registration.discoverable,
                transports: registration.transports,
                aaguid: registration.aaguid,
                attestation_fmt: registration.fmt,
                name: name.clone(),
            })?;
            auth_event(&state, &account, &me.username, "passkey.added", &ip, name);
            note_activity(
                &state,
                "users",
                &format!("{} added a passkey ({name})", me.username),
            );
            let codes = codes_for_first_factor(&state, &account, had_factor, &ip, &me.username)?;
            let rotated = settle_sessions(&state, &account, &token);
            let mut body = json!({ "passkey": passkey_json(&stored, Some(&ceremony.rp)) });
            if let Some(codes) = codes {
                body["recovery_codes"] = json!(codes);
            }
            Ok(Ok((body, rotated)))
        },
    )
    .await;
    match result {
        Ok(Ok(Ok((body, rotated)))) => ok_body_with_cookie(body, rotated),
        Ok(Ok(Err((status, message)))) => {
            (status, Json(json!({ "error": message }))).into_response()
        }
        Ok(Err(error)) => {
            tracing::error!(%error, "storing a passkey failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(error) => {
            tracing::error!(%error, "the passkey task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `PUT /admin/api/security/passkeys/{id}`: renames one of your passkeys.
pub(super) async fn passkey_rename(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(form): Json<PasskeyNameForm>,
) -> Response {
    let name = match check_passkey_name(&form.name) {
        Ok(name) => name,
        Err(message) => return bad_request(&message),
    };
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let rp = admin.relying_party(&headers);
    let state = admin.clone();
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<serde_json::Value>> {
            let account = me.account();
            let Some(credential) = state.db.rename_credential(&account, id, &name)? else {
                return Ok(None);
            };
            auth_event(
                &state,
                &account,
                &me.username,
                "passkey.renamed",
                &ip,
                &name,
            );
            Ok(Some(
                json!({ "passkey": passkey_json(&credential, rp.as_ref()) }),
            ))
        })
        .await;
    match result {
        Ok(Ok(Some(body))) => Json(body).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "renaming a passkey failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `DELETE /admin/api/security/passkeys/{id}` (fresh): removes one of your
/// passkeys. The last second factor takes the recovery codes with it.
pub(super) async fn passkey_delete(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let Some(token) = session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Option<String>>> {
        let account = me.account();
        let Some(name) = state.db.delete_credential(&account, id)? else {
            return Ok(None);
        };
        auth_event(
            &state,
            &account,
            &me.username,
            "passkey.removed",
            &ip,
            &name,
        );
        note_activity(
            &state,
            "users",
            &format!("{} removed a passkey ({name})", me.username),
        );
        Ok(Some(settle_sessions(&state, &account, &token)))
    })
    .await;
    match result {
        Ok(Ok(Some(rotated))) => ok_with_cookie(rotated),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "removing a passkey failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The name authenticator apps show: `LORE_TOTP_ISSUER`, or "lore (host)".
fn totp_issuer(admin: &Admin, headers: &HeaderMap) -> String {
    if let Some(issuer) = &admin.sign_in.totp_issuer {
        return issuer.clone();
    }
    match admin.relying_party(headers) {
        Some(rp) => {
            let host = rp
                .origin
                .split_once("://")
                .map_or(rp.id.clone(), |(_, host)| crate::oauth::host_name(host));
            format!("lore ({host})")
        }
        None => "lore".into(),
    }
}

/// `POST /admin/api/security/totp/setup` (fresh): a new secret for an
/// authenticator app, kept in the session until a code confirms it.
pub(super) async fn totp_setup(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    headers: HeaderMap,
) -> Response {
    let conflict =
        |message: &str| (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response();
    if admin.vault.is_none() {
        return conflict("the authenticator app needs LORE_VAULT_KEY; passkeys work without it");
    }
    let Some(token) = session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let account = me.account();
    match admin.db.totp(&account) {
        Ok(Some(_)) => return conflict("an authenticator app is already set up; remove it first"),
        Ok(None) => {}
        Err(error) => {
            tracing::error!(%error, "reading the authenticator app failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    let Ok(secret) = crate::totp::new_secret() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let uri = crate::totp::otpauth_uri(&totp_issuer(&admin, &headers), &me.username, &secret);
    let qr = match crate::totp::qr_data_url(&uri) {
        Ok(qr) => qr,
        Err(error) => {
            tracing::error!(%error, "making the QR code failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    {
        let mut sessions = admin.sessions();
        let Some(session) = sessions.get_mut(&token) else {
            return StatusCode::UNAUTHORIZED.into_response();
        };
        session.totp_setup = Some(TotpSetup {
            secret: secret.clone(),
            expires: Instant::now() + TOTP_SETUP_TTL,
            failures: 0,
        });
    }
    Json(json!({
        "secret": crate::totp::group_secret(&secret),
        "uri": uri,
        "qr": qr,
        "digits": crate::totp::DIGITS,
        "period": crate::totp::PERIOD,
        "expires_in": TOTP_SETUP_TTL.as_secs(),
    }))
    .into_response()
}

#[derive(Deserialize)]
pub(super) struct CodeForm {
    #[serde(default)]
    code: String,
}

impl std::fmt::Debug for CodeForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CodeForm { [redacted] }")
    }
}

/// `POST /admin/api/security/totp/confirm` (fresh): a code from the app
/// confirms the setup; the secret is stored encrypted with the vault key.
pub(super) async fn totp_confirm(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(form): Json<CodeForm>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let Some(token) = session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(vault) = admin.vault.clone() else {
        return bad_request("the authenticator app needs LORE_VAULT_KEY");
    };
    // Check the code against the pending secret, counting failures.
    let step = {
        let mut sessions = admin.sessions();
        let Some(session) = sessions.get_mut(&token) else {
            return StatusCode::UNAUTHORIZED.into_response();
        };
        let Some(setup) = session.totp_setup.as_mut() else {
            return bad_request("start the setup first");
        };
        if setup.expires <= Instant::now() {
            session.totp_setup = None;
            return bad_request("the setup expired; start again");
        }
        let key = crate::totp::decode_secret(&setup.secret).unwrap_or_default();
        match crate::totp::matching_step(&key, &form.code, crate::totp::now()) {
            Some(step) => (step, setup.secret.clone()),
            None => {
                setup.failures += 1;
                if setup.failures >= TOTP_SETUP_FAILURES {
                    session.totp_setup = None;
                    return bad_request(
                        "Wrong code five times; the setup was discarded. Start again.",
                    );
                }
                return bad_request("Wrong code. Check the time on the phone and try again.");
            }
        }
    };
    let (step, secret) = step;
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<(serde_json::Value, Option<String>)> {
            let account = me.account();
            let had_factor = state.db.second_factor_summary(&account)?.any();
            let (nonce, sealed) = vault.encrypt("totp", &account, &secret);
            // The confirming code's step counts as used: it cannot sign in.
            state.db.set_totp(&account, &nonce, &sealed, step)?;
            if let Some(session) = state.sessions().get_mut(&token) {
                session.totp_setup = None;
            }
            auth_event(&state, &account, &me.username, "totp.enabled", &ip, "");
            note_activity(
                &state,
                "users",
                &format!("{} set up an authenticator app", me.username),
            );
            let codes = codes_for_first_factor(&state, &account, had_factor, &ip, &me.username)?;
            let rotated = settle_sessions(&state, &account, &token);
            let mut body = json!({ "ok": true });
            if let Some(codes) = codes {
                body["recovery_codes"] = json!(codes);
            }
            Ok((body, rotated))
        },
    )
    .await;
    match result {
        Ok(Ok((body, rotated))) => ok_body_with_cookie(body, rotated),
        Ok(Err(error)) => {
            tracing::error!(%error, "storing the authenticator app failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(error) => {
            tracing::error!(%error, "the authenticator app task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `DELETE /admin/api/security/totp` (fresh): removes your authenticator
/// app.
pub(super) async fn totp_delete(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let Some(token) = session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Option<String>>> {
        let account = me.account();
        if !state.db.delete_totp(&account)? {
            return Ok(None);
        }
        auth_event(&state, &account, &me.username, "totp.removed", &ip, "");
        note_activity(
            &state,
            "users",
            &format!("{} removed their authenticator app", me.username),
        );
        Ok(Some(settle_sessions(&state, &account, &token)))
    })
    .await;
    match result {
        Ok(Ok(Some(rotated))) => ok_with_cookie(rotated),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "removing the authenticator app failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `POST /admin/api/security/recovery-codes` (fresh): ten new recovery
/// codes; the old ones stop working.
pub(super) async fn recovery_codes(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let Some(token) = session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<Option<(Vec<String>, Option<String>)>> {
            let account = me.account();
            let summary = state.db.second_factor_summary(&account)?;
            if summary.passkeys == 0 && !summary.totp {
                return Ok(None);
            }
            let (codes, hashes) = crate::totp::new_recovery_codes(&account)?;
            state.db.replace_recovery_codes(&account, &hashes)?;
            auth_event(
                &state,
                &account,
                &me.username,
                "recovery.generated",
                &ip,
                "",
            );
            note_activity(
                &state,
                "users",
                &format!("{} made new recovery codes", me.username),
            );
            Ok(Some((codes, settle_sessions(&state, &account, &token))))
        },
    )
    .await;
    match result {
        Ok(Ok(Some((codes, rotated)))) => ok_body_with_cookie(json!({ "codes": codes }), rotated),
        Ok(Ok(None)) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "recovery codes come with a passkey or an authenticator app; set one up first" })),
        )
            .into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "making recovery codes failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `DELETE /admin/api/users/{id}/second-factors` (fresh): removes every
/// passkey, the app and the recovery codes of a user you may manage; their
/// sessions end. Your own are managed in your Security section.
pub(super) async fn reset_user_factors(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if me.user_id == Some(id) {
        return bad_request("manage your own second steps in your Security section");
    }
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<UserChange<()>> {
        let Some(user) = state.db.user(id)? else {
            return Ok(UserChange::Missing);
        };
        if let Err(message) = may_manage(&me, &user) {
            return Ok(UserChange::Forbidden(message));
        }
        let account = db::user_account(id);
        state.db.reset_second_factors(&account)?;
        state.end_sessions_of_account(&account, None, None);
        auth_event(
            &state,
            &account,
            &me.username,
            "second_factors.reset",
            &ip,
            "",
        );
        note_activity(
            &state,
            "users",
            &format!(
                "{} reset the second factors of {}",
                me.username, user.username
            ),
        );
        Ok(UserChange::Done(()))
    })
    .await;
    match result {
        Ok(Ok(UserChange::Done(()))) => Json(json!({ "ok": true })).into_response(),
        Ok(Ok(UserChange::Missing)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Ok(UserChange::Forbidden(message))) => forbidden(&message),
        Ok(Ok(UserChange::Invalid(message))) => bad_request(&message),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "resetting second factors failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `DELETE /admin/api/builtin-users/{name}/second-factors` (fresh): the
/// same for a built-in user: the viewer's with `users`, admin's only by
/// admin itself.
pub(super) async fn reset_builtin_factors(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Err(refusal) = super::security::may_manage_builtin(&admin, &me, &name) {
        return super::security::builtin_refusal(refusal);
    }
    let ip = client_ip(&headers, Some(peer), admin.trust_proxy);
    let keep = session_token(&headers).filter(|_| me.user_id.is_none() && me.username == name);
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<String>> {
        state.db.reset_second_factors(&name)?;
        state.end_sessions_of_account(&name, keep.as_deref(), None);
        let rotated = keep.and_then(|keep| state.rotate_session(&keep, false));
        auth_event(&state, &name, &me.username, "second_factors.reset", &ip, "");
        note_activity(
            &state,
            "users",
            &format!("{} reset the second factors of {name}", me.username),
        );
        Ok(rotated)
    })
    .await;
    match result {
        Ok(Ok(rotated)) => ok_with_cookie(rotated),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "resetting second factors failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize, Debug)]
pub(super) struct EventsQuery {
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

/// `GET /admin/api/auth-events`: the sign-in log, of one account or all.
pub(super) async fn auth_events(
    State(admin): State<Arc<Admin>>,
    Query(query): Query<EventsQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let account = query.account.filter(|account| !account.is_empty());
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        Ok(json!({ "events": state.db.auth_events(account.as_deref(), limit)? }))
    })
    .await;
    respond(result)
}
