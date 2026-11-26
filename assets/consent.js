"use strict";

/* project-lore consent page: an application asks to connect as an agent;
   the user signs in (same endpoint and throttling as the admin view),
   names the agent, picks an avatar and approves or denies. Everything the
   application said about itself is shown with textContent only. */

const $ = (id) => document.getElementById(id);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

const REQUEST = (document.querySelector('meta[name="lore-request"]') || {}).content || "";
const state = { siteKey: null, data: null, csrf: "", avatar: "" };

function show(id) {
  for (const section of ["consent-loading", "consent-login", "consent-card", "consent-message"]) {
    $(section).hidden = section !== id;
  }
}

function message(title, text, options) {
  $("message-title").textContent = title;
  $("message-text").textContent = text;
  $("message-signout").hidden = !(options && options.signout);
  $("message-deny").hidden = !(options && options.deny);
  show("consent-message");
}

function loadRecaptcha(siteKey) {
  if (!siteKey || document.querySelector("script[data-recaptcha]")) return;
  const script = document.createElement("script");
  script.src = "https://www.google.com/recaptcha/api.js?render=" + encodeURIComponent(siteKey);
  script.async = true;
  script.dataset.recaptcha = "1";
  document.head.appendChild(script);
  $("captcha-note").hidden = false;
}

function captchaToken() {
  if (!state.siteKey) return Promise.resolve("");
  return new Promise((resolve, reject) => {
    if (!window.grecaptcha) return reject(new Error("reCAPTCHA has not loaded yet. Try again in a moment."));
    window.grecaptcha.ready(() => {
      window.grecaptcha.execute(state.siteKey, { action: "login" }).then(resolve, reject);
    });
  });
}

function showLogin() {
  show("consent-login");
  $("password").value = "";
  if ($("username").value) $("password").focus(); else $("username").focus();
}

$("consent-login").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("login-button"), error = $("login-error");
  button.disabled = true; error.textContent = "";
  try {
    const captcha = await captchaToken();
    const response = await fetch("/admin/api/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: $("username").value.trim(), password: $("password").value, captcha }),
    });
    if (response.ok) {
      $("password").value = "";
      await loadRequest();
    } else if (response.status === 429) {
      const wait = Number(response.headers.get("Retry-After")) || 60;
      error.textContent = `Too many attempts. Try again in ${Math.ceil(wait / 60)} min.`;
    } else {
      const body = await response.json().catch(() => ({}));
      error.textContent = body.error || "Sign-in failed.";
    }
  } catch (problem) {
    error.textContent = problem.message || "Sign-in failed.";
  } finally {
    button.disabled = false;
  }
});

async function signOut() {
  await fetch("/admin/api/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
  showLogin();
}
$("message-signout").addEventListener("click", signOut);

/* The request as the server checked it, and this page's one-time token. */
async function loadRequest() {
  show("consent-loading");
  let response;
  try {
    response = await fetch("/admin/api/oauth/requests/" + encodeURIComponent(REQUEST), { credentials: "same-origin" });
  } catch (_) {
    message("Lore cannot be reached", "Check the connection and reload this page.");
    return;
  }
  if (response.status === 401) { showLogin(); return; }
  const body = await response.json().catch(() => ({}));
  if (response.status === 403 && body.permission === false) {
    state.csrf = body.csrf || "";
    message("Not allowed", body.error || "This user cannot authorize agents.", { signout: true, deny: !!state.csrf });
    return;
  }
  if (!response.ok) {
    message("This request cannot be answered", body.error || "Start again from the application.");
    return;
  }
  state.data = body;
  state.csrf = body.csrf;
  render();
}

function render() {
  const data = state.data;
  $("consent-user").textContent = data.username;
  $("client-name").textContent = data.client_name ? `“${data.client_name}”` : "an application that gave no name";
  $("redirect-uri").textContent = data.redirect_uri;

  const grants = $("grant-list");
  grants.replaceChildren();
  grants.append(el("li", "", "Read and write the shared memory: search, log, amend and delete entries."));
  grants.append(el("li", "", "Read and write the board (tasks, messages, handoff notes) and the project files."));
  if (data.services_off) {
    // The approver lacks `integrations`: the server writes level off for
    // every service the agent has no level for yet.
    grants.append(el("li", "services",
      "No access to the services (Cloudflare, GitHub, GitLab, Dokploy), configured now or later: you do not hold " +
      "the integrations permission, so the agent gets level off on every service it has no level for yet. " +
      "Someone with that permission can raise it in the Integrations panel."));
  } else if (data.services.length) {
    const item = el("li", "services");
    item.append(el("span", "", "Full access to every configured service: "));
    const names = el("b", "", data.services.join(", "));
    item.append(names);
    item.append(el("span", "", ". Lower it per agent in the Integrations panel of the admin view."));
    if (!data.services_enabled) item.append(el("span", "muted", " (Agents may not operate services right now: the switch is off.)"));
    grants.append(item);
  } else {
    grants.append(el("li", "", "Full access to every service configured later, unless its level is lowered in the admin view. None is configured now."));
  }
  if (data.mailbox) {
    grants.append(el("li", "", "Not the mailbox: a new agent cannot look at it until someone with the integrations permission sets its mail level to read."));
  }

  const select = $("existing-agent");
  select.replaceChildren();
  for (const agent of data.existing) {
    const option = el("option", "", agent.disabled ? `${agent.name} (disabled)` : agent.name);
    option.value = agent.name;
    option.disabled = agent.disabled;
    option.dataset.avatar = agent.avatar;
    select.append(option);
  }
  $("mode-existing-choice").hidden = !data.existing.length;
  $("agent-name").value = data.suggested_name;
  state.avatar = data.suggested_avatar;
  renderAvatars();
  syncMode();
  show("consent-card");
  $("agent-name").focus();
}

function renderAvatars() {
  const picker = $("avatar-picker");
  picker.replaceChildren();
  for (const id of state.data.avatars) {
    const button = el("button", "avatar-choice" + (id === state.avatar ? " picked" : ""));
    button.type = "button";
    button.setAttribute("role", "radio");
    button.setAttribute("aria-checked", String(id === state.avatar));
    button.setAttribute("aria-label", id);
    button.title = id;
    const image = el("img");
    image.src = `/admin/avatars/${id}.svg`;
    image.alt = "";
    image.width = 44; image.height = 44;
    button.append(image);
    button.addEventListener("click", () => { state.avatar = id; renderAvatars(); });
    picker.append(button);
  }
}

function mode() {
  const picked = document.querySelector('input[name="mode"]:checked');
  return picked ? picked.value : "new";
}

function syncMode() {
  const existing = mode() === "existing";
  $("name-field").hidden = existing;
  $("agent-name").required = !existing;
  $("existing-field").hidden = !existing;
  if (existing) {
    const option = $("existing-agent").selectedOptions[0];
    if (option && option.dataset.avatar) { state.avatar = option.dataset.avatar; renderAvatars(); }
  }
}
for (const radio of document.querySelectorAll('input[name="mode"]')) radio.addEventListener("change", syncMode);
$("existing-agent").addEventListener("change", syncMode);

/* The server answers with the URL to go back to; following it hands the
   result to the application. */
function goBack(url, title, text) {
  message(title, text);
  window.location.assign(url);
}

$("consent-card").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = $("consent-error");
  error.textContent = "";
  const existing = mode() === "existing";
  const name = existing ? $("existing-agent").value : $("agent-name").value.trim().toLowerCase();
  if (!name) { error.textContent = existing ? "Pick an agent." : "Name the agent."; return; }
  $("approve").disabled = true; $("deny").disabled = true;
  try {
    const response = await fetch(`/admin/api/oauth/requests/${encodeURIComponent(REQUEST)}/approve`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ csrf: state.csrf, mode: existing ? "existing" : "new", name, avatar: state.avatar }),
    });
    const body = await response.json().catch(() => ({}));
    if (response.status === 401) { showLogin(); return; }
    if (!response.ok || !body.redirect) {
      error.textContent = body.error || "The approval failed.";
      return;
    }
    goBack(body.redirect, "Approved", `The agent ${body.agent} is authorized. The application takes it from here; you can close this window.`);
  } catch (_) {
    error.textContent = "The approval failed. Check the connection and try again.";
  } finally {
    $("approve").disabled = false; $("deny").disabled = false;
  }
});

async function deny() {
  try {
    const response = await fetch(`/admin/api/oauth/requests/${encodeURIComponent(REQUEST)}/deny`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ csrf: state.csrf }),
    });
    const body = await response.json().catch(() => ({}));
    if (response.status === 401) { showLogin(); return; }
    if (!response.ok || !body.redirect) {
      message("This request cannot be answered", body.error || "Start again from the application.");
      return;
    }
    goBack(body.redirect, "Denied", "The application was told no. You can close this window.");
  } catch (_) {
    $("consent-error").textContent = "Denying failed. Check the connection and try again.";
  }
}
$("deny").addEventListener("click", deny);
$("message-deny").addEventListener("click", deny);

(async () => {
  if (!/^[A-Za-z0-9_-]{43}$/.test(REQUEST)) {
    message("This request cannot be answered", "Start again from the application.");
    return;
  }
  try {
    const session = await (await fetch("/admin/api/session", { credentials: "same-origin" })).json();
    state.siteKey = session.recaptcha_site_key;
    loadRecaptcha(state.siteKey);
    if (session.authenticated) await loadRequest(); else showLogin();
  } catch (_) {
    message("Lore cannot be reached", "Check the connection and reload this page.");
  }
})();
