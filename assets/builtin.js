/* Built-in agents: the section at the top of the Agents panel. Shows each
   built-in agent's runner (connected, CLI version, signed in, when the
   sign-in ends) and, for the agents permission, signs it in and out and
   sets its model, its switches, its daily cap and its active hours.

   Pasted credentials go straight to the server, which hands them to the
   agent's container; the fields are cleared at once and nothing is kept
   in the page. Self-contained: it watches the Agents panel and draws into
   #builtin-section, so the rest of the page does not know about it. */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const section = $("builtin-section");
  const panel = $("agents-panel");
  if (!section || !panel) return;

  const ui = {
    data: null,
    /* Which credential form is open, per agent. */
    credential: {},
    /* Unsaved settings, per agent, so a refresh does not lose them. */
    drafts: {},
    poll: null,
    busy: new Set(),
  };

  const KIND_LABEL = { claude: "Claude Code", codex: "Codex", opencode: "opencode" };
  const METHOD_LABEL = {
    device: "Sign in with ChatGPT (device code)",
    interactive: "Sign in with claude.ai",
  };
  const CREDENTIAL_HELP = {
    setup_token: "Run claude setup-token on your own computer and paste the token it prints (valid for a year).",
    auth_json: "Paste the contents of an auth.json from a computer where you signed Codex in (~/.codex/auth.json).",
    api_key: "Paste the API key.",
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function status(text, tone) {
    const node = $("builtin-status");
    node.textContent = text || "";
    node.className = "small-text" + (tone ? " " + tone : "");
  }

  function ago(iso) {
    if (!iso) return "never";
    const seconds = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
    if (seconds < 90) return "just now";
    if (seconds < 5400) return `${Math.round(seconds / 60)} min ago`;
    if (seconds < 129600) return `${Math.round(seconds / 3600)} h ago`;
    return `${Math.round(seconds / 86400)} days ago`;
  }

  function day(iso) {
    const date = new Date(iso);
    return isNaN(date) ? iso : date.toISOString().slice(0, 10);
  }

  function bytes(value) {
    if (value === null || value === undefined) return "";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let n = value, unit = 0;
    while (n >= 1024 && unit < units.length - 1) { n /= 1024; unit += 1; }
    return `${n.toFixed(n < 10 && unit ? 1 : 0)} ${units[unit]}`;
  }

  async function call(path, options) {
    const response = await fetch(path, { credentials: "same-origin", ...options });
    const body = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, body };
  }

  function post(path, payload) {
    return call(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload || {}),
    });
  }

  function url(name, suffix) {
    return "/admin/api/builtin/" + encodeURIComponent(name) + (suffix || "");
  }

  /* Puts one agent's fresh view in place of the old one. */
  function replaceAgent(agent) {
    if (!ui.data || !agent) return;
    ui.data.agents = ui.data.agents.map((old) => (old.name === agent.name ? agent : old));
  }

  async function load() {
    let result;
    try {
      result = await call("/admin/api/builtin");
    } catch (_) {
      return;
    }
    if (!result.ok) return;
    ui.data = result.body;
    section.hidden = !ui.data.configured;
    if (!ui.data.configured) return;
    render();
    schedule();
  }

  /* Polls while a sign-in waits for the owner, and slowly otherwise. */
  function schedule() {
    clearTimeout(ui.poll);
    if (panel.hidden || !ui.data || !ui.data.configured) return;
    const waiting = ui.data.agents.some((agent) => agent.login && ["starting", "waiting"].includes(agent.login.state));
    ui.poll = setTimeout(load, waiting ? 3000 : 30000);
  }

  function render() {
    // Not while the owner types in the section: the next poll draws it.
    if (section.contains(document.activeElement) && document.activeElement.tagName !== "BUTTON") return;
    const list = $("builtin-list");
    list.replaceChildren();
    for (const agent of ui.data.agents) list.append(card(agent));
    const connected = ui.data.agents.filter((agent) => agent.connected).length;
    $("builtin-count").textContent = `${connected} of ${ui.data.agents.length} connected`;
  }

  function pill(text, className) {
    return el("span", "pill " + className, text);
  }

  function card(agent) {
    const manage = ui.data.manage;
    const item = el("li", "board-item agent-card builtin-card" + (agent.connected ? "" : " offline"));
    const head = el("div", "board-item-head agent-head");
    const image = el("img", "builtin-avatar");
    image.src = `/admin/avatars/${encodeURIComponent(agent.avatar)}.svg`;
    image.alt = "";
    head.append(image, el("span", "board-title", agent.name));
    const kind = (KIND_LABEL[agent.kind] || "unknown CLI") + (agent.kind === "opencode" && agent.provider ? ` · ${agent.provider}` : "");
    head.append(pill(kind, "token"));
    head.append(agent.connected ? pill("connected", "open") : pill("not connected", "closed"));
    head.append(agent.signed_in ? pill("signed in", "open") : pill("not signed in", "implicit"));
    if (agent.enabled) head.append(pill("enabled", "oauth"));
    item.append(head);

    const lines = [];
    if (agent.connected) {
      lines.push(`Runner connected ${ago(agent.connected_at)}` + (agent.cli_version ? ` · ${agent.cli_version}` : ""));
    } else {
      lines.push(agent.last_seen_at
        ? `Its container was last connected ${ago(agent.last_seen_at)}.`
        : "Its container has not connected yet: start it with docker compose --profile agents up -d.");
    }
    if (agent.signed_in) {
      let line = `Signed in${agent.login_method ? " with " + agent.login_method : ""}`;
      if (agent.login_ends) line += ` · ends ${day(agent.login_ends)}`;
      if (agent.status_at) line += ` · checked ${ago(agent.status_at)}`;
      lines.push(line);
    }
    const resources = agent.resources;
    if (resources) {
      const parts = [];
      if (resources.load !== null && resources.load !== undefined) parts.push(`load ${resources.load.toFixed(2)}`);
      if (resources.mem_used_bytes) parts.push(`memory ${bytes(resources.mem_used_bytes)}` + (resources.mem_limit_bytes ? ` of ${bytes(resources.mem_limit_bytes)}` : ""));
      if (resources.work_free_bytes) parts.push(`${bytes(resources.work_free_bytes)} free for work`);
      if (parts.length) lines.push(parts.join(" · "));
    }
    for (const line of lines) item.append(el("div", "board-meta", line));
    if (agent.status_detail) item.append(el("pre", "builtin-detail", agent.status_detail));

    const box = el("dl", "agent-stats");
    const stat = (label, value) => box.append(el("dt", "", label), el("dd", "", value));
    stat("Model", agent.model || "the CLI's default");
    stat("Board tasks", agent.enabled ? `up to ${agent.daily_cap} a day` + (agent.active_hours ? `, ${agent.active_hours} UTC` : "") : "off");
    stat("Help for other agents", agent.available ? "available" : "off");
    item.append(box);

    if (!manage) return item;
    if (agent.login) item.append(loginBox(agent));
    item.append(signInActions(agent));
    if (ui.credential[agent.name]) item.append(credentialForm(agent, ui.credential[agent.name]));
    item.append(settingsForm(agent));
    return item;
  }

  function button(text, className, onClick) {
    const node = el("button", "ghost small" + (className ? " " + className : ""), text);
    node.type = "button";
    node.addEventListener("click", onClick);
    return node;
  }

  /* What the owner must do to finish an interactive sign-in. */
  function loginBox(agent) {
    const login = agent.login;
    const box = el("div", "builtin-login " + login.state);
    if (login.state === "starting") box.append(el("p", "", "Starting the sign-in…"));
    if (login.state === "waiting") {
      if (login.url) {
        const step = el("p", "");
        step.append(document.createTextNode("1. Open "));
        const link = el("a", "", login.url);
        link.href = login.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        step.append(link);
        step.append(document.createTextNode(" and sign in with your own account."));
        box.append(step);
      }
      if (login.code) {
        box.append(el("p", "", "2. Enter this one-time code there:"));
        box.append(el("p", "builtin-code", login.code));
        box.append(el("p", "muted small-text", "Device code sign-in must be allowed in your ChatGPT security settings. This page notices when it is done."));
      }
      if (login.needs_code) {
        const form = el("form", "board-form builtin-inline");
        form.autocomplete = "off";
        const field = el("input");
        field.type = "password";
        field.autocomplete = "off";
        field.spellcheck = false;
        field.placeholder = "2. Paste the code the page shows";
        field.setAttribute("aria-label", "Sign-in code");
        const send = el("button", "ghost small", "Send code");
        send.type = "submit";
        form.append(field, send);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          const code = field.value;
          field.value = "";
          if (!code.trim()) return;
          send.disabled = true;
          const result = await post(url(agent.name, "/login/code"), { code }).catch(() => null);
          send.disabled = false;
          if (!result || !result.ok) {
            status((result && result.body.error) || "The code could not be passed on.", "bad");
            return;
          }
          status("Code sent; waiting for the sign-in to finish…", "ok");
          replaceAgent(result.body.agent);
          render();
          schedule();
        });
        box.append(form);
      }
      if (!login.url && login.message) box.append(el("pre", "builtin-detail", login.message));
    }
    if (login.state === "done") box.append(el("p", "ok", "Signed in."));
    if (login.state === "failed") {
      box.append(el("p", "bad", "The sign-in did not finish."));
      if (login.message) box.append(el("pre", "builtin-detail", login.message));
    }
    const actions = el("div", "board-actions");
    const open = ["starting", "waiting"].includes(login.state);
    actions.append(button(open ? "Cancel sign-in" : "Dismiss", "", async () => {
      const result = await post(url(agent.name, "/login/cancel")).catch(() => null);
      if (result && result.ok) replaceAgent(result.body.agent);
      await load();
    }));
    box.append(actions);
    return box;
  }

  function signInActions(agent) {
    const actions = el("div", "board-actions builtin-actions");
    const busy = ui.busy.has(agent.name);
    const add = (node) => { node.disabled = busy || !agent.connected; actions.append(node); };
    for (const method of agent.methods || []) {
      add(button(METHOD_LABEL[method] || "Sign in", "", () => startLogin(agent, method)));
    }
    for (const credential of agent.credentials || []) {
      add(button(`Paste ${credential.label}`, "", () => {
        ui.credential[agent.name] = ui.credential[agent.name] === credential.id ? undefined : credential.id;
        render();
      }));
    }
    add(button("Check", "", () => refreshAgent(agent)));
    if (agent.signed_in) add(button("Sign out", "danger", () => signOut(agent)));
    return actions;
  }

  async function withBusy(agent, work) {
    ui.busy.add(agent.name);
    render();
    try {
      await work();
    } finally {
      ui.busy.delete(agent.name);
      render();
      schedule();
    }
  }

  function startLogin(agent, method) {
    return withBusy(agent, async () => {
      status(`Starting the sign-in of ${agent.name}…`);
      const result = await post(url(agent.name, "/login"), { method }).catch(() => null);
      if (!result || !result.ok) {
        status((result && result.body.error) || "The sign-in could not be started.", "bad");
        await load();
        return;
      }
      status("");
      replaceAgent(result.body.agent);
    });
  }

  function refreshAgent(agent) {
    return withBusy(agent, async () => {
      status(`Asking ${agent.name}…`);
      const result = await post(url(agent.name, "/refresh")).catch(() => null);
      if (!result || !result.ok) {
        status((result && result.body.error) || `${agent.name} did not answer.`, "bad");
        return;
      }
      replaceAgent(result.body.agent);
      status(`${agent.name} is ${result.body.agent.signed_in ? "signed in" : "not signed in"}.`, "ok");
    });
  }

  function signOut(agent) {
    if (!window.confirm(`Sign ${agent.name} out?\n\nIts stored sign-in is removed from its container's volume.`)) return;
    return withBusy(agent, async () => {
      const result = await post(url(agent.name, "/logout")).catch(() => null);
      if (!result || !result.ok) {
        status((result && result.body.error) || "Signing out failed.", "bad");
        return;
      }
      replaceAgent(result.body.agent);
      status(`${agent.name} is signed out.`, "ok");
    });
  }

  /* One pasted credential. The value goes to the server once and the field
     is emptied whatever happens. */
  function credentialForm(agent, kind) {
    const credential = (agent.credentials || []).find((c) => c.id === kind);
    const form = el("form", "board-form builtin-credential");
    form.autocomplete = "off";
    const label = el("label", "board-field");
    let field;
    if (kind === "auth_json") {
      field = el("textarea");
      field.rows = 4;
    } else {
      field = el("input");
      field.type = "password";
    }
    field.autocomplete = "off";
    field.spellcheck = false;
    label.append(el("span", "", (credential ? credential.label : kind) + " for " + agent.name), field);
    form.append(label, el("p", "muted small-text", CREDENTIAL_HELP[kind] + " It is stored only in the agent's own volume, never in lore."));
    const actions = el("div", "board-actions");
    actions.append(button("Cancel", "", () => { ui.credential[agent.name] = undefined; render(); }));
    const save = el("button", "ghost small", "Store");
    save.type = "submit";
    actions.append(save);
    form.append(actions);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = field.value;
      field.value = "";
      if (!value.trim()) return;
      save.disabled = true;
      const result = await post(url(agent.name, "/credential"), { credential: kind, value }).catch(() => null);
      save.disabled = false;
      if (!result || !result.ok) {
        status((result && result.body.error) || "The credential could not be stored.", "bad");
        return;
      }
      ui.credential[agent.name] = undefined;
      replaceAgent(result.body.agent);
      status(`Stored in ${agent.name}'s volume; it is ${result.body.agent.signed_in ? "signed in" : "not signed in yet"}.`, "ok");
      document.activeElement && document.activeElement.blur();
      render();
    });
    return form;
  }

  function settingsForm(agent) {
    const draft = ui.drafts[agent.name] || {};
    const value = (key) => (key in draft ? draft[key] : agent[key]);
    const form = el("form", "board-form builtin-settings");
    form.autocomplete = "off";
    const remember = (key, read) => (event) => {
      ui.drafts[agent.name] = { ...(ui.drafts[agent.name] || {}), [key]: read(event.target) };
    };

    const model = el("input");
    model.type = "text";
    model.maxLength = 100;
    model.spellcheck = false;
    model.value = value("model");
    model.placeholder = "the CLI's default";
    const listId = "builtin-models-" + agent.name.replace(/[^a-z0-9_-]/gi, "");
    model.setAttribute("list", listId);
    const options = el("datalist");
    options.id = listId;
    for (const id of (agent.models && agent.models.models) || []) {
      const option = el("option");
      option.value = id;
      options.append(option);
    }
    model.addEventListener("input", remember("model", (node) => node.value));
    const modelField = el("label", "board-field");
    const source = agent.models && agent.models.source === "cli" ? "listed by the CLI" : "pick one or type a name";
    modelField.append(el("span", "", `Default model (${source})`), model, options);

    const check = (key, text) => {
      const label = el("label", "builtin-check");
      const box = el("input");
      box.type = "checkbox";
      box.checked = Boolean(value(key));
      box.addEventListener("change", remember(key, (node) => node.checked));
      label.append(box, el("span", "", text));
      return label;
    };

    const cap = el("input");
    cap.type = "number";
    cap.min = "0";
    cap.max = String(ui.data.max_daily_cap || 100);
    cap.value = String(value("daily_cap"));
    cap.addEventListener("input", remember("daily_cap", (node) => node.value));
    const capField = el("label", "board-field");
    capField.append(el("span", "", "Board tasks a day"), cap);

    const hours = el("input");
    hours.type = "text";
    hours.maxLength = 11;
    hours.placeholder = "always, or 08:00-20:00";
    hours.value = value("active_hours");
    hours.addEventListener("input", remember("active_hours", (node) => node.value));
    const hoursField = el("label", "board-field");
    hoursField.append(el("span", "", "Active hours (UTC)"), hours);

    const row = el("div", "builtin-row");
    row.append(capField, hoursField);
    const checks = el("div", "builtin-row");
    checks.append(check("enabled", "Works on idle board tasks"), check("available", "Available to help other agents"));

    const actions = el("div", "board-actions");
    const save = el("button", "ghost small", "Save settings");
    save.type = "submit";
    actions.append(save);
    form.append(modelField, checks, row, actions);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const payload = {
        model: model.value.trim(),
        enabled: form.querySelectorAll("input[type=checkbox]")[0].checked,
        available: form.querySelectorAll("input[type=checkbox]")[1].checked,
        daily_cap: Number.parseInt(cap.value, 10) || 0,
        active_hours: hours.value.trim(),
      };
      save.disabled = true;
      const result = await call(url(agent.name), {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }).catch(() => null);
      save.disabled = false;
      if (!result || !result.ok) {
        status((result && result.body.error) || "The settings could not be saved.", "bad");
        return;
      }
      delete ui.drafts[agent.name];
      replaceAgent(result.body.agent);
      status(`Saved ${agent.name}.`, "ok");
      document.activeElement && document.activeElement.blur();
      render();
    });
    return form;
  }

  /* Loads when the Agents panel opens; stops polling when it closes. */
  new MutationObserver(() => {
    if (panel.hidden) {
      clearTimeout(ui.poll);
      ui.credential = {};
      status("");
    } else {
      load();
    }
  }).observe(panel, { attributes: true, attributeFilter: ["hidden"] });
})();
