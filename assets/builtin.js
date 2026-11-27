/* Built-in agents: the section at the top of the Agents panel. Shows each
   built-in agent's runner (connected, CLI version, signed in, when the
   sign-in ends) and, for the agents permission, signs it in and out and
   sets its model, its switches, its daily cap and its active hours.

   Pasted credentials go straight to the server, which hands them to the
   agent's container; the fields are cleared at once and nothing is kept
   in the page. Self-contained: it watches the Agents panel and draws into
   #builtin-section, so the rest of the page does not know about it.

   With the agents permission, a connected agent also opens a terminal: the
   CLI's own interface, or (behind "More") a shell, from its card or from
   the terminal icon in Live activity's head. It is shown in a floating
   window holding /admin/terminal in a frame, a document with its own
   policy because xterm.js writes inline styles. The window is moved by its
   bar and resized by its edges and corner grip; its size and place are
   remembered per browser, Expand fills the page and a double-click on the
   bar puts it back where it starts. Under 700px wide it takes the whole
   width at the bottom and only its height changes. Every key, Escape too,
   belongs to the terminal, so the window closes only with Close. */
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
  /* The agent's persistent volume holds only its sign-in and a week of
     conversation transcripts (50 MiB each at most): above this, say so. */
  const STATE_WARN_BYTES = 512 * 1024 * 1024;
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

  /* The name the page shows: the owner's display name, else the
     technical one (which every request and record keeps using). */
  function shown(agent) {
    return (agent && (agent.display_name || agent.name)) || "";
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
    ui.poll = setTimeout(() => { load(); if (!waiting) loadRunner(); }, waiting ? 3000 : 30000);
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
    const title = el("span", "board-title", shown(agent));
    if (agent.display_name) title.append(el("small", "agent-tech", agent.name));
    head.append(image, title);
    const kind = (KIND_LABEL[agent.kind] || "unknown CLI") + (agent.kind === "opencode" && agent.provider ? ` · ${agent.provider}` : "");
    head.append(pill(kind, "token"));
    head.append(agent.connected ? pill("connected", "open") : pill("not connected", "closed"));
    head.append(agent.signed_in ? pill("signed in", "open") : pill("not signed in", "implicit"));
    if (agent.enabled) head.append(pill("enabled", "oauth"));
    if (agent.second_runner) head.append(pill("second runner refused", "closed"));
    item.append(head);
    if (agent.second_runner) {
      const seen = agent.second_runner;
      item.append(el("p", "builtin-warning",
        `A second runner tried to connect as ${agent.name} from ${seen.address} ${ago(seen.at)}`
        + (seen.count > 1 ? ` (${seen.count} times)` : "")
        + " while its own runner was connected, and was refused. Its runner secret may have leaked:"
        + " generate a new one and restart its container."));
    }

    const lines = [];
    if (agent.connected) {
      lines.push(`Runner connected ${ago(agent.connected_at)}` + (agent.cli_version ? ` · ${agent.cli_version}` : ""));
    } else {
      lines.push(agent.last_seen_at
        ? `Its container was last connected ${ago(agent.last_seen_at)}.`
        : "Its container has not connected yet: start it with docker compose -f docker-compose.agents.yml up -d.");
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
      if (resources.state_bytes !== null && resources.state_bytes !== undefined) parts.push(`volume ${bytes(resources.state_bytes)}`);
      if (resources.state_free_bytes) parts.push(`${bytes(resources.state_free_bytes)} free on the volume`);
      if (resources.cleaned) parts.push(`cleaned ${resources.cleaned} leftover item${resources.cleaned === 1 ? "" : "s"}`);
      if (parts.length) lines.push(parts.join(" · "));
    }
    for (const line of lines) item.append(el("div", "board-meta", line));
    if (resources && resources.state_bytes > STATE_WARN_BYTES) {
      item.append(el("p", "builtin-warning",
        `Its volume holds ${bytes(resources.state_bytes)}: more than the stored sign-in and a week of`
        + " conversation transcripts should need. Look at the container's /var/lib/lore-runner."));
    }
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
    if (agent.connected) item.append(terminalActions(agent));
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
      if (login.url && login.url_host) {
        /* The host on its own line, so a link to an unexpected place
           stands out before anyone opens it (lore only passes links to the
           CLI's own sign-in hosts). */
        const step = el("p", "");
        step.append(document.createTextNode("1. Sign in with your own account at "));
        step.append(el("strong", "builtin-host", login.url_host));
        step.append(document.createTextNode(":"));
        box.append(step);
        const link = el("a", "builtin-link", login.url);
        link.href = login.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        const linkLine = el("p", "");
        linkLine.append(link);
        box.append(linkLine);
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
    const help = agent.kind === "claude" && kind === "api_key"
      ? "Paste an Anthropic API key from the Anthropic console. With a key, Claude is billed per token to that account instead of the subscription: set a spend limit on the key there."
      : CREDENTIAL_HELP[kind];
    form.append(label, el("p", "muted small-text", help + " It is stored only in the agent's own volume, never in lore."));
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
    const enabledBox = check("enabled", "Works on idle board tasks");
    const availableBox = check("available", "Available to help other agents");
    checks.append(enabledBox, availableBox);
    /* Shown once the server knows the switch. */
    const readsBox = "read_other_services" in agent
      ? check("read_other_services", "May read other services during runs")
      : null;
    const readsNote = readsBox && el("p", "muted small-text builtin-help-note",
      "Off: a run reads only the services its task names. On: it may also read what the task's author may read (mail, other repositories, Dokploy, Cloudflare), and could copy it into its commit.");

    const actions = el("div", "board-actions");
    const save = el("button", "ghost small", "Save settings");
    save.type = "submit";
    actions.append(save);
    const helpNote = el("p", "muted small-text builtin-help-note",
      "Available to help: while it is idle, your other agents may hand it a task (delegate) or ask it a question (ask, read-only) through lore. Off: it only works on board tasks.");
    form.append(modelField, checks, helpNote);
    if (readsBox) form.append(readsBox, readsNote);
    form.append(row, actions);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const payload = {
        model: model.value.trim(),
        enabled: enabledBox.querySelector("input").checked,
        available: availableBox.querySelector("input").checked,
        daily_cap: Number.parseInt(cap.value, 10) || 0,
        active_hours: hours.value.trim(),
      };
      if (readsBox) payload.read_other_services = readsBox.querySelector("input").checked;
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

  /* ---------- Terminal ---------- */

  function terminalActions(agent) {
    const row = el("div", "board-actions builtin-actions builtin-terminal");
    row.append(button("Open terminal", "", () => openTerminal(agent, "cli")));
    const more = el("details", "builtin-more");
    more.append(el("summary", "", "More"));
    const inside = el("div", "builtin-more-body");
    inside.append(
      button("Shell", "", () => openTerminal(agent, "shell")),
      el("span", "muted small-text", "bash as the agent user, with its sign-in"),
    );
    more.append(inside);
    row.append(more);
    return row;
  }

  /* The window: a bar to drag it by, the frame, a grip and edges to resize
     it. Its place and size (floating), its height on narrow screens and
     whether it is maximised are remembered per browser under one key. */
  const WINDOW_KEY = "lore.terminal.window";
  const MIN_W = 320, MIN_H = 200;
  /* Below this width the window takes the whole width at the bottom and
     only its height changes. */
  const narrowScreen = window.matchMedia("(max-width: 699px)");
  const EDGES = ["n", "s", "e", "w", "ne", "nw", "se", "sw"];

  const term = {
    win: null, frame: null, bar: null, state: null, expand: null, reconnect: null,
    geo: null, narrowH: null, max: false, closing: null,
  };
  try { localStorage.removeItem("lore.terminal.mode"); } catch { /* private mode */ }

  function readWindow() {
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(WINDOW_KEY) || "null"); } catch { saved = null; }
    const number = (value) => (typeof value === "number" && isFinite(value) ? value : null);
    if (!saved || typeof saved !== "object") return;
    const geo = { x: number(saved.x), y: number(saved.y), w: number(saved.w), h: number(saved.h) };
    term.geo = Object.values(geo).every((value) => value !== null) ? geo : null;
    term.narrowH = number(saved.nh);
    term.max = saved.max === true;
  }

  function saveWindow() {
    const value = { max: term.max };
    if (term.geo) Object.assign(value, term.geo);
    if (term.narrowH) value.nh = term.narrowH;
    try { localStorage.setItem(WINDOW_KEY, JSON.stringify(value)); } catch { /* private mode */ }
  }

  /* Where the window may be: under the top bar, above the phone tab bar. */
  function bounds() {
    const top = document.querySelector(".top");
    const tabs = $("tabbar");
    let upper = 0, lower = window.innerHeight;
    const app = $("app");
    if (top && app && !app.hidden && getComputedStyle(top).display !== "none") {
      upper = Math.max(0, Math.round(top.getBoundingClientRect().bottom));
    }
    if (tabs && getComputedStyle(tabs).display !== "none") lower = Math.round(tabs.getBoundingClientRect().top);
    return { left: 0, top: upper, right: window.innerWidth, bottom: Math.max(upper + MIN_H, lower) };
  }

  /* The default place: the bottom right of the graph, clear of the side
     column and of Live activity when it shows. */
  function defaultGeo() {
    const b = bounds();
    const side = $("side") || document.querySelector(".side");
    const feed = $("feed");
    let left = 16, right = window.innerWidth - 16;
    if (side && getComputedStyle(side).display !== "none" && getComputedStyle(side).position === "fixed") {
      left = Math.round(side.getBoundingClientRect().right) + 16;
    }
    if (feed && window.innerWidth > 1180 && getComputedStyle(feed).display !== "none") {
      right = Math.round(feed.getBoundingClientRect().left) - 16;
    }
    const w = Math.max(MIN_W, Math.min(720, right - left));
    const h = Math.max(MIN_H, Math.min(440, Math.round((b.bottom - b.top) * 0.55)));
    return { x: right - w, y: b.bottom - 16 - h, w, h };
  }

  function clampGeo(geo, b) {
    const w = Math.min(Math.max(geo.w, MIN_W), b.right - b.left);
    const h = Math.min(Math.max(geo.h, MIN_H), b.bottom - b.top);
    const x = Math.min(Math.max(geo.x, b.left), b.right - w);
    const y = Math.min(Math.max(geo.y, b.top), b.bottom - h);
    return { x, y, w, h };
  }

  /* The rectangle the window has now, whatever its mode. */
  function currentRect() {
    const b = bounds();
    if (term.max) {
      const m = narrowScreen.matches ? 0 : 8;
      return { x: b.left + m, y: b.top + m, w: b.right - b.left - 2 * m, h: b.bottom - b.top - 2 * m };
    }
    if (narrowScreen.matches) {
      const h = Math.min(Math.max(term.narrowH || Math.round((b.bottom - b.top) * 0.6), MIN_H), b.bottom - b.top);
      return { x: b.left, y: b.bottom - h, w: b.right - b.left, h };
    }
    return clampGeo(term.geo || defaultGeo(), b);
  }

  /* Geometry goes through the CSSOM, which the page's policy allows. */
  function place(rect) {
    const style = term.win.style;
    style.setProperty("left", rect.x + "px");
    style.setProperty("top", rect.y + "px");
    style.setProperty("width", rect.w + "px");
    style.setProperty("height", rect.h + "px");
  }

  function applyWindow() {
    if (!term.win) return;
    term.win.classList.toggle("maximised", term.max);
    term.win.classList.toggle("narrow", narrowScreen.matches);
    term.expand.textContent = term.max ? "Restore" : "Expand";
    term.expand.title = term.max ? "Back to the window's own size and place" : "Fill the page with the terminal";
    term.expand.setAttribute("aria-pressed", String(term.max));
    place(currentRect());
  }

  function tellFrame(message) {
    if (term.frame && term.frame.contentWindow) term.frame.contentWindow.postMessage(message, location.origin);
  }

  function focusTerminal() {
    if (!term.frame) return;
    term.frame.focus();
    tellFrame({ type: "lore-terminal-command", command: "focus" });
  }

  function setTerminalState(name, text) {
    if (!term.state || !["connecting", "open", "closed"].includes(name)) return;
    term.state.className = "term-state " + name;
    term.state.textContent = text || "";
    term.state.title = text || "";
    term.reconnect.hidden = name !== "closed";
  }

  /* Moving (the bar) and resizing (an edge or the grip) with Pointer
     Events, captured, so mouse, pen and touch behave alike; a shield over
     the frame keeps it from swallowing the pointer meanwhile. The terminal
     refits as the frame changes (its own observer, once a frame) and is
     told when the drag ends, which sends the new size to the server. */
  function startDrag(event, edge) {
    if (event.button !== 0 || !term.win) return;
    if (!edge && (term.max || narrowScreen.matches)) return;
    if (edge && term.max) return;
    event.preventDefault();
    const target = event.currentTarget;
    try { target.setPointerCapture(event.pointerId); } catch { /* already released */ }
    const start = { x: event.clientX, y: event.clientY, rect: currentRect() };
    let latest = start.rect, frame = 0;
    term.win.classList.add("moving");
    if (edge) tellFrame({ type: "lore-terminal-resizing", active: true });

    const compute = (dx, dy) => {
      const b = bounds();
      const r = start.rect;
      if (!edge) return clampGeo({ x: r.x + dx, y: r.y + dy, w: r.w, h: r.h }, b);
      if (narrowScreen.matches) {
        const h = Math.min(Math.max(r.h - dy, MIN_H), b.bottom - b.top);
        return { x: r.x, y: b.bottom - h, w: r.w, h };
      }
      let { x, y, w, h } = r;
      const right = r.x + r.w, bottom = r.y + r.h;
      if (edge.includes("e")) w = Math.min(Math.max(r.w + dx, MIN_W), b.right - r.x);
      if (edge.includes("s")) h = Math.min(Math.max(r.h + dy, MIN_H), b.bottom - r.y);
      if (edge.includes("w")) { x = Math.min(Math.max(r.x + dx, b.left), right - MIN_W); w = right - x; }
      if (edge.includes("n")) { y = Math.min(Math.max(r.y + dy, b.top), bottom - MIN_H); h = bottom - y; }
      return { x, y, w, h };
    };
    const move = (e) => {
      if (e.pointerId !== event.pointerId) return;
      latest = compute(e.clientX - start.x, e.clientY - start.y);
      if (!frame) frame = requestAnimationFrame(() => { frame = 0; if (term.win) place(latest); });
    };
    const end = (e) => {
      if (e.pointerId !== event.pointerId) return;
      target.removeEventListener("pointermove", move);
      target.removeEventListener("pointerup", end);
      target.removeEventListener("pointercancel", end);
      cancelAnimationFrame(frame);
      if (!term.win) return;
      term.win.classList.remove("moving");
      place(latest);
      if (narrowScreen.matches) term.narrowH = latest.h;
      else term.geo = latest;
      saveWindow();
      if (edge) tellFrame({ type: "lore-terminal-resizing", active: false });
      focusTerminal();
    };
    target.addEventListener("pointermove", move);
    target.addEventListener("pointerup", end);
    target.addEventListener("pointercancel", end);
  }

  function openTerminal(agent, mode) {
    closeTerminal(true);
    readWindow();
    const label = `${mode === "shell" ? "Shell" : "Terminal"} of ${shown(agent)}`;
    const win = el("section", "term-win");
    win.setAttribute("role", "dialog");
    win.setAttribute("aria-label", label);
    win.dataset.agent = agent.name;

    const bar = el("div", "term-bar");
    bar.title = "Drag to move · double-click to reset its size and place";
    if (agent.avatar) {
      const image = el("img", "term-avatar");
      image.src = `/admin/avatars/${encodeURIComponent(agent.avatar)}.svg`;
      image.alt = "";
      bar.append(image);
    }
    const title = el("div", "term-title");
    const what = mode === "shell" ? "Shell as the agent user" : "The CLI's own interface";
    title.append(el("strong", "", shown(agent)),
      el("span", "muted", agent.display_name ? `${agent.name} · ${what}` : what));
    const stateNode = el("span", "term-state connecting", "Connecting…");
    stateNode.setAttribute("role", "status");
    stateNode.setAttribute("aria-live", "polite");
    const buttons = el("div", "term-buttons");
    const reconnect = button("Reconnect", "", () => tellFrame({ type: "lore-terminal-command", command: "reconnect" }));
    reconnect.hidden = true;
    const expand = button("Expand", "", () => {
      term.max = !term.max;
      saveWindow();
      applyWindow();
      focusTerminal();
    });
    const close = button("Close", "", () => closeTerminal());
    buttons.append(reconnect, expand, close);
    bar.append(title, stateNode, buttons);
    bar.addEventListener("pointerdown", (event) => {
      if (event.target.closest("button")) return;
      startDrag(event, null);
    });
    bar.addEventListener("dblclick", (event) => {
      if (event.target.closest("button")) return;
      term.geo = null;
      term.narrowH = null;
      term.max = false;
      try { localStorage.removeItem(WINDOW_KEY); } catch { /* private mode */ }
      applyWindow();
      focusTerminal();
    });

    const body = el("div", "term-body");
    const frame = el("iframe", "terminal-frame");
    frame.title = label;
    const query = new URLSearchParams({ agent: agent.name, mode, avatar: agent.avatar || "" });
    frame.src = "/admin/terminal?" + query.toString();
    frame.addEventListener("load", focusTerminal);
    body.append(frame, el("div", "term-shield"));
    win.append(bar, body);
    for (const edge of EDGES) {
      const handle = el("div", `term-edge term-edge-${edge}`);
      handle.setAttribute("aria-hidden", "true");
      handle.addEventListener("pointerdown", (event) => startDrag(event, edge));
      win.append(handle);
    }
    const grip = el("div", "term-grip");
    grip.setAttribute("aria-hidden", "true");
    grip.title = "Drag to resize";
    grip.addEventListener("pointerdown", (event) => startDrag(event, "se"));
    win.append(grip);

    Object.assign(term, { win, frame, bar, state: stateNode, expand, reconnect, closing: null });
    document.body.append(win);
    applyWindow();
    launcherSync();
  }

  /* Close asks the frame to end the terminal (it tells the server, then
     answers); removing the frame closes its socket in any case, so the
     window goes after a moment even without an answer. */
  function closeTerminal(now) {
    if (!term.win) return;
    if (!now && term.frame && term.frame.contentWindow && !term.closing) {
      tellFrame({ type: "lore-terminal-command", command: "close" });
      term.closing = setTimeout(() => closeTerminal(true), 600);
      return;
    }
    clearTimeout(term.closing);
    term.win.remove();
    Object.assign(term, { win: null, frame: null, bar: null, state: null, expand: null, reconnect: null, closing: null });
    launcherSync();
  }

  window.addEventListener("resize", applyWindow);
  narrowScreen.addEventListener("change", applyWindow);

  window.addEventListener("message", (event) => {
    if (!term.frame || event.origin !== location.origin || event.source !== term.frame.contentWindow) return;
    const data = event.data || {};
    if (data.type === "lore-terminal-close") closeTerminal(true);
    else if (data.type === "lore-terminal-state" || data.type === "lore-terminal-ready") setTerminalState(data.state, data.text);
  });

  /* ---------- Terminal launcher ---------- */

  /* The terminal icon in Live activity's head and the one beside "Hide
     activity" (which stays when Live activity is hidden). Shown only to
     users with the agents permission on a server with built-in agents.
     One connected agent: its terminal opens. Several: a menu lists them;
     the last one picked comes first and is remembered per browser. */
  const LAST_KEY = "lore.terminal.agent";
  const launchers = ["terminal-launch", "terminal-launch-float"].map($).filter(Boolean);
  const launch = { configured: false, manage: false, agents: [], menu: null, from: null };

  function launcherVisible() {
    const app = $("app");
    const toggle = $("agents-toggle");
    return Boolean(app && !app.hidden && toggle && !toggle.hidden && launch.configured && launch.manage);
  }

  function launcherSync() {
    const show = launcherVisible();
    for (const node of launchers) {
      node.hidden = !show;
      node.classList.toggle("active", Boolean(term.win));
    }
    if (!show) closeMenu();
  }

  async function launcherLoad() {
    const app = $("app");
    const toggle = $("agents-toggle");
    if (!app || app.hidden || !toggle || toggle.hidden) { launcherSync(); return false; }
    let result;
    try { result = await call("/admin/api/builtin"); } catch { result = null; }
    if (result && result.ok) {
      launch.configured = Boolean(result.body.configured);
      launch.manage = Boolean(result.body.manage);
      launch.agents = result.body.agents || [];
    } else if (result) {
      launch.configured = false;
    }
    launcherSync();
    return Boolean(result && result.ok);
  }

  function lastAgent() {
    try { return localStorage.getItem(LAST_KEY) || ""; } catch { return ""; }
  }

  function pickAgent(agent) {
    try { localStorage.setItem(LAST_KEY, agent.name); } catch { /* private mode */ }
    closeMenu(false);
    openTerminal(agent, "cli");
  }

  async function onLauncher(event) {
    const from = event.currentTarget;
    if (launch.menu) { closeMenu(true); return; }
    if (term.win) {
      applyWindow();
      focusTerminal();
      return;
    }
    await launcherLoad();
    if (!launcherVisible()) return;
    const connected = launch.agents.filter((agent) => agent.connected);
    if (launch.agents.length === 1 && connected.length === 1) pickAgent(connected[0]);
    else openMenu(from);
  }

  function openMenu(from) {
    closeMenu(false);
    const menu = el("div", "term-menu");
    menu.setAttribute("role", "menu");
    menu.setAttribute("aria-label", "Open the terminal of");
    menu.append(el("div", "term-menu-head", "Open a terminal"));
    const last = lastAgent();
    const agents = launch.agents.filter((agent) => agent.connected)
      .sort((a, b) => (b.name === last) - (a.name === last));
    if (!agents.length) menu.append(el("p", "muted small-text term-menu-empty", "No built-in agent is connected."));
    for (const agent of agents) {
      const item = el("button", "term-menu-item");
      item.type = "button";
      item.setAttribute("role", "menuitem");
      const image = el("img", "term-avatar");
      image.src = `/admin/avatars/${encodeURIComponent(agent.avatar || "orbit")}.svg`;
      image.alt = "";
      const text = el("span", "term-menu-text");
      text.append(el("strong", "", shown(agent)),
        el("span", agent.signed_in ? "ok" : "warn", agent.signed_in ? "signed in" : "not signed in"));
      item.append(image, text);
      if (agent.display_name) item.title = agent.name;
      if (agent.name === last) item.append(el("span", "muted small-text", "last"));
      item.addEventListener("click", () => pickAgent(agent));
      menu.append(item);
    }
    menu.addEventListener("keydown", (event) => {
      const items = [...menu.querySelectorAll(".term-menu-item")];
      const at = items.indexOf(document.activeElement);
      if (event.key === "Escape") { event.preventDefault(); closeMenu(true); }
      else if (event.key === "ArrowDown" && items.length) { event.preventDefault(); items[(at + 1) % items.length].focus(); }
      else if (event.key === "ArrowUp" && items.length) { event.preventDefault(); items[(at - 1 + items.length) % items.length].focus(); }
      else if (event.key === "Tab") closeMenu(false);
    });
    document.body.append(menu);
    launch.menu = menu;
    launch.from = from;
    from.setAttribute("aria-expanded", "true");
    // Below the icon, or above it when there is no room below.
    const anchor = from.getBoundingClientRect();
    const box = menu.getBoundingClientRect();
    const left = Math.max(8, Math.min(anchor.right - box.width, window.innerWidth - box.width - 8));
    let top = anchor.bottom + 6;
    if (top + box.height > window.innerHeight - 8) top = Math.max(8, anchor.top - 6 - box.height);
    menu.style.setProperty("left", left + "px");
    menu.style.setProperty("top", top + "px");
    const first = menu.querySelector(".term-menu-item");
    if (!first) menu.tabIndex = -1;
    (first || menu).focus();
  }

  function closeMenu(refocus) {
    if (!launch.menu) return;
    launch.menu.remove();
    launch.menu = null;
    if (launch.from) {
      launch.from.setAttribute("aria-expanded", "false");
      if (refocus) launch.from.focus();
    }
    launch.from = null;
  }

  for (const node of launchers) {
    node.setAttribute("aria-haspopup", "menu");
    node.setAttribute("aria-expanded", "false");
    node.addEventListener("click", onLauncher);
  }
  document.addEventListener("pointerdown", (event) => {
    if (!launch.menu || launch.menu.contains(event.target) || launchers.some((node) => node.contains(event.target))) return;
    closeMenu(false);
  });
  window.addEventListener("resize", () => closeMenu(false));
  /* The icons follow the session: signing in or out shows or hides #app,
     and the Agents button shows only with the agents permission. */
  {
    const watch = new MutationObserver(() => { launcherLoad(); });
    for (const id of ["app", "agents-toggle"]) {
      const node = $(id);
      if (node) watch.observe(node, { attributes: true, attributeFilter: ["hidden"] });
    }
    launcherLoad();
  }

  /* ---------- Task runner ---------- */

  const runner = {
    data: null,
    /* Output lines per run id, and the newest seq seen. */
    lines: new Map(),
    seen: new Map(),
    /* Run ids whose output the page shows. */
    open: new Set(),
    /* The server refused run output to this user. */
    denied: false,
  };
  const OUTPUT_KEEP = 400;
  const STATUS_LABEL = {
    starting: "starting", running: "running", pushed: "pushed", done: "done", failed: "failed",
    stopped: "stopped", timeout: "timed out", interrupted: "interrupted", answered: "answered",
    busy: "container busy, retried later",
  };

  async function loadRunner() {
    let result;
    try {
      result = await call("/admin/api/builtin/runs");
    } catch (_) {
      return;
    }
    const box = $("runner-section");
    if (!result.ok || !result.body.configured) { box.hidden = true; return; }
    runner.data = result.body;
    box.hidden = false;
    /* Run output is for the agents permission only: without it the page
       shows each run's line, not its output. */
    if (runner.data.manage) {
      for (const run of runner.data.active) {
        runner.open.add(run.id);
        if (!runner.lines.has(run.id)) await loadOutput(run.id);
      }
    }
    renderRunner();
  }

  async function loadOutput(id) {
    const result = await call(`/admin/api/builtin/runs/${encodeURIComponent(id)}/events?after=0`).catch(() => null);
    if (result && (result.status === 403 || result.status === 401)) {
      runner.denied = true;
      return;
    }
    if (!result || !result.ok) return;
    const lines = result.body.events.map((event) => ({ seq: event.seq, stream: event.stream, line: event.body }));
    runner.lines.set(id, lines.slice(-OUTPUT_KEEP));
    runner.seen.set(id, lines.length ? lines[lines.length - 1].seq : 0);
  }

  function outputBox(id) {
    if (runner.denied || (runner.data && !runner.data.manage)) {
      return el("p", "muted small-text runner-denied", "The output of runs is shown only with the agents permission.");
    }
    const pre = el("pre", "runner-output");
    pre.dataset.run = id;
    pre.setAttribute("aria-label", "Output of run " + id);
    for (const item of runner.lines.get(id) || []) pre.append(outputLine(item));
    if (!pre.childNodes.length) pre.append(el("span", "muted", "No output yet."));
    requestAnimationFrame(() => { pre.scrollTop = pre.scrollHeight; });
    return pre;
  }

  function outputLine(item) {
    return el("span", item.stream, `${item.stream === "text" ? "" : item.stream + ": "}${item.line}\n`);
  }

  function minutes(from, to) {
    const start = Date.parse(from), end = to ? Date.parse(to) : Date.now();
    if (isNaN(start) || isNaN(end)) return "";
    const m = Math.max(0, Math.round((end - start) / 60000));
    return m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${m % 60} min`;
  }

  /* What a run is, in a few words: a board task, a task another agent
     handed over, or a question another agent asked. */
  function runWhat(run) {
    const by = run.requested_by ? ` · asked by ${run.requested_by}` : "";
    if (run.kind === "chat") return `question${run.requested_by ? ` from ${run.requested_by}` : ""}`;
    if (run.kind === "help") return `task #${run.task_id} (help)${by}`;
    return `task #${run.task_id}`;
  }

  function renderRunner() {
    const data = runner.data;
    if (!data) return;
    const active = $("runner-active");
    active.replaceChildren();
    for (const run of data.active) {
      const item = el("li", "board-item agent-card");
      const head = el("div", "board-item-head agent-head");
      const image = el("img", "builtin-avatar");
      image.src = `/admin/avatars/${encodeURIComponent(run.avatar || "orbit")}.svg`;
      image.alt = "";
      head.append(image, el("span", "board-title", `${run.agent} · ${runWhat(run)}`),
        pill(run.stopping ? "stopping" : STATUS_LABEL[run.status] || run.status, "open"));
      item.append(head);
      item.append(el("div", "board-meta",
        [run.task_title, run.repo || (run.kind === "chat" ? "no checkout, read-only" : ""),
          run.model || "default model", minutes(run.started_at)].filter(Boolean).join(" · ")));
      item.append(outputBox(run.id));
      if (data.manage && !run.stopping) {
        const row = el("div", "board-actions");
        row.append(button("Stop", "danger", () => stopRun(run)));
        item.append(row);
      }
      active.append(item);
    }
    const waiting = data.agents.filter((agent) => !agent.ready).map((agent) => `${agent.agent}: ${agent.why}`);
    const ready = data.agents.filter((agent) => agent.ready).map((agent) => agent.agent);
    $("runner-summary").textContent = data.active.length
      ? `${data.active.length} running`
      : ready.length ? `ready: ${ready.join(", ")}` : "no agent is ready";
    $("runner-summary").title = waiting.join("\n");

    const queue = $("runner-queue");
    queue.replaceChildren();
    const eligible = data.queue.filter((task) => task.state === "eligible").length;
    $("runner-queue-count").textContent = `(${data.queue.length} open, ${eligible} eligible · idle after ${data.settings.idle_minutes} min)`;
    if (!data.queue.length) queue.append(el("li", "runner-why", "No open, unclaimed tasks."));
    for (const task of data.queue) {
      const item = el("li");
      item.append(el("span", "runner-line", `#${task.id} ${task.title} · ${task.project}`),
        el("span", "runner-why", `${task.state.replace("_", " ")}: ${task.why}`));
      queue.append(item);
    }

    const history = $("runner-history");
    history.replaceChildren();
    const ended = data.history.filter((run) => !["starting", "running"].includes(run.status));
    $("runner-history-count").textContent = `(${ended.length})`;
    if (!ended.length) history.append(el("li", "runner-why", "No runs yet."));
    for (const run of ended) {
      const item = el("li");
      const line = `${run.agent} · ${runWhat(run)} · ${STATUS_LABEL[run.status] || run.status}`
        + ` · ${minutes(run.started_at, run.ended_at)}` + (run.commit ? ` · ${run.commit.slice(0, 10)}` : "");
      item.append(el("span", "runner-line", line), el("span", "runner-why", run.summary ? `${day(run.created_at)} · ${run.summary}` : day(run.created_at)));
      if (data.manage && !runner.denied) {
        const show = button(runner.open.has(run.id) ? "Hide output" : "Show output", "", async () => {
          if (runner.open.has(run.id)) runner.open.delete(run.id);
          else { runner.open.add(run.id); await loadOutput(run.id); }
          renderRunner();
        });
        item.append(show);
      }
      if (runner.open.has(run.id)) item.append(outputBox(run.id));
      history.append(item);
    }
  }

  async function stopRun(run) {
    const after = run.kind === "chat"
      ? "the agent that asked is told there is no answer"
      : "the task is released with a note";
    if (!window.confirm(`Stop ${run.agent}'s run (${runWhat(run)})?\n\nIts token stops working at once; ${after}.`)) return;
    const result = await post(url(run.agent, "/stop")).catch(() => null);
    if (!result || !result.ok) {
      status((result && result.body.error) || "The run could not be stopped.", "bad");
      return;
    }
    status(`Stopping ${run.agent}'s run…`, "ok");
    await loadRunner();
  }

  /* Live run events, relayed by the page's event stream. */
  window.addEventListener("lore-run", (event) => {
    const run = event.detail || {};
    if (run.type === "output") {
      if (runner.denied || (runner.data && !runner.data.manage)) return;
      const last = runner.seen.get(run.run_id) || 0;
      if (run.seq <= last) return;
      runner.seen.set(run.run_id, run.seq);
      const lines = runner.lines.get(run.run_id) || [];
      lines.push({ seq: run.seq, stream: run.stream, line: run.line });
      if (lines.length > OUTPUT_KEEP) lines.splice(0, lines.length - OUTPUT_KEEP);
      runner.lines.set(run.run_id, lines);
      if (panel.hidden) return;
      const pre = section.querySelector(`pre.runner-output[data-run="${CSS.escape(run.run_id)}"]`);
      if (pre) {
        const stick = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 8;
        if (pre.firstChild && pre.firstChild.classList && pre.firstChild.classList.contains("muted")) pre.replaceChildren();
        pre.append(outputLine({ stream: run.stream, line: run.line }));
        while (pre.childNodes.length > OUTPUT_KEEP) pre.firstChild.remove();
        if (stick) pre.scrollTop = pre.scrollHeight;
      }
    } else if (!panel.hidden) {
      loadRunner();
    }
  });

  /* Loads when the Agents panel opens; stops polling when it closes. */
  new MutationObserver(() => {
    if (panel.hidden) {
      clearTimeout(ui.poll);
      ui.credential = {};
      status("");
    } else {
      load();
      loadRunner();
    }
  }).observe(panel, { attributes: true, attributeFilter: ["hidden"] });
})();
