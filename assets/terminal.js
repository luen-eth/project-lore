/* The terminal window's document. It opens one WebSocket to lore, which
   relays it to one terminal session in a built-in agent's container: typed
   bytes go out as binary frames, the terminal's bytes come back as binary
   frames, and open, resize, keep-alive, hide, end and what happened travel
   as small JSON text frames.

   A session outlives its window: closing the socket (Hide, a reload, the
   frame being removed, a dropped connection) only detaches this window,
   and the next window for the same agent and kind resumes the session,
   with its recent screen first. The session ends only with End session,
   when its program exits, or by lore (its idle limit, its runner's link,
   the opener's permission). A session that ended while no window showed
   it is reported once ("ended at 11:20: …"); a new one starts only with
   New session.

   Every key goes to the terminal, Escape included, so the window closes
   only with the admin page's buttons around it. */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const agent = params.get("agent") || "";
  const mode = params.get("mode") === "shell" ? "shell" : "cli";
  const avatar = params.get("avatar");

  /* The page shown says someone is looking, so the session is not idle. */
  const ALIVE_EVERY = 60 * 1000;

  $("name").textContent = agent || "Terminal";
  $("what").textContent = mode === "shell" ? "Shell as the agent user" : "The CLI's own interface";
  document.title = `${agent} · ${mode === "shell" ? "shell" : "terminal"} · project-lore`;
  if (avatar && /^[a-z0-9-]+$/.test(avatar)) {
    $("avatar").src = `/admin/avatars/${avatar}.svg`;
    $("avatar").hidden = false;
  }

  const term = new Terminal({
    cursorBlink: true,
    fontFamily: 'ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace',
    fontSize: window.matchMedia("(max-width: 760px)").matches ? 12 : 13,
    scrollback: 5000,
    theme: {
      background: "#05080f",
      foreground: "#e9eefb",
      cursor: "#6fb6ff",
      selectionBackground: "rgba(111, 182, 255, 0.35)",
    },
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($("screen"));
  fit.fit();

  let socket = null;
  /* connecting, open, ended (the session is over), taken (another window
     shows it), detached (this window lost it; the session goes on). */
  let state = "connecting";
  /* Shown in the admin page's window; a drag in progress; the size the
     server was last told (see the message handler below). */
  const embedded = window.parent !== window;
  let resizing = false;
  let told = null;
  /* From `attached` until xterm.js has parsed the replay: the recent
     screen may hold questions the program once asked the terminal (its
     attributes, the cursor position), which xterm.js answers through
     onData; those answers must not be typed into the live program. */
  let replaying = false;
  const encoder = new TextEncoder();

  /* What the one action button does in each state. */
  const ACTIONS = {
    ended: ["New session", () => connect(true)],
    taken: ["Take it back", () => connect(false)],
    detached: ["Reconnect", () => connect(false)],
  };

  function clock(unix) {
    const date = new Date((Number(unix) || 0) * 1000);
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function setState(name, text) {
    state = name;
    const node = $("state");
    node.className = "state " + name;
    node.textContent = text;
    node.title = text;
    const action = ACTIONS[name];
    $("action").hidden = !action;
    if (action) $("action").textContent = action[0];
    $("end").hidden = name !== "open";
    if (name !== "open") {
      closeConfirm(false);
      $("notice").hidden = true;
    }
    $("screen").classList.toggle("ended", name !== "open" && name !== "connecting");
    tellParent({ type: "lore-terminal-state", state: name, text, action: action ? action[0] : "" });
  }

  /* A line in the terminal itself, not only in the state's tooltip. */
  function say(text, colour) {
    term.write(`\r\n\x1b[${colour || 31}m${String(text).replace(/[\x00-\x1f]/g, " ")}\x1b[0m\r\n`);
  }

  function send(frame) {
    if (socket && socket.readyState === WebSocket.OPEN) socket.send(frame);
  }

  function connect(fresh) {
    if (socket) {
      const old = socket;
      socket = null;
      old.close();
    }
    replaying = false;
    setState("connecting", fresh ? "Starting a new session…" : "Connecting…");
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${scheme}//${location.host}/admin/api/builtin/${encodeURIComponent(agent)}/terminal`);
    ws.binaryType = "arraybuffer";
    socket = ws;
    ws.addEventListener("open", () => {
      told = `${term.cols}x${term.rows}`;
      ws.send(JSON.stringify({ type: "open", mode, cols: term.cols, rows: term.rows, fresh: Boolean(fresh) }));
    });
    ws.addEventListener("message", (event) => {
      if (ws !== socket) return;
      if (typeof event.data !== "string") {
        term.write(new Uint8Array(event.data));
        return;
      }
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (message.type === "opened") {
        term.reset();
        setState("open", `New session · since ${clock(message.since)}`);
        catchUpSize();
        term.focus();
      } else if (message.type === "attached") {
        // The recent screen follows; the program then draws its screen
        // again for this window's size.
        replaying = true;
        term.reset();
        const from = message.taken_from ? ` (taken from ${message.taken_from}'s window)` : "";
        setState("open", `Resumed · running since ${clock(message.since)}${from}`);
        catchUpSize();
      } else if (message.type === "replayed") {
        // term.write is asynchronous: this runs once everything written
        // before it, the whole replay, has been parsed.
        term.write("", () => {
          if (ws !== socket) return;
          replaying = false;
          term.scrollToBottom();
          term.focus();
        });
      } else if (message.type === "exit" || message.type === "ended") {
        const code = message.code === null || message.code === undefined ? "" : ` (exit ${message.code})`;
        const at = message.at ? ` at ${clock(message.at)}` : "";
        const text = `The session ended${at}${code}${message.message ? ": " + message.message : ""}`;
        setState("ended", text);
        say(text);
        if (message.type === "ended") say("Press New session to start another.", 90);
      } else if (message.type === "ends_soon") {
        // The maximum age is near: said in the terminal and to the page
        // around it, which keeps it beside the state.
        const text = `This session ends at ${clock(message.at)} (maximum ${message.max_hours} hours);`
          + " End it, or keep working and open a new one after";
        say(text, 33);
        $("notice").textContent = text;
        $("notice").hidden = false;
        tellParent({ type: "lore-terminal-notice", text });
      } else if (message.type === "taken") {
        const text = `Opened in another window${message.by ? " (" + message.by + ")" : ""}; the session goes on there`;
        setState("taken", text);
        say(text, 33);
      } else if (message.type === "detached") {
        const text = message.message || "This window was detached; the session goes on";
        setState("detached", text);
        say(text, 33);
      } else if (message.type === "error") {
        const text = message.message || "The terminal could not be opened";
        setState("detached", text);
        say(text);
      }
    });
    ws.addEventListener("close", () => {
      if (ws !== socket) return;
      socket = null;
      // Refused before it opened: signed out, no `agents` permission, or
      // another origin. The server says which only to a fetch, not here.
      if (state === "connecting") {
        setState("detached", "Disconnected: sign in again, or check the agents permission");
        say("Disconnected: sign in again, or check the agents permission");
      } else if (state === "open") {
        setState("detached", "Disconnected; the session goes on in the agent's container");
        say("Disconnected; the session goes on in the agent's container. Reconnect to see it again.", 33);
      }
    });
  }

  term.onData((data) => { if (state === "open" && !replaying) send(encoder.encode(data)); });
  term.onBinary((data) => {
    if (state !== "open" || replaying) return;
    const bytes = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i) & 0xff;
    send(bytes);
  });
  term.onResize(({ cols, rows }) => { if (!resizing) sendSize(cols, rows); });

  // The terminal follows the frame's size (the window, a phone turned).
  let pending = 0;
  new ResizeObserver(() => {
    cancelAnimationFrame(pending);
    pending = requestAnimationFrame(refit);
  }).observe($("screen"));

  function alive() {
    if (state === "open" && document.visibilityState === "visible") send(JSON.stringify({ type: "alive" }));
  }
  setInterval(alive, ALIVE_EVERY);
  document.addEventListener("visibilitychange", alive);

  $("action").addEventListener("click", () => {
    const action = ACTIONS[state];
    if (action) action[1]();
  });

  /* Hide: this window lets go; the session goes on. */
  function hide() {
    send(JSON.stringify({ type: "hide" }));
    if (socket) {
      const old = socket;
      socket = null;
      old.close();
    }
    setState("detached", "Hidden; the session goes on");
  }

  /* End session: the program and everything started in it stop. */
  function end() {
    if (state !== "open") return;
    send(JSON.stringify({ type: "end" }));
  }

  /* On the page of its own, End session asks first, with the focus on
     "Keep it running", so a key pressed by habit does not end it. */
  function askEnd() {
    if (state !== "open") return;
    $("confirm").hidden = false;
    $("confirm-keep").focus();
  }
  function closeConfirm(refocus) {
    if ($("confirm").hidden) return;
    $("confirm").hidden = true;
    if (refocus) term.focus();
  }
  $("end").addEventListener("click", askEnd);
  $("confirm-end").addEventListener("click", () => { closeConfirm(false); end(); });
  $("confirm-keep").addEventListener("click", () => closeConfirm(true));
  $("confirm").addEventListener("keydown", (event) => {
    if (event.key === "Escape") { event.preventDefault(); closeConfirm(true); }
  });

  /* In the admin page the window around the frame draws the bar (the
     agent, the state, the action, Expand, Hide, End session) and moves and
     resizes the frame; this document then shows only the terminal, tells
     the page its state and does what the page's buttons ask. While the
     owner drags an edge the terminal still refits every frame, but the
     server hears the new size only once, when the drag ends. */
  function tellParent(message) {
    if (embedded) window.parent.postMessage(message, location.origin);
  }
  function refit() { try { fit.fit(); } catch { /* not laid out yet */ } }
  /* The size goes to the server only once the session is shown: the
     first frame on a socket must be the `open`, which carries it. */
  function sendSize(cols, rows) {
    if (state !== "open") return;
    told = `${cols}x${rows}`;
    send(JSON.stringify({ type: "resize", cols, rows }));
  }
  /* A size that changed while the socket opened. */
  function catchUpSize() {
    refit();
    if (told !== `${term.cols}x${term.rows}`) sendSize(term.cols, term.rows);
  }
  if (embedded) document.body.classList.add("embedded");
  window.addEventListener("message", (event) => {
    if (event.origin !== location.origin || event.source !== window.parent) return;
    const data = event.data || {};
    if (data.type === "lore-terminal-resizing") {
      resizing = Boolean(data.active);
      if (!resizing) {
        refit();
        if (told !== `${term.cols}x${term.rows}`) sendSize(term.cols, term.rows);
      }
    } else if (data.type === "lore-terminal-command") {
      // "close" and "reconnect" are what an admin page loaded before
      // terminal sessions sends: its Close only hides now (the card then
      // offers Resume), which never ends a session by surprise.
      if (data.command === "hide" || data.command === "close") { hide(); tellParent({ type: "lore-terminal-close" }); }
      else if (data.command === "reconnect") $("action").click();
      else if (data.command === "end") end();
      else if (data.command === "action") $("action").click();
      else if (data.command === "focus") term.focus();
    }
  });

  connect(false);
  tellParent({ type: "lore-terminal-ready", state, text: $("state").textContent });
})();
