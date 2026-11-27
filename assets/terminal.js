/* The terminal window's document. It opens one WebSocket to lore, which
   relays it to one PTY in a built-in agent's container: typed bytes go out
   as binary frames, the terminal's bytes come back as binary frames, and
   open, resize, keep-alive, close and the end travel as small JSON text
   frames. Closing the socket (Close, or the frame being removed) closes the
   terminal and kills what runs in it.

   Every key goes to the terminal, Escape included, so the window closes
   only with its Close button, which asks the admin page around it to
   remove the frame. */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const agent = params.get("agent") || "";
  const mode = params.get("mode") === "shell" ? "shell" : "cli";
  const avatar = params.get("avatar");

  /* The page shown says someone is looking, so the terminal is not idle. */
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
  let state = "connecting";
  /* Shown in the admin page's window; a drag in progress; the size the
     server was last told (see the message handler below). */
  const embedded = window.parent !== window;
  let resizing = false;
  let told = null;
  const encoder = new TextEncoder();

  function setState(name, text) {
    state = name;
    const node = $("state");
    node.className = "state " + name;
    node.textContent = text;
    node.title = text;
    $("reconnect").hidden = name !== "closed";
    $("screen").classList.toggle("ended", name === "closed");
    tellParent({ type: "lore-terminal-state", state: name, text });
  }

  function send(frame) {
    if (socket && socket.readyState === WebSocket.OPEN) socket.send(frame);
  }

  function connect() {
    setState("connecting", "Connecting…");
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${scheme}//${location.host}/admin/api/builtin/${encodeURIComponent(agent)}/terminal`);
    ws.binaryType = "arraybuffer";
    socket = ws;
    ws.addEventListener("open", () => {
      told = `${term.cols}x${term.rows}`;
      ws.send(JSON.stringify({ type: "open", mode, cols: term.cols, rows: term.rows }));
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
        setState("open", "Connected");
        term.focus();
      } else if (message.type === "exit") {
        const code = message.code === null || message.code === undefined ? "" : ` (exit ${message.code})`;
        setState("closed", `Ended${code}${message.message ? ": " + message.message : ""}`);
      } else if (message.type === "error") {
        setState("closed", message.message || "The terminal could not be opened");
      }
    });
    ws.addEventListener("close", () => {
      if (ws !== socket) return;
      // Refused before it opened: signed out, no `agents` permission, or
      // another origin. The server says which only to a fetch, not here.
      if (state === "connecting") setState("closed", "Disconnected: sign in again, or check the agents permission");
      else if (state !== "closed") setState("closed", "Disconnected");
    });
  }

  term.onData((data) => { if (state === "open") send(encoder.encode(data)); });
  term.onBinary((data) => {
    if (state !== "open") return;
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

  setInterval(() => {
    if (state === "open" && document.visibilityState === "visible") send(JSON.stringify({ type: "alive" }));
  }, ALIVE_EVERY);

  $("reconnect").addEventListener("click", () => {
    if (socket) socket.close();
    term.reset();
    connect();
  });

  /* In the admin page the window around the frame draws the bar (the
     agent, the state, Reconnect, Expand, Close) and moves and resizes the
     frame; this document then shows only the terminal, tells the page its
     state and does what the page's buttons ask. While the owner drags an
     edge the terminal still refits every frame, but the server hears the
     new size only once, when the drag ends. */
  function tellParent(message) {
    if (embedded) window.parent.postMessage(message, location.origin);
  }
  function refit() { try { fit.fit(); } catch { /* not laid out yet */ } }
  function sendSize(cols, rows) {
    told = `${cols}x${rows}`;
    send(JSON.stringify({ type: "resize", cols, rows }));
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
      if (data.command === "close") $("close").click();
      else if (data.command === "reconnect") $("reconnect").click();
      else if (data.command === "focus") term.focus();
    }
  });

  $("close").addEventListener("click", () => {
    send(JSON.stringify({ type: "close" }));
    if (socket) socket.close();
    socket = null;
    setState("closed", "Closed");
    tellParent({ type: "lore-terminal-close" });
  });

  connect();
  tellParent({ type: "lore-terminal-ready", state, text: $("state").textContent });
})();
