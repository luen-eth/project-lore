/* The terminal overlay's document. It opens one WebSocket to lore, which
   relays it to one PTY in a built-in agent's container: typed bytes go out
   as binary frames, the terminal's bytes come back as binary frames, and
   open, resize, keep-alive, close and the end travel as small JSON text
   frames. Closing the socket (Close, or the frame being removed) closes the
   terminal and kills what runs in it.

   Every key goes to the terminal, Escape included, so the overlay closes
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
  const encoder = new TextEncoder();

  function setState(name, text) {
    state = name;
    const node = $("state");
    node.className = "state " + name;
    node.textContent = text;
    node.title = text;
    $("reconnect").hidden = name !== "closed";
    $("screen").classList.toggle("ended", name === "closed");
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
  term.onResize(({ cols, rows }) => send(JSON.stringify({ type: "resize", cols, rows })));

  // The terminal follows the frame's size (the window, a phone turned).
  let pending = 0;
  new ResizeObserver(() => {
    cancelAnimationFrame(pending);
    pending = requestAnimationFrame(() => { try { fit.fit(); } catch { /* not laid out yet */ } });
  }).observe($("screen"));

  setInterval(() => {
    if (state === "open" && document.visibilityState === "visible") send(JSON.stringify({ type: "alive" }));
  }, ALIVE_EVERY);

  $("reconnect").addEventListener("click", () => {
    if (socket) socket.close();
    term.reset();
    connect();
  });

  /* Docked in the side column or expanded: the admin page says which, and
     whether docking is possible at its width; Expand / Dock asks it to
     switch. The terminal refits through the ResizeObserver above. */
  let layout = "expanded";
  window.addEventListener("message", (event) => {
    if (event.origin !== location.origin || event.source !== window.parent) return;
    const data = event.data || {};
    if (data.type !== "lore-terminal-layout") return;
    layout = data.mode === "docked" ? "docked" : "expanded";
    document.body.classList.toggle("docked", layout === "docked");
    const button = $("layout");
    button.hidden = !data.canDock;
    button.textContent = layout === "docked" ? "Expand" : "Dock";
    button.title = layout === "docked"
      ? "Show the terminal large, over the page"
      : "Put the terminal in the side column, under Live activity";
  });
  $("layout").addEventListener("click", () => {
    if (window.parent === window) return;
    window.parent.postMessage({
      type: "lore-terminal-mode", mode: layout === "docked" ? "expanded" : "docked",
    }, location.origin);
  });
  if (window.parent !== window) window.parent.postMessage({ type: "lore-terminal-ready" }, location.origin);

  $("close").addEventListener("click", () => {
    send(JSON.stringify({ type: "close" }));
    if (socket) socket.close();
    socket = null;
    setState("closed", "Closed");
    if (window.parent !== window) window.parent.postMessage({ type: "lore-terminal-close" }, location.origin);
  });

  connect();
})();
