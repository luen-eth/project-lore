"use strict";

/* project-lore admin view: sign-in and the memory graph. No dependencies. */

const PALETTE = [
  "#5eb1ff", "#ff7a90", "#ffb454", "#7ee0a1", "#c79bff",
  "#4fd6d6", "#ff9e64", "#f2d35e", "#ff8ad8", "#9db4ff",
];
const KIND_LABEL = { update: "Update", decision: "Decision", bug: "Bug", note: "Note", todo: "Todo" };
const KIND_RADIUS = { update: 3.4, decision: 4.6, bug: 3.9, note: 3.1, todo: 3.4 };
const POLL_MS = 8000;
const REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const $ = (id) => document.getElementById(id);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

/* ---------- Graph ---------- */

class Graph {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.nodes = [];
    this.links = [];
    this.byId = new Map();
    this.neighbours = new Map();
    this.pulses = [];
    this.rings = [];
    this.sprites = new Map();
    this.view = { x: 0, y: 0, k: 1 };
    this.alpha = 0;
    this.hover = null;
    this.selected = null;
    this.focus = null; // Set of node keys to keep bright, or null for all
    this.onHover = () => {};
    this.onSelect = () => {};
    this.pointer = { down: false, moved: false, node: null, x: 0, y: 0 };
    this.touched = false;
    this.sidePanel = false; // true while the app chrome covers the left edge
    this.resize();
    window.addEventListener("resize", () => this.resize());
    this.bind();
    requestAnimationFrame((t) => this.frame(t));
  }

  resize() {
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    this.ratio = ratio;
    this.width = window.innerWidth;
    this.height = window.innerHeight;
    this.canvas.width = Math.round(this.width * ratio);
    this.canvas.height = Math.round(this.height * ratio);
    // Keep the whole graph framed until the user takes over the camera.
    if (this.nodes && !this.touched) this.fit();
  }

  /* nodes: [{key, kind:'hub'|'neuron', color, radius, label, hub, data}]
     links: [{source, target, kind:'hub'|'synapse', strength}] */
  setData(nodes, links, { fireNew = false } = {}) {
    const previous = this.byId;
    const hadNodes = previous.size > 0;
    this.byId = new Map();
    this.nodes = nodes.map((node) => {
      const old = previous.get(node.key);
      const placed = { ...node, vx: 0, vy: 0, fixed: false };
      if (old) {
        placed.x = old.x; placed.y = old.y;
      } else {
        const anchor = node.hub ? this.byId.get(node.hub) || previous.get(node.hub) : null;
        const angle = Math.random() * Math.PI * 2;
        const spread = node.kind === "hub" ? 260 * Math.sqrt(Math.random()) + 40 : 30 + Math.random() * 50;
        placed.x = (anchor ? anchor.x : 0) + Math.cos(angle) * spread;
        placed.y = (anchor ? anchor.y : 0) + Math.sin(angle) * spread;
        if (fireNew && hadNodes && node.kind === "neuron") this.rings.push({ node: placed, age: 0 });
      }
      this.byId.set(node.key, placed);
      return placed;
    });
    this.links = [];
    this.neighbours = new Map();
    for (const link of links) {
      const a = this.byId.get(link.source), b = this.byId.get(link.target);
      if (!a || !b) continue;
      this.links.push({ ...link, a, b });
      if (link.kind === "synapse") {
        if (!this.neighbours.has(a.key)) this.neighbours.set(a.key, []);
        if (!this.neighbours.has(b.key)) this.neighbours.set(b.key, []);
        this.neighbours.get(a.key).push({ node: b, strength: link.strength });
        this.neighbours.get(b.key).push({ node: a, strength: link.strength });
      }
    }
    for (const node of this.nodes) {
      if (node.kind === "neuron") {
        const degree = (this.neighbours.get(node.key) || []).length;
        node.radius = node.baseRadius + Math.min(degree, 6) * 0.45;
      }
    }
    if (this.selected) this.selected = this.byId.get(this.selected.key) || null;
    this.hover = null;
    this.pulses = [];
    this.alpha = hadNodes ? Math.max(this.alpha, 0.5) : 1;
    if (!hadNodes) {
      // Settle off-screen so the first paint is already organised.
      for (let i = 0; i < 220; i++) this.tick();
      this.touched = false;
      this.fit();
    }
  }

  fit() {
    if (!this.nodes.length) { this.view = { x: 0, y: 0, k: 1 }; return; }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const n of this.nodes) {
      minX = Math.min(minX, n.x); maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y); maxY = Math.max(maxY, n.y);
    }
    const wide = this.width > 760 && this.sidePanel;
    const padLeft = wide ? 310 : 40, padRight = 40, padTop = this.sidePanel ? 80 : 40, padBottom = 50;
    const w = Math.max(this.width - padLeft - padRight, 100);
    const h = Math.max(this.height - padTop - padBottom, 100);
    const k = Math.min(w / Math.max(maxX - minX, 200), h / Math.max(maxY - minY, 200), 1.7);
    this.view.k = k;
    this.view.x = padLeft + w / 2 - ((minX + maxX) / 2) * k;
    this.view.y = padTop + h / 2 - ((minY + maxY) / 2) * k;
  }

  tick() {
    const nodes = this.nodes, count = nodes.length;
    for (let i = 0; i < count; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < count; j++) {
        const b = nodes[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        let d2 = dx * dx + dy * dy;
        if (d2 > 90000) continue;
        if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.25; }
        const charge = (a.kind === "hub" ? 5 : 1) * (b.kind === "hub" ? 5 : 1);
        const force = (charge * 520) / (d2 + 40);
        const d = Math.sqrt(d2);
        const fx = (dx / d) * force, fy = (dy / d) * force;
        a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
      }
    }
    for (const link of this.links) {
      const { a, b } = link;
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const rest = link.kind === "hub" ? 46 + Math.sqrt(a.members || b.members || 1) * 11 : 58;
      const stiffness = link.kind === "hub" ? 0.05 : 0.02 + link.strength * 0.05;
      const pull = (d - rest) * stiffness;
      const fx = (dx / d) * pull, fy = (dy / d) * pull;
      a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
    }
    for (const n of nodes) {
      const gravity = n.kind === "hub" ? 0.012 : 0.004;
      n.vx -= n.x * gravity; n.vy -= n.y * gravity;
      if (n.fixed) { n.vx = 0; n.vy = 0; continue; }
      n.vx *= 0.82; n.vy *= 0.82;
      n.x += n.vx * this.alpha; n.y += n.vy * this.alpha;
    }
    this.alpha *= 0.992;
  }

  sprite(color) {
    if (this.sprites.has(color)) return this.sprites.get(color);
    const size = 64, canvas = document.createElement("canvas");
    canvas.width = canvas.height = size;
    const ctx = canvas.getContext("2d");
    const glow = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
    glow.addColorStop(0, "#ffffff");
    glow.addColorStop(0.16, color);
    glow.addColorStop(0.3, color + "66");
    glow.addColorStop(1, color + "00");
    ctx.fillStyle = glow;
    ctx.fillRect(0, 0, size, size);
    this.sprites.set(color, canvas);
    return canvas;
  }

  bright(node) {
    if (this.hover) {
      if (node === this.hover) return true;
      if (this.hover.kind === "hub") return node.hub === this.hover.key;
      return (this.neighbours.get(this.hover.key) || []).some((n) => n.node === node)
        || node.key === this.hover.hub;
    }
    if (this.focus) return this.focus.has(node.key);
    return true;
  }

  frame(time) {
    requestAnimationFrame((t) => this.frame(t));
    const dt = Math.min((time - (this.last || time)) / 1000, 0.05);
    this.last = time;
    if (this.alpha > 0.02) this.tick();

    const ctx = this.ctx, { x, y, k } = this.view;
    ctx.setTransform(this.ratio, 0, 0, this.ratio, 0, 0);
    ctx.clearRect(0, 0, this.width, this.height);
    const backdrop = ctx.createRadialGradient(
      this.width * 0.55, this.height * 0.45, 0,
      this.width * 0.55, this.height * 0.45, Math.max(this.width, this.height) * 0.75);
    backdrop.addColorStop(0, "#0b1222");
    backdrop.addColorStop(1, "#04060c");
    ctx.fillStyle = backdrop;
    ctx.fillRect(0, 0, this.width, this.height);
    if (!this.nodes.length) return;

    ctx.setTransform(this.ratio * k, 0, 0, this.ratio * k, this.ratio * x, this.ratio * y);
    const dimming = this.hover || this.focus;

    // Links, batched by colour and brightness.
    const batches = new Map();
    for (const link of this.links) {
      const lit = !dimming || (this.bright(link.a) && this.bright(link.b));
      const color = link.kind === "hub" ? link.a.color : link.b.color;
      const alpha = lit
        ? (link.kind === "hub" ? 0.16 : 0.2 + link.strength * 0.4)
        : 0.03;
      const key = color + "|" + alpha.toFixed(2) + "|" + link.kind;
      if (!batches.has(key)) batches.set(key, { color, alpha, kind: link.kind, lines: [] });
      batches.get(key).lines.push(link);
    }
    for (const batch of batches.values()) {
      ctx.beginPath();
      for (const { a, b } of batch.lines) { ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); }
      ctx.strokeStyle = batch.color;
      ctx.globalAlpha = batch.alpha;
      ctx.lineWidth = (batch.kind === "hub" ? 0.5 : 0.9) / Math.sqrt(k);
      ctx.stroke();
    }

    // Signals travelling along synapses.
    if (!REDUCED_MOTION) {
      const synapses = this.links.filter((l) => l.kind === "synapse");
      const wanted = Math.min(60, Math.ceil(synapses.length / 6));
      while (this.pulses.length < wanted && synapses.length) {
        const link = synapses[Math.floor(Math.random() * synapses.length)];
        this.pulses.push({ link, t: 0, speed: 0.35 + Math.random() * 0.5, reverse: Math.random() < 0.5 });
      }
      ctx.globalCompositeOperation = "lighter";
      this.pulses = this.pulses.filter((pulse) => {
        pulse.t += dt * pulse.speed;
        if (pulse.t >= 1) return false;
        const { a, b } = pulse.link;
        if (dimming && !(this.bright(a) && this.bright(b))) return true;
        const t = pulse.reverse ? 1 - pulse.t : pulse.t;
        const px = a.x + (b.x - a.x) * t, py = a.y + (b.y - a.y) * t;
        const size = 5 / Math.sqrt(k);
        ctx.globalAlpha = Math.sin(pulse.t * Math.PI) * 0.9;
        ctx.drawImage(this.sprite("#ffffff"), px - size, py - size, size * 2, size * 2);
        return true;
      });
      ctx.globalCompositeOperation = "source-over";
    }

    // Neurons and project hubs.
    ctx.globalCompositeOperation = "lighter";
    for (const node of this.nodes) {
      const lit = !dimming || this.bright(node);
      const breathing = REDUCED_MOTION ? 1 : 1 + Math.sin(time / 900 + node.phase) * 0.07;
      const r = node.radius * (node === this.hover || node === this.selected ? 1.5 : 1) * breathing;
      const glow = r * (node.kind === "hub" ? 2.5 : 3.2);
      ctx.globalAlpha = lit ? (node.hollow ? 0.55 : 1) : 0.1;
      ctx.drawImage(this.sprite(node.color), node.x - glow, node.y - glow, glow * 2, glow * 2);
    }
    ctx.globalCompositeOperation = "source-over";

    // Rings: selection, open todos, and freshly logged entries.
    ctx.lineWidth = 1.2 / Math.sqrt(k);
    for (const node of this.nodes) {
      const lit = !dimming || this.bright(node);
      if (node === this.selected) {
        ctx.globalAlpha = 0.95; ctx.strokeStyle = "#ffffff";
        ctx.beginPath(); ctx.arc(node.x, node.y, node.radius * 2.4, 0, Math.PI * 2); ctx.stroke();
      } else if (node.hollow || node.kind === "hub") {
        ctx.globalAlpha = lit ? (node.kind === "hub" ? 0.5 : 0.8) : 0.08;
        ctx.strokeStyle = node.color;
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius * (node.kind === "hub" ? 1.7 : 1.5), 0, Math.PI * 2);
        ctx.stroke();
      }
    }
    this.rings = this.rings.filter((ring) => {
      ring.age += dt;
      if (ring.age > 2.4) return false;
      const p = ring.age / 2.4;
      ctx.globalAlpha = (1 - p) * 0.9; ctx.strokeStyle = ring.node.color;
      ctx.lineWidth = 2 / Math.sqrt(k);
      ctx.beginPath(); ctx.arc(ring.node.x, ring.node.y, ring.node.radius + p * 46, 0, Math.PI * 2); ctx.stroke();
      return true;
    });

    // Labels: projects always, entries when zoomed in.
    ctx.textAlign = "center";
    for (const node of this.nodes) {
      const lit = !dimming || this.bright(node);
      if (node.kind === "hub") {
        ctx.globalAlpha = lit ? 0.92 : 0.15;
        ctx.fillStyle = "#e7ecf7";
        ctx.font = `600 ${12.5 / k}px ui-sans-serif, system-ui, sans-serif`;
        ctx.fillText(node.label, node.x, node.y - node.radius * 2 - 7 / k);
      } else if (k > 2.1 && lit) {
        ctx.globalAlpha = Math.min((k - 2.1) * 1.6, 0.75);
        ctx.fillStyle = "#c5cee0";
        ctx.font = `${10.5 / k}px ui-sans-serif, system-ui, sans-serif`;
        const text = node.label.length > 34 ? node.label.slice(0, 33) + "…" : node.label;
        ctx.fillText(text, node.x, node.y + node.radius + 12 / k);
      }
    }
    ctx.globalAlpha = 1;
  }

  toWorld(px, py) {
    return { x: (px - this.view.x) / this.view.k, y: (py - this.view.y) / this.view.k };
  }

  toScreen(node) {
    return { x: node.x * this.view.k + this.view.x, y: node.y * this.view.k + this.view.y };
  }

  nodeAt(px, py) {
    const point = this.toWorld(px, py);
    let best = null, bestDistance = Infinity;
    for (const node of this.nodes) {
      const reach = Math.max(node.radius * 1.8, 9 / this.view.k);
      const d = Math.hypot(node.x - point.x, node.y - point.y);
      if (d < reach && d < bestDistance) { best = node; bestDistance = d; }
    }
    return best;
  }

  centerOn(node) {
    const wide = this.width > 760;
    const targetX = wide ? (310 + this.width - 430) / 2 : this.width / 2;
    const targetY = this.height / 2;
    this.touched = true;
    const k = Math.max(this.view.k, 1.6);
    const from = { ...this.view }, to = { k, x: targetX - node.x * k, y: targetY - node.y * k };
    const started = performance.now();
    const step = (now) => {
      const p = Math.min((now - started) / 450, 1), e = 1 - Math.pow(1 - p, 3);
      this.view.k = from.k + (to.k - from.k) * e;
      this.view.x = from.x + (to.x - from.x) * e;
      this.view.y = from.y + (to.y - from.y) * e;
      if (p < 1) requestAnimationFrame(step);
    };
    if (REDUCED_MOTION) this.view = to; else requestAnimationFrame(step);
  }

  bind() {
    const canvas = this.canvas, pointer = this.pointer;
    canvas.addEventListener("pointerdown", (event) => {
      canvas.setPointerCapture(event.pointerId);
      pointer.down = true; pointer.moved = false;
      pointer.x = event.clientX; pointer.y = event.clientY;
      pointer.node = this.nodeAt(event.clientX, event.clientY);
      if (pointer.node) pointer.node.fixed = true;
      canvas.classList.add("dragging");
    });
    canvas.addEventListener("pointermove", (event) => {
      if (pointer.down) {
        const dx = event.clientX - pointer.x, dy = event.clientY - pointer.y;
        if (Math.abs(dx) + Math.abs(dy) > 3) pointer.moved = true;
        pointer.x = event.clientX; pointer.y = event.clientY;
        if (pointer.node) {
          pointer.node.x += dx / this.view.k; pointer.node.y += dy / this.view.k;
          this.alpha = Math.max(this.alpha, 0.3);
        } else {
          this.view.x += dx; this.view.y += dy;
          this.touched = true;
        }
        return;
      }
      const node = this.nodeAt(event.clientX, event.clientY);
      if (node !== this.hover) {
        this.hover = node;
        canvas.classList.toggle("pointing", !!node);
      }
      this.onHover(node, event.clientX, event.clientY);
    });
    const release = (event) => {
      if (!pointer.down) return;
      pointer.down = false;
      canvas.classList.remove("dragging");
      if (pointer.node) pointer.node.fixed = false;
      if (!pointer.moved && event.type === "pointerup") this.onSelect(pointer.node);
      pointer.node = null;
    };
    canvas.addEventListener("pointerup", release);
    canvas.addEventListener("pointercancel", release);
    canvas.addEventListener("pointerleave", () => { this.hover = null; this.onHover(null); });
    canvas.addEventListener("wheel", (event) => {
      event.preventDefault();
      const factor = Math.exp(-event.deltaY * 0.0015);
      const k = Math.min(Math.max(this.view.k * factor, 0.15), 6);
      const scale = k / this.view.k;
      this.view.x = event.clientX - (event.clientX - this.view.x) * scale;
      this.view.y = event.clientY - (event.clientY - this.view.y) * scale;
      this.view.k = k;
      this.touched = true;
    }, { passive: false });
  }
}

/* ---------- Data shaping ---------- */

function relative(seconds) {
  if (seconds === null || seconds === undefined) return "never connected";
  if (seconds < 60) return "just now";
  if (seconds < 3600) return Math.floor(seconds / 60) + " min ago";
  if (seconds < 86400) return Math.floor(seconds / 3600) + " h ago";
  return Math.floor(seconds / 86400) + " d ago";
}

function shortDate(iso) {
  const date = new Date(iso);
  return isNaN(date) ? iso : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function projectColors(neurons) {
  const counts = new Map();
  for (const n of neurons) counts.set(n.project, (counts.get(n.project) || 0) + 1);
  const ordered = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const colors = new Map();
  ordered.forEach(([project], index) => colors.set(project, PALETTE[index % PALETTE.length]));
  return { counts: ordered, colors };
}

function toGraph(brain, colors, counts) {
  const nodes = [], links = [];
  for (const [project, members] of counts) {
    nodes.push({
      key: "p:" + project, kind: "hub", color: colors.get(project), label: project,
      radius: 6 + Math.min(Math.sqrt(members), 8), members, phase: Math.random() * 6.28,
    });
  }
  for (const neuron of brain.neurons) {
    const radius = KIND_RADIUS[neuron.kind] || 3.3;
    nodes.push({
      key: "n:" + neuron.id, kind: "neuron", color: colors.get(neuron.project), label: neuron.title,
      radius, baseRadius: radius, hub: "p:" + neuron.project, hollow: neuron.kind === "todo",
      phase: Math.random() * 6.28, data: neuron,
    });
    links.push({ source: "p:" + neuron.project, target: "n:" + neuron.id, kind: "hub", strength: 0 });
  }
  for (const synapse of brain.synapses) {
    links.push({ source: "n:" + synapse.source, target: "n:" + synapse.target, kind: "synapse", strength: synapse.similarity });
  }
  return { nodes, links };
}

/* A decorative network shown behind the sign-in form. It contains no data. */
function decorativeGraph() {
  const nodes = [], links = [];
  for (let c = 0; c < 6; c++) {
    nodes.push({ key: "p:" + c, kind: "hub", color: PALETTE[c], label: "", radius: 7, members: 14, phase: c });
    for (let i = 0; i < 16; i++) {
      const key = "n:" + c + ":" + i;
      nodes.push({ key, kind: "neuron", color: PALETTE[c], label: "", radius: 3.4, baseRadius: 3.4, hub: "p:" + c, phase: Math.random() * 6.28 });
      links.push({ source: "p:" + c, target: key, kind: "hub", strength: 0 });
      if (i > 0 && Math.random() < 0.7) {
        links.push({ source: key, target: "n:" + c + ":" + Math.floor(Math.random() * i), kind: "synapse", strength: 0.7 });
      }
      if (Math.random() < 0.12) {
        links.push({ source: key, target: "n:" + ((c + 1) % 6) + ":0", kind: "synapse", strength: 0.6 });
      }
    }
  }
  return { nodes, links };
}

/* ---------- App ---------- */

const graph = new Graph($("graph"));
const state = {
  version: null, brain: null, colors: new Map(), counts: [],
  filter: null, // { type: 'project' | 'agent', value }
  query: "", timer: null, siteKey: null, decorative: false,
};

async function api(path, options) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  if (response.status === 401 && !path.endsWith("/login")) {
    showLogin();
    throw new Error("signed out");
  }
  return response;
}

function showLogin() {
  clearInterval(state.timer);
  state.version = null; state.brain = null;
  $("app").hidden = true;
  $("login").hidden = false;
  if (!state.decorative) {
    graph.byId = new Map(); graph.selected = null; graph.focus = null;
    graph.sidePanel = false;
    const fake = decorativeGraph();
    graph.setData(fake.nodes, fake.links);
    state.decorative = true;
  }
  $("password").focus();
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

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("login-button"), error = $("login-error");
  button.disabled = true; error.textContent = "";
  try {
    const captcha = await captchaToken();
    const response = await api("/admin/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: $("password").value, captcha }),
    });
    if (response.ok) {
      $("password").value = "";
      await enter();
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

$("logout").addEventListener("click", async () => {
  await fetch("/admin/api/logout", { method: "POST", credentials: "same-origin" });
  showLogin();
});

async function enter() {
  $("login").hidden = true;
  $("app").hidden = false;
  graph.byId = new Map();
  graph.sidePanel = true;
  state.decorative = false;
  await refresh(true);
  clearInterval(state.timer);
  state.timer = setInterval(poll, POLL_MS);
}

async function poll() {
  if (document.hidden) return;
  try {
    const pulse = await (await api("/admin/api/pulse")).json();
    renderAgents(pulse.agents);
    if (pulse.version !== state.version) await refresh(false);
  } catch (_) { /* signed out or offline; the next poll retries */ }
}

async function refresh(first) {
  const payload = await (await api("/admin/api/brain")).json();
  state.version = payload.version;
  state.brain = payload.brain;
  const { counts, colors } = projectColors(payload.brain.neurons);
  state.counts = counts; state.colors = colors;
  const { nodes, links } = toGraph(payload.brain, colors, counts);
  graph.setData(nodes, links, { fireNew: !first });
  renderAgents(payload.agents);
  renderProjects();
  renderActivity(payload.brain.activity);
  renderSummary(payload);
  applyFocus();
  $("empty").hidden = payload.brain.neurons.length > 0;
}

function renderSummary(payload) {
  const brain = payload.brain;
  const shown = brain.neurons.length < brain.total_entries ? ` (newest ${brain.neurons.length} shown)` : "";
  const model = payload.embedding_model ? ` · ${payload.embedding_model}` : " · keyword search only";
  $("summary").textContent =
    `${brain.total_entries} memories${shown} · ${brain.synapses.length} links · ${state.counts.length} projects${model}`;
}

function listItem(leading, name, count, sub, active, onClick) {
  const item = el("li");
  item.tabIndex = 0;
  item.setAttribute("role", "button");
  if (active) item.classList.add("active");
  item.append(leading, el("span", "name", name), el("span", "count", count));
  if (sub) item.append(el("span", "sub", sub));
  item.addEventListener("click", onClick);
  item.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onClick(); }
  });
  return item;
}

function toggleFilter(type, value) {
  const same = state.filter && state.filter.type === type && state.filter.value === value;
  state.filter = same ? null : { type, value };
  renderProjects();
  renderAgents(state.agents || []);
  applyFocus();
}

function renderAgents(agents) {
  state.agents = agents;
  const list = $("agents");
  list.replaceChildren();
  if (!agents.length) {
    list.append(el("li", "none", "No agent has connected yet."));
    return;
  }
  for (const agent of agents) {
    const dot = el("span", "dot");
    const seen = agent.seconds_since_seen;
    if (seen !== null && seen < 300) dot.classList.add("online");
    else if (seen !== null && seen < 86400) dot.classList.add("recent");
    dot.title = seen !== null && seen < 300 ? "Active in the last 5 minutes" : "Idle";
    const details = [relative(seen)];
    if (agent.client) details.push(agent.client);
    const active = state.filter && state.filter.type === "agent" && state.filter.value === agent.name;
    list.append(listItem(dot, agent.name, `${agent.entries}`, details.join(" · "), active,
      () => toggleFilter("agent", agent.name)));
  }
}

function renderProjects() {
  const list = $("projects");
  list.replaceChildren();
  if (!state.counts.length) {
    list.append(el("li", "none", "Nothing logged yet."));
    return;
  }
  for (const [project, count] of state.counts) {
    const swatch = el("span", "swatch");
    swatch.style.background = state.colors.get(project);
    swatch.style.boxShadow = `0 0 10px ${state.colors.get(project)}`;
    const active = state.filter && state.filter.type === "project" && state.filter.value === project;
    list.append(listItem(swatch, project, `${count}`, "", active, () => toggleFilter("project", project)));
  }
}

function renderActivity(activity) {
  const byDay = new Map(activity);
  const box = $("activity");
  box.replaceChildren();
  const days = [];
  for (let i = 29; i >= 0; i--) {
    const day = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    days.push([day, byDay.get(day) || 0]);
  }
  const peak = Math.max(1, ...days.map((d) => d[1]));
  let total = 0;
  for (const [day, count] of days) {
    total += count;
    const bar = el("i", count ? "has" : "");
    bar.style.height = Math.max(4, (count / peak) * 100) + "%";
    bar.title = `${day}: ${count}`;
    box.append(bar);
  }
  $("activity-note").textContent = `${total} entries logged`;
}

function applyFocus() {
  const query = state.query.trim().toLowerCase();
  if (!state.brain || (!query && !state.filter)) { graph.focus = null; return; }
  const focus = new Set();
  for (const neuron of state.brain.neurons) {
    if (state.filter && state.filter.type === "project" && neuron.project !== state.filter.value) continue;
    if (state.filter && state.filter.type === "agent" && neuron.agent !== state.filter.value) continue;
    if (query) {
      const haystack = `${neuron.title} ${neuron.tags} ${neuron.project} ${neuron.kind} ${neuron.agent}`.toLowerCase();
      if (!haystack.includes(query)) continue;
    }
    focus.add("n:" + neuron.id);
    focus.add("p:" + neuron.project);
  }
  graph.focus = focus;
}

$("search").addEventListener("input", (event) => { state.query = event.target.value; applyFocus(); });

$("panel-toggle").addEventListener("click", () => {
  const open = $("side").classList.toggle("open");
  $("panel-toggle").setAttribute("aria-expanded", String(open));
});

/* Tooltip and detail drawer */

graph.onHover = (node, x, y) => {
  const tip = $("tooltip");
  if (!node || state.decorative) { tip.hidden = true; return; }
  tip.replaceChildren();
  if (node.kind === "hub") {
    tip.append(el("div", "", node.label), el("div", "sub", `${node.members} memories`));
  } else {
    tip.append(el("div", "", node.data.title),
      el("div", "sub", `${KIND_LABEL[node.data.kind] || node.data.kind} · ${node.data.project}` +
        (node.data.agent ? ` · ${node.data.agent}` : "")));
  }
  tip.hidden = false;
  const box = tip.getBoundingClientRect();
  tip.style.left = Math.min(x + 14, window.innerWidth - box.width - 8) + "px";
  tip.style.top = Math.min(y + 14, window.innerHeight - box.height - 8) + "px";
};

graph.onSelect = (node) => {
  if (state.decorative) return;
  if (!node) { closeDetail(); return; }
  if (node.kind === "hub") { toggleFilter("project", node.label); return; }
  openDetail(node);
};

function closeDetail() {
  $("detail").hidden = true;
  graph.selected = null;
}
$("detail-close").addEventListener("click", closeDetail);
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeDetail(); });

async function openDetail(node) {
  graph.selected = node;
  graph.centerOn(node);
  $("tooltip").hidden = true;
  const box = $("detail-body");
  box.replaceChildren(el("p", "muted", "Loading…"));
  $("detail").hidden = false;
  let entry;
  try {
    const response = await api(`/admin/api/entries/${node.data.id}`);
    if (!response.ok) throw new Error("gone");
    entry = await response.json();
  } catch (_) {
    box.replaceChildren(el("p", "muted", "This entry could not be loaded. It may have been deleted."));
    return;
  }
  if (graph.selected !== node) return;
  box.replaceChildren();

  const badge = el("span", "badge", KIND_LABEL[entry.kind] || entry.kind);
  badge.style.color = node.color;
  box.append(badge, el("h3", "", entry.title));
  const meta = [`#${entry.id}`, entry.project, shortDate(entry.created_at)];
  if (entry.agent) meta.push(`by ${entry.agent}`);
  if (entry.updated_at) meta.push(`amended ${shortDate(entry.updated_at)}`);
  box.append(el("div", "meta", meta.join(" · ")), el("p", "body", entry.body));

  const chips = (title, text, className) => {
    const items = text.split(",").map((s) => s.trim()).filter(Boolean);
    if (!items.length) return;
    const row = el("div", "chips");
    for (const item of items) row.append(el("span", className, item));
    box.append(el("h4", "", title), row);
  };
  chips("Tags", entry.tags, "chip");
  chips("Files", entry.files, "chip file");

  const related = (graph.neighbours.get(node.key) || []).slice().sort((a, b) => b.strength - a.strength);
  if (related.length) {
    const list = el("ul", "related");
    for (const { node: other, strength } of related) {
      const item = el("li");
      item.tabIndex = 0;
      item.append(el("span", "", other.data.title), el("span", "pct", Math.round(strength * 100) + "%"));
      item.addEventListener("click", () => openDetail(other));
      item.addEventListener("keydown", (event) => { if (event.key === "Enter") openDetail(other); });
      list.append(item);
    }
    box.append(el("h4", "", "Related memories"), list);
  }
}

/* Boot */

(async () => {
  try {
    const session = await (await fetch("/admin/api/session", { credentials: "same-origin" })).json();
    state.siteKey = session.recaptcha_site_key;
    loadRecaptcha(state.siteKey);
    if (session.authenticated) await enter(); else showLogin();
  } catch (_) {
    showLogin();
    $("login-error").textContent = "The server cannot be reached.";
  }
})();
