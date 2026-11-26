"use strict";

/* project-lore admin view: sign-in, the memory graph and the live activity
   feed. No dependencies. */

const PROJECT_COLORS = [
  "#5eb1ff", "#ff7a90", "#7ee0a1", "#c79bff", "#4fd6d6",
  "#ff9e64", "#f2d35e", "#ff8ad8", "#9db4ff", "#8fd3a0",
];
const AGENT_COLORS = ["#ffd479", "#8be9fd", "#ff9ecd", "#b4f8c8", "#d0b3ff", "#ffab70"];
const KINDS = ["update", "decision", "bug", "note", "todo"];
const KIND_LABEL = { update: "Update", decision: "Decision", bug: "Bug", note: "Note", todo: "Todo" };
const KIND_RADIUS = { update: 3.4, decision: 4.6, bug: 3.9, note: 3.1, todo: 3.4 };
const TOOLS = {
  hello: { verb: "opened a session", tone: "write" },
  checkin: { verb: "checked in", tone: "write" },
  bye: { verb: "closed the session", tone: "remove" },
  log: { verb: "logged", tone: "write" },
  amend: { verb: "amended", tone: "write" },
  forget: { verb: "deleted", tone: "remove" },
  recall: { verb: "searched", tone: "read" },
  recent: { verb: "checked recent work", tone: "read" },
  projects: { verb: "listed projects", tone: "read" },
  get: { verb: "read", tone: "read" },
  profile: { verb: "updated the profile", tone: "write" },
  rules: { verb: "edited the rules", tone: "write" },
  import: { verb: "imported a backup", tone: "write" },
  restore: { verb: "restored a backup", tone: "remove" },
  reindex: { verb: "re-indexed memories", tone: "write" },
  task_add: { verb: "added a task", tone: "write" },
  task_update: { verb: "updated a task", tone: "write" },
  tasks: { verb: "looked at the tasks", tone: "read" },
  send: { verb: "sent a message", tone: "write" },
  handoff: { verb: "left a handoff note", tone: "write" },
  inbox: { verb: "read the inbox", tone: "read" },
  file_save: { verb: "saved a file", tone: "write" },
  file_get: { verb: "read a file", tone: "read" },
  files: { verb: "looked at the files", tone: "read" },
  file_delete: { verb: "deleted a file", tone: "remove" },
  integrations: { verb: "looked at the integrations", tone: "read" },
  cloudflare: { verb: "called Cloudflare", tone: "write" },
  github: { verb: "called GitHub (personal)", tone: "write" },
  github_org: { verb: "called GitHub (organization)", tone: "write" },
  git_server: { verb: "called the git server", tone: "write" },
  dokploy: { verb: "called Dokploy", tone: "write" },
  mail: { verb: "looked at the mailbox", tone: "read" },
  git_fetch: { verb: "fetched a repository", tone: "read" },
  git_push: { verb: "pushed to a repository", tone: "write" },
  users: { verb: "changed the users", tone: "write" },
  authorize: { verb: "authorized an agent", tone: "write" },
  revoke: { verb: "revoked an authorization", tone: "remove" },
  disable: { verb: "disabled an agent", tone: "remove" },
  enable: { verb: "enabled an agent", tone: "write" },
};
const WRITES = new Set([
  "hello", "checkin", "bye", "log", "amend", "forget", "profile", "rules", "import", "restore", "reindex",
  "task_add", "task_update", "send", "handoff", "file_save", "file_delete",
  "cloudflare", "github", "github_org", "git_server", "dokploy", "git_push", "users",
]);
/* The permission ids the server knows; a signed-in user holds some of them. */
const ALL_PERMISSIONS = ["write", "backup", "restore", "settings", "integrations", "agents", "users"];
const FALLBACK_POLL_MS = 30000;
const FEED_MAX = 120;
const REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const $ = (id) => document.getElementById(id);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

/* The ten built-in avatars, in the server's order. An agent without a
   chosen one shows the one its name derives: FNV-1a over the name's UTF-8
   bytes, as the server computes it. */
const AVATAR_IDS = ["orbit", "comet", "nova", "prism", "wave", "ember", "lattice", "crescent", "pulsar", "hexa"];

function defaultAvatar(name) {
  let hash = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(name)) {
    hash = Math.imul(hash ^ byte, 0x01000193) >>> 0;
  }
  return AVATAR_IDS[hash % AVATAR_IDS.length];
}

function avatarOf(name) {
  const known = state.agents.find((agent) => agent.name === name);
  return (known && known.avatar) || defaultAvatar(name);
}

/* An agent's avatar picture; `className` adds "small" and the like. */
function avatarNode(name, className, id) {
  const holder = el("span", "avatar pic" + (className ? " " + className : ""));
  const image = el("img");
  image.src = `/admin/avatars/${id || avatarOf(name)}.svg`;
  image.alt = "";
  image.decoding = "async";
  holder.append(image);
  return holder;
}

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
    this.beams = [];
    this.sprites = new Map();
    this.view = { x: 0, y: 0, k: 1 };
    this.alpha = 0;
    this.hover = null;
    this.selected = null;
    this.focus = null; // Set of node keys to keep bright, or null for all
    this.onCamera = () => {};
    this.onHover = () => {};
    this.onSelect = () => {};
    this.pointer = { down: false, moved: false, node: null, x: 0, y: 0 };
    this.touched = false;
    this.chrome = false; // true while the side columns cover the edges
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

  /* nodes: [{key, kind:'hub'|'neuron'|'agent', color, radius, label, hub, data}]
     links: [{source, target, kind:'hub'|'synapse'|'agent', strength}] */
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
        let spread = 30 + Math.random() * 50;
        if (node.kind === "hub") spread = 260 * Math.sqrt(Math.random()) + 40;
        if (node.kind === "agent") spread = 380 + Math.random() * 60;
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
    this.beams = this.beams.filter((beam) => this.byId.has(beam.a.key) && this.byId.has(beam.b.key))
      .map((beam) => ({ ...beam, a: this.byId.get(beam.a.key), b: this.byId.get(beam.b.key) }));
    this.alpha = hadNodes ? Math.max(this.alpha, 0.5) : 1;
    if (!hadNodes) {
      // Settle off-screen so the first paint is already organised.
      for (let i = 0; i < 240; i++) this.tick();
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
    const padLeft = this.chrome && this.width > 760 ? 336 : 40;
    const padRight = this.chrome && this.width > 1180 ? 380 : 40;
    const padTop = this.chrome ? 84 : 40, padBottom = this.chrome ? 84 : 48;
    const w = Math.max(this.width - padLeft - padRight, 100);
    const h = Math.max(this.height - padTop - padBottom, 100);
    const k = Math.min(w / Math.max(maxX - minX, 200), h / Math.max(maxY - minY, 200), 1.7);
    this.view.k = k;
    this.view.x = padLeft + w / 2 - ((minX + maxX) / 2) * k;
    this.view.y = padTop + h / 2 - ((minY + maxY) / 2) * k;
  }

  tick() {
    const nodes = this.nodes, count = nodes.length;
    const weight = (n) => (n.kind === "neuron" ? 1 : 5);
    for (let i = 0; i < count; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < count; j++) {
        const b = nodes[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        let d2 = dx * dx + dy * dy;
        if (d2 > 90000) continue;
        if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.25; }
        const force = (weight(a) * weight(b) * 520) / (d2 + 40);
        const d = Math.sqrt(d2);
        const fx = (dx / d) * force, fy = (dy / d) * force;
        a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
      }
    }
    for (const link of this.links) {
      const { a, b } = link;
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
      let rest = 58, stiffness = 0.02 + link.strength * 0.05;
      if (link.kind === "hub") { rest = 46 + Math.sqrt(a.members || b.members || 1) * 11; stiffness = 0.05; }
      if (link.kind === "agent") { rest = 230; stiffness = 0.008; }
      const pull = (d - rest) * stiffness;
      const fx = (dx / d) * pull, fy = (dy / d) * pull;
      a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
    }
    for (const n of nodes) {
      const gravity = n.kind === "hub" ? 0.012 : n.kind === "agent" ? 0.0025 : 0.004;
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
      if (this.hover.kind === "agent") return node.data && node.data.agent === this.hover.label;
      return (this.neighbours.get(this.hover.key) || []).some((n) => n.node === node)
        || node.key === this.hover.hub;
    }
    if (this.focus) return this.focus.has(node.key);
    return true;
  }

  /* An agent reaching for an entry: a streak of light from a to b. */
  beam(fromKey, toKey, color) {
    const a = this.byId.get(fromKey), b = this.byId.get(toKey);
    if (!b) return;
    if (!a || REDUCED_MOTION) { this.rings.push({ node: b, age: 0, color }); return; }
    this.beams.push({ a, b, color, t: 0 });
  }

  ring(key, color) {
    const node = this.byId.get(key);
    if (node) this.rings.push({ node, age: 0, color });
  }

  frame(time) {
    requestAnimationFrame((t) => this.frame(t));
    const dt = Math.min((time - (this.last || time)) / 1000, 0.05);
    this.last = time;
    if (this.alpha > 0.02) this.tick();

    const ctx = this.ctx, { x, y, k } = this.view;
    this.onCamera(x, y, k);
    ctx.setTransform(this.ratio, 0, 0, this.ratio, 0, 0);
    ctx.clearRect(0, 0, this.width, this.height);
    if (!this.nodes.length) return;

    ctx.setTransform(this.ratio * k, 0, 0, this.ratio * k, this.ratio * x, this.ratio * y);
    const dimming = this.hover || this.focus;
    const thin = 1 / Math.sqrt(k);

    // Links, batched by colour and brightness.
    const batches = new Map();
    for (const link of this.links) {
      const lit = !dimming || (this.bright(link.a) && this.bright(link.b));
      const color = link.kind === "synapse" ? link.b.color : link.a.color;
      let alpha = 0.03;
      if (lit) alpha = link.kind === "hub" ? 0.16 : link.kind === "agent" ? 0.1 : 0.2 + link.strength * 0.4;
      const key = color + "|" + alpha.toFixed(2) + "|" + link.kind;
      if (!batches.has(key)) batches.set(key, { color, alpha, kind: link.kind, lines: [] });
      batches.get(key).lines.push(link);
    }
    for (const batch of batches.values()) {
      ctx.beginPath();
      for (const { a, b } of batch.lines) { ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); }
      ctx.strokeStyle = batch.color;
      ctx.globalAlpha = batch.alpha;
      ctx.lineWidth = (batch.kind === "synapse" ? 0.9 : 0.5) * thin;
      ctx.setLineDash(batch.kind === "agent" ? [3 * thin, 5 * thin] : []);
      ctx.stroke();
    }
    ctx.setLineDash([]);

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
        const size = 5 * thin;
        ctx.globalAlpha = Math.sin(pulse.t * Math.PI) * 0.9;
        ctx.drawImage(this.sprite("#ffffff"), px - size, py - size, size * 2, size * 2);
        return true;
      });
      ctx.globalCompositeOperation = "source-over";
    }

    // Nodes.
    ctx.globalCompositeOperation = "lighter";
    for (const node of this.nodes) {
      const lit = !dimming || this.bright(node);
      const breathing = REDUCED_MOTION ? 1 : 1 + Math.sin(time / 900 + node.phase) * 0.07;
      const r = node.radius * (node === this.hover || node === this.selected ? 1.5 : 1) * breathing;
      const glow = r * (node.kind === "neuron" ? 3.2 : 2.5);
      ctx.globalAlpha = lit ? (node.hollow ? 0.55 : 1) : 0.1;
      ctx.drawImage(this.sprite(node.color), node.x - glow, node.y - glow, glow * 2, glow * 2);
    }
    ctx.globalCompositeOperation = "source-over";

    // Outlines: selection, open todos, project hubs and agents.
    for (const node of this.nodes) {
      const lit = !dimming || this.bright(node);
      ctx.lineWidth = 1.2 * thin;
      if (node === this.selected) {
        ctx.globalAlpha = 0.95; ctx.strokeStyle = "#ffffff";
        ctx.beginPath(); ctx.arc(node.x, node.y, node.radius * 2.4, 0, Math.PI * 2); ctx.stroke();
      } else if (node.kind === "agent") {
        // Agents are diamonds, so they never read as a memory or a project.
        const s = node.radius * 1.9;
        ctx.globalAlpha = lit ? 0.9 : 0.12; ctx.strokeStyle = node.color;
        ctx.beginPath();
        ctx.moveTo(node.x, node.y - s); ctx.lineTo(node.x + s, node.y);
        ctx.lineTo(node.x, node.y + s); ctx.lineTo(node.x - s, node.y); ctx.closePath();
        ctx.stroke();
        if (node.online && !REDUCED_MOTION) {
          const p = (time / 1600 + node.phase) % 1;
          ctx.globalAlpha = (1 - p) * (lit ? 0.5 : 0.08);
          ctx.beginPath(); ctx.arc(node.x, node.y, s + p * 16, 0, Math.PI * 2); ctx.stroke();
        }
      } else if (node.hollow || node.kind === "hub") {
        ctx.globalAlpha = lit ? (node.kind === "hub" ? 0.5 : 0.8) : 0.08;
        ctx.strokeStyle = node.color;
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius * (node.kind === "hub" ? 1.7 : 1.5), 0, Math.PI * 2);
        ctx.stroke();
      }
    }

    // Beams from agents to the entries they touch.
    ctx.globalCompositeOperation = "lighter";
    this.beams = this.beams.filter((beam) => {
      beam.t += dt / 0.85;
      const head = Math.min(beam.t, 1), tail = Math.max(0, head - 0.35);
      const ease = (v) => 1 - Math.pow(1 - v, 2);
      const at = (v) => ({
        x: beam.a.x + (beam.b.x - beam.a.x) * ease(v),
        y: beam.a.y + (beam.b.y - beam.a.y) * ease(v),
      });
      const from = at(tail), to = at(head);
      const fade = beam.t > 1 ? Math.max(0, 1 - (beam.t - 1) * 3) : 1;
      const stroke = ctx.createLinearGradient(from.x, from.y, to.x, to.y);
      stroke.addColorStop(0, beam.color + "00");
      stroke.addColorStop(1, beam.color);
      ctx.globalAlpha = fade; ctx.strokeStyle = stroke; ctx.lineWidth = 2.2 * thin;
      ctx.beginPath(); ctx.moveTo(from.x, from.y); ctx.lineTo(to.x, to.y); ctx.stroke();
      const size = 9 * thin;
      ctx.drawImage(this.sprite("#ffffff"), to.x - size, to.y - size, size * 2, size * 2);
      if (beam.t >= 1 && !beam.landed) {
        beam.landed = true;
        this.rings.push({ node: beam.b, age: 0, color: beam.color });
      }
      return beam.t < 1.35;
    });
    ctx.globalCompositeOperation = "source-over";

    this.rings = this.rings.filter((ring) => {
      ring.age += dt;
      if (ring.age > 2.2) return false;
      const p = ring.age / 2.2;
      ctx.globalAlpha = (1 - p) * 0.9; ctx.strokeStyle = ring.color || ring.node.color;
      ctx.lineWidth = 2 * thin;
      ctx.beginPath(); ctx.arc(ring.node.x, ring.node.y, ring.node.radius + p * 46, 0, Math.PI * 2); ctx.stroke();
      return true;
    });

    // Labels: projects and agents always, entries when zoomed in.
    ctx.textAlign = "center";
    for (const node of this.nodes) {
      const lit = !dimming || this.bright(node);
      if (!node.label) continue;
      // With labels hidden only the agents keep their names.
      if (!this.showLabels && node.kind !== "agent") continue;
      if (node.kind === "hub") {
        ctx.globalAlpha = lit ? 0.94 : 0.15;
        ctx.fillStyle = "#e9eefb";
        ctx.font = `600 ${12.5 / k}px ui-sans-serif, system-ui, sans-serif`;
        ctx.fillText(node.label, node.x, node.y - node.radius * 2 - 7 / k);
      } else if (node.kind === "agent") {
        ctx.globalAlpha = lit ? 0.95 : 0.15;
        ctx.fillStyle = node.color;
        ctx.font = `700 ${11 / k}px ui-monospace, Menlo, Consolas, monospace`;
        ctx.fillText(node.label, node.x, node.y + node.radius * 1.9 + 15 / k);
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

  nodeAt(px, py, slop = 9) {
    const point = this.toWorld(px, py);
    let best = null, bestDistance = Infinity;
    for (const node of this.nodes) {
      const reach = Math.max(node.radius * 1.9, slop / this.view.k);
      const d = Math.hypot(node.x - point.x, node.y - point.y);
      if (d < reach && d < bestDistance) { best = node; bestDistance = d; }
    }
    return best;
  }

  centerOn(node) {
    this.touched = true;
    const targetX = this.width > 760 ? (336 + this.width - 450) / 2 : this.width / 2;
    const targetY = this.height / 2;
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
    // Fingers on the canvas: one drags (a node or the view), two pinch.
    const touches = new Map();
    let pinch = null;
    const startPinch = () => {
      const [a, b] = [...touches.values()];
      const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
      pinch = { distance: Math.max(Math.hypot(a.x - b.x, a.y - b.y), 1), k: this.view.k, world: this.toWorld(mid.x, mid.y) };
      if (pointer.node) pointer.node.fixed = false;
      pointer.node = null;
      pointer.moved = true; // a pinch is never a tap
    };
    canvas.addEventListener("pointerdown", (event) => {
      canvas.setPointerCapture(event.pointerId);
      if (event.pointerType === "touch") {
        touches.set(event.pointerId, { x: event.clientX, y: event.clientY });
        if (touches.size === 2) { startPinch(); return; }
        if (touches.size > 2) return;
      }
      pointer.down = true; pointer.moved = false;
      pointer.x = event.clientX; pointer.y = event.clientY;
      pointer.node = this.nodeAt(event.clientX, event.clientY, event.pointerType === "touch" ? 18 : 9);
      if (pointer.node) pointer.node.fixed = true;
      canvas.classList.add("dragging");
    });
    canvas.addEventListener("pointermove", (event) => {
      if (touches.has(event.pointerId)) {
        touches.set(event.pointerId, { x: event.clientX, y: event.clientY });
        if (pinch && touches.size >= 2) {
          const [a, b] = [...touches.values()];
          const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
          const distance = Math.max(Math.hypot(a.x - b.x, a.y - b.y), 1);
          const k = Math.min(Math.max(pinch.k * distance / pinch.distance, 0.15), 6);
          // Keep the point that started under the fingers under them.
          this.view.k = k;
          this.view.x = mid.x - pinch.world.x * k;
          this.view.y = mid.y - pinch.world.y * k;
          this.touched = true;
          return;
        }
      }
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
      if (event.pointerType === "touch") return;
      const node = this.nodeAt(event.clientX, event.clientY);
      if (node !== this.hover) {
        this.hover = node;
        canvas.classList.toggle("pointing", !!node);
      }
      this.onHover(node, event.clientX, event.clientY);
    });
    const release = (event) => {
      if (touches.delete(event.pointerId) && pinch) {
        if (touches.size >= 2) { startPinch(); return; }
        pinch = null;
        if (touches.size === 1) {
          // The finger left on the glass carries on panning from where it is.
          const [rest] = [...touches.values()];
          pointer.down = true; pointer.x = rest.x; pointer.y = rest.y;
          return;
        }
      }
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

function secondsSince(iso) {
  const then = Date.parse(iso);
  return isNaN(then) ? null : Math.max(0, Math.round((Date.now() - then) / 1000));
}

function relative(seconds) {
  if (seconds === null || seconds === undefined) return "never";
  if (seconds < 45) return "now";
  if (seconds < 3600) return Math.max(1, Math.floor(seconds / 60)) + "m";
  if (seconds < 86400) return Math.floor(seconds / 3600) + "h";
  return Math.floor(seconds / 86400) + "d";
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
  ordered.forEach(([project], index) => colors.set(project, PROJECT_COLORS[index % PROJECT_COLORS.length]));
  return { counts: ordered, colors };
}

/* An agent's colour comes from its name, so it is the same on every visit and
   never shifts when another agent shows up. Clashes move to the next free one. */
function agentColor(name) {
  if (name === "admin") return "#cbd5e1";
  if (!state.agentColors.has(name)) {
    let hash = 0;
    for (const char of name) hash = (hash * 31 + char.codePointAt(0)) >>> 0;
    const taken = new Set(state.agentColors.values());
    let index = hash % AGENT_COLORS.length;
    for (let tries = 0; tries < AGENT_COLORS.length && taken.has(AGENT_COLORS[index]); tries++) {
      index = (index + 1) % AGENT_COLORS.length;
    }
    state.agentColors.set(name, AGENT_COLORS[index]);
  }
  return state.agentColors.get(name);
}

function toGraph(brain, colors, counts, agents) {
  const nodes = [], links = [];
  for (const [project, members] of counts) {
    nodes.push({
      key: "p:" + project, kind: "hub", color: colors.get(project), label: project,
      radius: 6 + Math.min(Math.sqrt(members), 8), members, phase: Math.random() * 6.28,
    });
  }
  const wroteIn = new Map();
  for (const neuron of brain.neurons) {
    const radius = KIND_RADIUS[neuron.kind] || 3.3;
    nodes.push({
      key: "n:" + neuron.id, kind: "neuron", color: colors.get(neuron.project), label: neuron.title,
      radius, baseRadius: radius, hub: "p:" + neuron.project, hollow: neuron.kind === "todo",
      phase: Math.random() * 6.28, data: neuron,
    });
    links.push({ source: "p:" + neuron.project, target: "n:" + neuron.id, kind: "hub", strength: 0 });
    if (neuron.agent) {
      if (!wroteIn.has(neuron.agent)) wroteIn.set(neuron.agent, new Set());
      wroteIn.get(neuron.agent).add(neuron.project);
    }
  }
  for (const synapse of brain.synapses) {
    links.push({ source: "n:" + synapse.source, target: "n:" + synapse.target, kind: "synapse", strength: synapse.similarity });
  }
  for (const agent of agents) {
    nodes.push({
      key: "a:" + agent.name, kind: "agent", color: agentColor(agent.name), label: agent.name,
      radius: 5.5, phase: Math.random(), online: agent.seconds_since_seen !== null && agent.seconds_since_seen < 300,
    });
    for (const project of wroteIn.get(agent.name) || []) {
      links.push({ source: "a:" + agent.name, target: "p:" + project, kind: "agent", strength: 0 });
    }
  }
  return { nodes, links };
}

/* A decorative network shown behind the sign-in form. It contains no data. */
function decorativeGraph() {
  const nodes = [], links = [];
  for (let c = 0; c < 6; c++) {
    nodes.push({ key: "p:" + c, kind: "hub", color: PROJECT_COLORS[c], label: "", radius: 7, members: 14, phase: c });
    for (let i = 0; i < 16; i++) {
      const key = "n:" + c + ":" + i;
      nodes.push({ key, kind: "neuron", color: PROJECT_COLORS[c], label: "", radius: 3.4, baseRadius: 3.4, hub: "p:" + c, phase: Math.random() * 6.28 });
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

/* ---------- Scene ---------- */

/* Stars are drawn once; CSS moves and twinkles the layer. */
function drawStars() {
  const canvas = $("stars");
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  const width = window.innerWidth * 1.08, height = window.innerHeight * 1.08;
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  const tints = ["#ffffff", "#cfe2ff", "#b9c8ff", "#ffe9c4", "#d9c2ff"];
  // A fixed seed keeps the sky the same on every visit.
  let seed = 1337;
  const random = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
  const count = Math.round((width * height) / 5200);
  for (let i = 0; i < count; i++) {
    const depth = random();
    const radius = depth > 0.97 ? 1.5 + random() * 0.9 : 0.35 + depth * 0.75;
    const px = random() * width, py = random() * height;
    ctx.globalAlpha = 0.25 + depth * 0.6;
    ctx.fillStyle = tints[Math.floor(random() * tints.length)];
    ctx.beginPath(); ctx.arc(px, py, radius, 0, Math.PI * 2); ctx.fill();
    if (radius > 1.5) {
      const halo = ctx.createRadialGradient(px, py, 0, px, py, radius * 6);
      halo.addColorStop(0, "rgba(190, 215, 255, 0.35)");
      halo.addColorStop(1, "rgba(190, 215, 255, 0)");
      ctx.globalAlpha = 0.6; ctx.fillStyle = halo;
      ctx.beginPath(); ctx.arc(px, py, radius * 6, 0, Math.PI * 2); ctx.fill();
    }
  }
}
drawStars();
window.addEventListener("resize", drawStars);

/* ---------- App ---------- */

const graph = new Graph($("graph"));

// Project and memory labels can be hidden; the choice is remembered per browser.
const LABELS_KEY = "lore.graph.labels";
function setLabels(show, remember) {
  graph.showLabels = show;
  const button = $("labels-toggle");
  button.textContent = show ? "Hide labels" : "Show labels";
  button.setAttribute("aria-pressed", String(show));
  if (remember) { try { localStorage.setItem(LABELS_KEY, show ? "1" : "0"); } catch { /* private mode */ } }
}
{
  let stored = null;
  try { stored = localStorage.getItem(LABELS_KEY); } catch { /* private mode */ }
  setLabels(stored !== "0", false);
}
$("labels-toggle").addEventListener("click", () => setLabels(!graph.showLabels, true));

/* The scene follows the camera: far layers move less than near ones. */
{
  const scene = document.querySelector(".scene");
  let last = "";
  graph.onCamera = (x, y, k) => {
    if (REDUCED_MOTION) return;
    const clamp = (v, limit) => Math.max(-limit, Math.min(limit, v));
    const panX = clamp((x - window.innerWidth / 2) * 0.06, 46);
    const panY = clamp((y - window.innerHeight / 2) * 0.06, 34);
    const zoom = 1 + clamp(Math.log(k) * 0.03, 0.05);
    const key = `${panX.toFixed(1)}|${panY.toFixed(1)}|${zoom.toFixed(3)}`;
    if (key === last) return;
    last = key;
    scene.style.setProperty("--pan-x", panX.toFixed(1) + "px");
    scene.style.setProperty("--pan-y", panY.toFixed(1) + "px");
    scene.style.setProperty("--zoom", zoom.toFixed(3));
  };
}
const state = {
  version: null, brain: null, colors: new Map(), counts: [], agents: [],
  agentColors: new Map(), lastAction: new Map(), feed: [], seen: new Set(),
  filter: null, // { type: 'project' | 'agent' | 'kind', value }
  query: "", timer: null, clock: null, source: null, refreshing: null,
  siteKey: null, decorative: false, role: "viewer",
  username: "", perms: new Set(), stored: false,
  sessions: [], openSessions: 0, openTasks: 0, fileCount: 0,
};

async function api(path, options) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  if (response.status === 401 && !path.endsWith("/login")) {
    // Sessions do not survive a restart, so a 401 often means a new deploy.
    reloadIfOutdated();
    showLogin();
    throw new Error("signed out");
  }
  return response;
}

function showLogin() {
  clearInterval(state.timer); clearInterval(state.clock);
  if (state.source) { state.source.close(); state.source = null; }
  state.version = null; state.brain = null;
  // Panels keep their rendered state; a fresh sign-in must not inherit it.
  $("backup").hidden = true;
  $("backup-toggle").setAttribute("aria-expanded", "false");
  $("profile").hidden = true;
  $("profile-toggle").setAttribute("aria-expanded", "false");
  resetOwnPassword();
  resetBackup();
  closeUsers();
  resetUsers();
  closeAgentsPanel();
  resetAgentsPanel();
  closeBoard();
  Object.assign(board, { data: null, tab: "tasks", filter: "open", project: "" });
  closeFiles();
  resetFiles();
  closeIntegrations();
  resetIntegrations();
  closeDetail();
  $("side").classList.remove("open");
  $("feed").classList.remove("open");
  closeMore();
  closeSearch();
  $("app").hidden = true;
  $("login").hidden = false;
  if (!state.decorative) {
    graph.byId = new Map(); graph.selected = null; graph.focus = null;
    graph.chrome = false;
    const fake = decorativeGraph();
    graph.setData(fake.nodes, fake.links);
    state.decorative = true;
  }
  $("password").value = "";
  if ($("username").value) $("password").focus(); else $("username").focus();
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
      body: JSON.stringify({ username: $("username").value.trim(), password: $("password").value, captcha }),
    });
    if (response.ok) {
      $("password").value = "";
      const body = await response.json().catch(() => ({}));
      await enter(body);
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

/* Whether the signed-in user holds a permission. */
function can(permission) {
  return state.perms.has(permission);
}

/* Every signed-in user reads; each control that changes something shows
   only with its permission. The server enforces the same on every route,
   so hiding a control is a courtesy, not the lock. */
function applySession(session) {
  // A server from before permissions sent only the role.
  const perms = Array.isArray(session.permissions)
    ? session.permissions
    : session.role === "admin" ? ALL_PERMISSIONS : [];
  state.perms = new Set(perms);
  state.role = session.role === "admin" ? "admin" : "viewer";
  state.username = session.username || state.role;
  state.stored = !!session.stored;
  const backupMenu = can("backup") || can("restore");
  $("backup-toggle").hidden = !backupMenu;
  $("more-backup").hidden = !backupMenu;
  $("users-toggle").hidden = !can("users");
  $("more-users").hidden = !can("users");
  $("agents-toggle").hidden = !can("agents");
  $("more-agents").hidden = !can("agents");
  // The badge next to the brand names who is signed in.
  for (const badge of [$("role"), $("more-role")]) {
    badge.textContent = state.username;
    badge.title = perms.length ? "Permissions: " + perms.join(", ") : "Read only";
    badge.hidden = false;
  }
  // The board and file forms write; reading needs no permission.
  $("task-form").hidden = !can("write");
  $("message-form").hidden = !can("write");
  $("file-form").hidden = !can("write");
  // The backup dialog: downloads need backup, restores need restore.
  $("backup-export").hidden = !can("backup");
  $("full-download").hidden = !can("backup");
  $("backup-import").hidden = !can("restore");
  $("backup-restore").hidden = !can("restore");
  // A full database brings its own users and tokens: restoring one is for
  // a user holding every permission, as the server enforces.
  $("full-restore-box").hidden = !ALL_PERMISSIONS.every(can);
  // Stored users change their own password; built-in ones in the environment.
  $("own-password").hidden = !state.stored;
  $("own-username").value = state.username;
  if (!backupMenu) {
    $("backup").hidden = true;
    $("backup-toggle").setAttribute("aria-expanded", "false");
  }
  if (!can("users")) closeUsers();
  if (!can("agents")) closeAgentsPanel();
}

async function enter(session) {
  applySession(session || {});
  $("login").hidden = true;
  $("app").hidden = false;
  graph.byId = new Map();
  graph.chrome = true;
  state.decorative = false;
  await refresh(true);
  connectStream();
  clearInterval(state.timer); clearInterval(state.clock);
  state.timer = setInterval(fallbackPoll, FALLBACK_POLL_MS);
  state.clock = setInterval(tickClock, 15000);
}

/* Live updates arrive over server-sent events; the poll below only covers
   a dropped stream and notices an expired session. */
function connectStream() {
  if (state.source) state.source.close();
  const source = new EventSource("/admin/api/events");
  state.source = source;
  source.addEventListener("open", () => {
    // A stream that had to reconnect may be talking to a redeployed server.
    if (state.dropped) reloadIfOutdated();
    state.dropped = false;
    setLive(true);
  });
  source.addEventListener("error", () => { state.dropped = true; setLive(false); });
  source.addEventListener("activity", (event) => {
    try { onActivity(JSON.parse(event.data)); } catch (_) { /* malformed event: ignore */ }
  });
}

/* After a deploy the server runs newer page code than an open tab holds.
   Reloading then is the only way the tab gets it. */
async function reloadIfOutdated() {
  try {
    const session = await (await fetch("/admin/api/session", { credentials: "same-origin" })).json();
    if (state.build && session.build && session.build !== state.build) location.reload();
  } catch (_) { /* offline: try again on the next occasion */ }
}

function setLive(on) {
  $("live").classList.toggle("off", !on);
  $("live-text").textContent = on ? "Live" : "Reconnecting";
}

async function fallbackPoll() {
  if (document.hidden) return;
  try {
    const pulse = await (await api("/admin/api/pulse")).json();
    state.agents = pulse.agents;
    renderAgents();
    if (pulse.open_sessions !== state.openSessions) {
      state.openSessions = pulse.open_sessions;
      renderStats();
      loadSessions();
    }
    if (pulse.open_tasks !== state.openTasks) {
      state.openTasks = pulse.open_tasks;
      renderStats();
      boardActivity();
    }
    if (pulse.files !== state.fileCount) {
      state.fileCount = pulse.files;
      renderStats();
      filesActivity();
    }
    if (pulse.version !== state.version) await refresh(false);
  } catch (_) { /* signed out or offline; the next poll retries */ }
}

function tickClock() {
  for (const agent of state.agents) {
    if (agent.seconds_since_seen !== null) agent.seconds_since_seen += 15;
  }
  renderAgents();
  for (const item of $("feed-list").children) {
    const when = item.querySelector(".when");
    if (when) when.textContent = relative(secondsSince(item.dataset.at));
  }
}

function refresh(first) {
  // Collapse bursts of writes: while one reload runs, at most one more is
  // queued behind it, so the page always ends on the newest data.
  if (state.refreshing) {
    state.stale = true;
    return state.refreshing;
  }
  state.refreshing = (async () => {
    try {
      do {
        state.stale = false;
        await load(first);
        first = false;
      } while (state.stale);
    } finally {
      state.refreshing = null;
    }
  })();
  return state.refreshing;
}

async function load(first) {
  {
    {
      const payload = await (await api("/admin/api/brain")).json();
      state.version = payload.version;
      state.brain = payload.brain;
      state.agents = payload.agents;
      state.model = payload.embedding_model;
      state.openSessions = payload.open_sessions;
      state.openTasks = payload.open_tasks;
      state.fileCount = payload.files;
      const { counts, colors } = projectColors(payload.brain.neurons);
      state.counts = counts; state.colors = colors;
      for (const agent of payload.agents) agentColor(agent.name);
      const { nodes, links } = toGraph(payload.brain, colors, counts, payload.agents);
      graph.setData(nodes, links, { fireNew: !first });
      if (first) {
        state.feed = []; state.seen = new Set(); state.lastAction = new Map();
        $("feed-list").replaceChildren();
        for (const activity of payload.activity.slice().reverse()) addToFeed(activity, false);
      }
      renderStats();
      renderAgents();
      renderProjects();
      renderKinds();
      renderBars(payload.brain.activity);
      applyFocus();
      $("empty").hidden = payload.brain.neurons.length > 0;
    }
  }
  await loadSessions();
}

/* ---------- Sessions ---------- */

/* The panel lists the open sessions first, then the latest closed ones. */
async function loadSessions() {
  try {
    const [open, closed] = await Promise.all([
      (await api("/admin/api/sessions?status=open&limit=20")).json(),
      (await api("/admin/api/sessions?status=closed&limit=10")).json(),
    ]);
    state.sessions = [...open, ...closed];
    renderSessions();
  } catch (_) { /* signed out or offline; the next refresh retries */ }
}

function renderSessions() {
  const list = $("sessions");
  list.replaceChildren();
  if (!state.sessions.length) {
    list.append(el("li", "none", "No sessions yet. They appear when an agent calls hello."));
    return;
  }
  for (const session of state.sessions) {
    const open = session.status === "open";
    const item = el("li", open ? "session" : "session closed");
    const avatar = avatarNode(session.agent || "unknown", "small");
    const name = el("span", "name", session.agent || "unknown agent");
    const when = el("span", "count", relative(secondsSince(session.last_seen_at)));
    const sub = el("span", "sub");
    sub.textContent = `${session.project} · ${session.title}`;
    sub.append(el("span", "pill " + (open ? "open" : "closed"), open ? "open" : "closed"));
    if (session.implicit) {
      const pill = el("span", "pill implicit", "implicit");
      pill.title = "Opened by lore for a client with an outdated tool list";
      sub.append(pill);
    }
    item.title = `${session.title} · started ${shortDate(session.started_at)}`;
    item.append(avatar, name, when, sub);
    clickable(item, () => openSessionDetail(session));
    list.append(item);
  }
}

/* The chat drawer: a session's fields and its check-in timeline. */
async function openSessionDetail(session) {
  graph.selected = null;
  $("tooltip").hidden = true;
  const box = $("detail-body");
  box.replaceChildren(el("p", "muted", "Loading…"));
  $("detail").hidden = false;
  let data;
  try {
    const response = await api("/admin/api/sessions/" + encodeURIComponent(session.id));
    if (!response.ok) throw new Error("gone");
    data = await response.json();
  } catch (_) {
    box.replaceChildren(el("p", "muted", "This session could not be loaded. It may be gone."));
    return;
  }
  box.replaceChildren();
  const open = data.status === "open";
  const badge = el("span", "pill " + (open ? "open" : "closed"), open ? "open" : "closed");
  box.append(badge);
  if (data.implicit) box.append(el("span", "pill implicit", "implicit"));
  box.append(el("h3", "", data.title || "(untitled chat)"));
  const meta = [
    `by ${data.agent || "unknown agent"}`,
    data.project,
    `started ${shortDate(data.started_at)}`,
    `last activity ${shortDate(data.last_seen_at)}`,
  ];
  if (data.ended_at) meta.push(`ended ${shortDate(data.ended_at)}`);
  box.append(el("div", "meta", meta.join(" · ")));
  if (data.summary) box.append(el("p", "muted", `Summary: ${data.summary}`));
  if (data.commit || data.repo || data.path) {
    const where = el("div", "chips");
    if (data.commit) {
      where.append(el("span", "chip file",
        data.commit.slice(0, 10) + (data.branch ? ` · ${data.branch}` : "")));
    }
    if (data.repo) where.append(el("span", "chip file", data.repo));
    if (data.path) where.append(el("span", "chip file", data.path));
    box.append(el("h4", "", "Working at"), where);
  }
  box.append(el("h4", "", "Check-ins"));
  if (!data.updates.length) {
    box.append(el("p", "muted", "No check-ins recorded in this chat."));
    return;
  }
  const timeline = el("ul", "timeline");
  for (const update of data.updates) {
    const item = el("li");
    item.append(el("div", "at", shortDate(update.at)));
    item.append(el("div", "note", update.body));
    if (update.commit) {
      const label = update.commit.slice(0, 10)
        + (update.branch ? ` · ${update.branch}` : "")
        + (update.dirty ? " · uncommitted changes" : "");
      item.append(el("span", "chip file", label));
    }
    timeline.append(item);
  }
  box.append(timeline);
}

/* ---------- Live activity ---------- */

/* A restore rewinds activity ids, so an id alone does not identify an action. */
const activityKey = (activity) => `${activity.id}|${activity.at}|${activity.tool}`;

async function onActivity(activity) {
  if (state.seen.has(activityKey(activity))) return;
  addToFeed(activity, true);
  boardActivity();
  filesActivity(activity);
  integrationsActivity(activity);

  const agent = state.agents.find((a) => a.name === activity.agent);
  if (agent) {
    agent.seconds_since_seen = 0;
    agent.requests += 1;
  } else if (activity.agent !== "admin") {
    state.agents.unshift({ name: activity.agent, client: "", seconds_since_seen: 0, requests: 1, entries: 0, avatar: defaultAvatar(activity.agent) });
  }
  renderAgents(activity.agent);
  renderStats();

  if (WRITES.has(activity.tool)) await refresh(false).catch(() => {});
  const color = agentColor(activity.agent);
  const from = "a:" + activity.agent;
  const targets = activity.entry_id ? [activity.entry_id] : activity.targets.slice(0, 8);
  const node = graph.byId.get(from);
  if (node) node.online = true;
  if (!targets.length) graph.ring(from, color);
  targets.forEach((id, index) => {
    setTimeout(() => graph.beam(from, "n:" + id, color), index * 90);
  });
}

function addToFeed(activity, live) {
  if (state.seen.has(activityKey(activity))) return;
  state.seen.add(activityKey(activity));
  state.feed.unshift(activity);
  state.lastAction.set(activity.agent, activity);

  const list = $("feed-list");
  const tool = TOOLS[activity.tool] || { verb: activity.tool, tone: "read" };
  const item = el("li", live ? "fresh" : "");
  item.dataset.at = activity.at;
  item.style.borderLeftColor = agentColor(activity.agent);

  const avatar = avatarNode(activity.agent, "small");
  const line = el("div", "line");
  line.append(el("span", "who", activity.agent), el("span", "verb", tool.verb),
    el("span", "when", relative(secondsSince(activity.at))));
  item.append(avatar, line);
  if (activity.summary) item.append(el("div", "what", activity.summary));

  const tags = el("div", "tagline");
  tags.append(el("span", "tag tool " + tool.tone, activity.tool));
  if (activity.project) tags.append(el("span", "tag", activity.project));
  if (activity.entry_id) tags.append(el("span", "tag", "#" + activity.entry_id));
  item.append(tags);

  const target = activity.entry_id || activity.targets[0];
  if (target && activity.tool !== "forget") {
    item.classList.add("clickable");
    item.tabIndex = 0;
    const open = () => {
      const node = graph.byId.get("n:" + target);
      if (node) openDetail(node);
    };
    item.addEventListener("click", open);
    item.addEventListener("keydown", (event) => { if (event.key === "Enter") open(); });
  }

  list.prepend(item);
  while (list.children.length > FEED_MAX) list.lastElementChild.remove();
  $("feed-empty").hidden = true;
  $("feed-count").textContent = `${list.children.length} shown`;
}

/* ---------- Panels ---------- */

function setStat(id, value) {
  const node = $(id);
  if (node.textContent === String(value)) return;
  node.textContent = String(value);
  const card = node.parentElement;
  card.classList.remove("bump");
  void card.offsetWidth; // restart the animation
  card.classList.add("bump");
}

function renderStats() {
  if (!state.brain) return;
  setStat("stat-memories", state.brain.total_entries);
  setStat("stat-links", state.brain.synapses.length);
  setStat("stat-projects", state.counts.length);
  setStat("stat-online", state.agents.filter((a) => a.seconds_since_seen !== null && a.seconds_since_seen < 300).length);
  setStat("stat-tasks", state.openTasks);
  setStat("stat-sessions", state.openSessions);
  setStat("stat-files", state.fileCount);
}

function clickable(item, onClick) {
  item.tabIndex = 0;
  item.setAttribute("role", "button");
  item.addEventListener("click", onClick);
  item.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onClick(); }
  });
}

function isFilter(type, value) {
  return state.filter && state.filter.type === type && state.filter.value === value;
}

function toggleFilter(type, value) {
  state.filter = isFilter(type, value) ? null : { type, value };
  renderProjects(); renderAgents(); renderKinds();
  applyFocus();
}

function renderAgents(flash) {
  const list = $("agents");
  list.replaceChildren();
  if (!state.agents.length) {
    list.append(el("li", "none", "No agent has connected yet."));
    return;
  }
  const ordered = state.agents.slice().sort((a, b) =>
    (a.seconds_since_seen ?? Infinity) - (b.seconds_since_seen ?? Infinity) || a.name.localeCompare(b.name));
  for (const agent of ordered) {
    const seen = agent.seconds_since_seen;
    const avatar = avatarNode(agent.name, "", agent.avatar);
    if (seen !== null && seen < 300) avatar.classList.add("online");
    else if (seen !== null && seen < 86400) avatar.classList.add("recent");

    const last = state.lastAction.get(agent.name);
    let sub;
    if (last) {
      const tool = TOOLS[last.tool] || { verb: last.tool };
      sub = `${tool.verb}${last.summary ? " · " + last.summary : ""}`;
    } else if (seen === null) {
      sub = "never connected";
    } else {
      sub = agent.client || "connected";
    }
    const item = el("li", isFilter("agent", agent.name) ? "active" : "");
    if (flash === agent.name) item.classList.add("flash");
    item.title = [agent.client, `${agent.requests} requests`, `${agent.entries} entries written`].filter(Boolean).join(" · ");
    item.append(avatar, el("span", "name", agent.name),
      el("span", "count", seen === null ? "—" : relative(seen)), el("span", "sub", sub));
    clickable(item, () => toggleFilter("agent", agent.name));
    list.append(item);

    const node = graph.byId.get("a:" + agent.name);
    if (node) node.online = seen !== null && seen < 300;
  }
}

function renderProjects() {
  const list = $("projects");
  list.replaceChildren();
  if (!state.counts.length) {
    list.append(el("li", "none", "Nothing logged yet."));
    return;
  }
  const peak = Math.max(...state.counts.map((c) => c[1]));
  for (const [project, count] of state.counts) {
    const color = state.colors.get(project);
    const swatch = el("span", "swatch");
    swatch.style.background = color;
    swatch.style.boxShadow = `0 0 10px ${color}`;
    const meter = el("span", "meter"), fill = el("i");
    fill.style.width = Math.max(6, (count / peak) * 100) + "%";
    fill.style.background = color;
    meter.append(fill);
    const item = el("li", isFilter("project", project) ? "active" : "");
    item.append(swatch, el("span", "name", project), el("span", "count", String(count)), meter);
    clickable(item, () => toggleFilter("project", project));
    list.append(item);
  }
}

function renderKinds() {
  const box = $("kinds");
  box.replaceChildren();
  if (!state.brain || !state.brain.neurons.length) return;
  const counts = new Map();
  for (const neuron of state.brain.neurons) counts.set(neuron.kind, (counts.get(neuron.kind) || 0) + 1);
  for (const kind of KINDS) {
    if (!counts.has(kind)) continue;
    const button = el("button", isFilter("kind", kind) ? "active" : "", KIND_LABEL[kind]);
    button.type = "button";
    button.append(el("b", "", String(counts.get(kind))));
    button.addEventListener("click", () => toggleFilter("kind", kind));
    box.append(button);
  }
}

function renderBars(activity) {
  const byDay = new Map(activity);
  const box = $("activity-bars");
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
  const model = state.model ? `${state.model} embeddings` : "keyword search only";
  $("activity-note").textContent = `${total} entries logged · ${model}`;
}

function applyFocus() {
  const query = state.query.trim().toLowerCase();
  if (!state.brain || (!query && !state.filter)) { graph.focus = null; return; }
  const focus = new Set();
  for (const neuron of state.brain.neurons) {
    if (state.filter && state.filter.type === "project" && neuron.project !== state.filter.value) continue;
    if (state.filter && state.filter.type === "agent" && neuron.agent !== state.filter.value) continue;
    if (state.filter && state.filter.type === "kind" && neuron.kind !== state.filter.value) continue;
    if (query) {
      const haystack = `${neuron.title} ${neuron.tags} ${neuron.project} ${neuron.kind} ${neuron.agent}`.toLowerCase();
      if (!haystack.includes(query)) continue;
    }
    focus.add("n:" + neuron.id);
    focus.add("p:" + neuron.project);
    if (neuron.agent) focus.add("a:" + neuron.agent);
  }
  if (state.filter && state.filter.type === "agent") focus.add("a:" + state.filter.value);
  graph.focus = focus;
}

$("search").addEventListener("input", (event) => { state.query = event.target.value; applyFocus(); });

function bindToggle(buttonId, panelId) {
  $(buttonId).addEventListener("click", () => {
    const open = $(panelId).classList.toggle("open");
    $(buttonId).setAttribute("aria-expanded", String(open));
  });
}
bindToggle("side-toggle", "side");
bindToggle("feed-toggle", "feed");

/* ---------- Backup and restore ---------- */

let backupMode = "merge";

function backupStatus(text, tone) {
  const status = $("backup-status");
  status.textContent = text;
  status.className = "small-text" + (tone ? " " + tone : "");
}

$("backup-toggle").addEventListener("click", () => {
  const panel = $("backup");
  panel.hidden = !panel.hidden;
  $("backup-toggle").setAttribute("aria-expanded", String(!panel.hidden));
  if (!panel.hidden) {
    backupStatus("");
    // The menus share a corner; only one is open at a time.
    $("profile").hidden = true;
    $("profile-toggle").setAttribute("aria-expanded", "false");
    closeBoard();
    closeFiles();
    closeIntegrations();
    closeUsers();
    closeAgentsPanel();
  } else {
    resetBackup();
  }
});

/* The typed confirmation and the last restore's table counts do not
   outlive the dialog. */
function resetBackup() {
  $("full-confirm").value = "";
  $("full-restore").disabled = true;
  $("full-result").hidden = true;
  $("full-result").replaceChildren();
}

$("backup-export").addEventListener("click", () => {
  // A plain navigation: the server answers with a file attachment.
  const link = document.createElement("a");
  link.href = "/admin/api/export";
  link.download = "";
  document.body.append(link);
  link.click();
  link.remove();
  backupStatus("Backup download started.", "ok");
});

$("backup-import").addEventListener("click", () => { backupMode = "merge"; $("backup-file").click(); });
$("backup-restore").addEventListener("click", () => { backupMode = "replace"; $("backup-file").click(); });

$("backup-file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  let backup;
  try {
    backup = JSON.parse(await file.text());
  } catch (_) {
    backupStatus("That file is not valid JSON.", "bad");
    return;
  }
  const count = Array.isArray(backup.entries) ? backup.entries.length : 0;
  if (backup.format !== "project-lore-backup") {
    backupStatus("That file is not a project-lore backup.", "bad");
    return;
  }
  if (backupMode === "replace") {
    const current = state.brain ? state.brain.total_entries : 0;
    const sure = window.confirm(
      `Restore from "${file.name}"?\n\nThis deletes the ${current} memories here now and replaces them ` +
      `with the ${count} in the backup (exported ${backup.exported_at || "at an unknown time"}).\n\n` +
      "Export a backup first if you might want the current contents back.");
    if (!sure) { backupStatus("Restore cancelled. Nothing changed."); return; }
  }
  backupStatus(backupMode === "replace" ? "Restoring…" : "Importing…");
  try {
    const response = await api("/admin/api/import?mode=" + backupMode, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(backup),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      backupStatus(result.error || "The backup could not be loaded. Nothing changed.", "bad");
      return;
    }
    backupStatus(result.replaced
      ? `Restored ${result.added} memories.`
      : `Added ${result.added}; ${result.present} were already here.`, "ok");
    await refresh(false);
  } catch (_) {
    backupStatus("The backup could not be sent. Nothing changed.", "bad");
  }
});

/* The full database: a .sqlite download, and a restore that replaces
   everything after the word RESTORE is typed. */
$("full-download").addEventListener("click", () => {
  const link = document.createElement("a");
  link.href = "/admin/api/backup/full";
  link.download = "";
  document.body.append(link);
  link.click();
  link.remove();
  backupStatus("Full database download started. Keep the file private: it holds the encrypted credentials and the password hashes.", "ok");
});

$("full-confirm").addEventListener("input", () => {
  $("full-restore").disabled = $("full-confirm").value.trim() !== "RESTORE";
});

$("full-restore").addEventListener("click", () => {
  if ($("full-confirm").value.trim() !== "RESTORE") return;
  $("full-file").click();
});

$("full-file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  if ($("full-confirm").value.trim() !== "RESTORE") return;
  const sure = window.confirm(
    `Replace the whole database with "${file.name}"?\n\n` +
    "Every memory, session, file, setting, credential and user here is replaced by the file's contents. " +
    "A safety copy of the current database is kept on the server.");
  if (!sure) { backupStatus("Restore cancelled. Nothing changed."); return; }
  $("full-restore").disabled = true;
  $("full-result").hidden = true;
  backupStatus("Uploading and checking the database…");
  try {
    const response = await api("/admin/api/restore/full", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: file,
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      const reason = response.status === 413
        ? "The file is larger than 2 GiB."
        : result.error || "The database could not be restored.";
      // Only a failure after the database was replaced says so itself;
      // every other refusal changed nothing.
      backupStatus(result.check === "after-load" ? reason : `${reason} Nothing changed.`, "bad");
      $("full-restore").disabled = $("full-confirm").value.trim() !== "RESTORE";
      return;
    }
    $("full-confirm").value = "";
    backupStatus(`Restored. The previous database was kept on the server as ${result.snapshot}.`, "ok");
    const list = $("full-result");
    list.replaceChildren();
    for (const [table, count] of Object.entries(result.tables || {})) {
      const item = el("li");
      item.append(el("span", "", table), el("b", "", String(count)));
      list.append(item);
    }
    list.hidden = !list.children.length;
    // The restored database may not know this user any more.
    const session = await (await fetch("/admin/api/session", { credentials: "same-origin" })).json();
    if (!session.authenticated) { showLogin(); return; }
    applySession(session);
    await refresh(false);
  } catch (_) {
    backupStatus("The answer did not arrive, so it is not known whether the database was replaced. Reload the page to see.", "bad");
    $("full-restore").disabled = $("full-confirm").value.trim() !== "RESTORE";
  }
});

/* ---------- Profile and rules ---------- */

function profileStatus(text, tone) {
  const node = $("profile-status");
  node.textContent = text;
  node.className = "small-text" + (tone ? " " + tone : "");
}

$("profile-toggle").addEventListener("click", () => {
  const panel = $("profile");
  const open = panel.hidden;
  panel.hidden = !open;
  $("profile-toggle").setAttribute("aria-expanded", String(open));
  if (open) {
    $("backup").hidden = true;
    $("backup-toggle").setAttribute("aria-expanded", "false");
    closeBoard();
    closeFiles();
    closeIntegrations();
    closeUsers();
    closeAgentsPanel();
    profileStatus("");
    loadProfile();
  } else {
    resetOwnPassword();
  }
});

async function loadProfile() {
  let data;
  try {
    const response = await api("/admin/api/profile");
    if (!response.ok) throw new Error("gone");
    data = await response.json();
  } catch (_) {
    profileStatus("The profile could not be loaded.", "bad");
    return;
  }
  const admin = can("settings");
  $("profile-address").value = data.address || "";
  $("profile-language").value = data.language || "";
  $("profile-address").readOnly = !admin;
  $("profile-language").readOnly = !admin;
  $("profile-save").hidden = !admin;
  $("profile-add-rule").hidden = !admin;

  const byAgent = new Map(data.agents.map((row) => [row.agent, row.address]));
  // Saving replaces the whole per-agent list, so an agent that has an
  // address but is no longer known (say, after a restore) still gets a row;
  // otherwise the next save would silently drop its address.
  const names = [...new Set([...data.known_agents, ...byAgent.keys()])];
  const rows = $("profile-agents");
  rows.replaceChildren();
  if (!names.length) {
    rows.append(el("p", "muted small-text", "No agents have connected yet."));
  }
  for (const name of names) {
    const row = el("div", "profile-row");
    const input = el("input");
    input.type = "text";
    input.value = byAgent.get(name) || "";
    input.placeholder = "uses the default";
    if (!admin) input.readOnly = true;
    input.dataset.agent = name;
    row.append(el("span", "name", name), input);
    rows.append(row);
  }

  const rules = $("profile-rules");
  rules.replaceChildren();
  if (!data.rules.length) {
    rules.append(el("p", "muted small-text", "No rules yet. Every agent gets the briefing without rules."));
  } else {
    for (const rule of data.rules) rules.append(ruleRow(rule, admin));
  }
}

/* One editable rule. `rule` without an id is a fresh row that is added on
   its save click; existing rows save individually. */
function ruleRow(rule, admin) {
  const row = el("div", "rule-row");
  const top = el("div", "rule-top");

  const scope = el("select");
  for (const value of ["global", "agent", "project"]) {
    const option = el("option", "", value);
    option.value = value;
    scope.append(option);
  }
  scope.value = rule.scope;

  const target = el("input");
  target.type = "text";
  target.value = rule.target || "";

  const enabled = el("input");
  enabled.type = "checkbox";
  enabled.checked = rule.enabled !== false && rule.enabled !== 0;
  const toggle = el("label", "rule-toggle");
  toggle.append(enabled, el("span", "", "enabled"));

  const syncTarget = () => {
    target.hidden = scope.value === "global";
    target.placeholder = scope.value === "agent" ? "agent name" : "project name";
  };
  scope.addEventListener("change", syncTarget);
  syncTarget();

  const body = el("textarea");
  body.value = rule.body || "";
  body.placeholder = "What every matching agent must do";

  top.append(scope, target, toggle);
  if (admin) {
    const save = el("button", "ghost small", rule.id ? "Save" : "Add");
    save.type = "button";
    save.addEventListener("click", async () => {
      const payload = {
        scope: scope.value,
        target: target.value.trim(),
        body: body.value,
        enabled: enabled.checked,
      };
      try {
        const path = rule.id ? "/admin/api/rules/" + rule.id : "/admin/api/rules";
        const method = rule.id ? "PUT" : "POST";
        const response = await api(path, {
          method,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(rule.id ? { ...payload, position: rule.position || 0 } : payload),
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok) {
          profileStatus(result.error || "The rule could not be saved.", "bad");
          return;
        }
        profileStatus(`Rule #${result.id} saved.`, "ok");
        await loadProfile();
      } catch (_) {
        profileStatus("The rule could not be saved.", "bad");
      }
    });
    const remove = el("button", "ghost small danger", "Delete");
    remove.type = "button";
    remove.addEventListener("click", async () => {
      if (!rule.id) { row.remove(); return; }
      if (!window.confirm(`Delete rule #${rule.id}?`)) return;
      try {
        const response = await api("/admin/api/rules/" + rule.id, { method: "DELETE" });
        if (!response.ok) {
          profileStatus("The rule could not be deleted.", "bad");
          return;
        }
        profileStatus(`Rule #${rule.id} deleted.`, "ok");
        await loadProfile();
      } catch (_) {
        profileStatus("The rule could not be deleted.", "bad");
      }
    });
    top.append(save, remove);
  } else {
    scope.disabled = true;
    target.readOnly = true;
    enabled.disabled = true;
    body.readOnly = true;
  }
  row.append(top, body);
  return row;
}

$("profile-add-rule").addEventListener("click", () => {
  const rules = $("profile-rules");
  const placeholder = rules.querySelector("p");
  if (placeholder) rules.replaceChildren();
  rules.append(ruleRow({ scope: "global", target: "", body: "", enabled: true }, true));
});

$("profile-save").addEventListener("click", async () => {
  const agents = [];
  for (const input of $("profile-agents").querySelectorAll("input")) {
    agents.push({ agent: input.dataset.agent, address: input.value.trim() });
  }
  try {
    const response = await api("/admin/api/profile", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        address: $("profile-address").value.trim(),
        language: $("profile-language").value.trim(),
        agents,
      }),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      profileStatus(result.error || "The profile could not be saved.", "bad");
      return;
    }
    profileStatus("Profile saved. The next chat gets the new briefing.", "ok");
    await loadProfile();
  } catch (_) {
    profileStatus("The profile could not be saved.", "bad");
  }
});

/* ---------- Board: tasks, messages and handoff notes ---------- */

/* The forms are static markup and are never rebuilt, so a refresh while the
   admin is typing only replaces the lists and the select options. */
const board = {
  tab: "tasks", filter: "open", project: "",
  data: null, loading: null, again: false, timer: null,
};
const TASK_FILTERS = [["open", "Open"], ["done", "Done"], ["all", "All"]];
const TASK_ACTIONS = {
  open: ["done", "cancel"],
  claimed: ["done", "release", "cancel"],
  done: ["reopen"],
  cancelled: ["reopen"],
};
const ACTION_LABEL = { done: "Done", cancel: "Cancel", release: "Release", reopen: "Reopen" };
const ACTION_DONE = { done: "marked done", cancel: "cancelled", release: "released", reopen: "reopened" };

function ago(iso) {
  const text = relative(secondsSince(iso));
  return text === "now" || text === "never" ? text : text + " ago";
}

function boardStatus(text, tone) {
  const node = $("board-status");
  node.textContent = text;
  node.className = "small-text" + (tone ? " " + tone : "");
}

function closeBoard() {
  $("board").hidden = true;
  $("board-toggle").setAttribute("aria-expanded", "false");
  clearTimeout(board.timer);
}

$("board-toggle").addEventListener("click", () => {
  const panel = $("board");
  const open = panel.hidden;
  if (!open) { closeBoard(); return; }
  panel.hidden = false;
  $("board-toggle").setAttribute("aria-expanded", "true");
  closeUsers();
  closeAgentsPanel();
  $("backup").hidden = true;
  $("backup-toggle").setAttribute("aria-expanded", "false");
  $("profile").hidden = true;
  $("profile-toggle").setAttribute("aria-expanded", "false");
  closeFiles();
  closeIntegrations();
  boardStatus("");
  renderBoard();
  loadBoard();
});

/* Collapses bursts the same way `refresh` does: one load at a time, and at
   most one more queued behind it. */
function loadBoard() {
  if (board.loading) {
    board.again = true;
    return board.loading;
  }
  board.loading = (async () => {
    try {
      do {
        board.again = false;
        const response = await api("/admin/api/board?limit=300");
        if (!response.ok) throw new Error("failed");
        board.data = await response.json();
        state.openTasks = board.data.counts.open_tasks;
        renderStats();
        if (!$("board").hidden) renderBoard();
      } while (board.again);
    } catch (_) {
      if (!$("board").hidden) boardStatus("The board could not be loaded.", "bad");
    } finally {
      board.loading = null;
    }
  })();
  return board.loading;
}

/* Live events reload the board only while it is open. */
function boardActivity() {
  if ($("board").hidden) return;
  clearTimeout(board.timer);
  board.timer = setTimeout(loadBoard, 250);
}

function boardAgents() {
  const names = new Set(state.agents.map((agent) => agent.name));
  if (board.data) {
    for (const task of board.data.tasks) {
      for (const name of [task.created_by, task.assignee, task.claimed_by, task.done_by]) names.add(name);
    }
    for (const message of board.data.messages) {
      for (const name of [message.from_agent, message.to_agent, message.delivered_to]) names.add(name);
    }
  }
  names.delete("");
  names.delete("admin");
  return [...names].filter(Boolean).sort();
}

function boardProjects() {
  const names = new Set(state.counts.map(([project]) => project));
  if (board.data) {
    for (const task of board.data.tasks) names.add(task.project);
    for (const message of board.data.messages) names.add(message.project);
  }
  names.delete("");
  return [...names].sort();
}

/* Replaces a select's options and keeps the current choice when it still exists. */
function fillSelect(select, options) {
  const keep = select.value;
  select.replaceChildren();
  for (const [value, label] of options) {
    const option = el("option", "", label);
    option.value = value;
    select.append(option);
  }
  select.value = options.some(([value]) => value === keep) ? keep : options.length ? options[0][0] : "";
}

function renderBoard() {
  const admin = can("write");
  const tasksTab = board.tab === "tasks";
  $("board-tab-tasks").classList.toggle("active", tasksTab);
  $("board-tab-tasks").setAttribute("aria-selected", String(tasksTab));
  $("board-tab-messages").classList.toggle("active", !tasksTab);
  $("board-tab-messages").setAttribute("aria-selected", String(!tasksTab));
  $("board-tasks").hidden = !tasksTab;
  $("board-messages").hidden = tasksTab;
  $("board-chips").hidden = !tasksTab;
  $("task-form").hidden = !admin;
  $("message-form").hidden = !admin;

  const projects = boardProjects();
  if (board.project && !projects.includes(board.project)) projects.push(board.project);
  fillSelect($("board-project"), [["", "All projects"], ...projects.map((p) => [p, p])]);
  board.project = $("board-project").value;
  const datalist = $("board-projects");
  datalist.replaceChildren();
  for (const project of projects) {
    const option = el("option");
    option.value = project;
    datalist.append(option);
  }
  const agents = boardAgents();
  fillSelect($("task-assignee"), [["", "anyone"], ...agents.map((a) => [a, a])]);
  fillSelect($("message-to"), [["", "everyone"], ...agents.map((a) => [a, a])]);

  if (!board.data) {
    $("task-list").replaceChildren(el("li", "none", "Loading…"));
    $("message-list").replaceChildren(el("li", "none", "Loading…"));
    $("board-chips").replaceChildren();
    return;
  }
  renderTasks(admin);
  renderMessages();
}

function renderTasks(admin) {
  const inProject = board.data.tasks.filter((task) => !board.project || task.project === board.project);
  const matches = {
    open: (task) => task.status === "open" || task.status === "claimed",
    done: (task) => task.status === "done",
    all: () => true,
  };
  const chips = $("board-chips");
  chips.replaceChildren();
  for (const [value, label] of TASK_FILTERS) {
    const chip = el("button", board.filter === value ? "active" : "", label);
    chip.type = "button";
    chip.setAttribute("aria-pressed", String(board.filter === value));
    chip.append(el("b", "", String(inProject.filter(matches[value]).length)));
    chip.addEventListener("click", () => { board.filter = value; renderBoard(); });
    chips.append(chip);
  }

  const list = $("task-list");
  list.replaceChildren();
  const tasks = inProject.filter(matches[board.filter]);
  if (!tasks.length) {
    const what = board.filter === "all" ? "No tasks" : `No ${board.filter} tasks`;
    list.append(el("li", "none", what + (board.project ? ` on ${board.project}.` : " yet.")));
    return;
  }
  for (const task of tasks) list.append(taskItem(task, admin));
}

function taskItem(task, admin) {
  const item = el("li", "board-item " + task.status);
  const head = el("div", "board-item-head");
  head.append(el("span", "pill " + task.status, task.status),
    el("span", "board-title", task.title), el("span", "board-id", "#" + task.id));
  const meta = [task.project, `added by ${task.created_by}`];
  if (task.assignee) meta.push(`for ${task.assignee}`);
  if (task.claimed_by && task.status !== "open") meta.push(`claimed by ${task.claimed_by}`);
  if (task.done_by) {
    meta.push(`done by ${task.done_by}` + (task.done_commit ? ` at ${task.done_commit.slice(0, 10)}` : ""));
  }
  meta.push(ago(task.updated_at));
  const metaLine = el("div", "board-meta", meta.join(" · "));
  metaLine.title = `added ${shortDate(task.created_at)} · updated ${shortDate(task.updated_at)}`;
  item.append(head, metaLine);
  if (task.body) item.append(el("p", "board-body", task.body));
  if (task.note) item.append(el("p", "board-note", "Note: " + task.note));
  if (admin) {
    const actions = TASK_ACTIONS[task.status] || [];
    if (actions.length) {
      const row = el("div", "board-actions");
      for (const action of actions) {
        const button = el("button", "ghost small" + (action === "cancel" ? " danger" : ""), ACTION_LABEL[action]);
        button.type = "button";
        button.addEventListener("click", () => updateTask(task, action, row));
        row.append(button);
      }
      item.append(row);
    }
  }
  return item;
}

async function updateTask(task, action, row) {
  for (const button of row.querySelectorAll("button")) button.disabled = true;
  try {
    const response = await api("/admin/api/tasks/" + task.id, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, note: "" }),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      boardStatus(result.error || (response.status === 404
        ? `Task #${task.id} no longer exists.` : "The task could not be updated."), "bad");
    } else {
      boardStatus(`Task #${task.id} ${ACTION_DONE[action]}.`, "ok");
    }
  } catch (_) {
    boardStatus("The task could not be updated.", "bad");
  }
  await loadBoard();
}

function renderMessages() {
  const list = $("message-list");
  list.replaceChildren();
  const messages = board.data.messages.filter((m) => !board.project || m.project === board.project);
  if (!messages.length) {
    list.append(el("li", "none", board.project
      ? `No messages or handoff notes about ${board.project}.`
      : "No messages or handoff notes yet."));
    return;
  }
  for (const message of messages) list.append(messageItem(message));
}

function messageItem(message) {
  const handoff = message.kind === "handoff";
  const item = el("li", "board-item " + message.kind);
  const head = el("div", "board-item-head");
  const to = handoff ? `next agent on ${message.project}` : message.to_agent || "everyone";
  const when = el("span", "board-id", ago(message.created_at));
  when.title = shortDate(message.created_at);
  head.append(el("span", "pill " + message.kind, handoff ? "handoff" : "message"),
    el("span", "board-title", `${message.from_agent} → ${to}`), when);
  item.append(head);
  const meta = [`#${message.id}`];
  if (message.project && !handoff) meta.push(message.project);
  item.append(el("div", "board-meta", meta.join(" · ")), el("p", "board-body", message.body));
  let foot;
  if (handoff) {
    foot = message.delivered_at
      ? el("div", "board-foot", `delivered to ${message.delivered_to || "an agent"} · ${ago(message.delivered_at)}`)
      : el("div", "board-foot waiting", "waiting for the next session on " + message.project);
  } else {
    foot = message.read_by.length
      ? el("div", "board-foot", "read by: " + message.read_by.join(", "))
      : el("div", "board-foot waiting", "not read yet");
  }
  item.append(foot);
  return item;
}

$("board-tab-tasks").addEventListener("click", () => { board.tab = "tasks"; renderBoard(); });
$("board-tab-messages").addEventListener("click", () => { board.tab = "messages"; renderBoard(); });
$("board-project").addEventListener("change", (event) => { board.project = event.target.value; renderBoard(); });

function syncMessageKind() {
  const handoff = $("message-kind").value === "handoff";
  $("message-to-field").hidden = handoff;
  $("message-project").required = handoff;
  $("message-project-label").textContent = handoff ? "Project" : "Project (optional)";
  $("message-body").placeholder = handoff
    ? "Where the work stands and what is left, for whoever continues"
    : "What the agents must know";
  $("message-submit").textContent = handoff ? "Leave note" : "Send";
}
$("message-kind").addEventListener("change", syncMessageKind);
syncMessageKind();

async function postBoard(path, payload, button) {
  button.disabled = true;
  try {
    const response = await api(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      boardStatus(result.error || "That could not be saved.", "bad");
      return null;
    }
    return result;
  } catch (_) {
    boardStatus("That could not be saved.", "bad");
    return null;
  } finally {
    button.disabled = false;
  }
}

$("task-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const task = await postBoard("/admin/api/tasks", {
    project: $("task-project").value.trim(),
    title: $("task-title").value.trim(),
    body: $("task-body").value.trim(),
    assignee: $("task-assignee").value,
  }, $("task-submit"));
  if (!task) return;
  // The project and the assignee stay for the next task.
  $("task-title").value = "";
  $("task-body").value = "";
  boardStatus(`Task #${task.id} added to ${task.project}.`, "ok");
  await loadBoard();
});

$("message-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const handoff = $("message-kind").value === "handoff";
  const message = await postBoard("/admin/api/messages", {
    kind: handoff ? "handoff" : "message",
    project: $("message-project").value.trim(),
    to: handoff ? "" : $("message-to").value,
    body: $("message-body").value.trim(),
  }, $("message-submit"));
  if (!message) return;
  $("message-body").value = "";
  boardStatus(handoff
    ? `Handoff note #${message.id} left for the next session on ${message.project}.`
    : `Message #${message.id} sent to ${message.to_agent || "everyone"}.`, "ok");
  await loadBoard();
});

/* ---------- Files kept for the projects ---------- */

/* The form is static markup and is never rebuilt, so a refresh while the
   admin is typing only replaces the list, the detail and the select options. */
const FILE_MAX_BYTES = 2 * 1024 * 1024;
const FILE_KINDS = ["idea", "doc", "data", "config", "other"];
/* Actions that change which files exist; only these reload an open panel. */
const FILE_WRITES = new Set(["file_save", "file_delete", "import", "restore"]);
const filesState = {
  data: null, loading: null, again: false, timer: null, searchTimer: null,
  query: "", project: "", projects: new Set(), openId: null,
  picked: null, reading: 0,
};

function humanSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function kindPill(kind) {
  const known = FILE_KINDS.includes(kind) ? kind : "other";
  return el("span", "pill kind-" + known, kind);
}

function filesStatus(text, tone) {
  const node = $("files-status");
  node.textContent = text;
  node.className = "small-text" + (tone ? " " + tone : "");
}

function closeFiles() {
  $("files").hidden = true;
  $("files-toggle").setAttribute("aria-expanded", "false");
  clearTimeout(filesState.timer);
  clearTimeout(filesState.searchTimer);
}

/* A fresh sign-in starts from the list, with nothing picked or pasted. */
function resetFiles() {
  Object.assign(filesState, { data: null, query: "", project: "", openId: null });
  filesState.projects = new Set();
  $("files-search").value = "";
  $("file-text").value = "";
  clearPicked();
  $("file-detail").replaceChildren();
  $("file-detail").hidden = true;
  $("files-browse").hidden = false;
}

$("files-toggle").addEventListener("click", () => {
  const panel = $("files");
  if (!panel.hidden) { closeFiles(); return; }
  panel.hidden = false;
  $("files-toggle").setAttribute("aria-expanded", "true");
  closeUsers();
  closeAgentsPanel();
  $("backup").hidden = true;
  $("backup-toggle").setAttribute("aria-expanded", "false");
  $("profile").hidden = true;
  $("profile-toggle").setAttribute("aria-expanded", "false");
  closeBoard();
  closeIntegrations();
  filesStatus("");
  renderFiles();
  loadFiles();
});

/* One load at a time, and at most one more queued behind it. An open detail
   is reloaded with the list, so a version deleted elsewhere does not linger. */
function loadFiles() {
  if (filesState.loading) {
    filesState.again = true;
    return filesState.loading;
  }
  filesState.loading = (async () => {
    try {
      do {
        filesState.again = false;
        const params = new URLSearchParams({ limit: "300" });
        if (filesState.query) params.set("q", filesState.query);
        if (filesState.project) params.set("project", filesState.project);
        const response = await api("/admin/api/files?" + params.toString());
        if (!response.ok) throw new Error("failed");
        filesState.data = await response.json();
        state.fileCount = filesState.data.counts.files;
        renderStats();
        if (!$("files").hidden) renderFiles();
      } while (filesState.again);
      if (filesState.openId !== null && !$("files").hidden) await showFile(filesState.openId, true);
    } catch (_) {
      if (!$("files").hidden) filesStatus("The files could not be loaded.", "bad");
    } finally {
      filesState.loading = null;
    }
  })();
  return filesState.loading;
}

/* Live events reload the panel only while it is open, and only for actions
   that change which files exist. */
function filesActivity(activity) {
  if ($("files").hidden) return;
  if (activity && !FILE_WRITES.has(activity.tool)) return;
  clearTimeout(filesState.timer);
  filesState.timer = setTimeout(loadFiles, 250);
}

function renderFiles() {
  const admin = can("write");
  const detail = filesState.openId !== null;
  $("files-browse").hidden = detail;
  $("file-detail").hidden = !detail;
  $("file-form").hidden = !admin;

  const data = filesState.data;
  if (data) for (const file of data.files) filesState.projects.add(file.project);
  for (const [project] of state.counts) filesState.projects.add(project);
  if (filesState.project) filesState.projects.add(filesState.project);
  const projects = [...filesState.projects].filter(Boolean).sort();
  fillSelect($("files-project"), [["", "All projects"], ...projects.map((p) => [p, p])]);
  filesState.project = $("files-project").value;
  const datalist = $("files-projects");
  datalist.replaceChildren();
  for (const project of projects) {
    const option = el("option");
    option.value = project;
    datalist.append(option);
  }

  const list = $("file-list");
  if (!data) {
    $("files-count").textContent = "";
    list.replaceChildren(el("li", "none", "Loading…"));
    return;
  }
  const { counts } = data;
  $("files-count").textContent =
    `${counts.files} files · ${counts.versions} versions · ${humanSize(counts.bytes)}`;
  list.replaceChildren();
  if (!data.files.length) {
    let none = "No files kept yet. Agents keep them with file_save.";
    if (filesState.query) none = `No files match "${filesState.query}".`;
    else if (filesState.project) none = `No files kept for ${filesState.project}.`;
    list.append(el("li", "none", none));
    return;
  }
  for (const file of data.files) list.append(fileItem(file));
}

function fileItem(file) {
  const item = el("li", "board-item file-item");
  const head = el("div", "board-item-head");
  head.append(kindPill(file.kind), el("span", "board-title file-path", file.path),
    el("span", "board-id", "v" + file.version));
  const meta = el("div", "board-meta",
    [file.project, humanSize(file.size), `by ${file.agent}`, ago(file.created_at)].join(" · "));
  meta.title = shortDate(file.created_at);
  item.append(head, meta, el("p", "board-body", file.description));
  clickable(item, () => openFile(file.id));
  return item;
}

function openFile(id) {
  filesState.openId = id;
  filesStatus("");
  renderFiles();
  showFile(id, false);
}

function backToFiles() {
  filesState.openId = null;
  $("file-detail").replaceChildren();
  renderFiles();
}

function backButton() {
  const back = el("button", "ghost small", "← All files");
  back.type = "button";
  back.addEventListener("click", backToFiles);
  return back;
}

/* Loads one version into the detail view. `quiet` keeps the current view on
   screen while it reloads. */
async function showFile(id, quiet) {
  const box = $("file-detail");
  if (!quiet) box.replaceChildren(backButton(), el("p", "muted", "Loading…"));
  let data;
  try {
    const response = await api("/admin/api/files/" + encodeURIComponent(id));
    if (filesState.openId !== id) return;
    if (response.status === 404) {
      box.replaceChildren(backButton(), el("p", "muted", "This file version no longer exists."));
      return;
    }
    if (!response.ok) throw new Error("failed");
    data = await response.json();
  } catch (_) {
    if (filesState.openId === id) {
      box.replaceChildren(backButton(), el("p", "muted", "This file could not be loaded."));
    }
    return;
  }
  if (filesState.openId !== id) return;
  renderFileDetail(data);
}

function renderFileDetail(data) {
  const admin = can("write");
  const { file, versions } = data;
  const box = $("file-detail");
  box.replaceChildren(backButton());

  const head = el("div", "board-item-head file-detail-head");
  head.append(kindPill(file.kind), el("h3", "file-path", file.path), el("span", "board-id", "v" + file.version));
  box.append(head);
  const meta = [`#${file.id}`, file.project, humanSize(file.size), `saved by ${file.agent}`,
    shortDate(file.created_at), `sha256 ${file.sha256.slice(0, 12)}`];
  if (file.entry_id) meta.push(`entry #${file.entry_id}`);
  box.append(el("div", "board-meta", meta.join(" · ")), el("p", "board-body", file.description));

  const actions = el("div", "board-actions file-actions");
  const download = el("a", "ghost small button-link", "Download");
  download.href = `/admin/api/files/${encodeURIComponent(file.id)}/download`;
  download.setAttribute("download", "");
  actions.append(download);
  if (admin) {
    const one = el("button", "ghost small danger", "Delete this version");
    one.type = "button";
    one.addEventListener("click", () => deleteFile(file, versions, false, actions));
    actions.append(one);
    if (versions.length > 1) {
      const all = el("button", "ghost small danger", "Delete all versions");
      all.type = "button";
      all.addEventListener("click", () => deleteFile(file, versions, true, actions));
      actions.append(all);
    }
  }
  box.append(actions);

  box.append(el("h4", "", versions.length > 1 ? `Versions (${versions.length})` : "Versions"));
  const list = el("ul", "file-versions");
  for (const version of versions) {
    const current = version.id === file.id;
    const item = el("li", current ? "active" : "");
    item.append(el("span", "board-id", "v" + version.version),
      el("span", "", [humanSize(version.size), `by ${version.agent}`, ago(version.created_at)].join(" · ")));
    item.title = shortDate(version.created_at);
    if (current) item.setAttribute("aria-current", "true");
    else clickable(item, () => openFile(version.id));
    list.append(item);
  }
  box.append(list);

  box.append(el("h4", "", "Content"));
  if (data.text === null) {
    box.append(el("p", "muted small-text", "Binary file: download it to look inside."));
  } else {
    box.append(el("pre", "file-content", data.text));
    if (data.truncated) {
      box.append(el("p", "muted small-text",
        "Showing the first 200 000 characters; download the file for the rest."));
    }
  }
}

async function deleteFile(file, versions, all, row) {
  const what = all
    ? `all ${versions.length} versions of ${file.path}`
    : `${file.path} v${file.version}`;
  const sure = window.confirm(`Delete ${what} in ${file.project}?\n\n` +
    "This cannot be undone. Export a backup first if you might want it back.");
  if (!sure) return;
  for (const button of row.querySelectorAll("button")) button.disabled = true;
  try {
    const response = await api(`/admin/api/files/${encodeURIComponent(file.id)}` + (all ? "?all=true" : ""),
      { method: "DELETE" });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      filesStatus(result.error || (response.status === 404
        ? "That file version no longer exists." : "The file could not be deleted."), "bad");
    } else {
      filesStatus(all ? `Deleted every version of ${file.path}.` : `Deleted ${file.path} v${file.version}.`, "ok");
      // After one version goes, the newest one left is shown, if any.
      const left = all ? [] : versions.filter((version) => version.id !== file.id);
      if (left.length) {
        openFile(left[0].id);
      } else {
        backToFiles();
      }
    }
  } catch (_) {
    filesStatus("The file could not be deleted.", "bad");
  }
  for (const button of row.querySelectorAll("button")) button.disabled = false;
  await loadFiles();
}

$("files-search").addEventListener("input", (event) => {
  clearTimeout(filesState.searchTimer);
  filesState.searchTimer = setTimeout(() => {
    filesState.query = event.target.value.trim();
    filesState.openId = null;
    renderFiles();
    loadFiles();
  }, 250);
});

$("files-project").addEventListener("change", (event) => {
  filesState.project = event.target.value;
  filesState.openId = null;
  renderFiles();
  loadFiles();
});

/* ---------- The Add file form ---------- */

function clearPicked() {
  filesState.picked = null;
  filesState.reading += 1; // a read still running is now stale
  $("file-picker").value = "";
  $("file-picked").hidden = true;
  $("file-picked-name").textContent = "";
  $("file-text").disabled = false;
}

function toBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

/* A picked file is read in the page: text that decodes as UTF-8 is sent as
   it is, anything else as base64. Files over 2 MiB are refused here. */
$("file-picker").addEventListener("change", (event) => {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > FILE_MAX_BYTES) {
    clearPicked();
    filesStatus(`${file.name} is ${humanSize(file.size)}; a file may be at most 2 MiB.`, "bad");
    return;
  }
  const token = ++filesState.reading;
  filesStatus(`Reading ${file.name}…`);
  const reader = new FileReader();
  reader.addEventListener("load", () => {
    if (token !== filesState.reading) return;
    const bytes = new Uint8Array(reader.result);
    let text = null;
    if (!bytes.includes(0)) {
      try {
        text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      } catch (_) { text = null; }
    }
    filesState.picked = text !== null
      ? { name: file.name, encoding: "utf8", content: text }
      : { name: file.name, encoding: "base64", content: toBase64(bytes) };
    if (!$("file-path").value.trim()) $("file-path").value = file.name;
    $("file-picked-name").textContent =
      `${file.name} · ${humanSize(file.size)} · ${text !== null ? "text" : "binary, sent as base64"}`;
    $("file-picked").hidden = false;
    $("file-text").disabled = true;
    filesStatus("");
  });
  reader.addEventListener("error", () => {
    if (token !== filesState.reading) return;
    clearPicked();
    filesStatus(`${file.name} could not be read.`, "bad");
  });
  reader.readAsArrayBuffer(file);
});

$("file-clear").addEventListener("click", clearPicked);

$("file-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const picked = filesState.picked;
  const text = $("file-text").value;
  if (!picked && $("file-picker").files.length) {
    filesStatus("The picked file is still being read.", "bad");
    return;
  }
  if (!picked && !text) {
    filesStatus("Pick a file or paste its text.", "bad");
    return;
  }
  const button = $("file-submit");
  button.disabled = true;
  try {
    const response = await api("/admin/api/files", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        project: $("file-project").value.trim(),
        path: $("file-path").value.trim(),
        kind: $("file-kind").value,
        description: $("file-description").value.trim(),
        encoding: picked ? picked.encoding : "utf8",
        content: picked ? picked.content : text,
      }),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      filesStatus(result.error || (response.status === 413
        ? "That file is too large." : "The file could not be saved."), "bad");
      return;
    }
    const saved = result.file;
    filesStatus(result.unchanged
      ? `${saved.path} is unchanged (v${saved.version}).`
      : `Saved ${saved.path} v${saved.version} in ${saved.project}.`, "ok");
    // The project and the kind stay for the next file.
    $("file-path").value = "";
    $("file-description").value = "";
    $("file-text").value = "";
    clearPicked();
    await loadFiles();
  } catch (_) {
    filesStatus("The file could not be saved.", "bad");
  } finally {
    button.disabled = false;
  }
});

/* ---------- Integrations: the services lore can operate ---------- */

/* The provider cards are static markup and are never rebuilt, so a
   refresh while the admin is pasting a credential only replaces the
   status lines, the permission table and the operations log. */
const LEVELS = [["off", "Off"], ["read", "Read"], ["full", "Full"]];
const OPS_TOOLS = new Set(["integrations", "cloudflare", "github", "github_org", "git_server", "dokploy", "mail"]);
const integrationsState = {
  data: null, loading: null, again: false, timer: null,
};

function integrationsStatus(text, tone) {
  const node = $("integrations-status");
  node.textContent = text;
  node.className = "small-text" + (tone ? " " + tone : "");
}

function closeIntegrations() {
  $("integrations").hidden = true;
  $("integrations-toggle").setAttribute("aria-expanded", "false");
  clearTimeout(integrationsState.timer);
  // A credential pasted but not saved does not outlive the panel.
  for (const input of $("integrations").querySelectorAll(".int-secret")) input.value = "";
}

/* True when the browser filled the field in itself (a saved password),
   not the admin: such a value is never sent as a credential. */
function autofilled(input) {
  for (const selector of [":autofill", ":-webkit-autofill"]) {
    try {
      if (input.matches(selector)) return true;
    } catch (_) {
      // A browser that does not know the selector did not autofill by it.
    }
  }
  return false;
}

/* A fresh sign-in starts from nothing stored, with nothing typed. */
function resetIntegrations() {
  Object.assign(integrationsState, { data: null, loading: null, again: false });
  clearTimeout(integrationsState.timer);
  for (const input of $("integrations").querySelectorAll(".int-secret, .int-url, .int-host, .int-port, .int-account")) input.value = "";
  for (const result of $("integrations").querySelectorAll(".int-result")) {
    result.textContent = "";
    result.className = "int-result small-text";
  }
}

$("integrations-toggle").addEventListener("click", () => {
  const panel = $("integrations");
  if (!panel.hidden) { closeIntegrations(); return; }
  panel.hidden = false;
  $("integrations-toggle").setAttribute("aria-expanded", "true");
  closeUsers();
  closeAgentsPanel();
  $("backup").hidden = true;
  $("backup-toggle").setAttribute("aria-expanded", "false");
  $("profile").hidden = true;
  $("profile-toggle").setAttribute("aria-expanded", "false");
  closeBoard();
  closeFiles();
  integrationsStatus("");
  renderIntegrations();
  loadIntegrations();
});

/* One load at a time, and at most one more queued behind it, like the
   other panels. */
function loadIntegrations() {
  if (integrationsState.loading) {
    integrationsState.again = true;
    return integrationsState.loading;
  }
  integrationsState.loading = (async () => {
    try {
      do {
        integrationsState.again = false;
        const response = await api("/admin/api/integrations");
        if (!response.ok) throw new Error("failed");
        integrationsState.data = await response.json();
        if (!$("integrations").hidden) renderIntegrations();
      } while (integrationsState.again);
    } catch (_) {
      if (!$("integrations").hidden) integrationsStatus("The integrations could not be loaded.", "bad");
    } finally {
      integrationsState.loading = null;
    }
  })();
  return integrationsState.loading;
}

/* Live events reload the panel only while it is open, and only for
   actions that touch the services. */
function integrationsActivity(activity) {
  if ($("integrations").hidden) return;
  if (activity && !OPS_TOOLS.has(activity.tool)) return;
  clearTimeout(integrationsState.timer);
  integrationsState.timer = setTimeout(loadIntegrations, 250);
}

function renderIntegrations() {
  const admin = can("integrations");
  const data = integrationsState.data;

  $("integrations-vault").hidden = !data || data.vault_enabled;
  $("integrations-switch").hidden = !admin || !data;
  if (data) $("integrations-enabled").checked = data.enabled;

  let configured = 0;
  for (const item of $("integrations-list").children) {
    const provider = item.dataset.provider;
    const row = data && data.providers.find((entry) => entry.id === provider);
    const isSet = !!(row && row.configured);
    if (isSet) configured += 1;

    const status = item.querySelector(".int-status");
    const unreadable = isSet && data.vault_enabled && !row.readable;
    const isMail = !!(row && row.kind === "mail");
    // A password has no hint: the mailbox says whose it is instead.
    status.textContent = !isSet
      ? "Not set"
      : unreadable
        ? "Set · cannot be decrypted with the current key · enter it again"
        : isMail
          ? `Set · updated ${ago(row.updated_at)}`
          : `Set · ends in ••••${row.hint} · updated ${ago(row.updated_at)}`;
    status.title = isSet ? `saved ${shortDate(row.updated_at)}` : "";

    const urlView = item.querySelector(".int-url-view");
    // A viewer reads the URL (or the mailbox) as text; the admin has the
    // inputs for it.
    urlView.textContent = !isSet || !row
      ? ""
      : isMail
        ? `${row.account} at ${row.host}:${row.port}`
        : row.base_url || "";
    urlView.hidden = admin;

    const form = item.querySelector(".integration-form");
    form.hidden = !admin;
    if (admin) {
      // The URL field keeps what the admin typed; it is only pre-filled
      // when it is empty, and the credential field is never pre-filled.
      const urlInput = form.querySelector(".int-url");
      if (urlInput && !urlInput.value.trim() && row && row.base_url) urlInput.value = row.base_url;
      if (isMail && isSet) {
        for (const [selector, value] of [[".int-host", row.host], [".int-port", row.port], [".int-account", row.account]]) {
          const input = form.querySelector(selector);
          if (input && !String(input.value).trim() && value) input.value = value;
        }
      }
      item.querySelector(".int-test").hidden = !isSet;
      item.querySelector(".int-remove").hidden = !isSet;
    }
  }
  $("integrations-count").textContent = data
    ? `${configured} of ${data.providers.length} services set`
    : "";

  renderPermissions(admin);
  renderOpsLog();
}

/* One row per known agent, one column per provider: a select for the
   admin, the level as text for a viewer. */
function renderPermissions(admin) {
  const data = integrationsState.data;
  const box = $("integrations-perms");
  box.replaceChildren();
  if (!data) {
    box.append(el("p", "muted small-text", "Loading…"));
    return;
  }
  if (!data.agents.length) {
    box.append(el("p", "muted small-text", "No agents have connected yet."));
    return;
  }
  const byKey = new Map(data.permissions.map((row) => [`${row.agent}|${row.provider}`, row.level]));
  const table = el("table", "perm-grid");
  const head = el("tr");
  head.append(el("th", "", "agent"));
  for (const provider of data.providers) head.append(el("th", "", provider.id));
  table.append(head);
  for (const agent of data.agents) {
    const row = el("tr");
    row.append(el("th", "", agent));
    for (const provider of data.providers) {
      const cell = el("td");
      // Each provider has its own levels and default: the services are
      // full without a row, the mailbox is off and knows only off/read.
      const allowed = provider.levels || ["off", "read", "full"];
      let level = byKey.get(`${agent}|${provider.id}`) || provider.default_level || "full";
      if (!allowed.includes(level)) level = allowed[allowed.length - 1];
      if (admin) {
        const select = el("select");
        fillSelect(select, LEVELS.filter(([value]) => allowed.includes(value)));
        select.value = level;
        select.dataset.level = level;
        select.dataset.agent = agent;
        select.dataset.provider = provider.id;
        select.setAttribute("aria-label", `${agent} on ${provider.id}`);
        select.addEventListener("change", () => savePermission(select));
        cell.append(select);
      } else {
        cell.append(el("span", "pill level-" + level, level));
      }
      row.append(cell);
    }
    table.append(row);
  }
  box.append(table);
}

async function savePermission(select) {
  const payload = {
    agent: select.dataset.agent,
    provider: select.dataset.provider,
    level: select.value,
  };
  try {
    const response = await api("/admin/api/integrations/permissions", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      // The select shows what is stored, not what was refused.
      select.value = select.dataset.level;
      integrationsStatus(result.error || "The permission could not be saved.", "bad");
      return;
    }
    select.dataset.level = payload.level;
    integrationsStatus(`${payload.agent} → ${payload.provider}: ${payload.level}`, "ok");
  } catch (_) {
    select.value = select.dataset.level;
    integrationsStatus("The permission could not be saved.", "bad");
  }
}

/* The operations log: time, agent, provider, method, path, status,
   outcome. */
function renderOpsLog() {
  const data = integrationsState.data;
  const list = $("ops-log");
  list.replaceChildren();
  if (!data) {
    list.append(el("li", "none", "Loading…"));
    return;
  }
  if (!data.log.length) {
    list.append(el("li", "none", "No service calls yet."));
    return;
  }
  for (const row of data.log) {
    const item = el("li", "ops-row");
    const when = el("span", "ops-when", ago(row.created_at));
    when.title = shortDate(row.created_at);
    item.append(
      when,
      el("span", "ops-agent", row.agent),
      el("span", "ops-provider", row.provider),
      el("span", "ops-call", `${row.method} ${row.path}`),
      el("span", "ops-status", row.status ? String(row.status) : "—"),
      el("span", "pill " + row.outcome, row.outcome)
    );
    if (row.detail) item.title = row.detail;
    list.append(item);
  }
}

/* The card forms: static markup, bound once. Saving clears the
   credential field; nothing ever fills it back in. */
for (const form of $("integrations").querySelectorAll(".integration-form")) {
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    saveIntegration(form.dataset.provider, form);
  });
  form.querySelector(".int-test").addEventListener("click", () => {
    testIntegration(form.dataset.provider, form);
  });
  form.querySelector(".int-remove").addEventListener("click", () => {
    removeIntegration(form.dataset.provider, form);
  });
}

async function saveIntegration(provider, form) {
  const secretField = form.querySelector(".int-secret");
  if (autofilled(secretField)) {
    secretField.value = "";
    integrationsStatus("The browser filled the credential in by itself; paste the credential.", "bad");
    return;
  }
  if (provider === "mail") {
    saveMailbox(form, secretField);
    return;
  }
  const secret = secretField.value.trim();
  const urlField = form.querySelector(".int-url");
  const payload = { secret, base_url: urlField ? urlField.value.trim() : "" };
  if (!payload.secret) {
    // The server URL is sealed with the credential: changing it needs the
    // credential again.
    integrationsStatus(
      urlField ? "Paste the credential; changing the server URL needs it again." : "Paste the credential.",
      "bad"
    );
    return;
  }
  try {
    const response = await api(`/admin/api/integrations/${encodeURIComponent(provider)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      integrationsStatus(result.error || "The credential could not be saved.", "bad");
      return;
    }
    secretField.value = "";
    integrationsStatus(`Saved the ${provider} credential.`, "ok");
    await loadIntegrations();
  } catch (_) {
    integrationsStatus("The credential could not be saved.", "bad");
  }
}

/* The mailbox card: host, port, account and the password, which is
   always entered again (all four are sealed together). */
async function saveMailbox(form, secretField) {
  const portText = form.querySelector(".int-port").value.trim();
  const payload = {
    host: form.querySelector(".int-host").value.trim(),
    port: portText ? Number(portText) : null,
    account: form.querySelector(".int-account").value.trim(),
    // Not trimmed: spaces may belong to a password.
    secret: secretField.value,
  };
  if (!payload.host || !payload.account) {
    integrationsStatus("Enter the server host and the account.", "bad");
    return;
  }
  if (!payload.secret) {
    integrationsStatus("Enter the password; changing the host, port or account needs it again.", "bad");
    return;
  }
  try {
    const response = await api("/admin/api/integrations/mail", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      integrationsStatus(result.error || "The mailbox could not be saved.", "bad");
      return;
    }
    secretField.value = "";
    integrationsStatus("Saved the mailbox.", "ok");
    await loadIntegrations();
  } catch (_) {
    integrationsStatus("The mailbox could not be saved.", "bad");
  }
}

async function testIntegration(provider, form) {
  const result = form.closest(".integration").querySelector(".int-result");
  result.textContent = "Testing…";
  result.className = "int-result small-text";
  try {
    const response = await api(`/admin/api/integrations/${encodeURIComponent(provider)}/test`, {
      method: "POST",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      result.textContent = data.error || "The test could not run.";
      result.className = "int-result small-text bad";
      return;
    }
    result.textContent = data.message;
    result.className = "int-result small-text " + (data.ok ? "ok" : "bad");
  } catch (_) {
    result.textContent = "The test could not run.";
    result.className = "int-result small-text bad";
  }
}

async function removeIntegration(provider, form) {
  const sure = window.confirm(
    `Remove the ${provider} credential?\n\n` +
    "Agents will no longer be able to call it through lore. This cannot be undone."
  );
  if (!sure) return;
  try {
    const response = await api(`/admin/api/integrations/${encodeURIComponent(provider)}`, {
      method: "DELETE",
    });
    if (response.status === 404) {
      integrationsStatus(`No ${provider} credential was stored.`, "bad");
      await loadIntegrations();
      return;
    }
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      integrationsStatus(result.error || "The credential could not be removed.", "bad");
      return;
    }
    form.querySelector(".int-secret").value = "";
    integrationsStatus(`Removed the ${provider} credential.`, "ok");
    await loadIntegrations();
  } catch (_) {
    integrationsStatus("The credential could not be removed.", "bad");
  }
}

/* The master switch: whether agents may operate services at all. */
$("integrations-enabled").addEventListener("change", async (event) => {
  const enabled = event.target.checked;
  try {
    const response = await api("/admin/api/integrations/enabled", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      event.target.checked = !enabled;
      integrationsStatus(result.error || "The switch could not be saved.", "bad");
      return;
    }
    integrationsStatus(
      enabled ? "Agents may operate services." : "Service operations are switched off.",
      "ok"
    );
  } catch (_) {
    event.target.checked = !enabled;
    integrationsStatus("The switch could not be saved.", "bad");
  }
});

/* ---------- Your password (stored users) ---------- */

function resetOwnPassword() {
  for (const id of ["own-current", "own-new", "own-again"]) $(id).value = "";
}

$("own-password").addEventListener("submit", async (event) => {
  event.preventDefault();
  const current = $("own-current").value, password = $("own-new").value;
  if (password !== $("own-again").value) {
    profileStatus("The two new passwords differ.", "bad");
    return;
  }
  if (password.length < 10) {
    profileStatus("The new password must be at least 10 characters.", "bad");
    return;
  }
  $("own-submit").disabled = true;
  try {
    const response = await api("/admin/api/password", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current, password }),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      profileStatus(result.error || "The password could not be changed.", "bad");
      return;
    }
    resetOwnPassword();
    profileStatus("Password changed. Your other sessions were signed out.", "ok");
  } catch (_) {
    profileStatus("The password could not be changed.", "bad");
  } finally {
    $("own-submit").disabled = false;
  }
});

/* ---------- Users ---------- */

/* The add form is static markup; the permission checkboxes and the list
   are rebuilt from what the server sends. */
const usersState = { data: null, editing: null };

function usersStatus(text, tone) {
  const node = $("users-status");
  node.textContent = text;
  node.className = "small-text" + (tone ? " " + tone : "");
}

function closeUsers() {
  $("users").hidden = true;
  $("users-toggle").setAttribute("aria-expanded", "false");
  usersState.editing = null;
  // Typed passwords do not outlive the panel.
  for (const input of $("users").querySelectorAll('input[type="password"]')) input.value = "";
}

function resetUsers() {
  usersState.data = null;
  usersState.editing = null;
  $("user-form").reset();
  $("user-list").replaceChildren();
  $("user-perms").replaceChildren($("user-perms").querySelector("legend"));
  usersStatus("");
}

$("users-toggle").addEventListener("click", () => {
  const panel = $("users");
  if (!panel.hidden) { closeUsers(); return; }
  panel.hidden = false;
  $("users-toggle").setAttribute("aria-expanded", "true");
  closeAgentsPanel();
  $("backup").hidden = true;
  $("backup-toggle").setAttribute("aria-expanded", "false");
  $("profile").hidden = true;
  $("profile-toggle").setAttribute("aria-expanded", "false");
  closeBoard();
  closeFiles();
  closeIntegrations();
  usersStatus("");
  loadUsers();
});

async function loadUsers() {
  try {
    const response = await api("/admin/api/users");
    if (!response.ok) throw new Error("failed");
    usersState.data = await response.json();
  } catch (_) {
    usersStatus("The users could not be loaded.", "bad");
    return;
  }
  renderUsers();
}

/* One checkbox per permission, with its explanation. */
function permissionChecks(container, checked, disabledIds) {
  const data = usersState.data;
  for (const old of container.querySelectorAll(".perm-check")) old.remove();
  for (const perm of data ? data.permissions : []) {
    const label = el("label", "perm-check");
    const box = el("input");
    box.type = "checkbox";
    box.value = perm.id;
    box.checked = checked.includes(perm.id);
    // Only a permission the signed-in user holds can be granted or taken
    // away; the server refuses the others too.
    if ((disabledIds && disabledIds.includes(perm.id)) || !can(perm.id)) box.disabled = true;
    if (!can(perm.id)) label.title = "You do not hold this permission, so you cannot grant it.";
    const text = el("span");
    text.append(el("b", "", perm.id), el("span", "muted", perm.explanation));
    label.append(box, text);
    container.append(label);
  }
}

function checkedPermissions(container) {
  return [...container.querySelectorAll('.perm-check input[type="checkbox"]')]
    .filter((box) => box.checked)
    .map((box) => box.value);
}

function permissionPills(ids) {
  const row = el("div", "user-perms");
  if (!ids.length) row.append(el("span", "pill", "read only"));
  for (const id of ids) row.append(el("span", "pill perm", id));
  return row;
}

function renderUsers() {
  const data = usersState.data;
  if (!data) return;
  // The add form keeps what was typed; only the checkboxes are rebuilt,
  // and they keep their state.
  const form = $("user-perms");
  permissionChecks(form, form.querySelector(".perm-check") ? checkedPermissions(form) : []);

  const list = $("user-list");
  list.replaceChildren();
  for (const builtin of data.builtin) {
    const item = el("li", "board-item user-item builtin");
    const head = el("div", "board-item-head");
    head.append(el("span", "board-title", builtin.username), el("span", "board-id", "built-in"));
    item.append(head, permissionPills(builtin.permissions),
      el("p", "board-meta", "Its password is set in the server environment; it cannot be changed here."));
    list.append(item);
  }
  for (const user of data.users) list.append(userItem(user));
  $("users-count").textContent =
    `${data.users.length} stored user${data.users.length === 1 ? "" : "s"}, ${data.builtin.length} built-in`;
}

function userItem(user) {
  const item = el("li", "board-item user-item" + (user.disabled ? " disabled" : ""));
  const head = el("div", "board-item-head");
  head.append(el("span", "board-title", user.username));
  if (user.disabled) head.append(el("span", "pill cancelled", "disabled"));
  if (user.username === state.username && state.stored) head.append(el("span", "pill", "you"));
  head.append(el("span", "board-id", "#" + user.id));
  item.append(head);
  const meta = [user.email || "no e-mail",
    user.last_login_at ? `last sign-in ${ago(user.last_login_at)}` : "never signed in",
    `added by ${user.created_by || "unknown"}`];
  item.append(el("div", "board-meta", meta.join(" · ")), permissionPills(user.permissions));
  // A user who holds a permission the signed-in user lacks cannot be
  // changed or deleted by them; the server refuses it too.
  const stronger = user.permissions.filter((id) => !can(id));
  if (stronger.length) {
    item.append(el("p", "board-meta",
      `Holds ${stronger.join(", ")}, which you do not hold: only a user who holds them can change or delete this user.`));
    return item;
  }
  if (usersState.editing === user.id) {
    item.append(userEditor(user));
  } else {
    const actions = el("div", "board-actions");
    const edit = el("button", "ghost small", "Edit");
    edit.type = "button";
    edit.addEventListener("click", () => { usersState.editing = user.id; renderUsers(); });
    actions.append(edit);
    const myself = user.username === state.username && state.stored;
    if (!myself) {
      const remove = el("button", "ghost small danger", "Delete");
      remove.type = "button";
      remove.addEventListener("click", () => deleteUser(user));
      actions.append(remove);
    }
    item.append(actions);
  }
  return item;
}

/* The edit form of one user: e-mail, permissions, disabled, a new password. */
function userEditor(user) {
  const myself = user.username === state.username && state.stored;
  const form = el("form", "board-form user-editor");
  form.autocomplete = "off";
  const email = el("input");
  email.type = "email";
  email.maxLength = 254;
  email.value = user.email || "";
  const emailField = el("label", "board-field");
  emailField.append(el("span", "", "E-mail (empty removes it)"), email);
  const perms = el("fieldset", "perm-checks");
  perms.append(el("legend", "", "Permissions"));
  // Nobody takes the users permission away from themselves.
  permissionChecks(perms, user.permissions, myself ? ["users"] : null);
  const disabled = el("input");
  disabled.type = "checkbox";
  disabled.checked = user.disabled;
  disabled.disabled = myself;
  const disabledField = el("label", "rule-toggle user-disabled");
  disabledField.append(disabled, el("span", "", myself ? "disabled (not for yourself)" : "disabled: cannot sign in"));
  const password = el("input");
  password.type = "password";
  password.autocomplete = "new-password";
  password.maxLength = 256;
  const again = el("input");
  again.type = "password";
  again.autocomplete = "new-password";
  again.maxLength = 256;
  const passwordField = el("label", "board-field");
  passwordField.append(el("span", "", "New password (optional)"), password);
  const againField = el("label", "board-field");
  againField.append(el("span", "", "New password again"), again);
  const row = el("div", "board-form-row even");
  row.append(passwordField, againField);
  const actions = el("div", "board-actions");
  const save = el("button", "ghost small", "Save");
  save.type = "submit";
  const cancel = el("button", "ghost small", "Cancel");
  cancel.type = "button";
  cancel.addEventListener("click", () => { usersState.editing = null; renderUsers(); });
  actions.append(cancel, save);
  form.append(emailField, perms, disabledField, row, actions);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (password.value !== again.value) {
      usersStatus("The two passwords differ.", "bad");
      return;
    }
    const payload = {
      email: email.value.trim(),
      permissions: checkedPermissions(perms),
      disabled: disabled.checked,
    };
    if (password.value) payload.password = password.value;
    save.disabled = true;
    try {
      const response = await api("/admin/api/users/" + user.id, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) {
        usersStatus(result.error || "The user could not be saved.", "bad");
        return;
      }
      usersState.editing = null;
      usersStatus(`Saved ${user.username}.`, "ok");
      await loadUsers();
    } catch (_) {
      usersStatus("The user could not be saved.", "bad");
    } finally {
      save.disabled = false;
    }
  });
  return form;
}

async function deleteUser(user) {
  const sure = window.confirm(`Delete the user ${user.username}?\n\nThey are signed out and can no longer sign in. This cannot be undone.`);
  if (!sure) return;
  try {
    const response = await api("/admin/api/users/" + user.id, { method: "DELETE" });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      usersStatus(result.error || "The user could not be deleted.", "bad");
      return;
    }
    usersStatus(`Deleted ${user.username}.`, "ok");
    await loadUsers();
  } catch (_) {
    usersStatus("The user could not be deleted.", "bad");
  }
}

$("user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("user-password").value;
  if (password !== $("user-password-again").value) {
    usersStatus("The two passwords differ.", "bad");
    return;
  }
  const payload = {
    username: $("user-name").value.trim().toLowerCase(),
    email: $("user-email").value.trim(),
    password,
    permissions: checkedPermissions($("user-perms")),
  };
  $("user-submit").disabled = true;
  try {
    const response = await api("/admin/api/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      usersStatus(result.error || "The user could not be added.", "bad");
      return;
    }
    $("user-form").reset();
    usersStatus(`Added ${result.username}.`, "ok");
    await loadUsers();
  } catch (_) {
    usersStatus("The user could not be added.", "bad");
  } finally {
    $("user-submit").disabled = false;
  }
});

/* ---------- Agents ---------- */

/* Every agent lore knows, how it is connected and what it did. The panel
   is for users with the agents permission; the server refuses changes
   from anyone else. */
const agentsPanel = { data: null, editing: null };

function agentsStatus(text, tone) {
  const node = $("agents-status");
  node.textContent = text;
  node.className = "small-text" + (tone ? " " + tone : "");
}

function closeAgentsPanel() {
  $("agents-panel").hidden = true;
  $("agents-toggle").setAttribute("aria-expanded", "false");
  agentsPanel.editing = null;
}

function resetAgentsPanel() {
  agentsPanel.data = null;
  agentsPanel.editing = null;
  $("agent-list").replaceChildren();
  $("agents-count").textContent = "";
  agentsStatus("");
}

$("agents-toggle").addEventListener("click", () => {
  const panel = $("agents-panel");
  if (!panel.hidden) { closeAgentsPanel(); return; }
  panel.hidden = false;
  $("agents-toggle").setAttribute("aria-expanded", "true");
  $("backup").hidden = true;
  $("backup-toggle").setAttribute("aria-expanded", "false");
  $("profile").hidden = true;
  $("profile-toggle").setAttribute("aria-expanded", "false");
  closeUsers();
  closeBoard();
  closeFiles();
  closeIntegrations();
  agentsStatus("");
  loadAgentsPanel();
});

async function loadAgentsPanel() {
  try {
    const response = await api("/admin/api/agents");
    if (!response.ok) throw new Error("failed");
    agentsPanel.data = await response.json();
  } catch (_) {
    agentsStatus("The agents could not be loaded.", "bad");
    return;
  }
  renderAgentsPanel();
}

function renderAgentsPanel() {
  const data = agentsPanel.data;
  if (!data) return;
  const list = $("agent-list");
  list.replaceChildren();
  if (!data.agents.length) list.append(el("li", "none", "No agent yet."));
  const order = (agent) => (agent.last_seen ? -Date.parse(agent.last_seen) : Infinity);
  const agents = data.agents.slice().sort((a, b) => order(a) - order(b) || a.name.localeCompare(b.name));
  for (const agent of agents) list.append(agentCard(agent, data.manage));
  const oauth = data.agents.filter((agent) => agent.kind === "oauth").length;
  $("agents-count").textContent = `${data.agents.length} agent${data.agents.length === 1 ? "" : "s"}, ${oauth} through OAuth`;
}

function statRow(box, label, value) {
  box.append(el("dt", "", label), el("dd", "", String(value)));
}

function agentCard(agent, manage) {
  const item = el("li", "board-item agent-card" + (agent.disabled ? " disabled" : ""));
  const head = el("div", "board-item-head agent-head");
  head.append(avatarNode(agent.name, "large", agent.avatar), el("span", "board-title", agent.name));
  head.append(el("span", "pill " + (agent.kind === "oauth" ? "oauth" : "token"), agent.kind === "oauth" ? "OAuth" : "env token"));
  if (agent.disabled) head.append(el("span", "pill cancelled", "disabled"));
  item.append(head);
  if (agent.note) item.append(el("p", "board-body agent-note", agent.note));

  // How it connects.
  const how = [];
  if (agent.env_token) how.push("Connects with a token from the server environment.");
  else if (agent.kind === "token" && agent.registered_by === "environment") how.push("Its token is no longer in the server environment.");
  const live = agent.authorizations.filter((grant) => !grant.revoked);
  for (const grant of live) {
    how.push(`OAuth: ${grant.client_name || "an unnamed client"} · authorized by ${grant.authorized_by} ${ago(grant.authorized_at)} · ` +
      (grant.last_used_at ? `last used ${ago(grant.last_used_at)}` : "not used yet"));
  }
  if (agent.kind === "oauth" && !live.length) how.push("OAuth: no active authorization; it has to authorize again.");
  for (const line of how) item.append(el("div", "board-meta", line));
  const seen = [agent.first_seen ? `first seen ${ago(agent.first_seen)}` : "never connected"];
  if (agent.last_seen) seen.push(`last seen ${ago(agent.last_seen)}`);
  if (agent.requests) seen.push(`${agent.requests} requests`);
  if (agent.client) seen.push(agent.client);
  item.append(el("div", "board-meta", seen.join(" · ")));

  // What it did.
  const stats = agent.stats;
  const box = el("dl", "agent-stats");
  const kinds = Object.entries(stats.memories_by_kind).map(([kind, count]) => `${count} ${kind}`).join(", ");
  statRow(box, "Memories", stats.memories + (kinds ? ` (${kinds})` : ""));
  statRow(box, "Sessions", `${stats.sessions} (${stats.open_sessions} open)`);
  statRow(box, "Tool calls", `${stats.tool_calls_24h} / ${stats.tool_calls_7d} / ${stats.tool_calls_30d} in 24 h / 7 d / 30 d`);
  const services = stats.service_calls.map((call) => `${call.provider} ${call.outcome} ${call.count}`).join(", ");
  statRow(box, "Service calls", services || "none");
  statRow(box, "Tasks done", stats.tasks_done);
  statRow(box, "Files saved", stats.files_saved);
  item.append(box);

  if (!manage) return item;
  if (agentsPanel.editing === agent.name) {
    item.append(agentEditor(agent));
    return item;
  }
  const actions = el("div", "board-actions");
  const button = (text, className, onClick) => {
    const node = el("button", "ghost small" + (className ? " " + className : ""), text);
    node.type = "button";
    node.addEventListener("click", onClick);
    actions.append(node);
  };
  button("Avatar and note", "", () => { agentsPanel.editing = agent.name; renderAgentsPanel(); });
  button("Service levels", "", () => {
    closeAgentsPanel();
    $("integrations-toggle").click();
    setTimeout(() => {
      const section = document.querySelector(".integrations-perms");
      if (section) section.scrollIntoView({ block: "start" });
    }, 400);
  });
  button(agent.disabled ? "Enable" : "Disable", agent.disabled ? "" : "danger", () => setAgentDisabled(agent, !agent.disabled));
  if (agent.kind === "oauth") {
    if (live.length) button("Revoke authorization", "danger", () => revokeAgent(agent));
    button("Delete authorization", "danger", () => deleteAgent(agent));
  }
  item.append(actions);
  return item;
}

/* The avatar picker and the note of one agent. */
function agentEditor(agent) {
  const form = el("form", "board-form agent-editor");
  form.autocomplete = "off";
  let picked = agent.avatar_chosen ? agent.avatar : "";
  const picker = el("div", "avatar-row");
  const draw = () => {
    picker.replaceChildren();
    for (const id of agentsPanel.data.avatars) {
      const choice = el("button", "avatar-choice" + (id === (picked || agent.avatar) ? " picked" : ""));
      choice.type = "button";
      choice.title = id;
      choice.setAttribute("aria-label", id);
      choice.setAttribute("aria-pressed", String(id === (picked || agent.avatar)));
      const image = el("img");
      image.src = `/admin/avatars/${id}.svg`;
      image.alt = "";
      choice.append(image);
      choice.addEventListener("click", () => { picked = id; draw(); });
      picker.append(choice);
    }
  };
  draw();
  const note = el("input");
  note.type = "text";
  note.maxLength = 300;
  note.value = agent.note;
  note.placeholder = "What this agent is, where it runs";
  const noteField = el("label", "board-field");
  noteField.append(el("span", "", "Note"), note);
  const actions = el("div", "board-actions");
  const reset = el("button", "ghost small", "Default avatar");
  reset.type = "button";
  reset.addEventListener("click", () => { picked = ""; agent.avatar = defaultAvatar(agent.name); draw(); });
  const cancel = el("button", "ghost small", "Cancel");
  cancel.type = "button";
  cancel.addEventListener("click", () => { agentsPanel.editing = null; loadAgentsPanel(); });
  const save = el("button", "ghost small", "Save");
  save.type = "submit";
  actions.append(reset, cancel, save);
  form.append(picker, noteField, actions);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    const ok = await changeAgent(agent, { avatar: picked, note: note.value });
    save.disabled = false;
    if (ok) {
      agentsPanel.editing = null;
      agentsStatus(`Saved ${agent.name}.`, "ok");
      await loadAgentsPanel();
      refresh(false).catch(() => {});
    }
  });
  return form;
}

async function changeAgent(agent, payload) {
  try {
    const response = await api("/admin/api/agents/" + encodeURIComponent(agent.name), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      agentsStatus(result.error || `${agent.name} could not be changed.`, "bad");
      return false;
    }
    return true;
  } catch (_) {
    agentsStatus(`${agent.name} could not be changed.`, "bad");
    return false;
  }
}

async function setAgentDisabled(agent, disabled) {
  if (disabled && !window.confirm(`Disable ${agent.name}?\n\nIts tokens are refused and its open sessions are closed until it is enabled again.`)) return;
  if (await changeAgent(agent, { disabled })) {
    agentsStatus(`${agent.name} is ${disabled ? "disabled" : "enabled"}.`, "ok");
    await loadAgentsPanel();
  }
}

async function revokeAgent(agent) {
  if (!window.confirm(`Revoke every authorization of ${agent.name}?\n\nAll its OAuth tokens stop working; it has to be authorized again.`)) return;
  try {
    const response = await api(`/admin/api/agents/${encodeURIComponent(agent.name)}/revoke`, { method: "POST" });
    if (!response.ok) throw new Error("failed");
    agentsStatus(`The authorization of ${agent.name} is revoked.`, "ok");
    await loadAgentsPanel();
  } catch (_) {
    agentsStatus("The authorization could not be revoked.", "bad");
  }
}

async function deleteAgent(agent) {
  if (!window.confirm(`Delete the authorization of ${agent.name} entirely?\n\nIts tokens and its entry in this list go; what it wrote stays. The name becomes free again.`)) return;
  try {
    const response = await api("/admin/api/agents/" + encodeURIComponent(agent.name), { method: "DELETE" });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      agentsStatus(result.error || "The authorization could not be deleted.", "bad");
      return;
    }
    agentsStatus(`The authorization of ${agent.name} is deleted.`, "ok");
    await loadAgentsPanel();
  } catch (_) {
    agentsStatus("The authorization could not be deleted.", "bad");
  }
}

/* ---------- Tooltip and entry drawer ---------- */

graph.onHover = (node, x, y) => {
  const tip = $("tooltip");
  if (!node || state.decorative) { tip.hidden = true; return; }
  tip.replaceChildren();
  if (node.kind === "hub") {
    tip.append(el("div", "", node.label), el("div", "sub", `${node.members} memories`));
  } else if (node.kind === "agent") {
    const agent = state.agents.find((a) => a.name === node.label);
    const last = state.lastAction.get(node.label);
    const tool = last ? (TOOLS[last.tool] || { verb: last.tool }).verb : null;
    tip.append(el("div", "", node.label),
      el("div", "sub", agent ? `${agent.entries} entries written · ${agent.requests} requests` : "agent"));
    if (last) tip.append(el("div", "sub", `last: ${tool}${last.summary ? " · " + last.summary : ""}`));
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
  if (node.kind === "agent") { toggleFilter("agent", node.label); return; }
  openDetail(node);
};

function closeDetail() {
  $("detail").hidden = true;
  graph.selected = null;
}
$("detail-close").addEventListener("click", closeDetail);
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  if (!$("files").hidden) {
    closeFiles();
  } else if (!$("integrations").hidden) {
    closeIntegrations();
  } else if (!$("users").hidden) {
    closeUsers();
  } else if (!$("agents-panel").hidden) {
    closeAgentsPanel();
  } else if (!$("board").hidden) {
    closeBoard();
  } else if (!$("backup").hidden) {
    $("backup").hidden = true;
    $("backup-toggle").setAttribute("aria-expanded", "false");
  } else if (!$("profile").hidden) {
    $("profile").hidden = true;
    $("profile-toggle").setAttribute("aria-expanded", "false");
    resetOwnPassword();
  } else {
    closeDetail();
  }
});

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
  if (entry.commit || entry.repo || entry.path) {
    const where = el("div", "chips");
    if (entry.commit) {
      const label = entry.commit.slice(0, 10) + (entry.branch ? ` · ${entry.branch}` : "") +
        (entry.dirty ? " · uncommitted changes" : "");
      where.append(el("span", "chip file", label));
    }
    if (entry.repo) where.append(el("span", "chip file", entry.repo));
    if (entry.path) where.append(el("span", "chip file", entry.path));
    box.append(el("h4", "", "Logged at"), where);
  }
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

/* ---------- Phone layout: top bar, tab bar and the More sheet ----------

   At 760px and below the page shows one destination at a time, picked from
   the bottom tab bar. The destinations are the existing panels, opened and
   closed through their own toggles, so every other code path (Escape, the
   panels closing each other, a row opening a drawer) keeps working; the tab
   bar only reads the panels' state back. */

const PHONE = window.matchMedia("(max-width: 760px)");
const isPhone = () => PHONE.matches;

/* Each destination: whether it is showing, and how to show or hide it. */
const DESTINATIONS = {
  side: {
    shown: () => $("side").classList.contains("open"),
    open: () => { $("side").classList.add("open"); $("side-toggle").setAttribute("aria-expanded", "true"); },
    close: () => { $("side").classList.remove("open"); $("side-toggle").setAttribute("aria-expanded", "false"); },
  },
  feed: {
    shown: () => $("feed").classList.contains("open"),
    open: () => { $("feed").classList.add("open"); $("feed-toggle").setAttribute("aria-expanded", "true"); },
    close: () => { $("feed").classList.remove("open"); $("feed-toggle").setAttribute("aria-expanded", "false"); },
  },
  board: {
    shown: () => !$("board").hidden,
    open: () => $("board-toggle").click(),
    close: () => closeBoard(),
  },
  files: {
    shown: () => !$("files").hidden,
    open: () => $("files-toggle").click(),
    close: () => closeFiles(),
  },
  integrations: {
    shown: () => !$("integrations").hidden,
    open: () => $("integrations-toggle").click(),
    close: () => closeIntegrations(),
  },
  profile: {
    shown: () => !$("profile").hidden,
    open: () => $("profile-toggle").click(),
    close: () => { $("profile").hidden = true; $("profile-toggle").setAttribute("aria-expanded", "false"); resetOwnPassword(); },
  },
  users: {
    shown: () => !$("users").hidden,
    open: () => $("users-toggle").click(),
    close: () => closeUsers(),
  },
  agents: {
    shown: () => !$("agents-panel").hidden,
    open: () => $("agents-toggle").click(),
    close: () => closeAgentsPanel(),
  },
  backup: {
    shown: () => !$("backup").hidden,
    open: () => $("backup-toggle").click(),
    close: () => { $("backup").hidden = true; $("backup-toggle").setAttribute("aria-expanded", "false"); resetBackup(); },
  },
};
/* Profile, Users, Agents, Integrations and Backup live behind the More tab. */
const TAB_OF = { side: "side", feed: "feed", board: "board", files: "files", integrations: "more", profile: "more", users: "more", agents: "more", backup: "more" };

function moreOpen() { return !$("more").hidden; }

function openMore() {
  $("more").hidden = false;
  $("more-scrim").hidden = false;
  syncTabs();
}

function closeMore() {
  $("more").hidden = true;
  $("more-scrim").hidden = true;
  syncTabs();
}

function currentDestination() {
  for (const name of ["integrations", "profile", "users", "agents", "backup", "board", "files", "side", "feed"]) {
    if (DESTINATIONS[name].shown()) return name;
  }
  return "graph";
}

function syncTabs() {
  const active = moreOpen() ? "more" : TAB_OF[currentDestination()] || "graph";
  for (const tab of document.querySelectorAll("#tabbar .tab")) {
    const on = tab.dataset.tab === active;
    tab.classList.toggle("active", on);
    if (on) tab.setAttribute("aria-current", "page"); else tab.removeAttribute("aria-current");
  }
  document.querySelector('#tabbar [data-tab="more"]').setAttribute("aria-expanded", String(moreOpen()));
}

/* Shows one destination ("graph" for none) and closes every other one. */
function showDestination(name) {
  closeMore();
  closeDetail();
  for (const [other, destination] of Object.entries(DESTINATIONS)) {
    if (other !== name && destination.shown()) destination.close();
  }
  if (name !== "graph" && !DESTINATIONS[name].shown()) DESTINATIONS[name].open();
  for (const sheet of [$("side"), $("feed"), $("board"), $("files"), $("integrations"), $("profile"), $("users"), $("agents-panel"), $("backup")]) sheet.scrollTop = 0;
  syncTabs();
}

for (const tab of document.querySelectorAll("#tabbar .tab")) {
  tab.addEventListener("click", () => {
    const name = tab.dataset.tab;
    if (name === "more") { if (moreOpen()) closeMore(); else openMore(); return; }
    // The tab of the destination on screen takes it back to its start.
    if (name === "files" && DESTINATIONS.files.shown() && filesState.openId !== null && $("detail").hidden) {
      backToFiles();
      return;
    }
    showDestination(name);
  });
}
$("more-scrim").addEventListener("click", closeMore);
$("more-integrations").addEventListener("click", () => showDestination("integrations"));
$("more-profile").addEventListener("click", () => showDestination("profile"));
$("more-users").addEventListener("click", () => showDestination("users"));
$("more-agents").addEventListener("click", () => showDestination("agents"));
$("more-backup").addEventListener("click", () => showDestination("backup"));
$("more-logout").addEventListener("click", () => { closeMore(); $("logout").click(); });

/* On a phone only one panel shows at a time: whichever opened last wins,
   whatever code path opened it. */
{
  const panels = { side: $("side"), feed: $("feed"), board: $("board"), files: $("files"), integrations: $("integrations"), profile: $("profile"), users: $("users"), agents: $("agents-panel"), backup: $("backup") };
  const observer = new MutationObserver((records) => {
    if (isPhone()) {
      // The last record is the newest change; the panel it opened stays.
      for (const record of [...records].reverse()) {
        const name = Object.keys(panels).find((key) => panels[key] === record.target);
        if (!name || !DESTINATIONS[name].shown()) continue;
        for (const [other, destination] of Object.entries(DESTINATIONS)) {
          if (other !== name && destination.shown()) destination.close();
        }
        break;
      }
    }
    syncTabs();
  });
  for (const panel of Object.values(panels)) {
    observer.observe(panel, { attributes: true, attributeFilter: ["hidden", "class"] });
  }
}

/* The search field folds into a button on a phone and opens across the bar. */
function openSearch() {
  document.querySelector(".top").classList.add("searching");
  $("search-open").setAttribute("aria-expanded", "true");
  // Searching dims the graph, so the graph is what to look at.
  if (isPhone()) showDestination("graph");
  $("search").focus();
}

function closeSearch() {
  document.querySelector(".top").classList.remove("searching");
  $("search-open").setAttribute("aria-expanded", "false");
  $("search-open").classList.toggle("active", state.query.trim() !== "");
}

$("search-open").addEventListener("click", openSearch);
$("search-close").addEventListener("click", () => {
  // Closing an empty field just folds it; closing a filled one clears it.
  if (state.query) {
    $("search").value = "";
    state.query = "";
    applyFocus();
  }
  closeSearch();
});
$("search").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && isPhone()) $("search").blur();
});

/* Escape closes the More sheet or the search before anything underneath. */
window.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  if (moreOpen()) { closeMore(); event.stopPropagation(); return; }
  if (document.querySelector(".top").classList.contains("searching") && document.activeElement === $("search")) {
    closeSearch();
    $("search-open").focus();
    event.stopPropagation();
  }
}, true);

PHONE.addEventListener("change", () => {
  closeMore();
  if (!isPhone()) closeSearch();
  else {
    // Arriving at phone width with several panels open: keep the top one.
    const keep = currentDestination();
    for (const [other, destination] of Object.entries(DESTINATIONS)) {
      if (other !== keep && destination.shown()) destination.close();
    }
    syncTabs();
  }
});
syncTabs();

/* ---------- Boot ---------- */

(async () => {
  try {
    const session = await (await fetch("/admin/api/session", { credentials: "same-origin" })).json();
    state.siteKey = session.recaptcha_site_key;
    state.build = session.build;
    loadRecaptcha(state.siteKey);
    if (session.authenticated) await enter(session); else showLogin();
  } catch (_) {
    showLogin();
    $("login-error").textContent = "The server cannot be reached.";
  }
})();
