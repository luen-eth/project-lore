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
  log: { verb: "logged", tone: "write" },
  amend: { verb: "amended", tone: "write" },
  forget: { verb: "deleted", tone: "remove" },
  recall: { verb: "searched", tone: "read" },
  recent: { verb: "checked recent work", tone: "read" },
  projects: { verb: "listed projects", tone: "read" },
  get: { verb: "read", tone: "read" },
  import: { verb: "imported a backup", tone: "write" },
  restore: { verb: "restored a backup", tone: "remove" },
  reindex: { verb: "re-indexed memories", tone: "write" },
};
const WRITES = new Set(["log", "amend", "forget", "import", "restore", "reindex"]);
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

  nodeAt(px, py) {
    const point = this.toWorld(px, py);
    let best = null, bestDistance = Infinity;
    for (const node of this.nodes) {
      const reach = Math.max(node.radius * 1.9, 9 / this.view.k);
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
  siteKey: null, decorative: false,
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
  clearInterval(state.timer); clearInterval(state.clock);
  if (state.source) { state.source.close(); state.source = null; }
  state.version = null; state.brain = null;
  $("app").hidden = true;
  $("login").hidden = false;
  if (!state.decorative) {
    graph.byId = new Map(); graph.selected = null; graph.focus = null;
    graph.chrome = false;
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
      const body = await response.json().catch(() => ({}));
      await enter(body.role);
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

/* A viewer session watches; only the admin role is offered the backup menu.
   The server enforces this too, so hiding the button is a courtesy, not the lock. */
function applyRole(role) {
  state.role = role === "admin" ? "admin" : "viewer";
  const admin = state.role === "admin";
  $("backup-toggle").hidden = !admin;
  $("role").hidden = admin;
  if (!admin) {
    $("backup").hidden = true;
    $("backup-toggle").setAttribute("aria-expanded", "false");
  }
}

async function enter(role) {
  applyRole(role);
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
  source.addEventListener("open", () => setLive(true));
  source.addEventListener("error", () => setLive(false));
  source.addEventListener("activity", (event) => {
    try { onActivity(JSON.parse(event.data)); } catch (_) { /* malformed event: ignore */ }
  });
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
}

/* ---------- Live activity ---------- */

/* A restore rewinds activity ids, so an id alone does not identify an action. */
const activityKey = (activity) => `${activity.id}|${activity.at}|${activity.tool}`;

async function onActivity(activity) {
  if (state.seen.has(activityKey(activity))) return;
  addToFeed(activity, true);

  const agent = state.agents.find((a) => a.name === activity.agent);
  if (agent) {
    agent.seconds_since_seen = 0;
    agent.requests += 1;
  } else if (activity.agent !== "admin") {
    state.agents.unshift({ name: activity.agent, client: "", seconds_since_seen: 0, requests: 1, entries: 0 });
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

  const avatar = el("span", "avatar small", activity.agent.slice(0, 1));
  avatar.style.background = agentColor(activity.agent);
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
    const avatar = el("span", "avatar", agent.name.slice(0, 1));
    avatar.style.background = agentColor(agent.name);
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
  if (!panel.hidden) backupStatus("");
});

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
  if (!$("backup").hidden) {
    $("backup").hidden = true;
    $("backup-toggle").setAttribute("aria-expanded", "false");
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

/* ---------- Boot ---------- */

(async () => {
  try {
    const session = await (await fetch("/admin/api/session", { credentials: "same-origin" })).json();
    state.siteKey = session.recaptcha_site_key;
    loadRecaptcha(state.siteKey);
    if (session.authenticated) await enter(session.role); else showLogin();
  } catch (_) {
    showLogin();
    $("login-error").textContent = "The server cannot be reached.";
  }
})();
