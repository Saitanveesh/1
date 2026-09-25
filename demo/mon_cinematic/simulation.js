const canvas = document.querySelector("#scene");
const ctx = canvas.getContext("2d", { alpha: false });

const ui = {
  title: document.querySelector("#title"),
  subtitle: document.querySelector("#subtitle"),
  tenant: document.querySelector("#tenant"),
  site: document.querySelector("#site"),
  time: document.querySelector("#sim-time"),
  stageIndex: document.querySelector("#stage-index"),
  stageName: document.querySelector("#stage-name"),
  headline: document.querySelector("#headline"),
  plain: document.querySelector("#plain"),
  question: document.querySelector("#question"),
  evidence: document.querySelector("#evidence"),
  confidence: document.querySelector("#confidence"),
  confidenceBar: document.querySelector("#confidence-bar"),
  blastRadius: document.querySelector("#blast-radius"),
  ttl: document.querySelector("#ttl"),
  affected: document.querySelector("#affected"),
  decision: document.querySelector("#decision"),
  importance: document.querySelector("#importance-copy"),
  play: document.querySelector("#play"),
  restart: document.querySelector("#restart"),
  speed: document.querySelector("#speed"),
  camera: document.querySelector("#camera"),
  fullscreen: document.querySelector("#fullscreen"),
  scrubber: document.querySelector("#scrubber"),
  stages: document.querySelector("#stages"),
  loading: document.querySelector("#loading")
};

const palette = {
  bg: "#020407",
  white: "#f7fbff",
  muted: "#758599",
  cyan: "#4ee7ff",
  cyanSoft: "rgba(78,231,255,0.24)",
  red: "#ff4d62",
  amber: "#ffbd45",
  green: "#5cf2a2"
};

let scenario = null;
let nodes = new Map();
let simTime = 0;
let playing = true;
let speed = 1;
let lastFrame = performance.now();
let activeStageIndex = -1;
let drag = null;
let starfield = [];

const camera = {
  yaw: -0.42,
  pitch: 0.24,
  distance: 18,
  target: { x: 0, y: 2.1, z: 0 },
  auto: true
};

const cameraPresets = [
  { yaw: -0.45, pitch: 0.22, distance: 18.5 },
  { yaw: -0.64, pitch: 0.18, distance: 17.5 },
  { yaw: -0.22, pitch: 0.28, distance: 16.2 },
  { yaw: 0.18, pitch: 0.24, distance: 16.8 },
  { yaw: 0.48, pitch: 0.18, distance: 15.2 },
  { yaw: 0.20, pitch: 0.36, distance: 17.0 },
  { yaw: -0.12, pitch: 0.25, distance: 16.8 }
];

function clamp(value, low, high) {
  return Math.max(low, Math.min(high, value));
}

function lerp(a, b, t) {
  return a + (b - a) * t;
}

function ease(value) {
  const t = clamp(value, 0, 1);
  return t * t * (3 - 2 * t);
}

function vec(x = 0, y = 0, z = 0) {
  return { x, y, z };
}

function fromArray(value) {
  return vec(value[0], value[1], value[2]);
}

function add(a, b) {
  return vec(a.x + b.x, a.y + b.y, a.z + b.z);
}

function sub(a, b) {
  return vec(a.x - b.x, a.y - b.y, a.z - b.z);
}

function mul(a, scalar) {
  return vec(a.x * scalar, a.y * scalar, a.z * scalar);
}

function dot(a, b) {
  return a.x * b.x + a.y * b.y + a.z * b.z;
}

function cross(a, b) {
  return vec(
    a.y * b.z - a.z * b.y,
    a.z * b.x - a.x * b.z,
    a.x * b.y - a.y * b.x
  );
}

function norm(a) {
  const length = Math.hypot(a.x, a.y, a.z) || 1;
  return vec(a.x / length, a.y / length, a.z / length);
}

function mixPoint(a, b, t) {
  return vec(lerp(a.x, b.x, t), lerp(a.y, b.y, t), lerp(a.z, b.z, t));
}

function resize() {
  const dpr = clamp(window.devicePixelRatio || 1, 1, 2);
  const width = window.innerWidth;
  const height = window.innerHeight;
  canvas.width = Math.floor(width * dpr);
  canvas.height = Math.floor(height * dpr);
  canvas.style.width = width + "px";
  canvas.style.height = height + "px";
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const random = seededRandom(411);
  starfield = Array.from({ length: Math.floor((width * height) / 6500) }, () => ({
    x: random() * width,
    y: random() * height,
    r: 0.35 + random() * 1.1,
    a: 0.15 + random() * 0.55,
    depth: 0.15 + random() * 0.85
  }));
}

function seededRandom(seed) {
  let state = seed >>> 0;
  return function random() {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

function getStage(time) {
  if (!scenario) return null;
  return scenario.stages.find((stage) => time >= stage.from && time < stage.to)
    || scenario.stages[scenario.stages.length - 1];
}

function formatTime(value) {
  const minutes = Math.floor(value / 60);
  const seconds = value - minutes * 60;
  return String(minutes).padStart(2, "0") + ":" + seconds.toFixed(1).padStart(4, "0");
}

function listInto(element, items) {
  element.replaceChildren();
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    element.appendChild(li);
  }
}

function importanceCopy(name) {
  const copy = {
    DISCOVER: "MON cannot defend what it cannot identify. Asset, service, identity, topology, and enforcement context are built before a crisis.",
    DETECT: "A single alert is not treated as truth. MON keeps the evidence and confidence explicit while more telemetry arrives.",
    CORRELATE: "Instead of forcing an operator to inspect separate alerts, MON joins network and endpoint evidence into one scoped incident.",
    TRACE: "The fabric explains not just that something looks wrong, but the observed path, the affected systems, and critical dependencies at risk.",
    CONTAIN: "Detection and enforcement are separate. Policy chooses the narrowest safe control point, records blast radius, applies a TTL, and keeps rollback available.",
    VERIFY: "MON never assumes a block worked. It checks the enforcement result, continued telemetry, and service health before claiming success.",
    RECOVER: "Temporary controls are reversible. MON rolls them back when conditions permit and verifies that normal operation returned safely."
  };
  return copy[name] || "";
}

function updateUI(stage, index) {
  if (!stage) return;
  ui.time.textContent = formatTime(simTime);
  ui.scrubber.value = String(simTime);
  ui.stageIndex.textContent = String(index + 1).padStart(2, "0");
  ui.stageName.textContent = stage.name;
  ui.headline.textContent = stage.headline;
  ui.plain.textContent = stage.plain;
  ui.question.textContent = stage.question;
  listInto(ui.evidence, stage.evidence);
  listInto(ui.affected, stage.affected);
  ui.confidence.textContent = Math.round(stage.confidence * 100) + "%";
  ui.confidenceBar.style.width = Math.round(stage.confidence * 100) + "%";
  ui.blastRadius.textContent = stage.blast_radius;
  ui.ttl.textContent = stage.ttl;
  ui.decision.textContent = stage.decision;
  ui.importance.textContent = importanceCopy(stage.name);

  Array.from(ui.stages.children).forEach((button, buttonIndex) => {
    button.classList.toggle("active", buttonIndex === index);
  });
}

function averageFocus(stage) {
  if (!stage || !stage.focus || stage.focus.length === 0) return vec(0, 2, 0);
  let total = vec();
  let count = 0;
  for (const id of stage.focus) {
    const node = nodes.get(id);
    if (!node) continue;
    total = add(total, fromArray(node.position));
    count += 1;
  }
  if (!count) return vec(0, 2, 0);
  return mul(total, 1 / count);
}

function updateCamera(stage, index, dt) {
  if (!camera.auto) return;
  const target = averageFocus(stage);
  target.y += 0.5;

  const preset = cameraPresets[index] || cameraPresets[0];
  const rate = 1 - Math.exp(-dt * 1.8);
  camera.target.x = lerp(camera.target.x, target.x, rate);
  camera.target.y = lerp(camera.target.y, target.y, rate);
  camera.target.z = lerp(camera.target.z, target.z, rate);
  camera.yaw = lerp(camera.yaw, preset.yaw, rate * 0.55);
  camera.pitch = lerp(camera.pitch, preset.pitch, rate * 0.55);
  camera.distance = lerp(camera.distance, preset.distance, rate * 0.5);
}

function cameraBasis() {
  const cp = Math.cos(camera.pitch);
  const position = vec(
    camera.target.x + Math.sin(camera.yaw) * cp * camera.distance,
    camera.target.y + Math.sin(camera.pitch) * camera.distance,
    camera.target.z + Math.cos(camera.yaw) * cp * camera.distance
  );

  const forward = norm(sub(camera.target, position));
  let right = norm(cross(forward, vec(0, 1, 0)));
  if (Math.abs(dot(right, right)) < 0.01) right = vec(1, 0, 0);
  const up = norm(cross(right, forward));
  return { position, forward, right, up };
}

function project(point, basis) {
  const relative = sub(point, basis.position);
  const z = dot(relative, basis.forward);
  if (z <= 0.25) return null;

  const x = dot(relative, basis.right);
  const y = dot(relative, basis.up);
  const focal = Math.min(window.innerWidth, window.innerHeight) * 0.92;
  const scale = focal / z;

  return {
    x: window.innerWidth * 0.5 + x * scale,
    y: window.innerHeight * 0.49 - y * scale,
    depth: z,
    scale
  };
}

function line3d(a, b, basis, color, width = 1, alpha = 1, dash = []) {
  const pa = project(a, basis);
  const pb = project(b, basis);
  if (!pa || !pb) return;

  ctx.save();
  ctx.globalAlpha = alpha;
  ctx.strokeStyle = color;
  ctx.lineWidth = width;
  ctx.setLineDash(dash);
  ctx.beginPath();
  ctx.moveTo(pa.x, pa.y);
  ctx.lineTo(pb.x, pb.y);
  ctx.stroke();
  ctx.restore();
}

function drawBackground() {
  const width = window.innerWidth;
  const height = window.innerHeight;
  const gradient = ctx.createRadialGradient(
    width * 0.5, height * 0.43, 10,
    width * 0.5, height * 0.43, Math.max(width, height) * 0.72
  );
  gradient.addColorStop(0, "#0a1620");
  gradient.addColorStop(0.45, "#050a10");
  gradient.addColorStop(1, palette.bg);
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, width, height);

  ctx.save();
  for (const star of starfield) {
    const shift = Math.sin(camera.yaw) * 18 * star.depth;
    ctx.globalAlpha = star.a;
    ctx.fillStyle = "#d7efff";
    ctx.beginPath();
    ctx.arc((star.x + shift + width) % width, star.y, star.r, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.restore();

  ctx.save();
  ctx.globalAlpha = 0.05;
  ctx.strokeStyle = "#7acfff";
  ctx.lineWidth = 1;
  for (let x = 0; x < width; x += 48) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
    ctx.stroke();
  }
  for (let y = 0; y < height; y += 48) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }
  ctx.restore();
}

function drawWorldGrid(basis) {
  for (let x = -10; x <= 10; x += 2) {
    line3d(vec(x, -2.2, -7), vec(x, -2.2, 7), basis, "#63d8ff", 1, 0.06);
  }
  for (let z = -7; z <= 7; z += 2) {
    line3d(vec(-10, -2.2, z), vec(10, -2.2, z), basis, "#63d8ff", 1, 0.06);
  }
}

function edgeKey(a, b) {
  return a < b ? a + "::" + b : b + "::" + a;
}

function activeEdges(stage) {
  const set = new Set();
  for (const route of stage.routes || []) {
    for (let i = 0; i < route.length - 1; i += 1) {
      set.add(edgeKey(route[i], route[i + 1]));
    }
  }
  return set;
}

function linkStyle(link, stage, active) {
  if (active) {
    if (stage.name === "CONTAIN") return { color: palette.amber, alpha: 0.78, width: 2.1 };
    if (stage.name === "VERIFY") return { color: palette.cyan, alpha: 0.7, width: 1.9 };
    if (stage.name === "RECOVER") return { color: palette.green, alpha: 0.66, width: 1.8 };
    return { color: palette.red, alpha: 0.76, width: 2.0 };
  }

  if (link.kind === "telemetry") return { color: palette.cyan, alpha: 0.18, width: 1.0 };
  if (link.kind === "control") return { color: palette.white, alpha: 0.13, width: 1.0, dash: [4, 7] };
  if (link.kind === "enforcement") {
    const emphasis = stage.name === "CONTAIN" || stage.name === "VERIFY";
    return { color: palette.amber, alpha: emphasis ? 0.32 : 0.08, width: emphasis ? 1.3 : 1.0, dash: [3, 7] };
  }
  return { color: "#9db1c7", alpha: 0.10, width: 1.0 };
}

function drawLinks(stage, basis) {
  const active = activeEdges(stage);

  for (const link of scenario.links) {
    const a = nodes.get(link.from);
    const b = nodes.get(link.to);
    if (!a || !b) continue;
    const style = linkStyle(link, stage, active.has(edgeKey(link.from, link.to)));
    line3d(
      fromArray(a.position),
      fromArray(b.position),
      basis,
      style.color,
      style.width,
      style.alpha,
      style.dash || []
    );
  }
}

function pulseColor(stageName) {
  if (stageName === "CONTAIN") return palette.amber;
  if (stageName === "VERIFY") return palette.cyan;
  if (stageName === "RECOVER") return palette.green;
  if (stageName === "DISCOVER") return palette.cyan;
  return palette.red;
}

function drawGlowPoint(screenPoint, color, radius, alpha = 1) {
  if (!screenPoint) return;
  ctx.save();
  ctx.globalAlpha = alpha;
  const gradient = ctx.createRadialGradient(
    screenPoint.x, screenPoint.y, 0,
    screenPoint.x, screenPoint.y, radius * 3.2
  );
  gradient.addColorStop(0, color);
  gradient.addColorStop(0.15, color);
  gradient.addColorStop(1, "rgba(0,0,0,0)");
  ctx.fillStyle = gradient;
  ctx.beginPath();
  ctx.arc(screenPoint.x, screenPoint.y, radius * 3.2, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();
}

function drawRoutePulses(stage, basis) {
  const color = pulseColor(stage.name);
  const routes = stage.routes || [];

  routes.forEach((route, routeIndex) => {
    for (let i = 0; i < route.length - 1; i += 1) {
      const a = nodes.get(route[i]);
      const b = nodes.get(route[i + 1]);
      if (!a || !b) continue;

      const pa = fromArray(a.position);
      const pb = fromArray(b.position);
      const phase = (simTime * 0.42 + i * 0.21 + routeIndex * 0.31) % 1;
      const point = mixPoint(pa, pb, ease(phase));
      const projected = project(point, basis);
      drawGlowPoint(projected, color, stage.name === "CONTAIN" ? 4.5 : 3.6, 0.88);

      for (let ghost = 1; ghost <= 3; ghost += 1) {
        const ghostT = clamp(phase - ghost * 0.055, 0, 1);
        const ghostPoint = project(mixPoint(pa, pb, ease(ghostT)), basis);
        drawGlowPoint(ghostPoint, color, 2.2, 0.22 / ghost);
      }
    }
  });
}

function drawTelemetryPulses(basis) {
  const telemetryLinks = scenario.links.filter((link) => link.kind === "telemetry");
  telemetryLinks.forEach((link, index) => {
    const a = nodes.get(link.from);
    const b = nodes.get(link.to);
    if (!a || !b) return;
    const phase = (simTime * 0.31 + index * 0.17) % 1;
    const point = mixPoint(fromArray(a.position), fromArray(b.position), ease(phase));
    const projected = project(point, basis);
    drawGlowPoint(projected, palette.cyan, 2.3, 0.45);
  });
}

function nodeState(node, stage) {
  const focus = new Set(stage.focus || []);
  const result = {
    color: "#a9b6c5",
    glow: "#a9b6c5",
    active: focus.has(node.id),
    label: ""
  };

  if (node.kind === "sensor") {
    result.color = palette.cyan;
    result.glow = palette.cyan;
  } else if (node.kind === "enforcement") {
    result.color = palette.amber;
    result.glow = palette.amber;
  } else if (node.kind === "controller" || node.kind === "cloud" || node.kind === "console") {
    result.color = "#e7f7ff";
    result.glow = palette.cyan;
  } else if (node.kind === "external") {
    result.color = "#8795a7";
    result.glow = palette.red;
  }

  if (stage.name !== "DISCOVER") {
    if (node.id === "attacker") {
      result.color = palette.red;
      result.glow = palette.red;
      result.label = "UNTRUSTED";
    }
    if (node.id === "workstation") {
      if (stage.name === "CONTAIN" || stage.name === "VERIFY") {
        result.color = palette.amber;
        result.glow = palette.amber;
        result.label = "CONTAINED";
      } else if (stage.name === "RECOVER") {
        result.color = palette.green;
        result.glow = palette.green;
        result.label = "RESTORED";
      } else {
        result.color = palette.red;
        result.glow = palette.red;
        result.label = "OBSERVED";
      }
    }
    if (node.id === "app" && ["CORRELATE", "TRACE"].includes(stage.name)) {
      result.color = palette.amber;
      result.glow = palette.amber;
      result.label = "AFFECTED";
    }
    if (node.id === "db" && stage.name === "TRACE") {
      result.color = palette.amber;
      result.glow = palette.amber;
      result.label = "AT RISK";
    }
    if ((node.id === "app" || node.id === "db") && ["VERIFY", "RECOVER"].includes(stage.name)) {
      result.color = palette.green;
      result.glow = palette.green;
      result.label = "HEALTHY";
    }
  }

  return result;
}

function polygonPath(x, y, radius, sides, rotation = -Math.PI / 2) {
  ctx.beginPath();
  for (let i = 0; i < sides; i += 1) {
    const angle = rotation + (Math.PI * 2 * i) / sides;
    const px = x + Math.cos(angle) * radius;
    const py = y + Math.sin(angle) * radius;
    if (i === 0) ctx.moveTo(px, py);
    else ctx.lineTo(px, py);
  }
  ctx.closePath();
}

function drawShape(node, projected, radius) {
  if (node.kind === "sensor") {
    polygonPath(projected.x, projected.y, radius, 3);
  } else if (node.kind === "enforcement") {
    polygonPath(projected.x, projected.y, radius, 4, Math.PI / 4);
  } else if (node.kind === "controller" || node.kind === "cloud") {
    polygonPath(projected.x, projected.y, radius, 6);
  } else {
    ctx.beginPath();
    ctx.arc(projected.x, projected.y, radius, 0, Math.PI * 2);
  }
}

function drawNode(node, projected, stage) {
  const state = nodeState(node, stage);
  const perspective = clamp(projected.scale / 42, 0.65, 1.5);
  const radius = (node.kind === "controller" || node.kind === "cloud" ? 8 : 6.4) * perspective;

  ctx.save();
  ctx.shadowColor = state.glow;
  ctx.shadowBlur = state.active ? 22 : 10;
  ctx.fillStyle = "rgba(3,8,14,0.92)";
  ctx.strokeStyle = state.color;
  ctx.lineWidth = state.active ? 2 : 1.15;
  drawShape(node, projected, radius);
  ctx.fill();
  ctx.stroke();

  if (node.critical) {
    ctx.globalAlpha = 0.58;
    ctx.lineWidth = 0.8;
    ctx.setLineDash([2, 4]);
    drawShape(node, projected, radius + 5.5);
    ctx.stroke();
    ctx.setLineDash([]);
  }

  if (state.active) {
    const pulse = 4 + Math.sin(simTime * 4.1) * 2;
    ctx.globalAlpha = 0.16;
    ctx.lineWidth = 1;
    drawShape(node, projected, radius + 10 + pulse);
    ctx.stroke();
  }
  ctx.restore();

  const labelY = projected.y + radius + 12;
  ctx.save();
  ctx.textAlign = "center";
  ctx.font = "600 10px Inter, system-ui, sans-serif";
  ctx.fillStyle = state.active ? "#eef8ff" : "#91a0b1";
  ctx.fillText(node.label, projected.x, labelY);
  if (state.label) {
    ctx.font = "700 8px ui-monospace, SFMono-Regular, Menlo, monospace";
    ctx.fillStyle = state.color;
    ctx.fillText(state.label, projected.x, labelY + 11);
  }
  ctx.restore();
}

function drawContainmentWave(stage, basis) {
  if (!["CONTAIN", "VERIFY"].includes(stage.name)) return;
  const workstation = nodes.get("workstation");
  const nac = nodes.get("nac");
  if (!workstation || !nac) return;

  const points = [workstation, nac];
  points.forEach((node, index) => {
    const projected = project(fromArray(node.position), basis);
    if (!projected) return;
    const phase = (simTime * 0.65 + index * 0.35) % 1;
    ctx.save();
    ctx.globalAlpha = (1 - phase) * 0.42;
    ctx.strokeStyle = palette.amber;
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    ctx.arc(projected.x, projected.y, 14 + phase * 44, 0, Math.PI * 2);
    ctx.stroke();
    ctx.restore();
  });
}

function drawStageTitle(stage) {
  const elapsed = simTime - stage.from;
  if (elapsed < 0 || elapsed > 2.6) return;
  const alpha = elapsed < 0.45 ? elapsed / 0.45 : 1 - (elapsed - 0.45) / 2.15;

  ctx.save();
  ctx.globalAlpha = clamp(alpha, 0, 1) * 0.24;
  ctx.textAlign = "center";
  ctx.fillStyle = palette.white;
  ctx.font = "800 " + Math.round(clamp(window.innerWidth * 0.055, 34, 78)) + "px Inter, system-ui, sans-serif";
  ctx.fillText(stage.name, window.innerWidth * 0.5, window.innerHeight * 0.36);
  ctx.font = "700 11px ui-monospace, SFMono-Regular, Menlo, monospace";
  ctx.letterSpacing = "0.12em";
  ctx.fillStyle = pulseColor(stage.name);
  ctx.fillText("TIME IS THE FOURTH DIMENSION", window.innerWidth * 0.5, window.innerHeight * 0.36 + 30);
  ctx.restore();
}

function drawLocalAutonomy(stage, basis) {
  if (stage.name !== "CONTAIN") return;
  const site = nodes.get("site-controller");
  const cloud = nodes.get("saas");
  if (!site || !cloud) return;
  const a = project(fromArray(site.position), basis);
  const b = project(fromArray(cloud.position), basis);
  if (!a || !b) return;

  const progress = (simTime - stage.from) / (stage.to - stage.from);
  if (progress < 0.48 || progress > 0.84) return;

  ctx.save();
  ctx.strokeStyle = palette.red;
  ctx.globalAlpha = 0.55;
  ctx.lineWidth = 1.4;
  ctx.setLineDash([5, 7]);
  ctx.beginPath();
  ctx.moveTo(a.x, a.y);
  ctx.lineTo(b.x, b.y);
  ctx.stroke();
  ctx.setLineDash([]);

  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  ctx.fillStyle = "rgba(3,8,14,0.88)";
  ctx.fillRect(mx - 72, my - 14, 144, 25);
  ctx.strokeStyle = "rgba(255,77,98,0.55)";
  ctx.strokeRect(mx - 72, my - 14, 144, 25);
  ctx.fillStyle = palette.red;
  ctx.font = "700 8px ui-monospace, SFMono-Regular, Menlo, monospace";
  ctx.textAlign = "center";
  ctx.fillText("CLOUD LINK DEGRADED", mx, my + 2);

  ctx.fillStyle = palette.cyan;
  ctx.fillText("LOCAL RESPONSE CONTINUES", a.x, a.y - 22);
  ctx.restore();
}

function render(stage, index) {
  drawBackground();
  const basis = cameraBasis();

  drawWorldGrid(basis);
  drawLinks(stage, basis);
  drawTelemetryPulses(basis);
  drawRoutePulses(stage, basis);
  drawContainmentWave(stage, basis);
  drawLocalAutonomy(stage, basis);

  const projectedNodes = [];
  for (const node of scenario.nodes) {
    const projected = project(fromArray(node.position), basis);
    if (projected) projectedNodes.push({ node, projected });
  }
  projectedNodes.sort((a, b) => b.projected.depth - a.projected.depth);

  for (const item of projectedNodes) {
    drawNode(item.node, item.projected, stage);
  }

  drawStageTitle(stage);

  ctx.save();
  ctx.fillStyle = "rgba(255,255,255,0.10)";
  ctx.font = "700 9px ui-monospace, SFMono-Regular, Menlo, monospace";
  ctx.textAlign = "center";
  ctx.fillText(
    "DISCOVER → DETECT → CORRELATE → TRACE → CONTAIN → VERIFY → RECOVER",
    window.innerWidth * 0.5,
    112
  );
  ctx.restore();
}

function frame(now) {
  if (!scenario) return;
  const dt = clamp((now - lastFrame) / 1000, 0, 0.05);
  lastFrame = now;

  if (playing) {
    simTime += dt * speed;
    if (simTime >= scenario.duration_seconds) {
      simTime = scenario.loop ? 0 : scenario.duration_seconds - 0.001;
    }
  }

  const stage = getStage(simTime);
  const index = scenario.stages.indexOf(stage);
  updateCamera(stage, index, dt);

  if (activeStageIndex !== index) {
    activeStageIndex = index;
  }

  updateUI(stage, index);
  render(stage, index);
  requestAnimationFrame(frame);
}

function seek(value) {
  if (!scenario) return;
  simTime = clamp(value, 0, scenario.duration_seconds - 0.001);
  const stage = getStage(simTime);
  updateUI(stage, scenario.stages.indexOf(stage));
}

function togglePlay() {
  playing = !playing;
  ui.play.textContent = playing ? "PAUSE" : "PLAY";
}

function setCameraAuto(enabled) {
  camera.auto = enabled;
  ui.camera.textContent = enabled ? "AUTO CAMERA" : "FREE CAMERA";
}

function buildStageTabs() {
  ui.stages.replaceChildren();
  scenario.stages.forEach((stage, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = stage.name;
    button.dataset.short = String(index + 1);
    button.addEventListener("click", () => {
      seek(stage.from + 0.15);
      playing = false;
      ui.play.textContent = "PLAY";
    });
    ui.stages.appendChild(button);
  });
}

function installControls() {
  ui.play.addEventListener("click", togglePlay);
  ui.restart.addEventListener("click", () => {
    seek(0);
    playing = true;
    ui.play.textContent = "PAUSE";
    setCameraAuto(true);
  });

  const speeds = [0.5, 1, 2];
  ui.speed.addEventListener("click", () => {
    const current = speeds.indexOf(speed);
    speed = speeds[(current + 1) % speeds.length];
    ui.speed.textContent = speed + "×";
  });

  ui.camera.addEventListener("click", () => setCameraAuto(!camera.auto));

  ui.fullscreen.addEventListener("click", async () => {
    if (!document.fullscreenElement) {
      await document.documentElement.requestFullscreen();
    } else {
      await document.exitFullscreen();
    }
  });

  ui.scrubber.addEventListener("input", () => {
    seek(Number(ui.scrubber.value));
    playing = false;
    ui.play.textContent = "PLAY";
  });

  canvas.addEventListener("pointerdown", (event) => {
    drag = { x: event.clientX, y: event.clientY, yaw: camera.yaw, pitch: camera.pitch };
    canvas.setPointerCapture(event.pointerId);
    setCameraAuto(false);
  });

  canvas.addEventListener("pointermove", (event) => {
    if (!drag) return;
    camera.yaw = drag.yaw - (event.clientX - drag.x) * 0.006;
    camera.pitch = clamp(drag.pitch + (event.clientY - drag.y) * 0.004, -0.35, 0.9);
  });

  canvas.addEventListener("pointerup", (event) => {
    drag = null;
    if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
  });

  canvas.addEventListener("wheel", (event) => {
    event.preventDefault();
    setCameraAuto(false);
    camera.distance = clamp(camera.distance + event.deltaY * 0.012, 10, 28);
  }, { passive: false });

  window.addEventListener("keydown", (event) => {
    if (event.code === "Space") {
      event.preventDefault();
      togglePlay();
    } else if (event.code === "ArrowRight") {
      seek(simTime + 5);
    } else if (event.code === "ArrowLeft") {
      seek(simTime - 5);
    } else if (event.key.toLowerCase() === "r") {
      seek(0);
    } else if (event.key.toLowerCase() === "f") {
      ui.fullscreen.click();
    }
  });

  window.addEventListener("resize", resize);
}

async function init() {
  try {
    const response = await fetch("./scenario.json", { cache: "no-store" });
    if (!response.ok) throw new Error("Scenario request failed: " + response.status);
    scenario = await response.json();

    nodes = new Map(scenario.nodes.map((node) => [node.id, node]));
    ui.title.textContent = scenario.title;
    ui.subtitle.textContent = scenario.subtitle;
    ui.tenant.textContent = scenario.tenant_id;
    ui.site.textContent = scenario.site_id;
    ui.scrubber.max = String(scenario.duration_seconds);

    resize();
    buildStageTabs();
    installControls();

    const firstStage = getStage(0);
    updateUI(firstStage, 0);
    ui.loading.classList.add("hidden");

    lastFrame = performance.now();
    requestAnimationFrame(frame);
  } catch (error) {
    console.error(error);
    ui.loading.innerHTML = "";
    const strong = document.createElement("strong");
    strong.textContent = "SIMULATION FAILED TO INITIALIZE";
    const span = document.createElement("span");
    span.textContent = error instanceof Error ? error.message : String(error);
    ui.loading.append(strong, span);
  }
}

init();
