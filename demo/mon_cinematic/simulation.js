const ui = {
  startScreen: document.querySelector("#start-screen"),
  start: document.querySelector("#start"),
  presentation: document.querySelector("#presentation"),
  loading: document.querySelector("#loading"),
  chapter: document.querySelector("#chapter"),
  sceneCount: document.querySelector("#scene-count"),
  voiceState: document.querySelector("#voice-state"),
  headline: document.querySelector("#headline"),
  caption: document.querySelector("#caption"),
  viewport: document.querySelector("#viewport"),
  world: document.querySelector("#world"),
  links: document.querySelector("#links"),
  nodes: document.querySelector("#nodes"),
  pathLabel: document.querySelector("#path-label"),
  lesson: document.querySelector("#lesson"),
  term: document.querySelector("#term"),
  termDefinition: document.querySelector("#term-definition"),
  subtitle: document.querySelector("#subtitle"),
  summaryView: document.querySelector("#summary-view"),
  prev: document.querySelector("#prev"),
  playPause: document.querySelector("#play-pause"),
  replayVoice: document.querySelector("#replay-voice"),
  voiceToggle: document.querySelector("#voice-toggle"),
  next: document.querySelector("#next"),
  fullscreen: document.querySelector("#fullscreen"),
  sceneDots: document.querySelector("#scene-dots")
};

let scenario = null;
let nodeMap = new Map();
let nodeElements = new Map();
let linkElements = [];
let currentScene = 0;
let started = false;
let playing = true;
let muted = false;
let advanceTimer = null;
let narrationToken = 0;
let cachedVoice = null;
let voiceLoadPromise = null;

const kindLabels = {
  external: "OUTSIDE",
  network: "NETWORK",
  enforcement: "CONTROL",
  endpoint: "PC",
  critical: "SERVER",
  sensor: "SENSOR",
  controller: "LOCAL",
  cloud: "CLOUD",
  console: "SOC"
};

function clearAdvanceTimer() {
  if (advanceTimer !== null) {
    window.clearTimeout(advanceTimer);
    advanceTimer = null;
  }
}

function makeSvg(tag, attrs = {}) {
  const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [name, value] of Object.entries(attrs)) {
    element.setAttribute(name, String(value));
  }
  return element;
}

function nodeLabel(id) {
  return nodeMap.get(id)?.label || id;
}

function edgeKey(a, b) {
  return a < b ? `${a}::${b}` : `${b}::${a}`;
}

function sceneVisibleIds(scene) {
  const ids = new Set(scene.focus || []);
  for (const route of scene.route || []) {
    for (const id of route) ids.add(id);
  }
  return ids;
}

function buildDiagram() {
  ui.nodes.replaceChildren();
  ui.links.replaceChildren();
  nodeElements = new Map();
  linkElements = [];

  const defs = makeSvg("defs");
  const marker = makeSvg("marker", {
    id: "route-arrow",
    viewBox: "0 0 10 10",
    refX: 9,
    refY: 5,
    markerWidth: 6,
    markerHeight: 6,
    orient: "auto-start-reverse"
  });
  marker.appendChild(makeSvg("path", {
    d: "M 0 0 L 10 5 L 0 10 z",
    fill: "#fff"
  }));
  defs.appendChild(marker);
  ui.links.appendChild(defs);

  for (const link of scenario.links) {
    const from = nodeMap.get(link.from);
    const to = nodeMap.get(link.to);
    if (!from || !to) continue;

    const line = makeSvg("line", {
      x1: from.x,
      y1: from.y,
      x2: to.x,
      y2: to.y,
      class: `base-link ${link.kind}`
    });
    line.dataset.from = link.from;
    line.dataset.to = link.to;
    ui.links.appendChild(line);
    linkElements.push({link, element: line});
  }

  for (const node of scenario.nodes) {
    const element = document.createElement("div");
    element.className = `node kind-${node.kind}`;
    element.style.left = `${node.x}px`;
    element.style.top = `${node.y}px`;

    const icon = document.createElement("span");
    icon.className = "node-icon";
    icon.textContent = kindLabels[node.kind] || "NODE";

    const label = document.createElement("strong");
    label.textContent = node.label;

    const role = document.createElement("small");
    role.textContent = node.role;

    const state = document.createElement("div");
    state.className = "node-state";

    element.append(icon, label, role, state);
    ui.nodes.appendChild(element);
    nodeElements.set(node.id, element);
  }
}

function buildSceneDots() {
  ui.sceneDots.replaceChildren();
  scenario.scenes.forEach((scene, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = String(index + 1).padStart(2, "0");
    button.title = `${scene.chapter}: ${scene.headline}`;
    button.addEventListener("click", () => goToScene(index, true));
    ui.sceneDots.appendChild(button);
  });
}

function compactPathLabel(scene) {
  const chapter = scene.chapter;
  if (chapter === "ATTACK BEGINS") return "OUTSIDE → FIREWALL → ENGINEER WORKSTATION";
  if (chapter === "DETECT") return "TWO WATCHERS → ONE LOCAL CONTROLLER";
  if (chapter === "CORRELATE") return "SEPARATE CLUES → ONE INCIDENT";
  if (chapter === "TRACE") return "OUTSIDE → WORKSTATION → APPLICATION → DATABASE AT RISK";
  if (chapter === "CONTAIN") return "LOCAL CONTROLLER → NAC → WORKSTATION";
  if (chapter === "VERIFY") return "BAD PATH STOPPED · GOOD SERVICE STILL WORKING";
  if (chapter === "RECOVER") return "UNDO TEMPORARY BLOCK → WATCH THE RESTORED PATH";
  if (chapter === "DISCOVER") return "NORMAL PATH: WORKSTATION → APPLICATION → DATABASE";
  return "";
}

function clearActiveRoutes() {
  ui.links.querySelectorAll(".route-link, .route-pulse").forEach((element) => element.remove());
}

function drawActiveRoutes(scene) {
  clearActiveRoutes();

  (scene.route || []).forEach((route, routeIndex) => {
    for (let index = 0; index < route.length - 1; index += 1) {
      const from = nodeMap.get(route[index]);
      const to = nodeMap.get(route[index + 1]);
      if (!from || !to) continue;

      const line = makeSvg("line", {
        x1: from.x,
        y1: from.y,
        x2: to.x,
        y2: to.y,
        class: "route-link",
        "marker-end": "url(#route-arrow)"
      });
      ui.links.appendChild(line);

      const pulse = makeSvg("circle", {
        cx: from.x,
        cy: from.y,
        class: "route-pulse"
      });

      const duration = 1.45 + index * 0.08;
      const delay = routeIndex * 0.24 + index * 0.12;

      pulse.appendChild(makeSvg("animate", {
        attributeName: "cx",
        from: from.x,
        to: to.x,
        dur: `${duration}s`,
        begin: `${delay}s`,
        repeatCount: "indefinite"
      }));
      pulse.appendChild(makeSvg("animate", {
        attributeName: "cy",
        from: from.y,
        to: to.y,
        dur: `${duration}s`,
        begin: `${delay}s`,
        repeatCount: "indefinite"
      }));

      ui.links.appendChild(pulse);
    }
  });
}

function updateDiagramVisibility(scene) {
  const visible = sceneVisibleIds(scene);
  const focus = new Set(scene.focus || []);
  const states = scene.states || {};

  let revealIndex = 0;
  for (const [id, element] of nodeElements.entries()) {
    const isVisible = visible.has(id);
    const isFocused = focus.has(id);

    element.classList.toggle("visible", isVisible);
    element.classList.toggle("focus", isFocused);
    element.classList.toggle("stateful", isVisible && Object.hasOwn(states, id));

    if (isVisible) {
      element.style.transitionDelay = `${Math.min(revealIndex * 45, 360)}ms`;
      revealIndex += 1;
    } else {
      element.style.transitionDelay = "0ms";
    }

    const state = element.querySelector(".node-state");
    state.textContent = states[id] || "";
  }

  for (const {link, element} of linkElements) {
    element.classList.toggle(
      "visible",
      visible.has(link.from) && visible.has(link.to)
    );
  }
}

function cameraToScene(scene) {
  if (scene.view === "summary") return;

  const visibleIds = sceneVisibleIds(scene);
  const visibleNodes = [...visibleIds]
    .map((id) => nodeMap.get(id))
    .filter(Boolean);

  if (visibleNodes.length === 0) return;

  const viewportWidth = Math.max(ui.viewport.clientWidth, 320);
  const viewportHeight = Math.max(ui.viewport.clientHeight, 220);

  const xs = visibleNodes.map((node) => node.x);
  const ys = visibleNodes.map((node) => node.y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);

  const centerX = (minX + maxX) / 2;
  const centerY = (minY + maxY) / 2;
  const contentWidth = Math.max(maxX - minX + 430, 620);
  const contentHeight = Math.max(maxY - minY + 330, 460);

  const scale = Math.max(
    0.46,
    Math.min(1.12, viewportWidth / contentWidth, viewportHeight / contentHeight)
  );

  const tx = viewportWidth / 2 - centerX * scale;
  const ty = viewportHeight / 2 - centerY * scale;

  ui.world.style.transform = `translate(${tx}px, ${ty}px) scale(${scale})`;
}

function renderScene() {
  const scene = scenario.scenes[currentScene];
  const summary = scene.view === "summary";

  ui.chapter.textContent = scene.chapter;
  ui.sceneCount.textContent = `${currentScene + 1} / ${scenario.scenes.length}`;
  ui.headline.textContent = scene.headline;
  ui.caption.textContent = scene.caption;
  ui.lesson.textContent = scene.lesson;
  ui.term.textContent = scene.term;
  ui.termDefinition.textContent = scene.term_definition;
  ui.subtitle.textContent = scene.narration;

  ui.world.classList.toggle("hidden", summary);
  ui.summaryView.classList.toggle("hidden", !summary);

  const path = compactPathLabel(scene);
  ui.pathLabel.textContent = path;
  ui.pathLabel.classList.toggle("hidden", summary || !path);

  if (!summary) {
    updateDiagramVisibility(scene);
    drawActiveRoutes(scene);
    window.requestAnimationFrame(() => cameraToScene(scene));
  } else {
    clearActiveRoutes();
    for (const element of nodeElements.values()) {
      element.classList.remove("visible", "focus", "stateful");
    }
    for (const {element} of linkElements) element.classList.remove("visible");
  }

  Array.from(ui.sceneDots.children).forEach((button, index) => {
    button.classList.toggle("active", index === currentScene);
  });
}

function voiceScore(voice) {
  const language = (voice.lang || "").toLowerCase();
  if (!language.startsWith("en")) return -1000;

  const name = (voice.name || "").toLowerCase();
  let score = 0;

  if (/natural|neural|online/.test(name)) score += 140;
  if (/google/.test(name)) score += 18;
  if (/microsoft/.test(name)) score += 12;
  if (voice.default) score += 5;

  if (language === "en-us") score += 30;
  else if (language === "en-gb") score += 24;
  else if (language === "en-in") score += 20;
  else score += 10;

  const preferredNames = scenario?.presentation?.preferred_voice_names || [];
  preferredNames.forEach((fragment, index) => {
    if (name.includes(String(fragment).toLowerCase())) {
      score += 120 - index * 4;
    }
  });

  return score;
}

function selectPreferredVoice(voices) {
  const englishVoices = voices.filter((voice) =>
    (voice.lang || "").toLowerCase().startsWith("en")
  );
  if (englishVoices.length === 0) return null;

  return [...englishVoices].sort((a, b) => voiceScore(b) - voiceScore(a))[0] || null;
}

function loadVoices() {
  if (!("speechSynthesis" in window)) return Promise.resolve([]);
  const existing = window.speechSynthesis.getVoices();
  if (existing.length > 0) return Promise.resolve(existing);
  if (voiceLoadPromise) return voiceLoadPromise;

  voiceLoadPromise = new Promise((resolve) => {
    let finished = false;

    const finish = () => {
      if (finished) return;
      finished = true;
      window.clearTimeout(timer);
      window.speechSynthesis.removeEventListener?.("voiceschanged", onChanged);
      resolve(window.speechSynthesis.getVoices());
    };

    const onChanged = () => {
      if (window.speechSynthesis.getVoices().length > 0) finish();
    };

    const timer = window.setTimeout(finish, 1200);
    window.speechSynthesis.addEventListener?.("voiceschanged", onChanged);
  });

  return voiceLoadPromise;
}

async function preferredVoice() {
  if (cachedVoice) return cachedVoice;
  const voices = await loadVoices();
  cachedVoice = selectPreferredVoice(voices);
  return cachedVoice;
}

function narrationText(text) {
  return String(text)
    .replace(/\bTTL\b/g, "T T L")
    .replace(/\bNAC\b/g, "network access control")
    .replace(/\bSOC\b/g, "security operations center")
    .replace(/\s+/g, " ")
    .trim();
}

function buildUtterance(text, voice) {
  const utterance = new SpeechSynthesisUtterance(narrationText(text));
  if (voice) utterance.voice = voice;
  utterance.lang = voice?.lang || "en-US";
  utterance.rate = scenario.presentation?.voice_rate || 0.9;
  utterance.pitch = scenario.presentation?.voice_pitch || 0.98;
  utterance.volume = 1;
  return utterance;
}

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function scheduleSilentAdvance(sceneIndex) {
  clearAdvanceTimer();
  if (!started || !playing) return;

  const seconds = scenario.scenes[sceneIndex].silent_seconds || 24;
  advanceTimer = window.setTimeout(() => {
    if (playing && currentScene === sceneIndex) nextScene();
  }, seconds * 1000);
}

async function speakCurrentScene() {
  clearAdvanceTimer();
  if (!started || !playing) return;

  const sceneIndex = currentScene;
  const scene = scenario.scenes[sceneIndex];

  if (muted || !("speechSynthesis" in window)) {
    ui.voiceState.textContent = muted ? "Muted" : "Voice unavailable";
    scheduleSilentAdvance(sceneIndex);
    return;
  }

  narrationToken += 1;
  const token = narrationToken;
  window.speechSynthesis.cancel();

  const voice = await preferredVoice();
  if (
    token !== narrationToken ||
    currentScene !== sceneIndex ||
    muted ||
    !playing
  ) return;

  await wait(scenario.presentation?.voice_start_delay_ms || 140);
  if (
    token !== narrationToken ||
    currentScene !== sceneIndex ||
    muted ||
    !playing
  ) return;

  const utterance = buildUtterance(scene.narration, voice);

  utterance.onstart = () => {
    if (token === narrationToken) ui.voiceState.textContent = "Narrating";
  };

  utterance.onend = () => {
    if (token !== narrationToken || currentScene !== sceneIndex) return;
    ui.voiceState.textContent = "Voice on";
    if (!playing) return;

    advanceTimer = window.setTimeout(() => {
      if (playing && currentScene === sceneIndex) nextScene();
    }, scenario.presentation?.auto_advance_pause_ms || 1200);
  };

  utterance.onerror = () => {
    if (token !== narrationToken || currentScene !== sceneIndex) return;
    ui.voiceState.textContent = "Voice unavailable";
    scheduleSilentAdvance(sceneIndex);
  };

  window.speechSynthesis.speak(utterance);
}

function stopNarration() {
  narrationToken += 1;
  clearAdvanceTimer();
  if ("speechSynthesis" in window) window.speechSynthesis.cancel();
}

function goToScene(index, narrate = true) {
  stopNarration();
  const total = scenario.scenes.length;
  currentScene = (index + total) % total;
  renderScene();

  if (started && narrate && playing) {
    window.setTimeout(() => { void speakCurrentScene(); }, 220);
  }
}

function nextScene() {
  if (currentScene === scenario.scenes.length - 1) {
    playing = false;
    ui.playPause.textContent = "PLAY";
    ui.voiceState.textContent = "Complete";
    return;
  }
  goToScene(currentScene + 1, true);
}

function previousScene() {
  goToScene(currentScene - 1, true);
}

function togglePlay() {
  playing = !playing;
  ui.playPause.textContent = playing ? "PAUSE" : "PLAY";

  if (!playing) {
    clearAdvanceTimer();
    if ("speechSynthesis" in window && window.speechSynthesis.speaking) {
      window.speechSynthesis.pause();
      ui.voiceState.textContent = "Paused";
    }
    return;
  }

  if (
    !muted &&
    "speechSynthesis" in window &&
    window.speechSynthesis.speaking &&
    window.speechSynthesis.paused
  ) {
    window.speechSynthesis.resume();
    ui.voiceState.textContent = "Narrating";
  } else {
    void speakCurrentScene();
  }
}

function toggleVoice() {
  muted = !muted;
  ui.voiceToggle.textContent = muted ? "VOICE ON" : "MUTE";

  if (muted) {
    stopNarration();
    ui.voiceState.textContent = "Muted";
    scheduleSilentAdvance(currentScene);
  } else if (playing) {
    speakCurrentScene();
  }
}

async function replayVoice() {
  stopNarration();

  if (muted) {
    muted = false;
    ui.voiceToggle.textContent = "MUTE";
  }

  const wasPlaying = playing;
  playing = false;
  ui.playPause.textContent = "PLAY";

  if (!("speechSynthesis" in window)) {
    ui.voiceState.textContent = "Voice unavailable";
    return;
  }

  const sceneIndex = currentScene;
  const scene = scenario.scenes[sceneIndex];
  narrationToken += 1;
  const token = narrationToken;
  const voice = await preferredVoice();

  if (token !== narrationToken || currentScene !== sceneIndex) return;

  await wait(scenario.presentation?.voice_start_delay_ms || 140);
  if (token !== narrationToken || currentScene !== sceneIndex) return;

  const utterance = buildUtterance(scene.narration, voice);

  utterance.onstart = () => {
    if (token === narrationToken) ui.voiceState.textContent = "Replaying";
  };
  utterance.onend = () => {
    if (token !== narrationToken) return;
    ui.voiceState.textContent = wasPlaying ? "Paused after replay" : "Voice on";
  };
  utterance.onerror = () => {
    if (token === narrationToken) ui.voiceState.textContent = "Voice unavailable";
  };

  window.speechSynthesis.speak(utterance);
}

function installControls() {
  ui.start.addEventListener("click", () => {
    started = true;
    playing = true;
    ui.startScreen.classList.add("hidden");
    ui.presentation.classList.remove("hidden");
    ui.playPause.textContent = "PAUSE";
    renderScene();
    window.setTimeout(() => { void speakCurrentScene(); }, 500);
  });

  ui.prev.addEventListener("click", previousScene);
  ui.next.addEventListener("click", nextScene);
  ui.playPause.addEventListener("click", togglePlay);
  ui.voiceToggle.addEventListener("click", toggleVoice);
  ui.replayVoice.addEventListener("click", replayVoice);

  ui.fullscreen.addEventListener("click", async () => {
    if (!document.fullscreenElement) {
      await document.documentElement.requestFullscreen();
    } else {
      await document.exitFullscreen();
    }
  });

  window.addEventListener("keydown", (event) => {
    if (!started) return;

    if (event.code === "Space") {
      event.preventDefault();
      togglePlay();
    } else if (event.code === "ArrowRight") {
      nextScene();
    } else if (event.code === "ArrowLeft") {
      previousScene();
    } else if (event.key.toLowerCase() === "v") {
      toggleVoice();
    } else if (event.key.toLowerCase() === "r") {
      replayVoice();
    } else if (event.key.toLowerCase() === "f") {
      ui.fullscreen.click();
    }
  });

  window.addEventListener("resize", () => {
    if (!scenario || !started) return;
    const scene = scenario.scenes[currentScene];
    if (scene.view !== "summary") cameraToScene(scene);
  });

  if ("speechSynthesis" in window) {
    window.speechSynthesis.addEventListener?.("voiceschanged", () => {
      cachedVoice = null;
      voiceLoadPromise = null;
      void preferredVoice();
    });
    void preferredVoice();
  }
}

async function init() {
  try {
    const response = await fetch("./scenario.json", {cache: "no-store"});
    if (!response.ok) throw new Error(`Scenario request failed: ${response.status}`);
    scenario = await response.json();
    nodeMap = new Map(scenario.nodes.map((node) => [node.id, node]));

    buildDiagram();
    buildSceneDots();
    installControls();
    renderScene();

    ui.loading.classList.add("hidden");
  } catch (error) {
    console.error(error);
    ui.loading.replaceChildren();

    const strong = document.createElement("strong");
    strong.textContent = "DEMO FAILED TO LOAD";
    ui.loading.append(strong);
  }
}

init();
