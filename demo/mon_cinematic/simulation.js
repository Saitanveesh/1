const ui = {
  startScreen: document.querySelector("#start-screen"),
  start: document.querySelector("#start"),
  presentation: document.querySelector("#presentation"),
  loading: document.querySelector("#loading"),
  chapter: document.querySelector("#chapter"),
  sceneCount: document.querySelector("#scene-count"),
  voiceState: document.querySelector("#voice-state"),
  stageLabel: document.querySelector("#stage-label"),
  stageCaption: document.querySelector("#stage-caption"),
  viewport: document.querySelector("#viewport"),
  world: document.querySelector("#world"),
  links: document.querySelector("#links"),
  nodes: document.querySelector("#nodes"),
  routeNote: document.querySelector("#route-note"),
  sceneNumber: document.querySelector("#scene-number"),
  sceneTitle: document.querySelector("#scene-title"),
  happening: document.querySelector("#happening"),
  monAction: document.querySelector("#mon-action"),
  impact: document.querySelector("#impact"),
  term: document.querySelector("#term"),
  termDefinition: document.querySelector("#term-definition"),
  subtitle: document.querySelector("#subtitle"),
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
let currentScene = 0;
let started = false;
let playing = true;
let muted = false;
let advanceTimer = null;
let narrationToken = 0;

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

function buildDiagram() {
  ui.nodes.replaceChildren();
  ui.links.replaceChildren();
  nodeElements = new Map();

  const defs = makeSvg("defs");
  const marker = makeSvg("marker", {
    id: "route-arrow",
    viewBox: "0 0 10 10",
    refX: 8,
    refY: 5,
    markerWidth: 7,
    markerHeight: 7,
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

    ui.links.appendChild(makeSvg("line", {
      x1: from.x,
      y1: from.y,
      x2: to.x,
      y2: to.y,
      class: `base-link ${link.kind}`
    }));
  }

  for (const node of scenario.nodes) {
    const element = document.createElement("div");
    element.className = `node kind-${node.kind}`;
    element.style.left = `${node.x}px`;
    element.style.top = `${node.y}px`;

    const label = document.createElement("strong");
    label.textContent = node.label;

    const role = document.createElement("small");
    role.textContent = node.role;

    const state = document.createElement("div");
    state.className = "node-state";

    element.append(label, role, state);
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
    button.title = `${scene.chapter}: ${scene.title}`;
    button.addEventListener("click", () => goToScene(index, true));
    ui.sceneDots.appendChild(button);
  });
}

function routeDescription(scene) {
  if (!scene.route || scene.route.length === 0) {
    return "No attack path yet. MON is building context before making conclusions.";
  }

  return scene.route
    .map((route) => route.map(nodeLabel).join(" → "))
    .join("   |   ");
}

function drawActiveRoutes(scene) {
  ui.links.querySelectorAll(".route-link").forEach((line) => line.remove());

  for (const route of scene.route || []) {
    for (let index = 0; index < route.length - 1; index += 1) {
      const from = nodeMap.get(route[index]);
      const to = nodeMap.get(route[index + 1]);
      if (!from || !to) continue;

      ui.links.appendChild(makeSvg("line", {
        x1: from.x,
        y1: from.y,
        x2: to.x,
        y2: to.y,
        class: "route-link",
        "marker-end": "url(#route-arrow)"
      }));
    }
  }
}

function updateNodes(scene) {
  const focus = new Set(scene.focus || []);
  const states = scene.states || {};

  for (const [id, element] of nodeElements.entries()) {
    element.classList.toggle("focus", focus.has(id));
    element.classList.toggle("stateful", Object.hasOwn(states, id));

    const state = element.querySelector(".node-state");
    state.textContent = states[id] || "";
  }
}

function cameraToScene(scene) {
  const focusNodes = (scene.focus || [])
    .map((id) => nodeMap.get(id))
    .filter(Boolean);

  if (focusNodes.length === 0) {
    ui.world.style.transform = "translate(0px, 0px) scale(0.7)";
    return;
  }

  const viewportWidth = Math.max(ui.viewport.clientWidth, 320);
  const viewportHeight = Math.max(ui.viewport.clientHeight, 220);
  const xs = focusNodes.map((node) => node.x);
  const ys = focusNodes.map((node) => node.y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  const centerX = (minX + maxX) / 2;
  const centerY = (minY + maxY) / 2;
  const contentWidth = Math.max(maxX - minX + 360, 520);
  const contentHeight = Math.max(maxY - minY + 260, 390);
  const scale = Math.max(
    0.42,
    Math.min(1.08, viewportWidth / contentWidth, viewportHeight / contentHeight)
  );
  const tx = viewportWidth / 2 - centerX * scale;
  const ty = viewportHeight / 2 - centerY * scale;

  ui.world.style.transform = `translate(${tx}px, ${ty}px) scale(${scale})`;
}

function stageCaption(scene) {
  const copy = {
    INTRO: "The company network MON must understand and protect",
    DISCOVER: "Normal systems, dependencies, sensors, and control points",
    CASE: "Synthetic attacker begins at the outside edge",
    DETECT: "Two sensors observe different pieces of the same developing event",
    CORRELATE: "Separate evidence becomes one incident story",
    TRACE: "Observed path, internal movement, and critical dependency at risk",
    CONTAIN: "Response is pushed to the narrowest safe control point",
    VERIFY: "MON proves the threat path stopped and business service still works",
    RECOVER: "Temporary restrictions are reversed under observation",
    "WHY MON": "The complete end-to-end lifecycle"
  };
  return copy[scene.chapter] || scene.title;
}

function renderScene() {
  const scene = scenario.scenes[currentScene];

  ui.chapter.textContent = scene.chapter;
  ui.sceneCount.textContent = `Scene ${currentScene + 1} of ${scenario.scenes.length}`;
  ui.sceneNumber.textContent = String(currentScene + 1).padStart(2, "0");
  ui.sceneTitle.textContent = scene.title;
  ui.happening.textContent = scene.happening;
  ui.monAction.textContent = scene.mon_action;
  ui.impact.textContent = scene.impact;
  ui.term.textContent = scene.term;
  ui.termDefinition.textContent = scene.term_definition;
  ui.subtitle.textContent = scene.narration;
  ui.stageLabel.textContent = scene.chapter === "INTRO" ? "THE ENVIRONMENT" : "FOLLOW THE STORY";
  ui.stageCaption.textContent = stageCaption(scene);
  ui.routeNote.textContent = routeDescription(scene);

  updateNodes(scene);
  drawActiveRoutes(scene);

  Array.from(ui.sceneDots.children).forEach((button, index) => {
    button.classList.toggle("active", index === currentScene);
  });

  window.requestAnimationFrame(() => cameraToScene(scene));
}

function preferredVoice() {
  if (!("speechSynthesis" in window)) return null;
  const voices = window.speechSynthesis.getVoices();
  return (
    voices.find((voice) => voice.lang === "en-US" && /natural|neural|online/i.test(voice.name)) ||
    voices.find((voice) => voice.lang === "en-US") ||
    voices.find((voice) => voice.lang.startsWith("en")) ||
    null
  );
}

function scheduleSilentAdvance(sceneIndex) {
  clearAdvanceTimer();
  if (!started || !playing) return;

  const seconds = scenario.scenes[sceneIndex].silent_seconds || 24;
  advanceTimer = window.setTimeout(() => {
    if (playing && currentScene === sceneIndex) nextScene();
  }, seconds * 1000);
}

function speakCurrentScene() {
  clearAdvanceTimer();
  if (!started || !playing) return;

  const sceneIndex = currentScene;
  const scene = scenario.scenes[sceneIndex];

  if (muted || !("speechSynthesis" in window)) {
    ui.voiceState.textContent = muted ? "Narration muted" : "Speech unavailable";
    scheduleSilentAdvance(sceneIndex);
    return;
  }

  narrationToken += 1;
  const token = narrationToken;
  window.speechSynthesis.cancel();

  const utterance = new SpeechSynthesisUtterance(scene.narration);
  const voice = preferredVoice();
  if (voice) utterance.voice = voice;
  utterance.lang = voice?.lang || "en-US";
  utterance.rate = scenario.presentation?.voice_rate || 0.86;
  utterance.pitch = scenario.presentation?.voice_pitch || 1;

  utterance.onstart = () => {
    if (token !== narrationToken) return;
    ui.voiceState.textContent = "Narrating";
  };

  utterance.onend = () => {
    if (token !== narrationToken || currentScene !== sceneIndex) return;
    ui.voiceState.textContent = "Narration on";
    if (!playing) return;

    clearAdvanceTimer();
    advanceTimer = window.setTimeout(() => {
      if (playing && currentScene === sceneIndex) nextScene();
    }, scenario.presentation?.auto_advance_pause_ms || 1400);
  };

  utterance.onerror = () => {
    if (token !== narrationToken || currentScene !== sceneIndex) return;
    ui.voiceState.textContent = "Speech unavailable";
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
    window.setTimeout(speakCurrentScene, 180);
  }
}

function nextScene() {
  if (currentScene === scenario.scenes.length - 1) {
    playing = false;
    ui.playPause.textContent = "PLAY";
    ui.voiceState.textContent = "Presentation complete";
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
    speakCurrentScene();
  }
}

function toggleVoice() {
  muted = !muted;
  ui.voiceToggle.textContent = muted ? "ENABLE VOICE" : "MUTE VOICE";

  if (muted) {
    stopNarration();
    ui.voiceState.textContent = "Narration muted";
    scheduleSilentAdvance(currentScene);
  } else if (playing) {
    ui.voiceState.textContent = "Narration on";
    speakCurrentScene();
  }
}

function replayVoice() {
  stopNarration();

  if (muted) {
    muted = false;
    ui.voiceToggle.textContent = "MUTE VOICE";
  }

  const wasPlaying = playing;
  playing = false;
  ui.playPause.textContent = "PLAY";

  if (!("speechSynthesis" in window)) {
    ui.voiceState.textContent = "Speech unavailable";
    return;
  }

  const scene = scenario.scenes[currentScene];
  narrationToken += 1;
  const token = narrationToken;
  const utterance = new SpeechSynthesisUtterance(scene.narration);
  const voice = preferredVoice();
  if (voice) utterance.voice = voice;
  utterance.lang = voice?.lang || "en-US";
  utterance.rate = scenario.presentation?.voice_rate || 0.86;
  utterance.pitch = scenario.presentation?.voice_pitch || 1;

  utterance.onstart = () => {
    if (token === narrationToken) ui.voiceState.textContent = "Replaying narration";
  };
  utterance.onend = () => {
    if (token !== narrationToken) return;
    ui.voiceState.textContent = wasPlaying ? "Paused after replay" : "Narration on";
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
    window.setTimeout(speakCurrentScene, 450);
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
    if (scenario && started) cameraToScene(scenario.scenes[currentScene]);
  });

  if ("speechSynthesis" in window) {
    window.speechSynthesis.addEventListener?.("voiceschanged", preferredVoice);
  }
}

async function init() {
  try {
    const response = await fetch("./scenario.json", { cache: "no-store" });
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
    strong.textContent = "PRESENTATION FAILED TO INITIALIZE";
    const span = document.createElement("span");
    span.textContent = error instanceof Error ? error.message : String(error);
    ui.loading.append(strong, span);
  }
}

init();
