# MON Narrated Security-Fabric Walkthrough

This is a **synthetic educational presentation** of the MON lifecycle. It does not generate attack traffic, change firewall rules, or claim to be live telemetry.

The presentation is intentionally designed for professors, friends, interviewers, and other people who may not already understand SOC tooling. It does not begin with a dense dashboard. It begins by explaining the environment and then follows one synthetic incident in order.

The story is:

`INTRO → DISCOVER → CASE → DETECT → CORRELATE → TRACE → CONTAIN → VERIFY → RECOVER → WHY MON`

Within the MON lifecycle itself:

`DISCOVER → DETECT → CORRELATE → TRACE → CONTAIN → VERIFY → RECOVER`

## What changed in this presentation

The first version used a 3D topology-first visualization. That made the architecture visible, but it required the audience to already understand what the nodes and lines meant.

This version is deliberately content-first:

- black-and-white only;
- one narrated scene at a time;
- the camera follows only the systems relevant to the current explanation;
- every scene answers three questions:
  1. what is happening;
  2. what MON does;
  3. why it matters;
- each scene defines one important security term;
- the active path is written in plain text as well as drawn;
- browser text-to-speech explains the incident slowly;
- the synthetic database is marked **at risk** when appropriate rather than falsely marked compromised;
- containment explains blast radius, TTL, rollback, and why critical services should remain online;
- verification shows that MON must prove the response worked;
- recovery shows that temporary containment must be reversed under controlled observation.

## Synthetic incident used in the story

Assume an engineering company has:

- an Engineer Workstation;
- an Application Server;
- a Database Server;
- a Network Sensor;
- an Endpoint Sensor;
- a Local Site Controller;
- a MON SaaS Control Plane;
- a SOC Console;
- NAC / switch control and an edge firewall as possible enforcement points.

The demonstration then introduces a synthetic external attacker. The attacker probes the environment and repeatedly attempts authentication to the workstation. Later the scenario records a successful session and a new workstation-to-application connection.

MON does **not** immediately call this a compromise. Instead the walkthrough shows how evidence develops:

1. network and endpoint observations are detected;
2. related evidence is correlated;
3. the probable path is reconstructed;
4. the database is identified as a critical dependency at risk;
5. policy chooses a narrow workstation/NAC containment point;
6. the risky path is verified as stopped while the application and database remain healthy;
7. the temporary restriction is rolled back under observation.

All actors, timings, system states, and event details in this presentation are synthetic.

## Run

From the repository root:

```bash
python demo/mon_cinematic/server.py
```

On Windows, this also works:

```powershell
py demo\mon_cinematic\server.py
```

The launcher opens:

```text
http://127.0.0.1:8765/
```

No Python package installation is required for the presentation itself. The launcher uses the Python standard library and the presentation uses browser-native HTML, CSS, SVG, JavaScript, and Speech Synthesis.

## Voice narration

Click **START NARRATED DEMO**. The click is intentional because browsers may restrict speech until the user interacts with the page.

The presentation will:

- speak the current scene;
- wait briefly after the narration finishes;
- move automatically to the next scene.

The default voice rate is deliberately slower than normal conversational speech.

If the browser does not expose a speech-synthesis voice, the presentation remains usable in silent mode and advances using scene timing.

## Controls

- **Space** — pause or resume
- **Left / Right Arrow** — previous / next scene
- **V** — mute or enable narration
- **R** — replay the current narration
- **F** — fullscreen
- numbered scene buttons — jump directly to a scene

The **REPLAY VOICE** button pauses automatic progression so the current explanation can be heard again without immediately moving on.

## What the diagram means

The presentation is not trying to simulate physical 4D space. It uses a camera-like 2D network map that zooms to the systems relevant to each scene while time supplies the narrative sequence.

The bright moving route is the path currently being explained. Faded links remain only as context.

A filled white node represents a system whose current state is important to the explanation, for example:

- `UNDER PROBE`
- `SUSPICIOUS SESSION`
- `PROBABLE FOOTHOLD`
- `AT RISK — NOT CONFIRMED`
- `TEMPORARILY CONTAINED`
- `HEALTHY`
- `RESTORED + MONITORED`

These are synthetic presentation states, not live measurements.

## Files

- `scenario.json` — complete narrated story, terms, impact explanations, nodes, paths, and synthetic state
- `simulation.js` — scene sequencing, camera flow, active-path rendering, controls, and browser narration
- `styles.css` — monochrome presentation styling
- `index.html` — story layout
- `server.py` — loopback-first standard-library launcher

The presentation is deliberately isolated from MON's operational detection and enforcement code. Presentation effects cannot change real MON state.
