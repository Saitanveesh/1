# MON Narrated Incident Walkthrough

This is a presentation-only walkthrough of the MON lifecycle. It does not generate attack traffic, change firewall rules, or claim to show live telemetry.

It is designed for a non-technical audience. The screen stays clean: the current part of the network is centered, unrelated systems disappear, the important path is animated, and a slow browser voice explains the story in plain language.

The story is:

`INTRO → DISCOVER → ATTACK BEGINS → DETECT → CORRELATE → TRACE → CONTAIN → VERIFY → RECOVER → THE WHOLE IDEA`

The MON lifecycle itself remains:

`DISCOVER → DETECT → CORRELATE → TRACE → CONTAIN → VERIFY → RECOVER`

## Presentation approach

The walkthrough deliberately avoids a dense SOC dashboard. It uses:

- black-and-white visuals only;
- a centered network map;
- only the systems relevant to the current scene;
- short titles and one simple explanation line;
- animated paths that show where traffic, evidence, or response moves;
- one plain-language security term per scene;
- slow browser text-to-speech narration;
- a final seven-step visual summary instead of another architecture screen.

The narration avoids repeatedly saying the product name. It explains the situation first: what the company has, what changed, what the clues mean, where the activity moved, why a narrow containment point is safer, how the result is checked, and how normal operation is restored.

## Example incident

The demo uses an Engineer Workstation, Application Server, Database Server, Network Sensor, Endpoint Sensor, Local Controller, Control Plane, SOC Console, NAC / switch control, and edge firewall.

An outside attacker begins probing the company and repeatedly attempts authentication to the workstation. Later the demo introduces a successful session and a new workstation-to-application connection.

The walkthrough stays conservative about evidence. It never marks the database as compromised without evidence. During TRACE it is shown as **at risk — not confirmed**.

During CONTAIN, the demo restricts the workstation path rather than taking the application and database offline. It explains:

- **blast radius** — how much legitimate activity a response may disrupt;
- **TTL** — the time limit on a temporary action;
- **rollback** — the undo plan.

VERIFY checks that the risky path stopped while the business service still works. RECOVER removes the temporary restriction under observation.

All actors, timings, states, and event details in this walkthrough are demo data.

## Run

From the repository root:

```bash
python demo/mon_cinematic/server.py
```

On Windows:

```powershell
py demo\mon_cinematic\server.py
```

The launcher opens:

```text
http://127.0.0.1:8765/
```

No extra package installation is required for the presentation. It uses the Python standard library plus browser-native HTML, CSS, SVG, JavaScript, and Speech Synthesis.

## Voice

Click **START DEMO** once. Browsers generally require a user interaction before speech can begin.

The presentation speaks the current scene, pauses briefly, and advances automatically. It now waits for the browser voice list before speaking, prefers higher-quality English voices when available, uses slightly more natural pacing, and adds a short startup delay so the first word is not clipped. If browser speech is unavailable, the scenes still advance using their fallback timing.

Voice quality still depends on the browser and voices installed by the operating system. On browsers that expose Microsoft Natural/Neural or Google English voices, those are preferred automatically; otherwise the demo uses the best English fallback it can find.

Controls:

- **Space** — pause or resume
- **Left / Right Arrow** — previous / next scene
- **V** — mute or enable voice
- **R** — replay the current narration
- **F** — fullscreen
- numbered buttons — jump directly to a scene

## Visual rules

Inactive nodes are hidden rather than left as transparent text. This prevents the overlapping labels that made the earlier version hard to read.

A white filled node means its current state matters to the story, for example:

- `BEING TESTED`
- `SUSPICIOUS LOGIN`
- `AT RISK — NOT CONFIRMED`
- `TEMPORARILY RESTRICTED`
- `HEALTHY`
- `RESTORED + WATCHED`

The final scene replaces the topology with:

`LEARN → NOTICE → JOIN → FOLLOW → BLOCK → CHECK → RESTORE`

That is the same lifecycle expressed in language a first-time viewer can remember.

## Files

- `scenario.json` — simple narration, definitions, topology, paths, and demo states
- `simulation.js` — scene sequencing, active-path animation, automatic framing, controls, and browser narration
- `styles.css` — monochrome centered presentation
- `index.html` — minimal presentation shell
- `server.py` — loopback-first standard-library launcher

The presentation remains isolated from MON operational detection and enforcement code, so presentation effects cannot alter real MON state.
