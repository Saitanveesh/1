# MON Cinematic Security-Fabric Simulation

This is a **synthetic educational visualization** of the MON lifecycle. It is not an attack
tool and does not generate real network traffic.

The simulation turns the architecture into one continuous story:

`DISCOVER → DETECT → CORRELATE → TRACE → CONTAIN → VERIFY → RECOVER`

It shows how telemetry, evidence, topology, correlation, attack-path reconstruction, policy,
enforcement, TTL, rollback, audit, and recovery fit together.

## Why this exists

The production MON architecture is intentionally distributed. That makes it difficult to
explain to a non-technical audience using a static diagram. This demo uses a 3D perspective
scene plus time as the fourth dimension so an incident can be watched end to end.

The scenario is intentionally conservative:

- weak signals start with low confidence;
- the database is shown as **at risk**, not falsely claimed compromised;
- network and endpoint observations are correlated before confidence increases;
- containment chooses a narrow workstation/NAC path rather than taking critical services down;
- the response carries a simulated TTL and rollback;
- containment is verified instead of assumed successful;
- recovery is verified after rollback;
- the SaaS link briefly degrades during containment to demonstrate local Site Controller
  autonomy.

## Run

From the repository root:

```bash
python demo/mon_cinematic/server.py
```

The launcher opens:

```text
http://127.0.0.1:8765/
```

No Python package installation is required. The demo renderer uses the browser Canvas API and
ships with no third-party runtime dependencies.

Other options:

```bash
python demo/mon_cinematic/server.py --no-browser
python demo/mon_cinematic/server.py --port 9000
```

For an ephemeral port:

```bash
python demo/mon_cinematic/server.py --port 0
```

The default bind address is loopback-only. Do not bind the demo to a shared network unless you
actually intend other hosts to reach it.

## Presentation controls

- **Space** — play/pause
- **Left / Right arrow** — seek five seconds
- **Drag** — orbit the scene manually
- **Mouse wheel** — zoom
- **F** — fullscreen
- **R** — restart
- lifecycle buttons — jump directly to one MON stage
- speed control — 0.5× / 1× / 2×

For a professor or non-technical audience, use fullscreen and let the automatic camera run once
without interruption. On the second pass, pause at CORRELATE, TRACE, and CONTAIN and use the
left/right HUD to explain evidence, confidence, blast radius, TTL, and rollback.

## What is real vs simulated

Real MON concepts represented here include the Site Controller, SaaS Control Plane, network and
endpoint sensors, asset/topology context, correlation, attack graph, policy decision, multiple
enforcement points, audit/receipt behavior, TTL rollback, verification, and recovery.

All IP-like actors, incident events, timings, confidence values, asset names, and service-health
states in this demo are synthetic presentation data. They must not be cited as measurements from
a real deployment.

## Files

- `scenario.json` — deterministic story, topology, evidence, confidence, and response metadata
- `simulation.js` — dependency-free perspective renderer and timeline engine
- `styles.css` — cinematic SOC HUD styling
- `server.py` — loopback-first standard-library launcher
- `index.html` — simulation shell

The demo is deliberately isolated from production detection and enforcement code so presentation
effects can never alter MON operational state.
