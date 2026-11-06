# SERRATE — identity and compatibility

**Public-facing name:** SERRATE  
**Subtitle:** Network Security & Adversary Simulation Lab  
**Internal implementation:** MON Security Fabric  
**Introduced:** 6 November 2026

## Name and position

SERRATE is a single-word, tool-like name chosen for an offensive/defensive security engineering lab. The verb *serrate* means to form a saw-toothed edge: a functional and memorable name, not an acronym or an AI-marketing construction.

The brand is a **project identity**, not a statement of trademark exclusivity. A preliminary internet and GitHub search found uses of the word in other contexts; it was not a legal trademark or domain clearance.

**Public description:** A distributed critical-network detection and response fabric, demonstrated in authorized red-team / blue-team exercises using isolated lab infrastructure.

## Original visual assets, not AI-generated imagery

All README artwork under `docs/brand/` is **hand-authored SVG source**, with editable shapes and text. No generated people, dashboards, background photography, fictitious attack data, customer logos or fabricated performance charts.

- `serrate-hero.svg` — vector title and red/blue simulation lanes
- `lifecycle.svg` — seven-step incident pipeline
- `system-boundaries.svg` — lab/source/controller/control-plane boundaries
- `response-safety.svg` — response policy/TTL/rollback gates

Palette: charcoal `#101b24`, steel `#1b3342`, attack red `#cc6d67`, defender blue `#5f99b6`, control orange `#ef8e70`. Avoid playful shields, fake terminal logs, or invented dashboards.

## Compatibility boundary

This rebrand changes documentation, website-facing graphics and human-readable project identity only. Preserve:

- GitHub source `Saitanveesh/1`
- Python distribution `mon-security-fabric` and package `mon`
- `MON_*` settings, CLI entrypoints, existing Windows/Linux services and installer IDs
- Migrations, API schemas, network protocol contracts, database contents, deployed command lines and historical records

The 2026 lab branches may still contain “MON”, “RIFTWARD”, version codes or old presentation material as historical evidence. **Do not rewrite past branch tips or deployed code to match branding.** Only rename an operational identifier through a separate audited migration with compatibility and rollback.

## Portfolio claims

Use “built and exercised in an authorized multi-host lab” only when backed by lab runbooks, test results or committed evidence. Do not claim production certification, general-purpose attack-generation capability, measured performance or live sensor availability merely from a concept diagram.

## GitHub repository settings

Suggested About text and topics are in [`docs/GITHUB_ABOUT.md`](GITHUB_ABOUT.md). The historical repo slug `1` remains unchanged until deployment URLs and CI references are reconciled.
