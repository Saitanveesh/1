# RIFTWARD — brand and compatibility policy

**Public-facing name:** RIFTWARD Security Fabric  
**Existing engineering name:** MON Security Fabric  
**Brand introduction:** 6 November 2026

## Positioning

RIFTWARD is a distributed security fabric for **critical networks**. Its operating principle is **evidence to action; action to recovery**. It integrates network and endpoint observations, correlates incidents, maps attack and enforcement relationships, and plans reversible containment at the safest available control point.

This is **not** pitched as an AI model, autonomous black box, SIEM replacement or fully certified firewall product.

## Name rationale

- **Rift:** an exposure, break, segmentation gap or cross-boundary attack path that requires context.
- **Ward:** an engineering posture of defending assets and services with deliberate, controlled actions.
- **RIFTWARD:** a short, pronounceable working product brand without invented acronyms or generic AI words.

A preliminary public web/GitHub check did not identify a direct cybersecurity platform using this exact label in the results reviewed, but **other unrelated uses of “Riftward” exist**. This is not a formal trademark, domain or company-register clearance. Before paid distribution, perform appropriate legal and domain checks.

## Visual identity

| Token | Value | Purpose |
|---|---|---|
| Midnight | `#08121E` | Primary backgrounds |
| Steel blue | `#173345` | System blocks and boundaries |
| Copper | `#F0A36B` | Controlled action and evidence route |
| Ivory | `#F7F7F5` | Main titles |
| Muted blue | `#9FBAC9` | Supporting explanations |

Brand assets are original vector source: [hero](brand/riftward-hero.svg), [lifecycle](brand/lifecycle.svg), [system boundaries](brand/system-boundaries.svg), and [response decision](brand/response-safety.svg). They are schematic visuals, **not product screenshots, live incident evidence or benchmark results**.

Do not decorate the README with random shields, fake dashboards, invented organizations, fabricated attack data, uptime metrics, unverified customer logos or meaningless barometers.

## Deployment and API compatibility (mandatory)

This phase is **documentation-and-brand-only**. Keep existing identifiers and contracts unchanged:

- Repository: `Saitanveesh/1`
- Python distribution: `mon-security-fabric`
- Python module/package: `mon`
- Environment variables: `MON_*`
- Commands such as `mon-site`, `mon-sensor-ingress`, `mon-linux-endpoint-collector`
- Database names, migration IDs, deployment scripts, service units, credential locations and release artifact identifiers

Do **not** mass replace `MON` in application source, tests, persisted evidence, protobuf/schema/API contracts, CI, Docker/Compose or operational runbooks. Product name changes must not silently invalidate deployed agents or historical evidence.

A future implementation-package rename would require a separate migration ADR, inventory of deployed binaries, compatibility aliases, database and event schema review, rollout, rollback and tested release plan.

## Tagline and voice

Primary tagline: **Evidence to action. Action to recovery.**

Use precise engineering language. Explain what is implemented, what has only been validated in disposable CI, and what is planned. Never claim real production certification on the strength of a diagram or a synthetic demo.

## Repository settings

The GitHub repository name remains `1` during this safe branding rollout. A future slug change requires an explicit deployment audit because clone URLs, CI integrations, user scripts and external links may depend on the current name.

Suggested About description: *RIFTWARD Security Fabric — distributed detection, evidence-backed investigation, policy-gated containment and recovery for critical networks. Built on MON.*

Suggested topics: `network-security`, `ids`, `intrusion-detection`, `incident-response`, `network-monitoring`, `security-operations`, `suricata`, `zeek`.
