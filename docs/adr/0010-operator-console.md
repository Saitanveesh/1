# ADR 0010: Black-and-white live operator console

Status: Accepted

## Decision

The MON operator console is a TypeScript/React application with a restrained
black/white/gray visual system. It is a dense operational interface rather than a
decorative cyber-themed dashboard.

The normal live path is WebSocket push. The console connects first, then requests the
scope snapshot so reconnects recover durable state without waiting for periodic polling.
It uses same-origin credentials and does not place bearer tokens in WebSocket query
parameters.

## Visual rules

- charcoal/black surfaces;
- white primary text and gray hierarchy;
- thin borders and compact tables;
- severity primarily represented by weight, border intensity and pattern;
- no neon gradients, glow effects or decorative "hacker" visuals;
- no fabricated placeholder telemetry.

Metrics must name their derivation. Until a backing API exists, modules show an explicit
not-yet-wired state rather than fake values.

## Initial console modules

- Overview
- Incidents
- Attack Graph
- Assets
- Enforcement
- Sites
- System

Overview, incident queue, findings and graph consume the existing live contracts first.
The remaining modules are implemented as their durable APIs land.
