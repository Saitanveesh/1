# ADR 0043: Measured event-fabric load gate

## Status
Accepted

## Context
MON's SaaS architecture deliberately defers Kafka/Redpanda and high-volume analytical storage until measurements show that the current durable HTTPS event-fabric path is the limiting boundary. A repeatable measurement tool is required before making that infrastructure decision. CI timing is not a valid production capacity benchmark, and generated "healthy" telemetry must not be presented as observed system behavior.

## Decision
Add an opt-in load probe that replays caller-supplied canonical `FabricEnvelope` NDJSON against the authenticated HTTPS site-fabric ingress. The probe does not synthesize security events. It reports attempted, successful and failed requests, elapsed time, achieved request rate, p50/p95/p99 request latency, and HTTP/transport outcome counts.

The probe is intentionally outside normal CI load generation. It must be run only against disposable or explicitly designated performance environments with representative PostgreSQL, TLS, ingress, and control-plane topology. It rejects plaintext HTTP, disables ambient proxy configuration, verifies TLS by default, supports an explicit CA plus client certificate/key, and exits non-zero when any request fails.

Capacity decisions must retain the raw input corpus identity, deployment topology, concurrency, duration, resource measurements, and probe JSON output. A single throughput number is not a capacity claim.

## Broker adoption gate
A Kafka-compatible broker is justified only when repeatable measurements show that decoupling producers/consumers or increasing durable buffering materially addresses an observed bottleneck or recovery objective. The decision must also include broker operational cost, partition strategy, replay/recovery behavior, and tenant/site isolation tests.

ClickHouse/OpenSearch adoption follows the same evidence rule for telemetry query/storage pressure and is not implied by this probe.

## Consequences
- MON gains a reproducible measurement path without fabricating telemetry or adding a broker prematurely.
- Performance runs remain operationally isolated from developer laptops and production networks.
- Results are descriptive measurements, not hard-coded SLOs.
- Future hardening/load PRs can add resource sampling, soak profiles, failure injection, and broker comparisons against the same canonical envelope corpus.
