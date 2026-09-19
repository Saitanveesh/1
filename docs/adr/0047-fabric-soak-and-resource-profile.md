# ADR 0047: Fabric soak and resource profile gate

## Status
Accepted

## Context
ADR 0046 established a repeatable event-fabric request/latency probe, but a short throughput run cannot establish operational stability. Capacity decisions also require evidence about sustained delivery, resource pressure, and whether failures accumulate over time.

## Decision
Extend the opt-in performance workflow with a soak profile that repeatedly replays only a caller-supplied canonical `FabricEnvelope` corpus for an explicit duration. The profile remains outside normal production traffic and developer laptops. It records interval delivery results and optional externally supplied resource samples alongside immutable run metadata.

The profile must not invent security telemetry. Resource samples are observations from the designated performance environment and are kept separate from envelope data. A run is unsuccessful if any delivery interval reports failures, if the corpus changes during the run, or if the resource sampler fails.

Required run metadata includes corpus SHA-256, target identifier, concurrency, duration, interval, start/end timestamps, probe version, deployment/topology label, and resource-sampler command when used. Raw interval results and resource samples must be retained with the summary so averages cannot hide spikes or progressive degradation.

No universal CPU, memory, latency, or throughput SLO is encoded here. Promotion thresholds must be derived from an explicit deployment objective and recorded with the corresponding evidence.

## Consequences
- MON can distinguish short-burst throughput from sustained stability.
- Broker, database, and ingress decisions can use correlated delivery and resource evidence.
- The workflow remains safe for disposable or explicitly designated performance environments and does not run unvalidated binaries on the user's laptop.
- Failure injection and adversarial tenant/site isolation remain separate gates so soak success cannot be interpreted as resilience or isolation proof.
