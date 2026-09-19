# ADR 0047: Fabric soak and resource profile gate

## Status
Accepted

## Context
ADR 0046 established a repeatable event-fabric request/latency probe, but a short throughput run cannot establish operational stability. Capacity decisions also require evidence about sustained delivery, resource pressure, and whether failures accumulate over time.

## Decision
Extend the packaged `mon.fabric_load_probe` CLI with an opt-in soak profile that repeatedly replays only a caller-supplied canonical `FabricEnvelope` corpus for an explicit duration. The repository does not add or claim a standing performance workflow; normal CI continues to run unit/integration gates only. Soak runs are intended for disposable or explicitly designated performance environments with caller-supplied corpus and topology metadata.

The profile must not invent security telemetry. It reuses the ADR 0046 HTTPS-only probe path, including TLS verification by default, no ambient proxy use, exact canonical envelope bytes, optional explicit CA, and optional mTLS client credentials. It computes a SHA-256 identity for the exact input corpus and verifies the corpus before and after every interval. A run is unsuccessful if any delivery interval reports failures, if the corpus changes during the run, or if the resource sampler fails.

Required run metadata includes corpus SHA-256, target URL, concurrency, requested duration, interval length, actual start/end timestamps, probe version, and caller-supplied deployment/topology label. Raw interval results and resource samples are retained with the summary so averages cannot hide spikes or progressive degradation. Authorization values and certificate private-key material are not serialized into the evidence output.

Resource sampling is optional. When configured, MON runs an explicit command/argument vector with `shell=False`, bounded timeout, and bounded stdout/stderr capture. The sampler output is preserved as externally measured raw evidence with timestamp and sampler identity. MON does not parse arbitrary sampler output into invented CPU or memory fields.

No universal CPU, memory, latency, or throughput SLO is encoded here. Promotion thresholds must be derived from an explicit deployment objective and recorded with the corresponding evidence.

## Consequences
- MON can distinguish short-burst throughput from sustained stability.
- Broker, database, and ingress decisions can use correlated delivery and resource evidence.
- The soak runner remains opt-in for disposable or explicitly designated performance environments and is not run automatically on developer laptops or normal CI.
- Soak success is not proof of resilience, failure recovery, tenant isolation, or adversarial multi-tenant safety.
- Failure injection and adversarial tenant/site isolation remain separate gates.
- Measurements from one deployment topology are not automatically representative of another topology.
