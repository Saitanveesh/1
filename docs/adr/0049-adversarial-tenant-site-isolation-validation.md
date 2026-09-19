# ADR 0049: Adversarial tenant/site isolation validation

## Status

Accepted.

## Context

MON carries tenant and site identity through telemetry, the event fabric, durable stores, detection, investigation, and enforcement. Functional scope tests are necessary but insufficient for a SaaS security boundary: an attacker may deliberately alter an envelope's outer routing identity while retaining a payload that belongs to another tenant or site, reuse event identifiers across scopes, or substitute sensor identity.

The event-fabric boundary already validates normalized security-event payload identity against the envelope. This milestone makes those negative security properties explicit and continuously regression-tested before broader scale or release work.

## Decision

MON treats the tenant/site tuple as a security boundary, not a presentation filter. Adversarial regression coverage must prove that:

- changing only the outer tenant identity cannot relabel another tenant's payload;
- changing only the outer site identity cannot move telemetry to another site;
- changing the outer source identity cannot impersonate another sensor;
- rejected forged envelopes create no event in either the claimed or payload scope;
- identical event IDs may exist independently in different tenant/site scopes and are not treated as cross-scope duplicates.

Envelope/payload identity disagreement fails closed before domain persistence. Tests exercise the real `FabricEnvelope`, ingress, pipeline, and durable database boundary rather than a mock authorization layer.

## Boundary

These tests validate application-level event-fabric isolation. They do not prove network-layer mTLS identity, PostgreSQL row-level security, Kubernetes namespace isolation, cloud IAM policy, or broker ACL correctness. Those controls require deployment-specific integration and adversarial validation in disposable infrastructure.

No production traffic or user workstation is used for this profile. Test events are synthetic and exist only inside isolated CI temporary stores; they are not presented as observed telemetry.

## Consequences

A regression that allows scope relabeling, sensor substitution, or cross-scope duplicate collision becomes a CI failure rather than a latent multi-tenant defect. Release work must preserve these negative tests. Future deployment validation should add authenticated transport identity-to-scope binding and infrastructure-level tenant isolation tests without weakening this application boundary.
