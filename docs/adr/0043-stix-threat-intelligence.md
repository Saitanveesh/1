# ADR 0043: STIX threat-intelligence ingestion and indicator matching

## Status

Accepted

## Context

MON needs threat-intelligence enrichment without weakening the evidence model. Indicator
matches can help prioritize investigation, but an indicator match by itself is not proof of
compromise, malicious execution, or successful intrusion.

The repository already has tenant/site-scoped events, findings, incidents, evidence refs,
PostgreSQL row-level security, and local/site analysis persistence. This decision adds a
bounded STIX 2.1 ingestion and matching foundation on those existing contracts. TAXII polling
and feed scheduling are deliberately outside this milestone.

## Decision

MON accepts STIX 2.1 bundle documents containing `indicator` objects and persists the
supported indicators as tenant/site-scoped threat-intelligence state. Each source and
indicator is stored separately from raw event evidence. Matching produces ordinary MON
findings with `THREAT_INTEL` evidence references, so downstream correlation, incidents, and
attack graph attachment continue to use the existing evidence pipeline.

The supported STIX pattern subset is exact equality on these observables:

- `ipv4-addr:value`
- `ipv6-addr:value`
- `domain-name:value`
- `url:value`
- `file:hashes.'MD5'`, `file:hashes.'SHA-1'`, `file:hashes.'SHA-256'`, and
  `file:hashes.'SHA-512'`

Unsupported object types, unsupported pattern syntax, malformed timestamps, invalid
confidence values, and oversized bundles are rejected. MON does not silently reinterpret STIX
expressions it does not support.

## Persistence and versioning

Threat-intelligence sources and indicators are stored with tenant_id and site_id as first
class scope fields. PostgreSQL persistence includes row-level security policies matching the
existing tenant/site runtime scope model. The in-memory store implements the same repository
contract for deterministic unit tests and local composition.

Indicator identity is deterministic for `(tenant_id, site_id, stix_id)`. Re-importing the same
object is idempotent. A newer STIX `modified` or `created` timestamp replaces an older object;
an older version of the same STIX id is ignored.

## Matching semantics

Matching is exact after normalization:

- IP addresses are parsed and canonicalized.
- Domains are case-folded, IDNA-normalized, and trailing-dot-normalized.
- File hashes are lowercased and length-checked.
- URLs require a scheme and otherwise preserve exact value semantics.

Active matching excludes revoked indicators and indicators outside their validity window.
Findings created by indicator matches use medium severity, bounded confidence, and an explicit
claim that the match is not proof of compromise or successful malicious activity.

## Security and isolation assumptions

Tenant/site isolation is enforced at ingestion, storage, query, and pipeline matching time.
Cross-tenant and cross-site indicators do not match events from another scope.

STIX feed content is treated as untrusted input. The parser accepts only the explicit subset
above and fails closed for unsupported syntax rather than attempting broad pattern evaluation.

## Consequences

- MON can ingest STIX 2.1 indicator bundles and generate evidence-backed findings from
  matching observables.
- Indicator matches participate in existing correlation and incident handling without
  claiming confirmed compromise.
- TAXII polling, remote feed scheduling, feed authentication, and complex STIX pattern
  evaluation remain future work.
