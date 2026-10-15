# ADR 0080: Evidence-first four-PC exercise integration and host telemetry

Status: Software implementation committed; CI and physical certification are separate
Date: 2026-10-15
Extends: ADRs 0076–0079

## Context

MON's consolidated demonstration needs independent *real victim* CPU/RAM data
and durable, replayable red-team activity observations. Previously the console
showed ERP **process** RSS and CPU but no independently observed PC4 host
metrics, while red-team activity had no safe, provenance-labelled persistence
path into the SOC.

The campus includes uninstrumented and unknown assets. Seeing an IP address
or executing requests from one test machine is not automatically proof of
physical attacker identity, DDoS, MITM, compromise or effective containment.

## Decisions implemented

1. **PC4 host metrics:** Run a separate Node Exporter on the explicitly
   approved monitoring interface of the disposable victim host. It reads
   read-only host procfs/sysfs and is protected with external access controls.
   It must not publish host-resource data to the ordinary campus network.
   The default exporter scrape target list is **empty**, so unknown remains
   unknown when no PC4 host is onboarded.
2. **Independent metric calculation:** PC1 Prometheus receives the authorized
   PC4 host exporter. MON queries tenant/site-labelled CPU idle-time rates and
   memory available/total from the dedicated `erp-victim-host` job.
   The SOC renders these only when one fresh trusted time series is returned.
   Stale, absent, ambiguous and unreachable data remain UNKNOWN/DEGRADED.
   These metrics are operational observations, not attack conclusions or
   physical location proofs.
3. **Bounded operator exercise:** An explicit short-lived mode-0600 permit
   limits one station to at most 3 HTTP GET requests/second for at most 45
   seconds, against TCP/8081 at one explicit private/loopback IP. It verifies
   the special synthetic ERP marker before sending test requests, forbids
   redirects/proxies and does not run general scanners, credential abuse,
   MITM, flooding or other campus-facing attacks. The operator must separately
   verify network isolation; a local permit is not an institutional signature.
4. **Truthful evidence:** Each exercise produces measured request timestamps,
   HTTP response codes, latency or unknown values, aggregate counts and a
   canonical SHA-256 digest. The receipt explicitly states
   `attack_claim=NONE` and `containment_claim=NONE`. It is *self-reported*
   operator evidence, not an authenticated packet-capture record.
5. **Tenant-isolated retention:** A strict typed receipt schema validates the
   digest and counter consistency before storage. PostgreSQL revision 0014
   adds immutable range receipts and FORCE RLS by tenant and site; in-memory
   state uses the same collision and scope semantics. An authenticated
   `INGEST` endpoint accepts bounded receipts and a `VIEW` endpoint
   provides history; replay of identical evidence is idempotent and a
   conflicting receipt is rejected. A dedicated uploader uses a protected
   token file, no environment proxy, no follow-redirect and HTTPS.
6. **SOC presentation:** Add Exercise Timeline to the operator navigation.
   Its history is explicitly labelled *self-reported, bounded requests*,
   with timestamps, errors, digest and unconfirmed claims. It must never
   silently appear in the incident stream as a verified attack or as a
   successful containment.
7. **Topology safety:** LLDP names prefixed as unverified peer claims may
   be shown as unverified links, but are not used to compute verified
   physical hop distances. No switch-port block may be inferred from
   unauthenticated LLDP peer names.

## Security limitations and deployment gates

- Do not start deliberate traffic on the college management LAN. Even this
  bounded runner requires an approved, enforced exercise VLAN/VM fabric.
- Node Exporter is unauthenticated on its scrape port. Host firewall/ACL
  policy must restrict this port to PC1, verified with an independent
  negative test from PC3/campus before enabling production probes. CI's
  disposable loopback publishing does not certify physical isolation.
- The synthetic ERP identification string and locally issued permit can
  be forged; they are safety interlocks, **not a cryptographic attestation**
  of target ownership. Hardware-network isolation is authoritative.
- An INGEST credential still does not prove the observation's physical
  origin or operator approval; a hash detects changed bytes, not dishonest
  first-party reports. Requires separately attested site identity/evidence
  to support response automation.
- This stage is not a MITM/DDoS demonstration, does not inject packets,
  does not isolate real switch ports, and does not prove a router can stop
  volumetric upstream traffic. The production MON response-engine tests
  do not substitute for live lab validation.
- Live multi-asset victim-health enrollment, vendor switch certification,
  independent sensor packet evidence and verified containment TTL/rollback
  across the actual deployed path remain required.

## Verification

Code/test locations:
- `deploy/four-pc/compose.erp.yml`, `deploy/four-pc/prometheus.yml`,
  `deploy/four-pc/targets/erp-host.json`
- `src/mon/range_health.py`, `tests/test_range_health.py`
- `src/mon/range_exercise.py`, `tests/test_range_exercise.py`
- `src/mon/range_evidence.py`, `src/mon/range_receipt_upload.py`
- `src/mon/store.py`, `src/mon/database.py`, `src/mon/api.py`
- `migrations/versions/0014_range_exercise_receipts.py`
- `tests/test_range_evidence.py`, `tests/test_range_receipt_upload.py`
- `console/src/ExerciseTimeline.tsx` and `console/src/VictimHealth.tsx`
- `.github/workflows/ci.yml` (not a substitute for on-site evidence)

The existing 4-PC runbook describes both management and rollback.
Passing CI proves only the exact software checks actually executed.
Physical deployment and end-to-end malicious-traffic mitigation remain unverified.
