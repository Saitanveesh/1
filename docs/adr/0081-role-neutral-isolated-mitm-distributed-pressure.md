# ADR 0081: Role-neutral enrolled targets and executable isolated MITM / distributed-pressure range

Status: Implemented in development branch; campus hardware not certified
Date: 2026-10-15
Updates: ADR 0077, ADR 0080

## Decision: physical attacker and victim assignments are prohibited

No physical computer (including the previously named "PC3" or "PC4")
may be assigned permanent attacker or victim status. Those labels were an
incorrect interpretation of a limited equipment footprint. A physical
machine can be an operator console, disposable sensor, scenario generator
or instrumented test victim **only if individually enrolled and authorized
for the corresponding isolated exercise**.

The primary MON device graph is dynamic, with no assumed lab inventory,
fixed IP range, fixed attacker or fixed victim. Attack/source and affected
target must be attributed from real, time-scoped network/endpoint evidence.
An operator's test plan is not independent attacker identity proof.

## Any eligible observed asset may be selected for health monitoring

The `VictimHealth` operator screen displays discovered assets and passes
the **runtime-selected** `asset_id` to a tenant/site-scoped MON API.
Prometheus reads for independent availability, process health and host CPU/RAM
include the exact selected asset label when provided. Unenrolled devices
have no host data, and must show UNKNOWN rather than values from any other
asset. Exporter enrollment is distinct from passive discovery: observing
an endpoint IP is not proof of authenticated host telemetry.

The optional `deploy/four-pc/` directory is retained for backward
compatibility only. Its application workload can run on **any approved
isolated enrolled machine/VM**; there is no PC4 requirement.

## MITM and multi-origin test engine

A root-operated, disposable Ubuntu VM can execute
`tools/range_lab/run.sh`. It creates six fresh Linux namespaces and
veth pairs on a new bridge with **no real NIC membership, bridge host IP
or namespace default route**, with an explicit operator assertion that
the VM is not bridged to the campus LAN.

The runtime may select disposable victim `alpha` or `beta`. These are
internally created test workloads, not fixed physical campus PCs.

### MITM

A dedicated attacker namespace sends genuine ARP replies claiming two
other namespace addresses. This test requires **both** changed ARP
neighbor evidence and a separate capture of actual HTTP packets on the
attacker interface before declaring a verified on-path lab MITM. Without
both proofs, abort or report unknown. Recovery pins original observed
MAC bindings, disables test forwarding, checks service health and
restores normal ARP operation. Packet captures are restricted to the
isolated bridge and retained with artifact hashes.

A new rule `arp-binding-conflict` processes time-bounded, directly
observed ARP claims. It reports only MAC-binding inconsistency, not
confirmed MITM, since mobility, failover and spoofing can have
similar symptoms.

### Bounded multi-source pressure

Three different source namespaces each issue at most 5 HTTP requests/s
for at most 6 seconds against the selected disposable test service.
An independent fourth namespace measures service availability. The
victim's own HTTP server records actual source IPs/status/latency.
The new `http-multi-source-pressure` detector requires multiple
observed sources and a bounded window. It makes no claims of outage,
large-scale DDoS, upstream saturation or a uniquely guilty source.

Containment inserts a **namespace-local nftables rule** blocking the
three test sources only on the test service port; it must verify both
an affected source and an unaffected control client. Rollback removes
that test-specific table and independently verifies restored access.

This is not a campus DDoS generator. True high-volume/upstream DDoS
testing requires an appropriate isolated traffic facility and mitigation
contract/capability, not the college's ordinary shared network.

## Live MON event ingestion

Actual ARP packet transcriptions and victim HTTP access logs are
converted into typed, time-stamped MON `SecurityEvent` objects with
deterministic content-based IDs and evidence references. An opt-in
uploader posts to the existing `/api/v1/events/batch` using
least-privilege INGEST credentials on the approved management side,
HTTPS, disabled proxy/redirect and exact API event acknowledgements.

The sandbox does not automatically connect attack namespace interfaces
to the main campus management network. Raw PCAP artifacts must be
preserved by authorized operators; a dashboard finding is not a
substitute for packet evidence and verification.

## Acceptance evidence and limits

A GitHub Actions Linux runner executed the disposable virtual bridge
test successfully at commit `e4efb0dbb9a4aeecb9af42d3e86c639575f19973`,
workflow run 38765753217. Its job
`isolated-mitm-and-multi-origin-range` recorded:
- a selected beta victim with real attacker-namespace packet-path evidence;
- successful original MAC restoration and HTTP service recovery;
- three real source namespaces and bounded request generation;
- actual namespace-local nftables blocking, unaffected control access
  and rollback verification;
- a separate alternative alpha victim pressure test.

**This verifies the isolated virtual test environment only.**
Later software edits, including typed capture ingest and asset selection,
still require their own CI outcomes. CI runner simulation does not certify
campus switch visibility, tenant-proof endpoint identity, host telemetry
at every campus workstation, MITM on a physical campus switch or upstream
DDoS response. A real production-network deployment requires separate
institutional authorization, enforced exercise segmentation, hardware
survey, trusted sensor onboarding and physical rollback certification.

Safety gate remains: **do not conduct intentional ARP poisoning,
MITM or multi-source load against the shared institutional LAN**.
