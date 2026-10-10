# ADR 0040 — One-peer WireGuard cutover with independent timed rollback

- **Status:** Implemented as lab stage; physical PC5/PC6 acceptance pending
- **Date:** 2026-10-10

## Motivation

The PC2 WireGuard hub now reports `HUB_GUARD_VERIFIED`, but PC5 and PC6 remain attached to an existing separate WireGuard hub at `10.5.115.5:51820`. Replacing their wg0 configuration without a recovery path would risk losing the lab overlay. The management LAN/Tailscale must remain independent. The operator may step away during deployment, so the rollback must not depend on an ongoing SSH terminal.

## Decision

The `tools/lab_three_peer.py` helper is deployed as a root-only immutable copy on *only the peer selected* and controlled through `tools/lab_three_host.py` from PC2. The first role is **victim/PC5**; the second role **attacker/PC6** is blocked until PC5 has separately committed and proven a new handshake.

Before changing wg0, the helper requires exact peer role and address, exact original hub endpoint, exact allowed route (`10.77.0.0/24`), matching running and persistent original peer key, an intact mode-0600 root-only pre-cutover backup and matching SHA-256 digest, and a management route to PC2 independent of wg0. The PC2 orchestrator checks the protected new hub and guard first.

**Phase PENDING_ROLLBACK:** Record original identity/backup and operator-specified target. Schedule a transient **900-second systemd timer** that invokes the root-owned rollback helper, independently of SSH. Only after the timer is confirmed active, replace the old WireGuard peer key/endpoint live using `wg set` (no wg0 restart or LAN route edits). The original `/etc/wireguard/wg0.conf` remains unchanged on disk throughout the trial. A host reboot consequently defaults to its previous configuration. The timer restores the original running WireGuard peer using a native `wg-quick strip` + `wg syncconf` sequence, validates the restored peer and records `ROLLED_BACK`. If rollback cannot complete safely, a failure is visible and the machine's original persistent config is retained.

**Phase verified:** Independently check on the chosen peer and on PC2 that the genuine newly authenticated WireGuard handshake is fresh (within 120 seconds). No attacker packets, Suricata alerts or MON incidents are fabricated by this test. A separate explicit operator approval is required for commit. The helper refuses commit if the timer is missing/expired, the endpoint differs from `10.5.112.94:51820`, the route differs from wg0, or a recent genuine handshake is missing.

**Phase COMMITTED:** Replace only the peer public key and endpoint in the original persistent configuration with the new hub values, atomically. Do not modify the private key, any other peers, allowed networks or host routes. Validate the staged file using native `wg-quick strip` with a WireGuard-compatible temporary basename. Persist an owner-only audit record, then cancel the rollback timer. If timer cancellation races with commit, it re-reads the COMMITTED state under a filesystem lock and refuses to undo the committed tunnel. Existing backups remain protected for a separately authorized recovery.

## Boundaries and limitations

- PC5/PC6 must remain reachable via their management LAN for the entire change; no campus-LAN packet filtering, broad scanning or flooding is authorized
- Operator must not start both migrations simultaneously; PC5 verified+committed first, PC6 after
- Timer is a systemd transient timer; on host reboot it does not need to run because the original config was not changed until commit
- There is no claim of production persistence or site recovery from this lab-only migration; the PC2 hub guard is still volatile and the WireGuard hub must not auto-start without a guard-first unit
- Live sensor deployment is blocked until `site-preflight` confirms both peers, real handshakes and the guarded PC2 hub
- Rollback after commit requires a separate explicit recovery plan, because the original protected backups must not be overwritten blindly
- A wireguard key, JWT, private config, or login code must never appear in ChatGPT, CI output or GitHub source

## Evidence needed

Capture the `CUTOVER_PENDING_AUTOMATIC_ROLLBACK` stage and the independent `PEER_NEW_HUB_HANDSHAKE_VERIFIED` evidence from PC5 and PC2, then `PEER_CUTOVER_COMMITTED`. Test that management access remains usable and that an uncommitted peer reverts without SSH intervention. Document real timestamps, identities (public keys only), TTL, blast radius (one peer WG overlay), audit and rollback state. Passing Python/CI tests is not the same as demonstrating these on Ubuntu 26.04.
