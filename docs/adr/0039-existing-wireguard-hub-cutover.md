# ADR 0039 — Guarded migration from an existing WireGuard hub

- **Status:** Accepted for lab staging; physical cutover NOT authorized by this ADR
- **Date:** 2026-10-10

## Observed context

Three real lab systems share a college LAN. PC2 is the MON host, LAN `10.5.112.94`, Tailscale `100.75.116.62`; PC5 is victim `10.5.112.23` with overlay `10.77.0.50/32`; PC6 is attacker `10.5.112.4` with overlay `10.77.0.60/32`. PC5/6 both currently use another live hub (`10.5.115.5:51820`). PC2 had no `wg0` at audit time. Backups of existing root-owned, mode-0600 peer configs were created locally on each peer. A migration preview verified live public keys of both peers and derived PC2's new public key, but deliberately made no live network change.

## Decision and invariants

Prepare a **new PC2 WireGuard hub alone** before any peer cutover. Reuse the already-verified peer public keys, never copy/read their private keys. PC2's existing generated private key stays in its owner-only local file. The hub uses `10.77.0.1/24`, listens on UDP/51820, and accepts only PC5 `10.77.0.50/32` and PC6 `10.77.0.60/32`. There are no broad allowed networks.

Before creating `wg0`, transactionally install **only MON-owned `inet mon_three_guard`** nftables hooks at priority -150: deny attacker-origin traffic to the hub; deny forwarding between WG and non-WG networks; limit two WG peer traffic sources and destinations to the matching lab-overlay counterpart. Reject an existing `wg0`, `wg0.conf`, UDP/51820 listener or MON guard instead of adopting/removing unknown state. Verify management routes to PC5/6 remain on the LAN and not `wg0`. Do not touch campus switches, routes, DNS, existing firewall tables, the old WireGuard hub, or system-wide forwarding settings. The new hub does not claim packet visibility until its real peer handshakes and traffic are verified.

The one-time `hub-prepare` command is operator approved and invokes `tools/lab_three_hub.py` as root on PC2. It validates the staged configuration using native `wg-quick strip` and validates the new nft transaction via `nft -c -f`. Failure cleanup removes only the newly owned hub and MON table. `hub-verify` is read-only. `hub-rollback` is allowed only before **any** peer has ever handshaken with PC2; after handshakes occur, a new peer-side rollback is necessary to avoid dropping a live tunnel. The host-wide SSH/Tailscale management path is not reconfigured.

## Supervised peer migration remains a separate stage

The operator must review the PC2 hub output and establish local emergency access before changing any existing PC5 or PC6 peer. A future cutover must change **one** live spoke at a time, preserve its private key, create an automatically scheduled peer-side rollback in advance, prove a new handshake with PC2, verify narrow overlay routing, and separately commit or revert within a short TTL. Do not call a new hub installation evidence that a migration succeeded. Do not run `site`/`victim` unless `site-preflight` confirms both peers point to PC2 and the necessary sensor ingress path is reachable.

## Acceptance and remaining risks

Unit and CI checks validate hub configuration generation, fail-closed root checks, guard clauses and cleanup order. **They do not prove OS-native nft/WireGuard integration** on these Ubuntu 26.04 college systems. A disposable network-namespace or VM trial, physical PC2 guard output, handshake/route verification, explicit peer cutover, rollback exercise and live Suricata/endpoint evidence are mandatory before the lab is accepted. Container/Docker or a preexisting host nftables chain may impose additional routing conditions requiring inspection rather than forceful replacement.
