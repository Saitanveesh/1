# First real MON detection acceptance — three-host lab

**Date:** 2026-10-10  
**Status:** Lab execution pending; no event or attack detection is claimed from these instructions.  
**Goal:** Demonstrate real sensor observation, a bounded TCP SYN reconnaissance finding, evidence, correlation and (in a later separately approved stage) reversible containment.

## Physical topology and current verified evidence

- PC2 MON hub: LAN `10.5.112.94`, overlay `10.77.0.1/24`. Operator observed `HUB_GUARD_VERIFIED`.
- PC5 authorized victim: LAN `10.5.112.23`, overlay `10.77.0.50/32`. Operator observed `PEER_NEW_HUB_HANDSHAKE_VERIFIED` from PC5 and PC2 followed by `PEER_CUTOVER_COMMITTED`. The subsequent attempt to invoke *pending* rollback after commit was rejected as designed. Current state must still be independently verified.
- PC6 designated traffic source: LAN `10.5.112.4`, overlay `10.77.0.60/32`. **Migration not yet physically observed.**
- On the home laptop, authenticated MON operator console + LIVE WebSocket transport were observed. **This does not mean sensors are running or attacks are detected.**

## Gate 1 — Finish PC5 and PC6 cutover

On PC2 in `~/mon-three-operator`:

```bash
git fetch origin feat/three-host-tailscale-lab
git checkout --detach FETCH_HEAD

python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --peer-role victim peer-status
python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --peer-role victim peer-verify
```

**Stop if** PC5 is not `phase=COMMITTED`, if a handshake is not independently fresh on both ends, or if `peer-verify` fails. Do **not** reapply the expired pending rollback. After commit, reverting requires a separate post-commit recovery plan.

Once PC5 has been confirmed, migrate **PC6 only** in an attended 15-minute window:

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --peer-role attacker --approve-peer-start peer-start

# One small diagnostic packet to refresh the new hub handshake:
ssh pc-6@10.5.112.4 'ping -n -I wg0 -c 1 -W 2 10.77.0.1 || true'

python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --peer-role attacker peer-verify
```

Only after both PC6 and PC2 prove the fresh handshake and normal SSH still works, commit inside the 900-second rollback window:

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --peer-role attacker --approve-peer-commit peer-commit
python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --peer-role attacker peer-status
```

Expected: `phase=COMMITTED timer_active=False`. If not, stop and use the **pending** rollback for PC6 only, or allow the timer to expire:

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --peer-role attacker --approve-peer-rollback peer-rollback
```

Never initiate a new cutover while an existing pending timer remains unresolved.

## Gate 2 — Prove the actual sensor path

On PC2 after both peers are connected, and only if the hub and guard remain healthy:

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json site-preflight
```

The backend requires two recent real handshakes. If they have aged out, use one authorized ping from each peer to `10.77.0.1` to refresh, then retry the read-only preflight. Never fake timestamps.

Inspect PC2's forwarding bit **before** assuming that packets from PC6 can reach PC5:

```bash
sudo sysctl net.ipv4.ip_forward
sudo nft list table inet mon_three_guard
```

If forwarding is disabled, stop here: do not blindly enable global routing on a shared campus LAN host. Review and implement a scoped, guarded and rollback-tested forwarding change separately. Only proceed after a real PC6 → PC5 path is proven within the authorized overlay. Retain separate campus-LAN/Tailscale management connectivity.

If site preflight succeeds, stage the real collector services:

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json site
python3 tools/lab_three_host.py --inventory ~/lab-three.json victim
python3 tools/lab_three_host.py --inventory ~/lab-three.json ready
```

The `site` stage enrolls the mTLS Site Controller and Suricata sensor, starts Suricata on PC2 `wg0`, then enrolls real network telemetry into MON. The `victim` stage starts the PC5 Linux endpoint collector. **Any error is a failed gate, not grounds to generate attack traffic.** Verify raw Suricata EVE records, collector health, actual sensor heartbeat and MON API observations before testing a detector.

## Gate 3 — Exactly one low-volume recon test

**Scope:** only the private overlay source PC6 `10.77.0.60` and destination PC5 `10.77.0.50`, port range **20000–20099** (100 ports). The shared college LAN `10.5.112.0/20`, PC2 management ports and other college devices are out of scope.

The default `tcp-syn-recon` detector requires at least 60 **SYN-only observed flow events within 10 seconds**, with at least 18 unique destination ports (or ten destinations). Ordinary closed ports reply with RST/ACK and may not match; the lab's optional `demo-prepare` stage filters **only** these 100 TCP ports **only** for PC6 traffic at PC5's `wg0`, without touching management.

**Do not run this until Gates 1–2 pass and physical operator authorization is current.** On PC2:

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --approve-demo-setup demo-prepare
```

On PC6 itself, perform one **bounded** 100-port scan, not a flood:

```bash
sudo nmap -sS -Pn -n -p 20000-20099 --max-retries 0 --max-rate 100 10.77.0.50
```

This is a maximum-rate cap, not a guarantee that MON's 10-second threshold will fire. No password guessing, DDoS, broad CIDR scanning or unlimited retries. **Do not repeatedly increase the rate just to force a dashboard alert.**

From PC2, collect actual non-secret Suricata flow records without fabricating any:

```bash
sudo test -s /var/log/suricata/eve.json && echo 'Real Suricata EVE exists'
sudo jq -c 'select(.event_type == "flow" and .src_ip == "10.77.0.60" and .dest_ip == "10.77.0.50") | {timestamp,src_ip,dest_ip,dest_port,tcp}' /var/log/suricata/eve.json | tail -n 10
```

Verify *through the authenticated MON console and API* whether the corresponding normalized evidence, source/destination/ports, `tcp-syn-recon` finding and incident appear. The detector classifies a **reconnaissance-shaped traffic pattern**, *not* proof of compromise. Missing flow records means sensor/forwarding/flow-logging investigation is required, not a fabricated incident. Flow records without SYN-only flags may not satisfy the rule, and Suricata may emit them after flow expiration. Record measured latencies and any false negatives.

To revert **only** the optional victim demo filter after testing, on PC5 via an authorized console:

```bash
sudo nft list table inet mon_three_victim
sudo nft delete table inet mon_three_victim
```

Use deletion only after verifying this MON-owned table was created by this exact lab `demo-prepare` stage; never flush the host firewall. The normal PC5 SSH path on its management LAN must remain available throughout.

## Gate 4 — Containment, verification and recovery (separate approval)

Only after a real MON incident exists should an operator examine evidence, detector confidence, affected assets, enforcement point `mon-three-router`, blast radius and proposed TTL. Require explicit approval before any BLOCK_IP. Verify the source is contained only on the overlay and other traffic still works. Then execute a documented rollback and verify PC6→PC5 connectivity is restored. Save actual incident, response, audit and recovery records; no seeded data or fabricated timelines.

**Acceptance record:** source/destination, timestamps, sensor state, raw event references, classifier/rule evidence, latency, confidence, whether the incident appeared, policy/TTL, enforcement change, blast radius, rollback and observed service recovery. A negative test result is legitimate evidence and should trigger investigation.
