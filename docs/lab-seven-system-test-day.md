# Seven-system MON test-day topology

This runbook is for a controlled private lab. Do not bridge adversary traffic directly onto the physical management LAN. The physical LAN carries management and encrypted tunnel traffic only.

Exact copy-paste commands for every machine, in execution order, are in `docs/lab-seven-system-command-sheet.md`. This document explains the topology and the pass/fail rules.

## Professor poster -> MON

The poster maps to MON as: red-team action -> victim evidence -> Suricata + endpoint telemetry -> detection -> correlation -> incident/attack path -> policy decision -> router containment -> verification -> rollback/recovery.

Wazuh is not part of the current MON repository. Its endpoint-log role is performed by MON's Windows/Linux endpoint collectors. Do not claim Wazuh integration during the demo.

## Seven machines

| PC | Role | Recommended VM/OS | Responsibility |
| --- | --- | --- | --- |
| 1 | Control plane | Ubuntu 24.04 | PostgreSQL, MON API, site mTLS ingress, sensor CA, operator auth |
| 2 | Admin/PKI station | Ubuntu 24.04 | credential staging, enrollment commands, logs; no attack traffic |
| 3 | Site + router + network sensor | Ubuntu 24.04 | WireGuard hub, mon-site, sensor mTLS ingress, Suricata, MON Suricata collector, nftables router containment |
| 4 | Victim A | Windows 11 VM | MON Windows endpoint collector, dedicated test account/service |
| 5 | Victim B | Ubuntu 24.04 VM | MON Linux endpoint collector, SSH/test service |
| 6 | Attacker | Kali or Ubuntu VM | controlled scan/auth/network test traffic only |
| 7 | Operator | Windows/Linux browser | SOC console, verification terminal, presentation |

PC3 is intentionally the forwarding point and Site Controller. That is what makes containment real: the local controller receives an approved site command at the same host that forwards the lab traffic.

## Network isolation: overlay, not a second physical LAN

Because the physical machines share one private LAN, create a WireGuard overlay instead of sending test attacks over the management network.

- PC3 router: 10.77.0.1/24
- PC4 Windows victim: 10.77.0.40/32
- PC5 Linux victim: 10.77.0.50/32
- PC6 attacker: 10.77.0.60/32

Configure PC4/PC5/PC6 as peers of PC3 and route 10.77.0.0/24 through PC3. Enable IPv4 forwarding on PC3. Do not enable NAT from the overlay to the physical LAN. Suricata should capture wg0; the nftables router adapter controls forwarded traffic crossing PC3.

WireGuard alone is not an isolation boundary for the physical management LAN because PC6 still needs an underlay address to reach PC3's WireGuard UDP endpoint. Enforce that boundary before any attack traffic.

On PC3, block any overlay packet from escaping to a non-WireGuard interface and restrict the attacker overlay address to the two victims:

~~~bash
sudo nft add table inet mon_lab_guard
sudo nft 'add chain inet mon_lab_guard input { type filter hook input priority -100; policy accept; }'
sudo nft 'add chain inet mon_lab_guard forward { type filter hook forward priority -100; policy accept; }'
sudo nft 'add rule inet mon_lab_guard input iifname "wg0" ip saddr 10.77.0.60 drop'
sudo nft 'add rule inet mon_lab_guard forward iifname "wg0" ip saddr 10.77.0.60 ip daddr { 10.77.0.40, 10.77.0.50 } accept'
sudo nft 'add rule inet mon_lab_guard forward iifname "wg0" ip saddr 10.77.0.60 drop'
sudo nft 'add rule inet mon_lab_guard forward iifname "wg0" oifname != "wg0" drop'
sudo nft list table inet mon_lab_guard
~~~

On PC6, after WireGuard is established, prevent direct management-LAN egress. Replace the two values first:

~~~bash
export MGMT_IF=<pc6-management-interface>
export PC3_MGMT_IP=<pc3-management-ip>
sudo nft add table inet mon_lab_egress
sudo nft 'add chain inet mon_lab_egress output { type filter hook output priority -100; policy accept; }'
sudo nft add rule inet mon_lab_egress output oifname "$MGMT_IF" ip daddr "$PC3_MGMT_IP" udp dport 51820 accept
sudo nft add rule inet mon_lab_egress output oifname "$MGMT_IF" udp sport 68 udp dport 67 accept
sudo nft add rule inet mon_lab_egress output oifname "$MGMT_IF" drop
sudo nft list table inet mon_lab_egress
~~~

The second guard blocks all other PC6 traffic on the management interface, including IPv6, while leaving the wg0 test path available. Use IP addresses during the exercise so DNS is not required from PC6.

Before any attack test, prove all four statements: PC6 reaches 10.77.0.40 and 10.77.0.50 through wg0; PC6 cannot reach a management-LAN host; PC6 can still maintain the WireGuard peer to PC3; and PC3 cannot forward wg0 traffic onto its management interface; and PC6 cannot reach PC3 itself over the overlay. If any check fails, do not continue.

## Software baseline

Use the same code everywhere: branch lab/test-day-readiness. After this branch is merged, pin every machine to the merge commit SHA and do not change code during the demonstration.

Ubuntu install:

~~~bash
git clone https://github.com/Saitanveesh/1.git
cd 1
git checkout lab/test-day-readiness
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
~~~

Use the repository-owned Windows build/package path for PC4. Do not first-test a new binary on the professor's or primary laptop.

## PC3 router containment

Inside the disposable PC3 VM:

~~~bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo nft list ruleset
export MON_ENABLE_ROUTER_NFTABLES_ENFORCEMENT=1
export MON_SITE_ROUTER_NFTABLES_VENDOR=linux-nftables-router
~~~

Do not flush an existing host ruleset. Run mon-site on PC3 with its normal site identity/cloud variables plus the two variables above.

The operator must register an enforcement point with kind ROUTER, vendor linux-nftables-router, capability BLOCK_IP, and a binding whose blast-radius estimate is 'single hostile source IP on lab overlay'. The response target is 10.77.0.60.

A successful apply must create one MON-owned forward-path rule. Verification has two independent parts: MON reports the owned rule PRESENT, and PC6 can no longer reach the victim test service while management connectivity remains healthy. Rollback must remove that exact rule and restore the previously successful victim connection.

## Remote endpoint evidence

PC4 and PC5 no longer need a loopback Site Controller. Their endpoint collectors can send through PC3's authenticated sensor ingress.

Windows example:

~~~powershell
MONWindows.exe foreground `
  --tenant-id <TENANT> --site-id <SITE> --sensor-id windows-pc4 `
  --state-dir C:\ProgramData\MON\WindowsCollectorState `
  --sensor-ingress-url https://10.77.0.1:9443 `
  --server-ca-file C:\MON\sensor-ca.pem `
  --client-cert-file C:\MON\windows-pc4.pem `
  --client-key-file C:\MON\windows-pc4-key.pem
~~~

Linux example:

~~~bash
sudo mon-linux-endpoint-collector foreground \
  --tenant-id <TENANT> --site-id <SITE> --sensor-id linux-pc5 \
  --state-dir /var/lib/mon-linux-endpoint-collector \
  --sensor-ingress-url https://10.77.0.1:9443 \
  --server-ca-file /etc/mon/sensor-ca.pem \
  --client-cert-file /etc/mon/linux-pc5.pem \
  --client-key-file /etc/mon/linux-pc5-key.pem
~~~

Each client certificate must be enrolled for the exact tenant/site/sensor identity. The mTLS ingress rejects a payload that attempts to claim another sensor.

## Controlled test sequence

Use one bounded scenario. Do not improvise destructive payloads on test day.

1. Baseline: show PC4/PC5 assets and normal victim service reachability through the overlay.
2. Reconnaissance: from PC6, scan only one victim over at least 18 explicitly chosen TCP ports and generate at least 60 SYN attempts inside a 10-second observation window. Those are the current `tcp-syn-recon` detector conditions; do not broaden the target set to satisfy them. Confirm the resulting network-flow evidence reaches MON. The detector counts unanswered SYNs, so the scanned range must be silently filtered on that victim (a closed port answers RST/ACK and is not that shape); the command sheet makes a bounded range filtered for the attacker address only.
3. Authentication abuse: generate at least 8 failed logins within 300 seconds against one dedicated lab account from the same PC6 source address. Those are the current `endpoint-auth-failure-pressure` detector conditions. Do not harvest or reuse real credentials.
4. Correlation: the network and endpoint findings should join when they share the same observed attacker source address inside the correlation window. Show both detector IDs, evidence classes, affected asset, entities, and attack-graph edges. Describe confidence exactly as shown; do not call it a confirmed compromise unless evidence supports that claim.
5. Contain: operator selects/approves BLOCK_IP 10.77.0.60 with a short TTL. Confirm the selected point is the PC3 router and blast radius is one hostile source IP.
6. Verify: prove the MON-owned rule exists and repeat the victim connection test from PC6. Also prove victim and MON management paths remain healthy.
7. Recover: manually roll back before TTL expiry (or demonstrate TTL recovery), verify the exact rule is gone, and prove allowed victim connectivity is restored.
8. Audit: show request, approval, execution, rollback, actor, timestamps, result, and audit records in the operator console.

## Pass/fail gates

The demonstration is not a pass merely because an alert appears. It passes only if the following are observed with real evidence:

- at least one network event from the overlay;
- at least one endpoint event from a remote victim;
- incident correlation references real event/evidence IDs;
- the UI updates from the live backend, not demo JSON;
- containment changes the actual PC3 forwarding path;
- unrelated management connectivity remains available;
- rollback removes only the MON-owned rule;
- connectivity recovers;
- the audit trail records the action and rollback.

If any gate fails, report that stage as failed/degraded. Do not substitute the cinematic demo or seeded acceptance data and present it as live telemetry.

## Test-day fallback

If Zeek is not ready, use Suricata plus both endpoint collectors. That still gives independent network and endpoint evidence and is better than adding another unstable engine.

If PC4 service packaging is not ready, run the Windows collector in foreground. Do not weaken mTLS or expose mon-site on the LAN to save time.

If automated containment is not ready, do not fake an APPLIED response. Stop at response planning and show the failed/degraded execution honestly.
