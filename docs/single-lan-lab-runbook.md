# MON single-LAN seven-system lab runbook

## Status

Deployment/lab planning only. No feature development is introduced by this document.

Baseline source SHA:

`5c7ae457393bf1f69beb885113634867436688c8`

## Constraint

The available physical lab has one private Ethernet LAN shared by all systems. There is no separate physical attack LAN.

The lab therefore uses the existing LAN as an underlay while creating two lab IP subnets whose traffic is routed through the MON sensor/router. This allows Zeek/Suricata to observe the lab flows and prevents normal routed attacker traffic from reaching the management subnet.

This is logical isolation, not a replacement for a truly separate switch/VLAN. Raw layer-2 abuse is out of scope and must not be attempted.

## Seven-system allocation

| PC | Physical host | VM role |
|---|---|---|
| PC-1 | Windows | Ubuntu 24.04 MON Control Plane + PostgreSQL + operator-console dev server |
| PC-2 | Windows | Ubuntu 24.04 MON Site Controller + sensor mTLS ingress |
| PC-3 | Windows | Ubuntu 24.04 sensor/router + Zeek + Suricata + MON network collectors |
| PC-4 | Windows | disposable Windows victim VM |
| PC-5 | Windows | disposable Ubuntu 24.04 victim VM |
| PC-6 | Windows | disposable Ubuntu 24.04 controlled traffic-generator VM |
| PC-7 | Windows | operator browser/admin workstation; no MON runtime required initially |

All MON/runtime work occurs in disposable VMs. Physical Windows hosts remain management/hypervisor systems.

## Address plan

Existing physical LAN remains unchanged and is used for management/control-plane traffic. Record its actual subnet instead of assuming a value.

Lab routed subnets carried on the same physical Ethernet:

- attacker subnet: `10.81.0.0/24`
- victim subnet: `10.82.0.0/24`

Addresses:

- PC-3 sensor/router: existing management-LAN address + `10.81.0.1/24` + `10.82.0.1/24`
- PC-6 traffic generator: `10.81.0.50/24`, gateway `10.81.0.1`
- PC-4 Windows victim: `10.82.0.20/24`, gateway `10.82.0.1`
- PC-5 Linux victim: `10.82.0.21/24`, gateway `10.82.0.1`

PC-1, PC-2, PC-3 management address, and PC-7 remain on the existing private LAN.

The traffic-generator and victim VMs should not retain an additional management-LAN IPv4 address once the lab-routing stage starts.

## Routing and safety boundary

PC-3 enables IPv4 forwarding and owns a dedicated nftables forward chain:

- allow established/related flows;
- allow `10.81.0.0/24 -> 10.82.0.0/24`;
- allow return traffic only as established/related;
- default-drop forwarding to all other destinations.

No NAT from the lab subnets to the management LAN or Internet is configured.

This means normal IP traffic from the traffic generator to management-LAN systems is denied by PC-3.

The traffic generator must target only `10.82.0.20` and `10.82.0.21`.

## Why PC-3 must route

On an ordinary switched LAN, PC-3 cannot assume it will receive unicast traffic between PC-6 and PC-4/PC-5. By putting the generator and victims in different IP subnets and making PC-3 their gateway, their normal IP traffic traverses PC-3 and becomes observable by Zeek and Suricata without requiring a managed switch SPAN port.

## Supported MON communication path

The first cross-system end-to-end path is:

```text
PC-6 traffic generator
        |
        v
PC-3 router/sensor ----> PC-4 / PC-5 victims
        |
        | Zeek JSON / Suricata EVE
        v
MON Zeek/Suricata collectors
        |
        | sensor mTLS :9443
        v
PC-2 mon-sensor-ingress
        |
        | loopback HTTP
        v
PC-2 mon-site :8090
        |
        | site mTLS :8443 + bearer token
        v
PC-1 mTLS site ingress
        |
        | loopback HTTP
        v
PC-1 Control Plane :8080
        |
        v
PostgreSQL / incidents / evidence / audit
        |
        v
Operator console -> PC-7 browser
```

## Important current endpoint boundary

The repository's Windows and Linux endpoint collectors use `LocalSiteEventSender` and explicitly enforce a loopback-only `--site-url`.

Therefore the current code does **not** support:

```text
PC-4/PC-5 endpoint collector -> remote PC-2 mon-site
```

Do not expose `mon-site` on a non-loopback address to work around this; production configuration rejects that intentionally.

For this phase:

- Windows/Linux endpoint packages may be installed and their local collector/service/enforcement behavior certified on PC-4/PC-5.
- Network telemetry is the supported multi-machine ingestion path.
- Remote endpoint telemetry transport remains a product gap to address in a later engineering phase, not something to fake during deployment certification.

## Base repository checkout

Where MON source is needed:

```bash
git clone https://github.com/Saitanveesh/1.git mon
cd mon
git checkout 5c7ae457393bf1f69beb885113634867436688c8
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[dev]'
```

Do not use a later working-tree revision in this lab while claiming evidence for the frozen baseline.

## Test traffic policy

PC-6 is a controlled traffic generator, not an unrestricted attacker.

Allowed initial scenarios:

- ICMP connectivity to the two victim addresses;
- TCP connection attempts to explicitly enabled victim services;
- bounded authentication failures against a disposable test account;
- small, explicitly targeted port probes against the two victim IPs;
- known IDS test traffic.

Prohibited:

- subnet-wide scanning of the management LAN;
- broadcast/multicast flooding;
- ARP spoofing;
- raw layer-2 bypass attempts;
- volumetric flooding;
- targeting any IP other than the two designated victims unless a later written test case authorizes it.

## Bring-up order

1. VM snapshots.
2. Record real management-LAN IPs for PC-1/2/3/7.
3. Install/checkout frozen MON source where needed.
4. Bring up PC-1 PostgreSQL/control plane/auth/PKI.
5. Bring up PC-1 site-mTLS ingress.
6. Enroll PC-2 Site Controller and start `mon-site`.
7. Start PC-2 sensor mTLS ingress.
8. Configure PC-3 lab router addresses and nftables forwarding policy.
9. Configure PC-4/5/6 lab-only addresses.
10. Prove PC-6 can reach only PC-4/5 through PC-3 and cannot reach the management LAN.
11. Install Zeek/Suricata on PC-3.
12. Enroll PC-3 sensor identity and start MON network collectors.
13. Verify event arrival/fleet health before any security scenario.
14. Only then begin bounded test traffic.

## Stop conditions

Stop immediately if:

- PC-6 can reach a management-LAN host through routing;
- PC-4/5/6 retain an unintended management-LAN address;
- PC-3 forwarding policy is not default-deny;
- MON reports healthy cloud/sensor delivery during a known disconnect;
- telemetry appears under the wrong tenant/site/sensor;
- a containment test affects any non-victim system.
