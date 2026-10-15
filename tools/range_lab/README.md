# MON: runnable MITM and multi-origin pressure lab (NO CAMPUS UPLINK)

This directory implements **actual** kernel-level ARP redirection, packet
capture, a bounded multi-source application-pressure scenario, real host
firewall containment, verification and rollback. Its network is created
**inside a disposable Linux virtual machine** with six ephemeral Linux
network namespaces, attached only to a newly created virtual bridge
**without a physical port, host bridge IP or default route**.

This is not permission to intercept traffic or conduct DDoS against the
college LAN, ordinary PCs, or the college ERP. The only traffic targets
are two **ephemeral, generated** test workloads inside the VM. **There is
no designated physical attacker PC or victim PC.** Any approved computer
capable of hosting this **isolated Ubuntu VM** can run the scenario; MON's
real network discovery outside the VM must remain evidence-backed.

## Run at Lab A — only after verifying the VM is isolated

Use a new Ubuntu 24.04 disposable VM with networking set to **Internal
Network / Host-only without a campus uplink or bridge**. Verify that no
virtual NIC is bridged to the college LAN. Ensure you have permission to
perform the exercise in this VM. Do **not** run on the Windows host OS,
a campus production server, or an unrestricted management VM.

Inside the Ubuntu VM:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv iproute2 \
  iputils-ping curl tcpdump nftables
git clone https://github.com/Saitanveesh/1.git MON
cd MON
git fetch origin design/dynamic-multilab-cyber-range
git checkout design/dynamic-multilab-cyber-range
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

**One command** to execute both scenarios, after verifying the isolation
above (replace `alpha` with `beta` to select a different victim on the
fly; neither means a fixed physical PC):

```bash
sudo env MON_DISPOSABLE_VM_CONFIRMED=YES \
  MON_PYTHON="$PWD/.venv/bin/python" \
  bash tools/range_lab/run.sh --scenario all --victim alpha
```

Or run only the requested type of exercise:

```bash
sudo env MON_DISPOSABLE_VM_CONFIRMED=YES \
  MON_PYTHON="$PWD/.venv/bin/python" \
  bash tools/range_lab/run.sh --scenario mitm --victim beta

sudo env MON_DISPOSABLE_VM_CONFIRMED=YES \
  MON_PYTHON="$PWD/.venv/bin/python" \
  bash tools/range_lab/run.sh --scenario multi-origin --victim alpha
```

The script **refuses** to operate outside root-controlled disposable
namespaces without explicit confirmation. It builds one ephemeral virtual
bridge; six veth-only isolated participants; and hard-coded *internal*
test IPs in the `10.253.42.0/24` virtual lab. Those values are **not
college host addresses, nor a production inventory or attacker mapping**.

## Scenario A — MITM (real packet-path check)

1. A real client obtains the disposable victim's genuine MAC address.
2. The attacker namespace sends genuine ARP reply frames, claiming the
   victim's and client's addresses, over its isolated veth.
3. MON records actual ARP packet captures and tests whether neighbor
   caches changed.
4. The client requests a fictional record from the selected disposable
   victim. An actual TCP capture on the intermediate attacker namespace
   must prove that the packets traversed the attacker's interface.
5. When the MAC binding or packet-path proof fails, the script **fails**:
   there is no success animation, no invented MITM finding.
6. Containment pins the real original MACs in the isolated test neighbor
   tables, disables test forwarding, confirms the recovered service,
   and restores ordinary dynamic ARP when finished.
7. The real ARP pcap is parsed into `SecurityEvent` observations, then
   run through MON's `arp-binding-conflict` detector. A conflict alone
   does not prove an on-path adversary; actual TCP capture is separately
   required.

**Evidence**: `arp-packets.pcap`, `arp-binding-before.txt`,
`arp-binding-during.txt`, `arp-binding-recovered.txt`,
`arp-mon-findings.json`, `mitm-packets.pcap`,
`mitm-path-observed.txt`, `mitm-recovered.json`.

**Caveat:** ARP redirection depends on the disposable VM kernel's neighbor
behavior. If cache insertion is refused or capture is blocked, mark the
exercise **NOT VERIFIED** and inspect the failed gate; do not claim success.

## Scenario B — bounded distributed availability pressure

1. Three **distinct** source namespaces issue at most **5 requests/s
   per namespace for 6 seconds** (90 scheduled HTTP GETs maximum)
   against one disposable victim. These are independent virtual network
   identities, not three separate physical Internet origins.
2. The victim's **actual server access log** records source IP, timestamp,
   HTTP status and measured handling time. The log is analyzed by MON's
   `http-multi-source-pressure` detector, which never attributes all
   sources to one attacker.
3. An independent fourth namespace checks victim service health.
4. The victim's *namespace-local* nftables control point temporarily
   blocks only the three test-source IPs on TCP/8081.
5. The script verifies that an affected test source is blocked **and**
   that the independent client is not blocked.
6. The nftables table is removed and the blocked source is independently
   confirmed able to connect again.

This is a **real, bounded multi-source pressure exercise**, not evidence
of ISP-scale volumetric DDoS or upstream link saturation. It is appropriate
as a reproducible distributed attack-*shaped* SOC demonstration; a true
large-scale DDoS certification would require special isolated traffic
generation and upstream mitigation equipment, not ordinary lab PCs.

**Evidence**: `load-*.json`, `victim.jsonl`,
`multi-source-mon-findings.json`, `containment-rules.txt`,
`authorized-client-during-containment.json`,
`rollback-verified.json`, and `SHA256SUMS`.

The script outputs a directory such as
`/tmp/mon-isolated-range.XXXXXXXX/`. These are actual, raw
exercise observations; do not edit them or represent fixed unit-test
fixtures as live traffic. Review capture redaction/retention before
publishing or using a projector.

## Relation to MON's actual campus-network deployment

This sandbox is **the immediate executable safety-first starting point**.
It is not equivalent to instant attribution of any arbitrary college
workstation, since arbitrary campus switches may be unmanaged and the
SOC lacks validated SPAN/switch/VLAN capture paths.

For the real campus SOC, select a host **at runtime** from those whose
actual network/service endpoint is authorized, enrolled, visible to an
authenticated sensor, and proven in the isolated exercise fabric.
The observed source, selected victim and viable containment controls
must be separately corroborated from actual flow/endpoint/switch data.
The host-level victim-monitoring API can query any selected `asset_id`;
missing agents or incomplete provenance must yield **UNKNOWN**.

Even if the target is a classroom PC, **do not** run a deliberate MITM
or DoS against the shared college LAN. Create a genuinely isolated virtual
bridge or exercise VLAN and enroll only permitted disposable systems.
Before advancing to real hardware, record switch model, management access,
SPAN/flow coverage, uplink position, VLAN isolation and rollback feasibility.

## Gates for a trustworthy demonstration

- Before execution: nonbridged VM, no route from the virtual namespace
  to campus, approved test-only workloads, and identified test operator.
- MITM: changed ARP cache *plus real attacker-interface packet capture*
  before claiming an intercepted path. Recovered MAC and service afterward.
- Distributed pressure: three distinct *observed* test-source addresses,
  actual per-source request logs, endpoint health, verified source isolation,
  independently verified unaffected client and a successful rollback.
- After testing: all veths, namespaces, virtual bridge, forwarding and
  nftables controls must disappear on script exit, including on failure.
- Real campus/ERP inventory must never be seeded with virtual scenario
  addresses and passed off as discovered college devices.

## Known prerequisites and limitations

- Requires privileged `ip netns`, bridge/veth, packet sockets, tcpdump
  and nftables **inside the disposable Ubuntu VM**. Some nested VMs and
  heavily restricted cloud runners do not permit these capabilities.
- Only `bash -n`, parser/detector unit tests and other CI checks can be
  performed without a privileged disposable runner. A successful source
  commit is **not proof** that the ARP attack completed.
- Stop execution by interrupting the script; the trap deletes virtual
  namespaces and bridge. Discard the VM snapshot after the lab. Retain
  evidence only as permitted, separately from production student data.
