# SSH-driven seven-Ubuntu MON lab bootstrap (experimental)

This script automates **base package install and WireGuard configuration**, not the entire MON deployment yet. Do not treat it as an end-to-end install or as evidence the platform is operational. The full identity enrollment, Site Controller, sensor ingress, Suricata, endpoint collectors, control-plane database/API/UI, binding, attack, and rollback still require the pinned test-day runbook until implemented and verified as automation.

Run it on PC2, the admin machine, from a checkout of this branch. PCs must be dedicated disposable test hosts and reachable from PC2 via verified SSH host keys. **Do not run the script against your campus-managed main OS or a shared network appliance.** This procedure assumes all seven PCs boot Ubuntu 24.04 and are on the same management LAN.

Before automation, install Ubuntu and OpenSSH on each computer, establish PC2 public-key SSH authentication as your ordinary account (without disabling password authentication globally), and manually verify host keys. Each machine must be able to run sudo, and the script will ask for each remote sudo password interactively. Do **not** grant blanket NOPASSWD sudo to every account.

On PC2:

```bash
git clone https://github.com/Saitanveesh/1.git ~/mon
cd ~/mon
git checkout feature/lab-ssh-orchestration
cp tools/lab-inventory.example.env ~/lab-inventory.env
nano ~/lab-inventory.env
bash tools/lab-ssh-orchestrator.sh ~/lab-inventory.env preflight
bash tools/lab-ssh-orchestrator.sh ~/lab-inventory.env install
bash tools/lab-ssh-orchestrator.sh ~/lab-inventory.env wireguard-keys
bash tools/lab-ssh-orchestrator.sh ~/lab-inventory.env wireguard-config
bash tools/lab-ssh-orchestrator.sh ~/lab-inventory.env verify
```

The examples in the inventory are placeholders, **not** assumed lab addresses. Confirm every PC's actual IP before running. The script creates each WireGuard private key **on its own machine** and does not copy private keys to PC2. It makes backups of existing wg0.conf before rewriting it; inspect any existing VPN setup before using the script. The hub configuration enables IP forwarding. **Do not generate attack traffic until isolation is separately verified.**

After MON service setup and after confirming PC6 can reach only the intended lab victims via the overlay, use `isolate-attacker` as the last network-security step **only at a time when someone is physically at PC6**. This command cuts PC2's SSH access to PC6:

```bash
bash tools/lab-ssh-orchestrator.sh ~/lab-inventory.env isolate-attacker
```

To recover at PC6's physical keyboard:

```bash
sudo nft delete table inet mon_lab_egress
```

**Current limitation:** this bootstrap is a starting point requiring disposable-VM integration tests. The explicit isolation stage configures PC3's input/forward guard **before** PC6's egress guard. It still does not prove tenant/site certificates, correct VM interfaces, or complete lab safety; run the readiness/isolation checks on the actual disposable lab before generating test traffic. For the real lab, keep following the known runbook's PC3 guard and readiness gates before controlled attack traffic.

If a command fails, stop and capture its terminal output. Do not fall through to the next phase. Never fabricate health or telemetry.
