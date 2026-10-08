# All-Ubuntu MON lab — SSH automation (PC2 orchestrator)

**Status:** integration candidate. These scripts have static/syntax checks but **have not been executed on your seven real lab machines**. No guarantee of a first-run success. Run only on authorized disposable or dedicated Ubuntu 24.04 lab hosts; not on primary laptops or a production/shared network without administrative approval. The inventory has `CHANGE_ME` placeholders which must be replaced; there are no default management targets.

One PC (PC2) uses SSH to install and configure PC1, PC3, PC4, PC5 and PC6. PC7 needs only a browser. It eliminates switching terminals for most installation, PKI enrollments, service startup and network configuration. The stage driver is `controller.sh`; remote root-only operations are in `node.sh`. Code is pinned to the tested MON integration commit `8f66baa9f8d287b8c05da379259b289c661c5828` and must not be silently upgraded to current `main`.

Topology:

```text
Normal management LAN (existing physical switch/router): PC1 ... PC7
        PC2 --SSH--> PC1 PC3 PC4 PC5 PC6

WireGuard overlay 10.77.0.0/24 (separate attack path):
PC6 .60  -->  PC3 .1  --> PC4 .40 / PC5 .50
             Suricata, site controller, router nftables

PC4 and PC5 are Ubuntu + Linux endpoint collectors. Windows is NOT shown live.
```

## Required one-time manual actions

1. Boot Ubuntu 24.04 on all seven machines; record each management-LAN IP using `ip -4 -br addr`. All PCs must reach each other on the authorized physical LAN. You need Internet access for `apt`, GitHub, container images and npm during initial install. Give them a common administrative Ubuntu account name, or adapt the controller for per-host usernames before proceeding.
2. From **PC2**, generate a personal SSH public key if you do not already have one: `ssh-keygen -t ed25519`. Install only its **public** key onto PC1, PC3, PC4, PC5 and PC6 with `ssh-copy-id lab@<PC-IP>` once per host. Inspect and verify each host-key fingerprint before accepting it. `ssh -o BatchMode=yes lab@<PC-IP> hostname` must now work on all five hosts. The driver will not bypass host-key verification and will not ask for SSH passwords.
3. On PC2, clone MON and choose this directory: `git clone https://github.com/Saitanveesh/1.git ~/mon` then `cd ~/mon/lab/ssh-automation`. From the feature PR branch while under review, use the exact branch/commit containing this automation. Copy `lab.env.example` to `lab.env` and set **all seven real management IPs**, `LAB_USER`, and the pinned `MON_REF`. Run `chmod 600 lab.env`. Confirm the management network does **not overlap** `10.77.0.0/24`.
4. Confirm every target admin account can use `sudo` interactively. The driver transfers `node.sh`, launches it through `sudo` with a terminal, and permits a password prompt at each stage. It does **not** add `NOPASSWD:ALL` to sudoers. Some hosts may need the account added to the sudo group beforehand.
5. Ensure all seven PCs are **lab-owned**, not serving unrelated users or production services. The installation sets up nftables WireGuard tables, starts SSH on victims, changes the victim test account, runs Suricata as root and binds MON services. Do not execute on hosts where those changes could affect normal operations.

## From PC2 — staged first run

Paste **one command at a time**. Stop when one fails; collect the full output; rerun the same stage after fixing the cause. The scripts are designed to preserve identities, database volume and WG keys on retry.

```bash
cd ~/mon/lab/ssh-automation
chmod 600 lab.env
bash controller.sh preflight   # verify SSH, Ubuntu and management IP assignment
bash controller.sh install     # install packages; clone pinned repo
bash controller.sh keys        # generate WG keys (never export private keys)
bash controller.sh network     # create hub/spokes + PC3 guard; check tunnels
bash controller.sh control     # PC1 PostgreSQL / auth / mTLS / console
bash controller.sh site        # PC3 CSR => PC1 enrollment => PC3 Site Controller
bash controller.sh sensors     # Suricata and both remote Linux endpoint collectors
bash controller.sh register    # router enforcement point in MON
bash controller.sh status      # real control/site/overlay process checks
```

After these steps, **before running a controlled network probe**, explicitly isolate the PC6 attacker from the management LAN:

```bash
MON_LAB_CONFIRM_PC6_LOCKDOWN=YES bash controller.sh lockdown
bash controller.sh status
```

Lockdown preserves PC2 SSH *response* traffic and PC3 WireGuard UDP, but blocks PC6's other physical-management-interface egress, including downloads. Operate with someone physically at PC6 and record a recovery path first. PC6 cannot then reach PC1 management as an attack target. The script does **not** automatically initiate scanning, authentication attempts, blocks or other attack actions.

After isolation, use the existing [all-Ubuntu test-day flow](../../docs/lab-seven-system-command-sheet.md) for the bounded demonstration on PC6, bearing in mind that the linked older document describes a Windows PC4; the all-Ubuntu `MON-Lab-Day-Flow` treats both PC4 and PC5 as Linux victims. Prefer the **verified** test-day procedures to improvising anything outside the overlay. On PC7 open `http://<PC1-management-IP>:5173/?tenant=mon-lab&site=site-a`. Use a short-lived signed operator session from PC1, not a fake or seeded login.

A shortcut exists for a clean lab, but the staged commands are better for debugging:

```bash
bash controller.sh all
```

`all` deliberately **does not** run `lockdown` or launch attacks.

## What is and is not automated

Automated: pinned code distribution, packages, WireGuard keys/peers, PC3 traffic guard, durable PostgreSQL container volume, 48-hour disposable PKI/JWT generation (first install only), signed CSR enrollment, site/sensor certificates, Suricata, Linux collector processes, PC3 router registration, stage health checks.

Requires manual action: Ubuntu/SSH initial install, host-key verification, identifying management IPs, interactive sudo confirmation, PC6 egress lockdown approval, PC7 operator login, generating real baseline/attack traffic, binding newly discovered real asset IDs to PC3 enforcement, incident review, plan/approve/execute, packet-path verification and rollback.

**Important difference from the older PDF:** The victim account `monlab` gets a **random per-host password** stored root-only in `/etc/mon-lab/test-user-password`; the old PDF's fixed `Lab-Only-Not-A-Real-Password-1` is intentionally *not valid*. Use `nc -zv 10.77.0.50 22` and `nc -zv 10.77.0.40 22` for safe baseline reachability; wrong-password SSH attempts against this lab-only user produce authentication-failure evidence. Do not copy commands that presume successful `monlab` logins with the old shared password. The script refuses to take over a pre-existing unrelated `monlab` account. We do not invent asset IDs or incidents, and we do not auto-isolate any detected source.

**Security:** Keys for each site/sensor originate on their respective PCs and are not sent to PC1. Public CSRs pass through PC2 into PC1. Signed certificates, root-issued sensor ingress server key and the short-lived site token transiently pass through a PC2 temporary mode-0700 directory and a host-local, mode-0700 staging directory; they are removed after a successful stage. The primary CA private keys remain on PC1. The controller requires SSH host-key verification, and no passwords are embedded in the configuration. Do not run from an untrusted PC2.

**Idempotence limitations:** Persistent certificates, tokens and state are reused on reruns; there is no automatic renewal after the 48-hour operator/site token expires. Do not wipe `/etc/mon-lab/identity` or the PostgreSQL volume as a generic retry. A failed enrollment leaves its existing state in place; inspect rather than blindly repeating with new keys. Ubuntu 24.04 Node 22 installation may use Snap if the OS Node version is insufficient. Internet connectivity is required the first time.

## Troubleshooting: first failed hop

| Symptom | On PC2 / remote machine | What to inspect |
| --- | --- | --- |
| SSH refused | `ssh -vv lab@<MGMT-IP> hostname` | physical LAN, user, authorized_keys, sshd, host key |
| sudo password prompt | enter the target PC's admin password | user belongs to `sudo` group; no blanket NOPASSWD |
| WireGuard handshake missing | PC3 `sudo wg show`; peer `sudo wg show` | public key assignment, UDP 51820, PC3 management IP |
| PC1 API fails | PC1 `sudo tmux capture-pane -p -t mon-control -S -100` | PostgreSQL URL, role, migrations, JWT config |
| PC3 site fails | PC3 `sudo tmux capture-pane -p -t mon-site -S -100` | cert files, server SAN, cloud ingress |
| Sensor unauthorized | PC3 `sudo tmux capture-pane -p -t sensor-ingress -S -100` | signed sensor ID, site trust reconciliation |
| No Suricata flows | PC3 `sudo tcpdump -n -i wg0` | routed overlay path; capture/interface settings |
| PC4/PC5 collector fails | victim `sudo tmux capture-pane -p -t mon-linux -S -100` | `python3-systemd`, SSH journal permissions, cert scope |
| PC6 unreachable after lockdown | use local PC6 keyboard | `sudo nft delete table inet mon_lab_egress` |

The `status` phase confirms services and WireGuard only; it **does not certify** detection/correlation/containment. A full live exercise must record packet evidence, incident evidence, enforcement rule, independent traffic failure and rollback recovery.

## Shutdown (manual approval required)

```bash
MON_LAB_CONFIRM_TEARDOWN=YES bash controller.sh teardown
```

This stops MON tmux processes, disables WireGuard, removes only MON-owned lab firewall tables and removes only the throwaway `monlab` account if this automation created it. **It does not** remove `/opt/mon-lab`, delete the PostgreSQL Docker volume, erase `/etc/mon-lab` identities, or flush unrelated nftables rules. Keep those for investigating failures.