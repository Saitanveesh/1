# PC2 SSH lab deployment: first run

**Do not run the full MON deployment until every machine is authorized, reachable, and named in an inventory.** The previous runbook used Ubuntu 24.04 and one common username. Actual PC2 is Ubuntu 26.04.1 and username `pc-2`; neither the remaining OS versions nor user accounts are yet known. Never infer another PC's address from PC2's campus IP or blindly use placeholder `192.168.1.x` inventory entries.

On PC2 (from its Tailscale SSH terminal), fetch this script from `main` after merging the PR:

```bash
cd ~/mon-automation
git fetch origin main
git show origin/main:tools/lab-pc2-remote-readiness.sh > ~/lab-pc2-remote-readiness.sh
bash ~/lab-pc2-remote-readiness.sh | tee ~/lab-readiness-output.txt
```

The script queries only `lab-pcN.local` or `lab-pcN` via normal name resolution. It does **not** scan the college subnet. If a hostname does not resolve, get its IPv4 address at that specific computer. Verify each result before configuring anything.

The authorized operator must then create a trusted local inventory with **IP and SSH username per PC**; don't guess that usernames are the same. Set up SSH host-key verification and ordinary public-key authentication from PC2 before unattended operations. Run read-only connectivity/preflight before package installs. If unattended setup is desired, use purpose-limited sudoers rules reviewed on dedicated test VMs, rather than `NOPASSWD:ALL`.

See `docs/lab-ssh-orchestration.md` for the existing experimental bootstrap. It is not a complete end-to-end MON deployment. In particular, never enable PC6 egress isolation without someone physically present on PC6 to restore it. Do not expose the lab's demo passwords/short-lived operator tokens outside the authorized lab. Do not start scan/auth-failure tests until the separate WireGuard overlay, PC3 guard, endpoints, and operator controls have been verified.

**Required gate:** inventory has correct PC1/3/4/5/6/7 management IPs and usernames; all six hosts reachable via verified SSH; each machine is confirmed to be a dedicated lab OS instance; baseline services and safety checks before containment.
