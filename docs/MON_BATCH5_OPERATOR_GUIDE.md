# Batch 5 — What is happening? (plain-language side guide)

**Release target:** Stage 4 console installed on PC-2, existing PC-5 victim training site unchanged.

## Goal

For a nontechnical observer, explain the active Red Team–Blue Team demonstration without switching away from the operator's real dashboard. A right-side, hideable guide is shown on **Dashboard, Alerts, Cases, Investigation**.

The guide reads **existing measurements only**, with five understandable stages:

1. Network activity — packet measurements on the verified protected path, not fake traffic
2. Suspicious pattern — a fresh alert, not automatic proof of exploitation
3. Blue Team review — investigation page opened versus acknowledged review
4. Optional protection — only a kernel-reported, currently active timed block is called installed
5. Website response — actual PC-5 response metadata for the selected source, with fictional fixture disclosure identified

The guide does **not** issue blocks, alter investigations, connect to new external systems, or invent outcomes. It explicitly warns that a kernel rule must still be verified by a fresh attacker-side connectivity test, and server writes do not prove receipt by a remote client. A source label is taken from evidence, never hardcoded to the attacker role.

## Deploy only on PC-2

From `pc-2@lab-pc2`:

```bash
cd ~/mon-three-code
git fetch --no-tags https://github.com/Saitanveesh/1.git \
  refs/heads/feature/mon-batch5-plain-language-20261024
git show FETCH_HEAD:tools/mon-batch5-pc2.sh > /tmp/mon-batch5-pc2.sh
bash -n /tmp/mon-batch5-pc2.sh

# Non-destructive preflight and isolated full frontend build/tests:
bash /tmp/mon-batch5-pc2.sh --check

# Only after CHECK PASSED:
bash /tmp/mon-batch5-pc2.sh --apply
```

The installer backs up only the four UI source files it changes, builds and tests staged sources first, then restarts **only** the existing frontend service. The Stage 4 portal, firewall helper, passive detection service, WireGuard, and PC-5 application are not modified. On a failed installation it attempts to restore the previous frontend.

Verify:

```bash
sudo systemctl is-active mon-three-console-v2.service mon-three-lab-portal.service mon-stage4-gate.service
curl -fsS http://127.0.0.1:5174/ >/dev/null && echo "Batch 5 frontend serving"
```

Open `http://100.75.116.62:5174/?tenant=mon-lab&site=site-a` and refresh the browser (a hard refresh if it retained old assets). Check the **What's happening?** rail on the right, and the **Hide explanation / Explain this screen** toggle.

## Four simple acceptance checks

1. **Idle:** Without a qualifying new training detection, it must not show a made-up attack or a successful block. If packet or IDS data are missing, say so.
2. **Fresh alert:** A PC-7 authorized training request to the fictional PC-5 application generates a *real* Suricata alert. The rail describes a suspicious request, **not** a confirmed data loss.
3. **Investigate:** Open that alert. The rail says the Blue Team is examining the evidence. Acknowledging the alert changes the review state but **does not** claim traffic has been blocked.
4. **Mitigation / effect:** Only after the Stage 4 endpoint returns a live **KERNEL_RULE_PRESENT** for the selected source may it say that a block was installed. Verify separately from PC-7 that a new connection is blocked; check PC-2's real nft drop counter. PC-5's fictional response ledger appears only if that endpoint returns evidence. After the timed rule expires or access is released, the rail must stop claiming a currently active block.

You do not need to install anything on PC-5, PC-6, or PC-7 for Batch 5 itself; those machines continue the existing Stage 4 controlled demonstration.

The technical workflow still uses the normal operator controls. This guide is **read-only narration** and should never be used as a source of authorization decisions.
