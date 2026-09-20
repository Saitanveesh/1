# ADR 0068: Linux privileged-host nftables certification

## Status

Accepted.

## Context

ADR 0063 introduced `LinuxNftablesEndpointAdapter`; ADR 0066/0067 proved the
containment lifecycle and restart recovery inside a disposable network
namespace. What remained unproven was the adapter's behavior against the
*host* network namespace, alongside other nftables state.

## Decision

Add `tests/test_nftables_privileged_host.py` and the dedicated workflow
`.github/workflows/nftables-host-certification.yml`. The tests run the adapter
without `namespace=` on a GitHub-hosted `ubuntu-latest` runner, a single-use
VM. They skip unless `MON_TEST_PRIVILEGED_HOST=1`, the enable gate
`MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT=1`, Linux, root and `nft` are all
present, so they never run on a developer machine. Only IETF documentation
addresses (198.51.100.0/24, 2001:db8::/32) are ever blocked. The existing
unit and namespace tests are unchanged.

## What is proven on the host

- The adapter refuses to construct without the explicit enable gate.
- The MON-owned `inet mon_endpoint` table and `mon_block_ip` chain are created
  on demand with `policy accept`; nothing is default-denied.
- IPv4 and IPv6 `BLOCK_IP` apply, verify (PRESENT), roll back and verify
  (ABSENT); repeated apply and repeated rollback are idempotent.
- Operator-owned nftables tables (inet and ip families) are byte-identical
  before and after apply and rollback.
- Coexistence with the iptables-nft backend: a foreign iptables chain is
  unchanged (only when the runner's iptables uses the nf_tables backend).
- A conflicting rule or two rules sharing one execution marker make execute
  and rollback raise and verify report UNKNOWN; no rule is added or removed.
- A hung `nft` is killed at the timeout (bounded < 6 s for a 1 s limit), its
  whole process group is gone and no zombie children remain.
- A failing `nft` surfaces as an error, verify reports UNKNOWN and reconcile
  reports drift; it is never reported as success.
- A new adapter instance (simulated restart) reconciles against actual kernel
  state, observes out-of-band removal as drift, and does not repair it.
- After each test the fixture deletes the MON and test tables and asserts the
  full `nft list ruleset` equals the pre-test baseline. The workflow repeats
  the cleanup and a diff under `if: always()`.

The workflow writes `nftables-host-certification-report.json` with the kernel,
distribution and `nft` version actually used; the values are measured on each
run, not asserted here.

## Privilege requirements

Root (CAP_NET_ADMIN) is needed to run `nft`. The adapter has no privilege
escalation of its own; the deployment must supply it.

## Not proven / unsupported

- firewalld and ufw: not installed or exercised. Coexistence is NOT_PROVEN;
  those managers may reload and discard tables they did not create.
- Real packet drop on the host interface (only ruleset state is verified).
- Distributions other than the runner's Ubuntu image, other kernels, and the
  legacy iptables backend.
- Rule ordering versus operator chains at the same hook priority; the MON
  chain uses priority 0 and can be preceded by an operator accept/drop.
- Rollback removes the rule but leaves the empty MON table in place.
- Persistence across host reboot: rules are not written to any nftables
  configuration file and are lost on reboot.

This is disposable-runner certification, not production host certification.
