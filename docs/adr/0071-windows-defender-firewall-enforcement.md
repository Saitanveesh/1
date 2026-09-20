# ADR 0071: Windows Defender Firewall enforcement adapter

## Status

Accepted.

## Context

MON's only real endpoint enforcement path was Linux nftables (ADRs 0063, 0068).
Enforcement must not depend on one firewall implementation.

## Decision

Add `WindowsFirewallEndpointAdapter`
(`src/mon/connectors/windows_firewall_endpoint.py`), conforming to
`EnforcementAdapterCapabilities`: `BLOCK_IP` only, IPv4 and IPv6, SITE plane,
verify/rollback/reconcile supported, apply and rollback idempotent.

Safety:

- disabled unless `MON_ENABLE_WINDOWS_FIREWALL_ENFORCEMENT=1` and on Windows;
- native PowerShell NetSecurity cmdlets through `powershell.exe` with a fixed
  argv, a fixed `-EncodedCommand` script and no shell; the operation, rule
  name, display name and the `ipaddress`-validated address travel in
  environment variables, so no telemetry-derived text is ever script text;
- MON-owned rule group `MON Endpoint Containment`; rule display name is the
  bounded deterministic marker `mon:v1:<tenant>:<site>:<execution>`, rule name
  is `mon-v1-<sha256(marker)[:32]>`; removal is by exact name and additionally
  guarded by group membership inside the script;
- never disables the firewall, never changes profiles, never removes unrelated
  rules; a rule that exists but is disabled, differently addressed, or has a
  duplicate marker fails closed (execute/rollback raise, verify reports UNKNOWN);
- bounded runtime: timeout kills the whole process tree (`taskkill /T`), output
  and error text are bounded;
- `reconcile()` is observation-first and never recreates a missing rule.

## Evidence

- `tests/test_windows_firewall_endpoint_adapter.py`: 11 fake-runner tests
  (gate, capabilities, IPv4/IPv6 lifecycle, script contains no untrusted value,
  conflict, ambiguity, reconcile, failure/timeout, shared certification harness).
- `.github/workflows/windows-firewall-certification.yml` on `windows-latest`
  (Windows Server 2025, 10.0.26100): real rules for IPv4 and IPv6 applied,
  independently verified with `Get-NetFirewallRule`, repeated apply produced no
  duplicate, a fresh adapter reconciled PRESENT, rollback verified ABSENT,
  repeated rollback idempotent, reconcile did not repair, a controlled
  conflicting rule and a controlled duplicate-marker rule failed closed with no
  rule modified, the shared harness passed against the real firewall, a 1 s
  timeout was bounded with no leaked child process, and the complete unrelated
  rule and profile snapshot (including an operator-owned control rule) was
  identical before and after. Cleanup ran in `finally` and again under
  `if: always()`. The machine-readable
  `windows-firewall-certification-report.json` is uploaded.

## NOT_PROVEN

Packet-flow blocking (rule state is verified, not traffic); Windows versions
other than the runner image; Group Policy managed or third-party firewalls;
reboot persistence and firewall service restart behaviour; IP ranges/CIDR
targets (single addresses only); real enterprise fleets.
