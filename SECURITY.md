# Security policy — SERRATE (MON implementation)

MON handles potentially sensitive network telemetry, infrastructure credentials, and containment actions. **Do not post production JWTs, private keys, site credentials, packet captures, database dumps, or sensitive network inventories in public issues or PRs.**

## Vulnerability reporting

If GitHub's **Private vulnerability reporting** feature is enabled for this repository, use it under the repository Security tab. Otherwise, contact the repository owner through a trusted private channel and request a secure reporting route before sending reproduction material. Do not publish an active exploitation path in a public issue.

For non-sensitive defects, use [GitHub Issues](https://github.com/Saitanveesh/1/issues) with a minimal, redacted reproduction.

## Scope and supported environments

This is an actively developed engineering foundation, not an independently certified enterprise security product. See [the readiness ledger](docs/production-readiness.md) for exact subsystem gates and known limitations.

- Test enforcement adapters in disposable namespaces, VMs or CI runners, never first on a primary workstation or production router.
- Treat containment and rollback as operations requiring approvals, TTL, scope checks, auditing and verification.
- Treat the bundled `compose.yaml` as **development only**, due to its published example database credentials and network port mapping.
- Do not use the synthetic cinematic demo as proof of live detection.
- Assume credentials from old branches or historical commits may persist in git history; merely deleting a branch or file does **not** revoke leaked credentials. Rotate compromised keys and investigate exposure before history rewriting.

The repository owner should define a release/security support policy when a production release is actually available.
