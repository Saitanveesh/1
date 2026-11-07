# Contributing to SERRATE

SERRATE is a security-sensitive project. Its public source is currently proprietary and **not open-source licensed**. Read [LICENSE](LICENSE) and [docs/LICENSING.md](docs/LICENSING.md) before reusing code or submitting substantial changes. No automatic copyright assignment or general license grant is implied by a pull request.

## Development process

Use focused branches and pull requests. Keep `main` stable. Preserve deployed MON identifiers, database migrations, audit records, and API compatibility unless the change includes a reviewed migration plan.

A meaningful pull request should explain:

- Which modules, tenants, sites, and data boundaries are affected.
- How new detection or investigation claims are supported by actual evidence.
- Failure behavior, retries, timeouts, and offline Site Controller impact.
- Enforcement scope, approvals, time-to-live, verification, and rollback, if applicable.
- Exact tests run and what remains unverified.

For Python changes, run `python -m ruff check .` and `python -m pytest -q`. For console changes, run `npm test` and `npm run build` in `console/`. Test privileged network-enforcement code only in disposable namespaces or VMs.

Do not commit credentials, certificates, private packet captures, personal identifiers, or sensitive infrastructure information. Report vulnerabilities through [SECURITY.md](SECURITY.md).

For licensing or contribution permission, contact [Sai Tanveesh](https://github.com/Saitanveesh) before submitting code that requires a rights agreement.
