# Contributing to MON Security Fabric

MON is a security-sensitive, multi-tenant system. Changes must be reviewable, reversible and supported by evidence.

## Branch policy

- `main` is the stable integration branch. Do not push new experimental demos or deployment-specific shortcuts directly to it.
- Use a short-lived branch and PR for focused changes.
- Do not fork another long-running `v1/v2/v5` product line. Integrate a feature only after its test, migration, security and deployment boundaries are understood.
- The repository contains historical, still-open lab PRs with nontrivial unmerged work. **Do not delete or cherry-pick these solely because their dates look old**; consult [branch reconciliation](docs/repository-maintenance/README.md).
- Before deleting a branch, verify its exact tip is an ancestor of `main`, it is not referenced by active PRs/deployments, and its SHA is recorded for recovery.

## Definition of done

A meaningful change should explain:

1. Which `tenant_id` and `site_id` boundaries apply.
2. What evidence supports each detector/incident or calculated score.
3. What changes for offline Site Controller operation.
4. Which failures/timeouts/retries/idempotency cases were considered.
5. If response/enforcement changes: confidence, approval, TTL, blast radius, audit, verify and rollback.
6. Which tests were executed on disposable systems and which limitations remain unproven.

Run `ruff check .`, `pytest -q`, console tests/build, and relevant GitHub Actions gates. OS-native collectors and enforcement changes require appropriate disposable VM/namespace validation before any real deployment.

## Scope and licensing

Code review and issue discussion are welcome. **This repository currently has no root software license**; contributors should agree licensing terms with the owner before submitting substantive external code or redistributing source.

Do not commit API keys, production certificates, live host identifiers, real incident data or other tenant information. Follow [SECURITY.md](SECURITY.md) for disclosure.
