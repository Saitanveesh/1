## Change and rationale

Describe the MON subsystem, issue, and the operator outcome.

## Tenant/site and evidence boundaries

How are `tenant_id` and `site_id` enforced? Which evidence is factual rather than inferred?

## Safety and rollback

Describe TTL, scope, approval, blast-radius, verification, and rollback (or state why this PR cannot cause an enforcement action).

## Verification

- [ ] Python lint/tests
- [ ] Console typecheck/tests/build, if relevant
- [ ] Migrations/API contracts, if relevant
- [ ] Disposable VM/namespace testing for OS-native actions, if relevant
- [ ] Documentation/ADR updated
- [ ] No secrets, lab hostnames or fabricated telemetry committed

List exact commands, results, and limitations. For changes affecting a deployed lab, include pinned before/after commit SHA and a safe rollback plan.
