# MON repository maintenance and deployment reconciliation

**Audit date:** 6 November 2026  
**Audited stable baseline:** `main` at `0ee941ba72ee5978cf40c5acbc66c912b21cfcf1`  
**Status:** Repository governance/branch cleanup only; no live deployment or application behavior altered.

## Findings

The default branch includes 355 tracked files (Python engines, React console, migrations, tests, CI and accepted ADRs). These are primarily substantive source or traceability records, **not disposable clutter**. Deleting the schema migration chain, source engines, release tests or accepted ADRs would be a regression.

There were **107 branch refs** (including `main`) and **13 open pull requests** when [the branch-head snapshot](branch-inventory-2026-11-06.json) was captured. The inventory categorizes 83 branches by associated merged PR and 10 as other, but **association with a merged PR is not sufficient proof of safe deletion**: some such branch tips have diverged and may hold unique commits.

## Critical source-of-truth discrepancy

| Ref | Audit observation | Decision |
|---|---|---|
| `main` | Last audited integrated merge: PR #88 on 8 October 2026 | Preserve as stable foundation |
| `release/mon-batch4-rc1` | 461 commits ahead of old `main` when compared | **Do not auto-merge or delete**; candidate for controlled integration after review |
| `ops/mon-three-lab-docker-migration-20261028` / PR #99 | 8 commits ahead of old `main`, draft lab migration plan | Preserve; validate against deployment and backup strategy |
| Open PRs #79, #87, #89–#99 | 13 PRs with unmerged code/docs; several PRs target other feature branches | Preserve and reconcile one by one |
| Historic feature and build branches | Many have PRs marked merged, yet not all tip commits are in `main` | Prune **only verified ancestors**, never by name/date alone |

**No access to lab machines was used in this audit.** Git branch history cannot establish what is currently running on PC-2, sensors or control-plane hosts. A deployment should be pinned to an explicit commit SHA and an operator should verify runtime process/config, database backup and rollback before cutover. Do not infer a deployment state from a green GitHub Actions run.

## Retirement rules

The retirement automation uses the immutable snapshot and checks live state again. A branch is deleted only if all of the following hold:

- Its recorded PR class is `merged_pr`; the exact historical head SHA is preserved in the snapshot.
- The live remote head still equals that SHA; a changed branch is **never** removed.
- No currently open PR uses that branch as head **or base**.
- Its exact tip is an ancestor of the freshly fetched `origin/main`.
- It is not `main`, a release/backup/lab/deployment branch, or another protected pattern.
- Its branch name is not referenced in tracked project files outside this maintenance directory.
- The delete request is scoped to this repository only, with explicit GitHub Actions write permissions.

If any check fails, the branch is retained. Errors must not be treated as approval. This trades a smaller cleanup for data safety.

The maintenance workflow triggers once when the dated inventory lands on `main`, records its actions as a CI artifact and remains available for explicit manual reruns. A branch deleted in error can be recreated from the exact recorded SHA as long as the commit still exists on GitHub; for example:

```bash
git fetch origin <recorded-sha>
git push origin <recorded-sha>:refs/heads/<original-branch-name>
```

Restoration may require repository write privileges. **This does not rewrite or purge Git commit history.** The manifest is a recovery map, not a backup of runtime databases.

## Integration sequence for deployed lab work

1. On each lab host, record the currently running checkout SHA, service versions, DB/schema revision, and sensor/controller configuration without committing secrets.
2. Take and verify independent Postgres and Site Controller state backups; rehearse restore in disposable infrastructure.
3. Choose the desired functional branch (rather than assuming the newest branch is correct) and compare it to `main` for migrations, event schemas, auth, containment and UI APIs.
4. Build one reviewed integration PR with change-by-change provenance. Keep draft PRs as evidence until their unique work is merged or explicitly rejected.
5. Run Python, console, Windows/Linux native, networked mTLS, rollback, security, and deployment-specific load/resource gates.
6. Perform a staged cutover with a pinned commit and rollback point. Only after observing live recovery and sensor health should old release/feature branches be retired.

## Repository map and retained history

- Original long README preserved in [implementation-status-main-2026-10-08](../implementation-status-main-2026-10-08.md).
- Architectural records remain in [ADRs](../adr/).
- Database migration files remain intact in `migrations/versions/`.
- The cinematic demonstration remains clearly labeled synthetic; it is not a competing MON implementation.
- Cleanup intentionally leaves the 13 open PR heads, backups, release candidates and non-ancestor branches untouched.

The GitHub connector used for documentation work does not expose a direct branch-delete operation. The only remote branch retirement here is executed through the checked-in, audited GitHub Actions workflow; do not claim a branch is gone until GitHub reports its deletion.
