# ADR 0063: Enforcement adapter capability contract and Linux nftables endpoint candidate

## Status

Accepted.

## Context

MON already has `EnforcementPoint`/`EnforcementBinding` configuration, enforcement-graph
selection, policy gating, response orchestration with TTL rollback, site/control-plane
dispatch, an adapter registry, and a disposable-namespace-only nftables adapter
(`DisposableNftablesAdapter`). What was missing was a way for the registry to know not just
*that* an adapter exists for a kind/vendor, but *what it actually guarantees* -- and a first
real (if narrowly scoped) Linux endpoint enforcement adapter to exercise that contract against.

## Decision

### Adapter capability contract

`mon.enforcement.EnforcementAdapterCapabilities` is a typed, frozen Pydantic model describing
what an adapter *implementation* supports: `supported_actions`, `execution_plane`,
`supports_verify`/`supports_rollback`/`supports_reconcile`, `apply_idempotent`/
`rollback_idempotent`, `credential_requirement`/`supports_credential_ref`,
`external_timeout_seconds` (bounded to 300s), `remote_api` (local host-resident vs. remote
API), `critical_asset_approval_recommended`, and `supported_target_types` (`IP_ADDRESS`/
`ASSET`). This is distinct from `EnforcementPoint.capabilities` (the *configured* action set
for one deployed enforcement point) -- both remain, and this milestone integrates them rather
than replacing either.

The adapter protocol gains `ReconcilableEnforcementAdapter` (`reconcile(plan, execution_id, *,
expected_state) -> EnforcementReconciliation`) alongside the existing `execute`/`rollback`/
`VerifiableEnforcementAdapter.verify`. `EnforcementReconciliation` (new in `mon.domain`) is
observation-first: it reports `observed_state`, `expected_state`, and `drifted`, and never
implies anything was repaired. No adapter in this milestone auto-repairs drift inside
`reconcile()`.

`EnforcementRegistry.register()` takes an optional `capabilities=` keyword. When supplied, the
registry rejects impossible declarations at registration time (e.g. `supports_rollback=True`
on an adapter with no `rollback()`, or `supports_verify=True`/`supports_reconcile=True`
without the adapter actually implementing those protocols) by raising `EnforcementError`. When
omitted (every pre-existing call site), the registry infers a permissive default from actual
`isinstance`/`hasattr` checks rather than narrowing anything, so no pre-existing registration
or test needed to change. `EnforcementRegistry.get_capabilities(kind, vendor)` mirrors
`resolve()`'s exact-then-`"*"`-generic lookup and returns `None` when nothing is registered.

### Response planning integration

`ResponseOrchestrator.plan()` now also checks, when an adapter *is* registered for the
selected enforcement point, whether that adapter's declared `supported_actions` actually
include the requested action. A mismatch denies the plan with an explicit reason
(`PolicyDecision(outcome=DENY, reasons=[...])`) rather than silently downgrading or attempting
execution. When no adapter is registered at all, this check is skipped (unchanged from
before): the existing "no enforcement adapter" failure still surfaces at `execute()` time via
`EnforcementRegistry.resolve()`, so the pre-existing missing-adapter failure-closed test stays
correct without modification.

### Certification harness

`mon.enforcement_certification.certify_enforcement_adapter()` is a small, practical (not a
framework) async harness any adapter can be run through: it checks the capability declaration
matches actual protocol conformance, then drives apply -> verify PRESENT -> idempotent
re-apply -> reconcile (no drift) -> rollback -> verify ABSENT -> idempotent re-rollback ->
reconcile (no drift), plus pluggable negative cases (`invalid_target_plan`,
`unsupported_action_plan`, `scope_mismatch_plan`, `assert_timeout`) and an optional
`unrelated_state_snapshot` equality check before/after. It raises `AdapterCertificationError`
naming the first guarantee that broke. This is intended for reuse by future firewall/NAC/cloud
connectors, not just the nftables adapters.

### Linux nftables endpoint adapter candidate

`mon.connectors.nftables_endpoint.LinuxNftablesEndpointAdapter` is a new adapter, separate
from `DisposableNftablesAdapter` (which remains netns-only and unmodified). It supports only
`ActionType.BLOCK_IP` in this milestone -- no rate limiting, endpoint isolation, VLAN
quarantine, or arbitrary nft rules.

Safety invariants:

- gated behind `MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT=1` (disabled by default); this is a
  deployment safety guard, not authorization -- policy gating (`mon.policy`) remains
  authoritative, including critical-asset approval;
- operates only inside its own MON-owned `inet mon_endpoint` table and `mon_block_ip` chain;
  never flushes tables, never touches rules it did not create;
- no `shell=True`, no shell invocation at all -- commands run via `asyncio.create_subprocess_exec`
  with an argv list, exactly like `DisposableNftablesAdapter`;
- the only untrusted input (the target IP) is parsed through `ipaddress.ip_address()` before it
  can reach any command text, so it can never carry shell/nft-script metacharacters;
- every owned rule carries a bounded (<=120 byte), deterministic comment
  `mon:v1:<tenant>:<site>:<execution-id>`; tenant/site/execution values are used raw only when
  they already match a safe charset/length, otherwise a truncated SHA-256 hex digest is used
  instead of embedding arbitrary text in the rule;
- apply is idempotent (an identical existing rule returns success with
  `details["idempotent"]=True`); a *different* rule sharing the same execution-id marker is
  treated as a conflict and fails closed (`EnforcementError`), never silently overwritten;
  more than one rule sharing a marker is also treated as ambiguous and fails closed;
- rollback is idempotent (a missing rule is success); exactly one owned rule is removed by its
  nft rule handle; ambiguous duplicates fail closed rather than guessing which to delete;
- `verify()` returns `PRESENT`/`ABSENT`/`UNKNOWN` from an actual `nft -a list chain` read, never
  from a bare command exit code;
- `reconcile()` re-reads real state and reports drift only -- it does not repair anything;
- command failures return bounded (<=500 char) error text and never fabricate success; a
  timeout kills the process group (`start_new_session=True` + `os.killpg(..., SIGKILL)`), the
  same pattern `DisposableNftablesAdapter` already uses.

The adapter can optionally be constructed with `namespace=...` (validated against the same
`mon-ci-*`/`mon-sandbox-*` pattern as the disposable adapter), which routes every command
through `ip netns exec <namespace> nft ...` instead of the host network namespace. This exists
specifically so certification in this milestone's CI never touches the runner's own host
firewall, even though the adapter's eventual target is endpoint-host use.

## CI validation

The `linux-enforcement-sandbox` job now runs a second disposable-namespace step for this
adapter, separate from the existing `DisposableNftablesAdapter` step: it creates its own
`mon-sandbox-*` namespace, adds an unrelated table/rule as a control, then drives the full
apply/verify/idempotent-apply/reconcile/rollback/verify/idempotent-rollback sequence through
`LinuxNftablesEndpointAdapter`, asserts the unrelated rule is untouched throughout, and cleans
up the namespace in a trap that runs even on failure. This does not modify the GitHub runner's
own host firewall.

## Limitations

- The Linux nftables adapter is **not yet certified on arbitrary production hosts** --
  certification in this milestone is disposable-namespace-only.
- Host firewall interaction with `firewalld`, `ufw`, or vendor-managed nftables/iptables
  tooling is **not yet certified**; this adapter only ever creates its own separate table and
  does not attempt to integrate with, detect, or coexist-verify against those systems.
- Only `ActionType.BLOCK_IP` is supported by this adapter in this milestone.
- No network appliance, NAC, or cloud connector is production-certified by this milestone;
  the capability contract and certification harness exist to make *future* connectors
  certifiable, not to certify anything beyond what is stated here.
- Disposable-namespace success does not prove every Linux distribution, kernel version, or
  nftables version behaves identically; broader distro/kernel matrix validation remains future
  work.
