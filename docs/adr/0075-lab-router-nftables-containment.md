# ADR 0075: Lab containment uses a narrow nftables router adapter

Status: Accepted for controlled lab use

## Context

MON can plan, dispatch, audit, expire, and roll back site-plane response commands, but the default Site Controller intentionally does not activate a host firewall adapter. The existing Linux endpoint nftables adapter hooks input, so it protects its own host and cannot prove containment of traffic merely transiting a lab router.

For the seven-system test environment, adversary-to-victim traffic is routed through one Linux VM. A real containment demonstration therefore needs an enforcement point on that router, not a simulated response receipt.

## Decision

Add an opt-in LinuxNftablesRouterAdapter registered as EnforcementKind.ROUTER only when MON_ENABLE_ROUTER_NFTABLES_ENFORCEMENT=1.

The adapter supports only BLOCK_IP, validates the target as IPv4/IPv6 before command construction, owns only table inet mon_router and chain mon_block_ip, hooks forward rather than input, and drops forwarded packets whose source address equals the response target.

Every owned rule carries tenant/site/execution ownership metadata. Apply, verify, rollback, and observation-only reconcile are idempotent or fail closed on ambiguity. The adapter never flushes or edits unrelated nftables state and remains disabled by default.

For the lab, the Site Controller is colocated with the router so response execution occurs at the actual forwarding point.

## Safety boundary

This is not certification for an arbitrary production Linux router, enterprise firewall, or upstream DDoS control. The lab VM requires nftables privileges, so MON must run with only the capability needed by that disposable environment, or as root only inside that disposable lab VM.

Production deployments should move privileged enforcement behind a separately hardened local connector/service and certify coexistence with the host firewall manager before use.

## Consequences

The lab can demonstrate a real packet-path change and verify removal during rollback while the normal MON policy, TTL, blast-radius, audit, and response-state lifecycle remains in force.
