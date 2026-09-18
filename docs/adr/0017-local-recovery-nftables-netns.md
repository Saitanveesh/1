# ADR 0017: Local TTL recovery and disposable nftables adapter

Status: Accepted

## Decision

Finite-TTL containment must be recoverable at the site even when cloud connectivity is
unavailable. MON therefore provides a local Recovery Engine and a Site Controller Runtime
with independent cloud-flush and recovery loops. Recovery does not wait for successful
SaaS synchronization.

The recovery engine queries durable response state for expired APPLIED actions and invokes
the same enforcement adapter rollback path with the original execution id. A process-local
lock prevents overlapping maintenance ticks. Enforcement adapters still must be externally
idempotent because process restarts and retry races are normal.

## First OS-native adapter

The first OS-native enforcement adapter targets Linux nftables, but only inside a
disposable named network namespace. It is a certification harness, not a production host
firewall connector.

The adapter refuses to start unless all of the following are true:

- the operating system is Linux;
- MON_ENABLE_DISPOSABLE_NETNS_ENFORCEMENT=1 is explicitly set;
- the namespace name begins with mon-ci- or mon-sandbox-;
- ip and nft executables are available.

Every nft command is executed through ip netns exec. There is no code path that invokes
nft directly in the host network namespace. Commands use exec-style argument arrays rather
than a shell, have a finite timeout, and terminate the spawned process group on timeout.

The adapter currently supports source-address BLOCK_IP only. It validates the target as an
IP address, uses the response execution id as an idempotency marker, and removes the exact
rule handle during rollback.

## Release gate

GitHub Actions creates a disposable network namespace, runs a real apply/idempotency/
rollback test under that namespace, and deletes the namespace afterward. The adapter must
not be enabled on an operator workstation or a production host until a separate production
connector ADR, privilege model, resource limits and deployment validation are approved.
