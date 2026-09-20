# ADR 0062: Linux endpoint collector and systemd runtime boundary

## Status

Accepted.

## Context

ADR 0045 introduced MON's OS-neutral endpoint telemetry contract
(`EndpointTelemetryEvent` -> `normalize_endpoint_event()` -> `SecurityEvent`) and ADR 0051/0056/
0060/0061 built the first Windows collector, its runtime boundary, its SCM service host, and its
deployment lifecycle wrapper. MON needs the equivalent Linux collector: a narrow adapter into the
same telemetry contract, plus a long-running runtime suitable for a systemd-managed unit, without
duplicating normalization, buffering, checkpointing, or transport logic.

## Decision

### Core (unchanged from the initial milestone)

The Linux collector core normalizes two kinds of real, structured Linux evidence into
`EndpointTelemetryEvent`:

- systemd journal records from `sshd` (`SYSLOG_IDENTIFIER=sshd`), parsing the standard
  `Accepted <method> for <user> from <ip> port <port>` and `Failed <method> for [invalid user]
  <user> from <ip> port <port>` message text into `AUTH_SUCCESS`/`AUTH_FAILURE`;
- Linux audit (`auditd`) `SYSCALL`/`EXECVE`/`EOE` record groups, classified as `PROCESS_START`
  only when a `SYSCALL` record is explicitly paired with an `EXECVE` record in the same
  `audit(timestamp:serial)` group. MON never infers process execution from a raw,
  architecture-dependent syscall number.

Deterministic MON event IDs derive from the journal cursor or the audit `timestamp:serial` id
only; there is no random UUID, so replaying the same native record produces the same MON event
ID. Linux identity uses `auid` (falling back to `uid`, treating the `4294967295` unset sentinel as
absent) scoped to the collector's own hostname as `identity_namespace`; a bare UID with no
namespace/host context is never treated as globally unique. sshd authentication evidence carries
a username but not the authenticating principal's UID, so it is intentionally emitted as
username-only (WEAK identity), never a fabricated strong UID claim.

Durable per-source checkpointing (`LinuxCollectorCheckpointStore`) is tenant/site/sensor and
source-kind scoped, atomic (tempfile + fsync + `os.replace`), schema-versioned, and fails visibly
on corruption or scope mismatch rather than silently resetting. Local buffering
(`SQLiteLinuxEventBuffer`) mirrors the Windows collector's WAL/`synchronous=FULL` SQLite buffer:
tenant/site/sensor bound, deduplicated by event ID, and bounded by an explicit `max_events`.

### Runtime and CLI (this milestone)

`mon-linux-endpoint-collector` is a new console script. A one-shot invocation performs a single
`collect_once()` pass; `mon-linux-endpoint-collector foreground` runs
`LinuxCollectorServiceRuntime`, a plain asyncio loop around the same `collect_once()` path used by
the one-shot mode: it performs one pass before reporting `RUNNING`, waits on a cancellation event
rather than busy-looping, and closes registered resources (the SQLite buffer) exactly once on the
way out. There is no SCM-equivalent to integrate with on Linux; systemd supervises the process
directly, so `SIGINT`/`SIGTERM` are wired to the same `request_stop()` cancellation path through
`asyncio`'s signal handlers.

Configuration is explicit CLI flags: `--tenant-id`, `--site-id`, `--sensor-id`, `--state-dir`,
`--site-url` (loopback-only, enforced by the existing `LocalSiteEventSender` check),
`--audit-log-file`, `--ssh-unit`, `--batch-size`, `--max-buffered-events`, and
`--poll-interval-seconds` (bounded 0.01-3600s, same bound as the Windows collector). No credential
or token argument exists.

### Native source adapters

- `SystemdJournalReader` wraps the optional `python3-systemd` bindings. If those bindings (or a
  non-Linux platform) are unavailable, or the journal cannot be opened, construction raises
  `LinuxSourceUnavailable`/`LinuxSourcePermissionDenied` rather than crashing the process: the CLI
  wraps that failure in a small static-failure source so the collector still starts and correctly
  reports the failing state through health instead of fabricating telemetry or refusing to run.
- `FileAuditLogReader` reads real `auditd`-formatted lines from a configured log path. It holds
  back an audit event whose `EOE` record has not yet been written, so a caller never observes a
  partial `execve` group, and checkpoints a durable byte offset that only advances through the
  last complete event. It does not yet implement rotation-safe inode/anchor tracking (see
  Limitations).

Both adapters bound what they read (`_MAX_JOURNAL_ENTRY_BYTES`, `_MAX_AUDIT_LINE_BYTES`,
`_MAX_AUDIT_READ_BYTES`), never invoke a shell, never execute a path found in telemetry, and never
load a module from telemetry content.

### Health

`LinuxCollectorState` explicitly distinguishes `SYNCED`, `BUFFERING`, `DEGRADED`,
`SOURCE_UNAVAILABLE`, `PERMISSION_DENIED`, and `TRANSPORT_UNAVAILABLE`, aggregated per-source as
the worst state across all configured sources. The collector never reports `SYNCED` merely
because the process is running.

### systemd packaging

`tools/systemd/mon-linux-endpoint-collector.service` is a repository-owned example unit (not yet
a DEB/RPM package): a dedicated `ExecStart` command, a bounded/conservative restart policy
(`Restart=on-failure`, `RestartSec=10`, `StartLimitIntervalSec=300`, `StartLimitBurst=5`), an
explicit `StateDirectory=`, and no secrets in unit arguments (tenant/site/sensor identifiers and
the loopback site URL are not credentials). The unit runs as a dedicated non-root user by default;
it documents that journal access only needs `systemd-journal` group membership, while audit log
access commonly needs a narrower grant (a POSIX ACL) or, failing that, root, rather than defaulting
to root for convenience.

## CI validation

A new `linux-endpoint-collector` job on `ubuntu-latest` imports the module, runs the focused
Linux collector and runtime test files, runs Ruff against them, verifies `--help`, and starts the
`foreground` command with a short poll interval, sends it `SIGTERM`, and asserts a clean exit.
This does not require or assume privileged host audit access: on a stock GitHub-hosted runner
both native adapters report `SOURCE_UNAVAILABLE`/`PERMISSION_DENIED` rather than fabricating
telemetry, and the job asserts the process still starts and shuts down cleanly under that
condition. Portable parser/core tests (`tests/test_linux_endpoint_collector.py`) remain separate
from runtime/native-adapter-boundary tests (`tests/test_linux_endpoint_collector_runtime.py`), the
same separation the Windows collector's own test file documents for itself.

## Limitations

This is not a production-complete Linux EDR agent. It does not include DEB/RPM packaging, an
eBPF or other kernel-level collector, signed binary release, or privileged VM certification of
real journal/audit access. `FileAuditLogReader` does not yet implement rotation-safe inode/anchor
tracking (unlike `JsonLineFileReader` in `sensor_collector.py` for Zeek/Suricata); a log rotated
mid-event before the checkpoint is durably committed could require operator attention. There is
no guaranteed process-network association for Linux telemetry; MON only reports one when a native
source fixture explicitly supplies it, and neither adapter in this milestone does yet. Real
`python3-systemd` and `auditd` integration is exercised here only through parsers, adapters, and
CI-level unavailability paths; genuine privileged read access to a live journal/audit source still
requires disposable VM validation outside this milestone.
