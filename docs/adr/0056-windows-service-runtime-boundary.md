# ADR 0056: Windows collector service runtime boundary

## Status

Accepted.

## Context

ADR 0051 added a Windows Event Log collector that can read Security and optional Sysmon
records, normalize them into MON endpoint telemetry, checkpoint Windows record IDs, and
buffer locally through SQLite. That milestone intentionally stopped at a CLI/runtime adapter.
MON now needs a service-oriented runtime boundary without claiming MSI packaging, signing,
installer lifecycle, or privileged VM certification.

Microsoft's Service Control Manager model requires a service process to report lifecycle
state to the SCM and accept stop/shutdown controls through the Windows service API. MON keeps
that SCM integration boundary separate from the collector's telemetry health: a process can
be running while collection is permission denied, source unavailable, buffering, degraded, or
transport unavailable.

## Decision

MON adds a small Python service runtime around the existing `collect_once()` collector path.
The runtime:

- performs one collection pass before reporting its own lifecycle as `RUNNING`;
- runs subsequent collection passes on a validated bounded polling interval;
- waits through a cancellation-aware stop event rather than busy looping;
- treats collector health as data, not service-process health;
- lets transient source/transport health states remain visible without crashing the process;
- fails visibly on fatal checkpoint/configuration/state corruption;
- closes registered resources, including the SQLite buffer, during bounded shutdown.

The existing `mon-windows-endpoint-collector` entry point remains available. It now also
accepts `foreground` and `service-run` commands for the service loop. `service-run` is the
internal boundary intended for a future installer-managed Windows service. Secrets,
certificates, tokens, and tenant credentials are not added to service command-line
arguments; the existing explicit tenant/site/sensor/state-directory configuration remains
the only runtime configuration in this milestone.

MON also records a minimal native SCM boundary using `advapi32.dll` through `ctypes`. This is
kept separate from the testable service loop and does not install, uninstall, configure,
upgrade, or register a Windows service. No `pywin32` dependency is added because the current
boundary does not need a helper package.

## CI validation

The Windows endpoint collector CI job runs the focused collector/runtime tests, verifies the
existing CLI help path, verifies the foreground command help path, and imports the native SCM
boundary on `windows-latest`.

GitHub-hosted Windows runners are not used here as proof of installer-managed service
registration. This milestone does not create a disposable Windows service with `sc.exe`
because MON has not yet implemented the installer/registration contract that would make such
a test meaningful and reliable.

## Consequences

- The collector can now run under a long-lived service loop without duplicating
  normalization, buffering, checkpointing, or transport logic.
- Service lifecycle state is explicitly modeled separately from collector telemetry health.
- Fatal checkpoint/configuration/state corruption remains visible and fail-closed.
- Transient collection and transport failures do not silently become "healthy"; they remain
  visible in collector health while the service process continues.

## Limitations

This milestone does not provide MSI packaging, signed executable/package output, production
installer behavior, upgrade or rollback installer handling, tamper protection, recovery
policy registration, or privileged disposable-VM certification.
