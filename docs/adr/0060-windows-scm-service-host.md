# ADR 0060: Windows SCM service host

## Status

Accepted

## Context

ADR 0056 added a long-running Windows collector runtime and a native SCM boundary, but it did
not prove that `MONWindows.exe` could run as a real Windows Service Control Manager process.
MON needs a minimal service host before adding an installer layer.

## Decision

`service-run` is now the internal SCM-host entry point for `MONWindows.exe`. On Windows it
uses `pywin32` to connect to the Service Control Manager dispatcher, register stop/shutdown
controls, and report SCM lifecycle states separately from collector health.

The service reports `SERVICE_START_PENDING` during initialization, does not report
`SERVICE_RUNNING` until the existing collector runtime has completed its first collection
pass, reports stop pending on stop/shutdown controls, and routes stop to the existing
cancellation-aware runtime. Fatal checkpoint/configuration initialization failures remain
SCM-visible by stopping the service rather than claiming a healthy running state.

Collector health remains distinct from SCM lifecycle. The service may be SCM `RUNNING` while
collector health is `BUFFERING`, `TRANSPORT_UNAVAILABLE`, `SOURCE_UNAVAILABLE`,
`PERMISSION_DENIED`, or `DEGRADED`.

## CI validation

The Windows CI job builds `MONWindows.exe` with PyInstaller, registers a unique temporary
service on `windows-latest`, starts it, waits for SCM `RUNNING`, stops it, waits for
`STOPPED`, and deletes the service in cleanup. The CI configuration uses test-safe
tenant/site/sensor identifiers, a temporary state directory, and loopback transport only.

## Limitations

This is a service-host validation, not an installer. MON still does not provide MSI
packaging, Authenticode signing, production installer behavior, upgrade/rollback installer
certification, or tamper protection.
