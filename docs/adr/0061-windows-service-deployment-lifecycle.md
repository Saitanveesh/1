# ADR 0061: Windows service deployment lifecycle

## Status

Accepted

## Context

ADR 0060 proved that `MONWindows.exe` can run as a real Windows Service Control Manager
process, but the repository still lacked a deterministic install/start/status/stop/uninstall
lifecycle for the already-built executable.

## Decision

MON now keeps a repository-owned PowerShell lifecycle wrapper at
`tools/windows/mon-windows-service.ps1`. The wrapper registers only an existing
`MONWindows.exe` binary, passes tenant/site/sensor identity and collector state directory to
the existing `service-run` entry point, starts and stops the SCM service, reports status, and
uninstalls the service.

The install path validates that the target executable is named `MONWindows.exe`, requires a
state directory, uses demand start, and rolls back partial service registration if a later
install step fails. The command line deliberately carries only routing identity and runtime
location values; credentials, secrets, private keys, certificates, and telemetry are outside
this lifecycle boundary.

## CI validation

The Windows CI job builds `MONWindows.exe` with PyInstaller and then uses the repository
lifecycle wrapper to install, start, query, stop, and uninstall a uniquely named temporary
service on `windows-latest`. Cleanup calls uninstall even after failures so the disposable
runner does not retain the temporary service registration.

## Limitations

This remains a script-based service lifecycle, not production Windows packaging. MON still
does not provide Authenticode signing, MSI packaging, install/uninstall certification,
upgrade/rollback certification, privileged service-registration certification outside
disposable CI, or tamper protection.
