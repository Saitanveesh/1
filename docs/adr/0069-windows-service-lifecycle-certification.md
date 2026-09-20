# ADR 0069: Windows service lifecycle certification

## Status

Accepted.

## Context

ADRs 0056-0061 built the Windows collector, SCM service host, lifecycle
wrapper (`tools/windows/mon-windows-service.ps1`) and unsigned candidate. CI
only ran a brief install/start/stop smoke test. The full lifecycle of the
packaged `MONWindows.exe` was unproven.

## Decision

Add `tests/test_windows_service_certification.py` and the dedicated workflow
`.github/workflows/windows-service-certification.yml`. It runs only on a
disposable `windows-latest` runner, builds two byte-distinct candidates from
the same source (B adds a marker data file), uses a unique `mon-cert-<run>-<attempt>`
service name, has strict timeouts, and always cleans up. It writes
`windows-service-certification-report.json` containing measured facts only.

Exercised through the repository lifecycle script: build/digest verification,
install with SCM configuration inspection (quoted executable and state
directory, expected arguments, demand start, no credentials, exact candidate
path), start to RUNNING with process identity check, stop, restart, hard kill
of the exact service PID with observation of the SCM outcome and orphan check,
uninstall with SCM deletion and repeated `status` reporting absent, state
preservation across stop and uninstall, reinstall on the same state directory,
partial-install rollback, and stop/replace/start/restore binary upgrade and
rollback on preserved state. State is seeded through existing MON classes
(`SQLiteWindowsEventBuffer`, `WindowsEventCheckpointStore`) with a clearly
synthetic event; no telemetry is fabricated as health.

## Test-only hook

The install script gains one fault-injection point after SCM registration. It
throws only when `MON_TEST_FAIL_AFTER_SCM_CREATE=1` **and** the service name
starts with `mon-cert-`, so it cannot fire for a production service name.

## Crash behavior

No recovery policy is configured by the installer and none was added. The
certification records the actual SCM outcome after killing the service PID and
asserts it matches the configured policy (stopped when none). The service
does not restart automatically.

## Signing

The candidate's Authenticode state is read with `Get-AuthenticodeSignature`
and asserted to be `NotSigned`. Production signing is NOT_PROVEN; release
gates are unchanged.

## NOT_PROVEN

Production Authenticode signing; MSI packaging; enterprise deployment
tooling; a production upgrade orchestrator; tamper protection; Windows
versions beyond the runner image; the user's physical laptop; Security Event
Log read on the runner unless the report's `event_source_read` says PROVEN
(it is recorded from a real one-shot pass and does not gate the run).
Binary replacement is a lifecycle certification, not an updater.

## Defect found and fixed

Certifying with install and state paths containing spaces showed that
`mon-windows-service.ps1` could not register such a service: Windows
PowerShell 5.1 does not escape embedded quotes when invoking native
executables, so `sc.exe create binPath=` received a mangled command line
(earlier runs only worked because the quotes were silently dropped from
space-free paths, leaving the registered path unquoted). `Invoke-Sc` now builds
the `sc.exe` command line explicitly using `CommandLineToArgvW` quoting rules.
The lifecycle certification keeps space-containing paths as the regression
assertion, plus a static regression test.
