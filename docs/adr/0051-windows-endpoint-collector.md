# ADR 0051: First Windows endpoint telemetry collector

## Status

Accepted.

## Context

ADR 0045 introduced MON's endpoint telemetry contract and identity/process graph semantics
but intentionally did not ship a Windows or Linux endpoint collector. This milestone adds a
narrow Windows collector adapter that feeds the existing endpoint normalization and
`SecurityEvent` pipeline.

## Decision

Implement the first collector in Python, matching the current repository runtime and avoiding
a new compiler/toolchain while the collector API is still narrow. The Windows-native source
uses the official Windows Event Log API through `wevtapi.dll` (`EvtQuery`, `EvtNext`, and
`EvtRender`) and parses the returned XML. Portable tests use synthetic Windows Event XML
fixtures; GitHub Actions adds a Windows runner smoke test.

The collector supports:

- Windows Security event 4624 for logon success;
- Windows Security event 4625 for logon failure;
- Windows Security event 4688 for process creation when audit policy supplies it;
- optional Sysmon event 1 for process creation when Sysmon is present;
- optional Sysmon event 3 for process-network association when Sysmon supplies it.

MON does not assume Sysmon is installed and does not infer process-network relationships from
Security log records that do not contain them.

## Mapping

The collector preserves source-provided values when present: SID, account, domain, logon ID,
computer name, process IDs, image path, command line, Sysmon process GUID, hashes, network
addresses, event ID, channel, provider, record ID, and timestamp.

The output is `EndpointTelemetryEvent`, then the existing `normalize_endpoint_event()` path
creates the forensic `SecurityEvent`. There is no second event pipeline.

## Checkpoint and replay

The collector stores an atomic JSON checkpoint containing the channel and last observed
Windows record ID. Event IDs are deterministic from tenant, site, sensor, channel, provider,
Windows event ID, record ID, and timestamp, so replayed records produce the same MON event ID.
A corrupt or incompatible checkpoint fails visibly; the collector does not silently skip
records or report healthy recovery.

## Transport and buffering

The collector has a bounded SQLite local buffer. It sends normalized events to the local
Site Controller ingest API, which then uses the existing durable analysis, spool, and
event-fabric path. The collector only permits loopback HTTP for this local boundary; remote
site/SaaS transport remains the Site Controller's mTLS-authenticated fabric.

## Security

Event Log strings are untrusted. The collector bounds XML size and field length, rejects
credential-bearing endpoint attributes through the endpoint model, does not invoke shells,
does not execute event-provided paths, and does not dynamically load modules from event data.

The collector does not collect passwords, password hashes, Kerberos tickets, access tokens,
credential material, or private keys.

## Audit-policy dependency

If Windows audit policy does not emit Security 4624/4625/4688 records, MON does not fabricate
them. Health distinguishes source unavailable, permission denied, transport unavailable,
buffering, and synced states.

## Limitations

This is not a production-complete EDR agent. It does not include MSI packaging, signed
binary release, Windows service installation/recovery configuration, kernel callbacks, ETW
subscriptions, tamper protection, or privileged VM validation. Future Linux collectors remain
separate adapters into the same OS-neutral endpoint telemetry contract.
