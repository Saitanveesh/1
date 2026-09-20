# ADR 0057: Windows collector package trust contract

## Status

Accepted.

## Context

MON now has a bounded Windows collector service runtime, but the repository does not yet have a production-complete Windows package. A runnable service boundary is not sufficient evidence that an installer is safe to distribute. Packaging must preserve the release-candidate trust chain and must not turn a CI artifact into an implicit production-readiness claim.

## Decision

Windows collector packaging will use the following trust boundary:

1. Windows collector packages are built only in controlled CI from an immutable source commit. The operator laptop is not a build or validation target.
2. The package contains only the collector runtime and explicitly declared runtime dependencies. Tenant/site enrollment credentials, private keys, telemetry, checkpoints, local buffers, and environment-specific configuration are never embedded.
3. Package identity is versioned and source-bound. The produced bytes are included in the release candidate's exact-byte SHA-256 manifest and SBOM/provenance evidence.
4. Installer/service registration is explicit and reviewable. Installation must not silently weaken host firewall, audit policy, Defender, UAC, certificate validation, or other security controls.
5. Upgrade behavior must preserve durable collector state only through documented data locations and schema-compatible migrations. Failed upgrades must have a defined rollback path before the package can be called production-ready.
6. Uninstall must remove program/service material while treating retained forensic state and credentials according to an explicit operator-selected policy; destructive cleanup is never an undocumented default.
7. Code signing is a mandatory production-distribution gate. An unsigned CI package may be used only as a release candidate in disposable Windows validation and must be labeled as such.
8. Privileged install/start/stop/upgrade/uninstall testing occurs in disposable Windows CI/VM infrastructure. No unvalidated installer or executable is tested on the user's laptop.
9. Package verification fails closed if manifest, SBOM, provenance, expected source commit, or—once production signing is enabled—signature verification is missing or invalid.

## Consequences

The next implementation slice can add a deterministic Windows release-candidate package and disposable Windows validation without overstating it as a signed production installer. Production distribution remains blocked until signing, upgrade/rollback, uninstall-state policy, and privileged disposable-VM certification are implemented and green.

This keeps Windows packaging inside the same evidence chain already used by MON release candidates and prevents workstation-specific build state from becoming part of release identity.
