# ADR 0059: Windows collector release-chain integration

## Status

Accepted

## Context

ADR 0058 added an unsigned Windows collector executable candidate built on GitHub-hosted
Windows CI. That candidate proved the collector could be frozen and smoke-tested in a
disposable Windows runner, but its bytes were still outside the main MON release-candidate
trust chain.

## Decision

The `release-candidate` workflow now builds `MONWindows.exe` in a dedicated
`windows-latest` job using the existing PyInstaller path, runs only a non-privileged
`MONWindows.exe --help` smoke check, and generates `mon-windows-collector.cdx.json` from the
actual Windows build Python environment with CycloneDX tooling.

The final release job downloads those internal Windows build artifacts and includes:

- `windows/MONWindows.exe`;
- `mon-windows-collector.cdx.json`.

Both files are part of the required release artifact set, the SBOM gate, the exact-byte
manifest, keyless GitHub artifact attestations, attestation verification, upload, and
independent `mon-release-verify` verification. No covered artifact may change after manifest
generation.

The Windows SBOM describes the frozen CI build dependency context. It is evidence for the
environment used to build the executable; it is not claimed to perfectly reconstruct every PE
binary component inside the frozen executable.

## Consequences

- Missing or invalid Windows executable/SBOM evidence fails release-candidate generation.
- Independent verification fails closed if the Windows executable, Windows SBOM, manifest
  entry, exact bytes, artifact set, repository provenance, signer workflow, or source commit
  identity is missing or wrong.
- The Windows executable remains unsigned. This milestone does not provide Authenticode
  signing, MSI packaging, install/uninstall certification, upgrade/rollback certification,
  privileged service-registration certification, or tamper protection.
