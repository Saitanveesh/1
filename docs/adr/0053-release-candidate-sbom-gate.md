# ADR 0053: Release-candidate SBOM gate

## Status

Accepted

## Context

ADR 0050 requires release artifacts to be built only by CI and accompanied by an SBOM.
ADR 0052 adds deterministic SHA-256 manifests over final artifact bytes. MON still needs a
release-candidate gate that turns SBOM generation and validation into a hard failure before
artifacts can be uploaded.

## Decision

MON adds a controlled `release-candidate` GitHub Actions workflow triggered by
`workflow_dispatch`. The workflow uses read-only repository permissions, builds the Python
wheel and source distribution from the current commit, builds the operator console production
bundle, generates CycloneDX JSON SBOMs, validates the SBOMs, checks that required SBOM
evidence exists, then generates and verifies the release manifest last.

The Python SBOM is generated from the installed CI Python environment using
`cyclonedx-py environment`, which the CycloneDX Python project documents as the command for
environment SBOM generation. The console SBOM is generated from the npm project using
`@cyclonedx/cyclonedx-npm`, whose CLI supports JSON output, reproducible output, output files,
and validation.

The release-candidate artifact directory contains both application artifacts and evidence:

- `python/` with the Python wheel and source distribution.
- `console/mon-operator-console.zip` with the built console bundle.
- `mon-python.cdx.json` with the Python CycloneDX SBOM.
- `mon-console.cdx.json` with the console CycloneDX SBOM.
- `manifest.json`, generated only after all artifacts and SBOMs are present.

`mon.release_candidate` performs repository-owned evidence checks before manifest generation:
required SBOM files must exist, must be CycloneDX JSON, must use a supported schema version,
and must contain at least one named component. This does not replace the CycloneDX tools'
schema validation; it prevents the release workflow from silently uploading a bundle that is
missing required evidence.

## Consequences

- SBOM generation or validation failure blocks the release-candidate artifact upload.
- The deterministic manifest covers both application artifacts and SBOM evidence.
- The uploaded workflow artifact has bounded retention; this is retention for derived release
  evidence only and does not delete forensic telemetry or investigation evidence.
- The gate does not sign artifacts or attest provenance. Signing and attestations remain
  follow-on release hardening work under ADR 0050.

