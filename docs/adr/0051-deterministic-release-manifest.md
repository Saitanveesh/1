# ADR 0051: Deterministic release manifest

## Status
Accepted

## Context
ADR 0050 requires release artifacts to be constructed in CI with immutable source identity and SHA-256 evidence over the final published bytes. A release needs a small machine-readable contract that downstream verification can consume without trusting filenames or build logs.

## Decision
MON release packaging will generate `manifest.json` only after all release payload files have reached their final bytes. The manifest contains a schema version, the immutable source commit SHA, and a lexicographically sorted list of relative artifact paths, byte sizes, and SHA-256 digests.

The generator reads artifacts as bytes, never rewrites them, excludes the manifest itself, rejects an empty artifact set, and emits compact JSON with stable key ordering and a single trailing newline. Paths are relative to the designated artifact directory so build-host paths are never published.

The manifest is evidence, not a signature. Signing/provenance and SBOM generation remain separate mandatory release gates under ADR 0050. Release CI must generate the manifest before upload and must not build or validate release binaries on an operator laptop.

## Consequences
- Identical final artifact bytes and source identity produce identical manifest bytes.
- Any post-manifest artifact mutation invalidates the recorded digest and requires manifest regeneration.
- Consumers can verify exact release bytes independently of GitHub Actions logs.
- This does not by itself establish artifact authenticity; provenance/signing must bind the manifest and release artifacts to the trusted CI identity.
