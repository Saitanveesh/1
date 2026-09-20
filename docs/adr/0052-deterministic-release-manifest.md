# ADR 0052: Deterministic release manifest

## Status

Accepted

## Context

ADR 0050 requires release artifacts to be constructed in CI with immutable source identity
and SHA-256 evidence over the final published bytes. A release needs a small
machine-readable contract that downstream verification can consume without trusting
filenames or build logs.

ADR 0051 is already assigned to the Windows endpoint collector. This ADR therefore records
the release manifest design as ADR 0052. The repository currently also contains two merged
ADR 0049 files from parallel work; this milestone does not renumber historical accepted ADRs.

## Decision

MON release packaging generates `manifest.json` only after all release payload files have
reached their final bytes. The manifest contains a schema version, an immutable source commit
SHA, and a lexicographically sorted list of relative POSIX artifact paths, byte sizes, and
SHA-256 digests.

The generator reads artifacts as exact bytes, never rewrites them, excludes the manifest
itself, rejects an empty artifact set, rejects artifact paths outside the designated release
root, and emits compact JSON with stable key ordering plus a single trailing newline. Paths
are relative to the designated artifact directory so build-host paths are never published.

`source_sha` must be a full Git commit hash: either a 40-character SHA-1 or a 64-character
SHA-256 hex string. Ambiguous branch names, tags, abbreviated SHAs, and arbitrary labels are
rejected.

The packaged implementation lives in `mon.release_manifest`. The `tools/release_manifest.py`
file is only a thin CLI wrapper so tests and installed-package execution do not depend on the
repository root being importable.

The manifest module also provides verification. Verification fails if any listed artifact is
missing, its size changes, its SHA-256 changes, paths are unsorted or non-canonical, the
manifest source identity is invalid, or the artifact directory contains files not covered by
the manifest.

The manifest is evidence, not a signature. Signing/provenance and SBOM generation remain
separate mandatory release gates under ADR 0050. Release CI must generate the manifest before
upload and must not build or validate release binaries on an operator laptop.

## Consequences

- Identical final artifact bytes and source identity produce identical manifest bytes.
- Any post-manifest artifact mutation invalidates the recorded digest and requires manifest
  regeneration.
- Consumers can verify exact release bytes independently of GitHub Actions logs.
- This does not by itself establish artifact authenticity; provenance/signing must bind the
  manifest and release artifacts to the trusted CI identity.
