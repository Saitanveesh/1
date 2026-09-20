# ADR 0055: Release-candidate verification gate

## Status

Accepted

## Context

ADR 0052 gives MON release candidates an exact-byte manifest, ADR 0053 requires SBOM
evidence, and ADR 0054 adds GitHub provenance attestations. Operators also need a
repository-owned verifier for an already-built candidate. That verifier must not rebuild,
repack, publish, or mutate candidate bytes.

## Decision

MON adds `mon-release-verify`, backed by packaged release tooling. The verifier has two
explicit phases:

- Offline verification checks `manifest.json`, the expected source SHA, exact artifact set,
  SHA-256 hashes, sizes, required Python and console SBOMs, CycloneDX structure, path
  traversal, symlink escape, missing files, and unexpected file injection.
- Online verification additionally invokes `gh attestation verify` for every required final
  artifact subject, binding provenance to repository `Saitanveesh/1`, the release-candidate
  signer workflow, and the expected source commit digest.

The verifier fails closed. It does not silently ignore missing attestations, unexpected files,
wrong provenance repository identity, wrong workflow identity, wrong source commit identity,
or post-build byte mutation.

MON also adds a manual `verify-release-candidate` workflow. It accepts a workflow run ID,
artifact name, and expected source commit, downloads the existing candidate artifact from
GitHub Actions, then runs `mon-release-verify` with online attestation verification. The
workflow uses read-only permissions and never rebuilds artifacts or publishes a release.

## Consequences

- Release-candidate verification is repeatable from repository-owned code.
- Offline verification is deterministic and does not require GitHub network/API access.
- Attestation verification is explicitly online because it uses GitHub's attestation service
  through GitHub CLI.
- Successful provenance verification proves origin and integrity for the checked bytes; it
  does not prove vulnerability-free software, runtime safety, or production readiness.

