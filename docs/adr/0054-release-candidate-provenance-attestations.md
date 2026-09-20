# ADR 0054: Release-candidate provenance attestations

## Status

Accepted

## Context

ADR 0050 requires auditable release provenance, ADR 0052 defines exact-byte release
manifests, and ADR 0053 adds the SBOM hard gate. The remaining release-candidate trust gap is
authenticity: a candidate bundle must be independently tied to the GitHub Actions workflow
and immutable source commit that produced its final bytes.

## Decision

MON uses GitHub Artifact Attestations for release-candidate provenance. The
`release-candidate` workflow grants only `contents: read`, `id-token: write`, and
`attestations: write`. It does not use persistent private signing keys, release write
permissions, package write permissions, or arbitrary executable downloads.

After final payload construction, SBOM generation, release evidence gating, manifest
generation, and manifest verification, the workflow invokes GitHub's
`actions/attest` action pinned to an immutable commit. The action uses the workflow's GitHub
OIDC identity and Sigstore-backed signing path to create SLSA provenance attestations for the
final release-candidate subjects:

- Python wheel.
- Python source distribution.
- Operator-console archive.
- Python CycloneDX SBOM.
- Console CycloneDX SBOM.
- `manifest.json`.

The manifest remains the exact-byte inventory. Attestations bind those covered bytes to the
GitHub Actions identity and source commit; no covered file may be mutated between manifest
verification and attestation. The workflow verifies each attestation with `gh attestation
verify` before uploading the candidate bundle, enforcing repository identity, signer workflow,
and source commit digest.

## Consequences

- A candidate upload fails closed if any required subject lacks valid provenance.
- The uploaded bundle contains the same final bytes that were manifest-verified and
  attested.
- Verification requires GitHub's attestation service unless an offline bundle is explicitly
  supplied by a future verifier.
- Provenance proves origin and integrity of the attested build subjects. It does not prove
  vulnerability-free software, runtime safety, correct configuration, or production readiness.
