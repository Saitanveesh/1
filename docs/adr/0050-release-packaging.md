# ADR 0050: Release packaging trust contract

## Status
Accepted

## Context
MON now has CI-backed operator, telemetry, detection, investigation, enforcement, site-controller, scale, load, recovery, and adversarial-isolation gates. Release packaging must not turn those validated components into an opaque or laptop-tested binary. Operators need to identify exactly what source and dependency set produced an artifact before deployment.

## Decision

1. Release artifacts are produced only by CI from an immutable Git commit or annotated release tag. Developer workstations and the user's laptop are not release builders or validation targets.
2. Every distributable artifact must be accompanied by a machine-readable manifest containing the release version, source commit SHA, artifact filename, byte size, and SHA-256 digest.
3. The release pipeline must emit an SBOM for packaged application dependencies. SBOM generation failure is a release failure, not a warning.
4. Checksums and manifests are generated from the final bytes that will be published. Repacking after digest generation is prohibited.
5. Site-controller packages and control-plane/container artifacts remain distinct release units. A successful build of one must not imply validation of another.
6. No package may embed tenant credentials, site certificates, bearer tokens, captured telemetry, synthetic telemetry presented as real, or local developer configuration.
7. Installation and upgrade remain explicit operational actions. Packaging does not authorize automatic execution on an endpoint, and unvalidated binaries must never be tested on the user's laptop.
8. A release is publishable only after the repository's required CI gates are green for the source commit. Packaging jobs may add gates; they may not bypass or weaken existing tests.
9. Rollback metadata must identify the immediately previous compatible release and any schema/compatibility constraint that prevents rollback. A package must not claim rollback safety where database or protocol changes make it unsafe.
10. Release provenance must be auditable. Signing/attestation is the preferred publication boundary; until repository-managed signing is implemented, unsigned artifacts must be explicitly identified as unsigned and must not be represented as production-trusted releases.

## Consequences

The first packaging implementation will focus on deterministic manifests, checksums, SBOMs, and CI-only artifact construction. Platform-specific installers and signing are follow-on work after their build environments and trust roots are defined. This avoids shipping a convenient executable before MON has evidence that the exact published bytes correspond to reviewed source.
