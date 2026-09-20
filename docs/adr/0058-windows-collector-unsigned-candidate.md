# ADR 0058: Unsigned Windows collector CI candidate

## Status
Accepted

## Context
ADR 0057 requires Windows collector packaging to be constructed and exercised away from operator endpoints. Production signing, installer lifecycle behavior, privileged service certification, upgrade/rollback, and uninstall-state handling are separate gates and are not yet complete.

## Decision
MON will build the first standalone Windows collector executable only on GitHub-hosted Windows CI. The candidate is explicitly unsigned and short-lived.

The candidate workflow:

- builds from the checked-out commit using Python 3.12 and PyInstaller;
- executes only a non-privileged `--help` smoke check on the disposable CI runner;
- records the SHA-256 digest of the exact executable bytes;
- uploads the executable and digest as a seven-day CI artifact;
- does not embed tenant/site credentials, private keys, telemetry, buffers, checkpoints, or environment-specific configuration;
- does not install a Windows service, modify firewall state, or exercise privileged enforcement;
- must never be represented as a production-ready or signed MON release.

No unvalidated executable from this workflow is to be tested on an operator or developer laptop. Production distribution remains blocked until code signing, installer lifecycle semantics, privileged disposable-VM certification, and release-candidate provenance/SBOM integration are implemented and green.

## Consequences
This creates a bounded packaging proof without weakening the release trust contract. A successful workflow proves that the current collector can be frozen into a standalone executable and started in a disposable Windows environment; it does not prove production installability or trust.
