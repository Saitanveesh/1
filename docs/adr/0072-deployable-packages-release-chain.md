# ADR 0072: Deployable packages and the trusted release chain

## Status

Accepted.

## Context

The collectors shipped only as raw executables. Operators need installable,
upgradable, removable packages, and the packages must sit inside the existing
deterministic manifest / SBOM / provenance / independent-verification chain
rather than beside it.

## Decision

### Windows: MSI (WiX v5)

`packaging/windows/MONWindows.wxs`, built by `tools/package/build_msi.ps1` with
the `wix` dotnet tool (`5.0.2`, MS-RL, no proprietary infrastructure). The
package installs `MONWindows.exe` to `%ProgramFiles%\MON Windows Collector`,
registers the `MONWindows` service (demand start, `service-run`, non-secret
identifier properties `TENANT_ID`, `SITE_ID`, `SENSOR_ID`, `SITE_URL`), stops it
around upgrade/uninstall, and creates `%ProgramData%\MON\WindowsCollectorState`
in a **permanent** component, so upgrade and uninstall never delete durable
state. No tenant secret or token is embedded or accepted.
`MajorUpgrade` blocks in-place downgrade by design; rollback is uninstall of
the newer package then install of the older one on the preserved state.

### Linux: .deb

`tools/package/build_deb.sh` (plain `dpkg-deb`, no debhelper) packages the
PyInstaller collector binary, a unit derived by `sed` from the repository-owned
`tools/systemd/mon-linux-endpoint-collector.service` (env-file driven identifiers
instead of placeholders), and `/etc/mon-linux-endpoint-collector/collector.env`
as a dpkg conffile. `postinst` creates the `mon-collector` system user and
re-owns (never deletes) existing state; `prerm` stops the service; state under
`/var/lib/mon-linux-endpoint-collector` is preserved on remove **and** purge.

### Lifecycle certification

`.github/workflows/package-lifecycle.yml` on disposable runners, with
`tests/test_package_lifecycle_windows.py` and `tests/test_package_lifecycle_linux.py`
writing `windows-package-lifecycle-report.json` and
`linux-package-lifecycle-report.json`: artifact inspection (no embedded secrets,
unsigned state explicit), clean install, start/status/stop, upgrade A to B with
a byte-distinct build, preserved state (hash-identical), operator conffile edit
surviving upgrade, rollback B to A, remove/uninstall, purge, and residue checks.
The same tests run inside the release-candidate workflow against the **exact
package bytes that are then attested**.

### Trusted release chain

`REQUIRED_RELEASE_ARTIFACTS` and `REQUIRED_SBOMS` now enumerate, exactly:
`windows/MONWindows-0.1.0.msi`,
`linux/mon-linux-endpoint-collector_0.1.0_amd64.deb` and
`mon-linux-collector.cdx.json` in addition to the previous set. The manifest,
offline exact-set verification, attestation of every subject and the independent
`verify-release-candidate` workflow all use that set; nothing was loosened.
PyInstaller output is not bit-reproducible, so lifecycle evidence is tied to
package bytes by running the lifecycle inside the release job, not by rebuild.

## Defects found and fixed

- **Systemd unit:** `ProtectSystem=strict` makes `/tmp` read-only; the one-file
  collector died at start-up with "Could not create temporary directory". Added
  `PrivateTmp=true` to the repository-owned unit.

## Signing

`tools/package/sign_msi.ps1` is a hook that refuses to run without operator-
supplied certificate thumbprint and timestamp URL, never creates a certificate,
and only reports success when `Get-AuthenticodeSignature` says `Valid`. In CI the
Authenticode state of the MSIs is asserted `NotSigned`. There is no `.deb`
signing key; the `.deb` is unsigned. Production signing is NOT_PROVEN.

## NOT_PROVEN

Production Authenticode/MSI signing; `.deb`/apt repository signing and
publication; enterprise deployment tooling (GPO, SCCM, Intune, configuration
management); distributions other than the Ubuntu runner image; Windows versions
beyond the runner image; RPM and other package formats; in-place upgrade under
production load; bit-reproducible builds.
