from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from mon.release_candidate import (
    ReleaseCandidateError,
    ReleaseCandidateVerificationError,
    required_release_artifacts,
    validate_cyclonedx_sbom,
    validate_release_candidate_directory,
    verify_release_candidate,
    verify_release_candidate_attestations,
    verify_release_candidate_offline,
)
from mon.release_manifest import build_manifest, write_manifest

SOURCE_SHA = "b" * 40


def write_sbom(path: Path, *, name: str = "component") -> None:
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [{"type": "library", "name": name, "version": "1.0.0"}],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def write_candidate(path: Path, source_sha: str = SOURCE_SHA) -> None:
    (path / "python").mkdir()
    (path / "python" / "mon_security_fabric-0.1.0-py3-none-any.whl").write_bytes(
        b"wheel"
    )
    (path / "python" / "mon_security_fabric-0.1.0.tar.gz").write_bytes(b"sdist")
    (path / "console").mkdir()
    (path / "console" / "mon-operator-console.zip").write_bytes(b"console")
    (path / "windows").mkdir()
    (path / "windows" / "MONWindows.exe").write_bytes(b"windows-exe")
    (path / "windows" / "MONWindows-0.1.0.msi").write_bytes(b"windows-msi")
    (path / "linux").mkdir()
    (path / "linux" / "mon-linux-endpoint-collector_0.1.0_amd64.deb").write_bytes(b"linux-deb")
    write_sbom(path / "mon-python.cdx.json", name="mon-security-fabric")
    write_sbom(path / "mon-console.cdx.json", name="mon-operator-console")
    write_sbom(path / "mon-windows-collector.cdx.json", name="mon-windows-collector")
    write_sbom(path / "mon-linux-collector.cdx.json", name="mon-linux-collector")
    write_manifest(path, source_sha)


def test_cyclonedx_sbom_validation_accepts_supported_json(tmp_path: Path) -> None:
    sbom = tmp_path / "mon-python.cdx.json"
    write_sbom(sbom)

    validate_cyclonedx_sbom(sbom)


@pytest.mark.parametrize(
    "payload",
    [
        {"bomFormat": "SPDX", "specVersion": "1.6", "components": [{"name": "x"}]},
        {"bomFormat": "CycloneDX", "specVersion": "0.1", "components": [{"name": "x"}]},
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []},
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{}]},
    ],
)
def test_cyclonedx_sbom_validation_rejects_missing_or_weak_evidence(
    tmp_path: Path, payload: dict[str, object]
) -> None:
    sbom = tmp_path / "bad.cdx.json"
    sbom.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReleaseCandidateError):
        validate_cyclonedx_sbom(sbom)


def test_release_candidate_directory_requires_both_sboms(tmp_path: Path) -> None:
    write_sbom(tmp_path / "mon-python.cdx.json")
    write_sbom(tmp_path / "mon-console.cdx.json")

    with pytest.raises(ReleaseCandidateError, match="mon-windows"):
        validate_release_candidate_directory(tmp_path)


def test_release_candidate_directory_accepts_required_sbom_evidence(tmp_path: Path) -> None:
    write_sbom(tmp_path / "mon-python.cdx.json", name="mon-security-fabric")
    write_sbom(tmp_path / "mon-console.cdx.json", name="mon-operator-console")
    write_sbom(tmp_path / "mon-windows-collector.cdx.json", name="mon-windows-collector")
    write_sbom(tmp_path / "mon-linux-collector.cdx.json", name="mon-linux-collector")

    validate_release_candidate_directory(tmp_path)


def test_cli_wrapper_validates_after_installable_import(tmp_path: Path) -> None:
    write_sbom(tmp_path / "mon-python.cdx.json", name="mon-security-fabric")
    write_sbom(tmp_path / "mon-console.cdx.json", name="mon-operator-console")
    write_sbom(tmp_path / "mon-windows-collector.cdx.json", name="mon-windows-collector")
    write_sbom(tmp_path / "mon-linux-collector.cdx.json", name="mon-linux-collector")
    wrapper = Path("tools/release_candidate_gate.py").resolve()

    subprocess.run(
        [sys.executable, str(wrapper), str(tmp_path)],
        cwd=tmp_path,
        check=True,
    )


def test_manifest_generated_after_sboms_covers_sbom_evidence(tmp_path: Path) -> None:
    (tmp_path / "python").mkdir()
    (tmp_path / "python" / "mon_security_fabric-0.1.0-py3-none-any.whl").write_bytes(
        b"wheel"
    )
    (tmp_path / "python" / "mon_security_fabric-0.1.0.tar.gz").write_bytes(b"sdist")
    (tmp_path / "console").mkdir()
    (tmp_path / "console" / "mon-operator-console.zip").write_bytes(b"console")
    (tmp_path / "windows").mkdir()
    (tmp_path / "windows" / "MONWindows.exe").write_bytes(b"windows-exe")
    (tmp_path / "windows" / "MONWindows-0.1.0.msi").write_bytes(b"windows-msi")
    (tmp_path / "linux").mkdir()
    (tmp_path / "linux" / "mon-linux-endpoint-collector_0.1.0_amd64.deb").write_bytes(b"linux-deb")
    write_sbom(tmp_path / "mon-python.cdx.json", name="mon-security-fabric")
    write_sbom(tmp_path / "mon-console.cdx.json", name="mon-operator-console")
    write_sbom(tmp_path / "mon-windows-collector.cdx.json", name="mon-windows-collector")
    write_sbom(tmp_path / "mon-linux-collector.cdx.json", name="mon-linux-collector")

    validate_release_candidate_directory(tmp_path)
    manifest = build_manifest(tmp_path, SOURCE_SHA)

    assert [entry["path"] for entry in manifest["files"]] == [
        "console/mon-operator-console.zip",
        "linux/mon-linux-endpoint-collector_0.1.0_amd64.deb",
        "mon-console.cdx.json",
        "mon-linux-collector.cdx.json",
        "mon-python.cdx.json",
        "mon-windows-collector.cdx.json",
        "python/mon_security_fabric-0.1.0-py3-none-any.whl",
        "python/mon_security_fabric-0.1.0.tar.gz",
        "windows/MONWindows-0.1.0.msi",
        "windows/MONWindows.exe",
    ]


def test_required_release_artifact_set_is_explicit() -> None:
    assert required_release_artifacts() == (
        "console/mon-operator-console.zip",
        "linux/mon-linux-endpoint-collector_0.1.0_amd64.deb",
        "manifest.json",
        "mon-console.cdx.json",
        "mon-linux-collector.cdx.json",
        "mon-python.cdx.json",
        "mon-windows-collector.cdx.json",
        "python/mon_security_fabric-0.1.0-py3-none-any.whl",
        "python/mon_security_fabric-0.1.0.tar.gz",
        "windows/MONWindows-0.1.0.msi",
        "windows/MONWindows.exe",
    )


def test_release_candidate_workflow_has_required_provenance_permissions() -> None:
    workflow = Path(".github/workflows/release-candidate.yml").read_text(
        encoding="utf-8"
    )

    assert "workflow_dispatch:" in workflow
    assert "attestations: write" in workflow
    assert "contents: read" in workflow
    assert "id-token: write" in workflow
    assert "contents: write" not in workflow
    assert "packages: write" not in workflow
    assert "pull_request:" not in workflow


def test_release_candidate_workflow_attests_exact_final_artifact_set() -> None:
    workflow = Path(".github/workflows/release-candidate.yml").read_text(
        encoding="utf-8"
    )

    assert "pull_request:" not in workflow
    assert "cyclonedx-py environment" in workflow
    assert "@cyclonedx/cyclonedx-npm" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "python -m build --sdist --wheel" in workflow
    assert "runs-on: windows-latest" in workflow
    assert "pyinstaller --clean --noconfirm --onefile --name MONWindows" in workflow
    assert ".\\dist\\MONWindows.exe --help" in workflow
    assert "dist\\mon-windows-collector.cdx.json" in workflow
    assert "actions/download-artifact@v4" in workflow
    assert "python tools/release_candidate_gate.py release-artifacts" in workflow
    assert 'mon-release-manifest release-artifacts --source-sha "$GITHUB_SHA"' in workflow
    assert '--source-digest "$GITHUB_SHA"' in workflow
    assert "--repo Saitanveesh/1" in workflow
    assert (
        "--signer-workflow "
        "github.com/Saitanveesh/1/.github/workflows/release-candidate.yml"
    ) in workflow
    assert "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6" in workflow
    assert "retention-days: 14" in workflow

    for artifact in required_release_artifacts():
        assert f"release-artifacts/{artifact}" in workflow


def test_release_candidate_workflow_attests_after_manifest_verification() -> None:
    workflow = Path(".github/workflows/release-candidate.yml").read_text(
        encoding="utf-8"
    )

    gate = workflow.index("Gate release-candidate evidence")
    manifest = workflow.index("Generate final release manifest")
    verify = workflow.index("Verify final release manifest")
    attest = workflow.index("Attest final release-candidate artifacts")
    verify_attestations = workflow.index("Verify release-candidate attestations")
    upload = workflow.index("Upload release-candidate evidence bundle")
    assert gate < manifest < verify < attest < verify_attestations < upload

    protected_segment = workflow[verify:attest]
    assert "python -m build" not in protected_segment
    assert "npm run build" not in protected_segment
    assert "--output-file" not in protected_segment


def test_release_candidate_workflow_uploads_only_after_attestation_verification() -> None:
    workflow = Path(".github/workflows/release-candidate.yml").read_text(
        encoding="utf-8"
    )

    verify_attestations = workflow.index("Verify release-candidate attestations")
    upload = workflow.index("Upload release-candidate evidence bundle")
    assert verify_attestations < upload
    assert "gh attestation verify" in workflow[verify_attestations:upload]


def test_offline_release_verification_accepts_valid_candidate(tmp_path: Path) -> None:
    write_candidate(tmp_path)

    verify_release_candidate_offline(tmp_path, SOURCE_SHA)


def test_offline_release_verification_fails_for_changed_byte(tmp_path: Path) -> None:
    write_candidate(tmp_path)
    (tmp_path / "windows" / "MONWindows.exe").write_bytes(b"mutated")

    with pytest.raises(ReleaseCandidateVerificationError, match="size|sha256"):
        verify_release_candidate_offline(tmp_path, SOURCE_SHA)


def test_offline_release_verification_fails_for_mutated_windows_sbom(
    tmp_path: Path,
) -> None:
    write_candidate(tmp_path)
    (tmp_path / "mon-windows-collector.cdx.json").write_text("{", encoding="utf-8")
    write_manifest(tmp_path, SOURCE_SHA)

    with pytest.raises(ReleaseCandidateVerificationError):
        verify_release_candidate_offline(tmp_path, SOURCE_SHA)


def test_offline_release_verification_fails_for_missing_file(tmp_path: Path) -> None:
    write_candidate(tmp_path)
    (tmp_path / "windows" / "MONWindows.exe").unlink()

    with pytest.raises(ReleaseCandidateVerificationError, match="missing"):
        verify_release_candidate_offline(tmp_path, SOURCE_SHA)


def test_offline_release_verification_fails_for_missing_windows_sbom(
    tmp_path: Path,
) -> None:
    write_candidate(tmp_path)
    (tmp_path / "mon-windows-collector.cdx.json").unlink()

    with pytest.raises(ReleaseCandidateVerificationError, match="missing"):
        verify_release_candidate_offline(tmp_path, SOURCE_SHA)


def test_offline_release_verification_fails_for_extra_file(tmp_path: Path) -> None:
    write_candidate(tmp_path)
    (tmp_path / "unexpected.txt").write_text("injected\n", encoding="utf-8")

    with pytest.raises(ReleaseCandidateVerificationError, match="artifact set"):
        verify_release_candidate_offline(tmp_path, SOURCE_SHA)


def test_offline_release_verification_fails_for_wrong_source_sha(tmp_path: Path) -> None:
    write_candidate(tmp_path)

    with pytest.raises(ReleaseCandidateVerificationError, match="source_sha"):
        verify_release_candidate_offline(tmp_path, "c" * 40)


def test_offline_release_verification_fails_for_malformed_sbom(tmp_path: Path) -> None:
    write_candidate(tmp_path)
    (tmp_path / "mon-python.cdx.json").write_text("{", encoding="utf-8")
    write_manifest(tmp_path, SOURCE_SHA)

    with pytest.raises(ReleaseCandidateVerificationError):
        verify_release_candidate_offline(tmp_path, SOURCE_SHA)


def test_offline_release_verification_fails_for_missing_sbom(tmp_path: Path) -> None:
    write_candidate(tmp_path)
    (tmp_path / "mon-console.cdx.json").unlink()

    with pytest.raises(ReleaseCandidateVerificationError, match="missing"):
        verify_release_candidate_offline(tmp_path, SOURCE_SHA)


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="symlinks unavailable")
def test_offline_release_verification_fails_for_symlink_escape(tmp_path: Path) -> None:
    write_candidate(tmp_path)
    target = tmp_path.parent / "outside.txt"
    target.write_text("outside\n", encoding="utf-8")
    link = tmp_path / "escape-link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")

    with pytest.raises(ReleaseCandidateVerificationError, match="symlink"):
        verify_release_candidate_offline(tmp_path, SOURCE_SHA)


def test_online_release_verification_invokes_attestation_for_each_required_artifact(
    tmp_path: Path,
) -> None:
    write_candidate(tmp_path)
    calls: list[list[str]] = []

    def runner(args: list[str]) -> CompletedProcess[str]:
        calls.append(args)
        return CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    verify_release_candidate(
        tmp_path,
        SOURCE_SHA,
        online_attestations=True,
        runner=runner,
    )

    assert len(calls) == len(required_release_artifacts())
    for artifact in required_release_artifacts():
        assert any(str(tmp_path / artifact) in call for call in calls)


def test_online_release_verification_fails_for_missing_attestation(
    tmp_path: Path,
) -> None:
    write_candidate(tmp_path)

    def runner(args: list[str]) -> CompletedProcess[str]:
        return CompletedProcess(args=args, returncode=1, stdout="", stderr="not found")

    with pytest.raises(ReleaseCandidateVerificationError, match="attestation"):
        verify_release_candidate_attestations(tmp_path, SOURCE_SHA, runner=runner)


def test_online_release_verification_binds_repository_identity(tmp_path: Path) -> None:
    write_candidate(tmp_path)

    def runner(args: list[str]) -> CompletedProcess[str]:
        if args[args.index("--repo") + 1] != "Saitanveesh/1":
            return CompletedProcess(args=args, returncode=1, stdout="", stderr="wrong repo")
        return CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    verify_release_candidate_attestations(tmp_path, SOURCE_SHA, runner=runner)

    with pytest.raises(ReleaseCandidateVerificationError, match="attestation"):
        verify_release_candidate_attestations(
            tmp_path,
            SOURCE_SHA,
            repository="other/repo",
            runner=runner,
        )


def test_online_release_verification_binds_source_commit(tmp_path: Path) -> None:
    write_candidate(tmp_path)

    def runner(args: list[str]) -> CompletedProcess[str]:
        if args[args.index("--source-digest") + 1] != SOURCE_SHA:
            return CompletedProcess(args=args, returncode=1, stdout="", stderr="wrong sha")
        return CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    verify_release_candidate_attestations(tmp_path, SOURCE_SHA, runner=runner)

    with pytest.raises(ReleaseCandidateVerificationError, match="source_sha"):
        verify_release_candidate_attestations(tmp_path, "short", runner=runner)


def test_verification_workflow_downloads_existing_candidate_without_rebuild() -> None:
    workflow = Path(".github/workflows/verify-release-candidate.yml").read_text(
        encoding="utf-8"
    )

    assert "workflow_dispatch:" in workflow
    assert "run_id:" in workflow
    assert "artifact_name:" in workflow
    assert "expected_source_sha:" in workflow
    assert "actions: read" in workflow
    assert "contents: read" in workflow
    assert "write" not in workflow
    assert "gh run download" in workflow
    assert "mon-release-verify candidate-download" in workflow
    assert "--online-attestations" in workflow
    assert "python -m build" not in workflow
    assert "npm run build" not in workflow
    assert "upload-artifact" not in workflow


def test_release_candidate_certifies_the_shipped_packages_before_attesting() -> None:
    workflow = Path(".github/workflows/release-candidate.yml").read_text(encoding="utf-8")

    assert "needs: [windows-collector, linux-collector]" in workflow
    assert "tests/test_package_lifecycle_windows.py" in workflow
    assert "tests/test_package_lifecycle_linux.py" in workflow
    assert r"tools\package\build_msi.ps1" in workflow
    assert "tools/package/build_deb.sh" in workflow
    assert workflow.index("test_package_lifecycle_linux.py") < workflow.index(
        "actions/attest@"
    )
