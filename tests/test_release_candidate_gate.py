from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mon.release_candidate import (
    ReleaseCandidateError,
    required_release_artifacts,
    validate_cyclonedx_sbom,
    validate_release_candidate_directory,
)
from mon.release_manifest import build_manifest

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

    with pytest.raises(ReleaseCandidateError, match="mon-console"):
        validate_release_candidate_directory(tmp_path)


def test_release_candidate_directory_accepts_required_sbom_evidence(tmp_path: Path) -> None:
    write_sbom(tmp_path / "mon-python.cdx.json", name="mon-security-fabric")
    write_sbom(tmp_path / "mon-console.cdx.json", name="mon-operator-console")

    validate_release_candidate_directory(tmp_path)


def test_cli_wrapper_validates_after_installable_import(tmp_path: Path) -> None:
    write_sbom(tmp_path / "mon-python.cdx.json", name="mon-security-fabric")
    write_sbom(tmp_path / "mon-console.cdx.json", name="mon-operator-console")
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
    write_sbom(tmp_path / "mon-python.cdx.json", name="mon-security-fabric")
    write_sbom(tmp_path / "mon-console.cdx.json", name="mon-operator-console")

    validate_release_candidate_directory(tmp_path)
    manifest = build_manifest(tmp_path, SOURCE_SHA)

    assert [entry["path"] for entry in manifest["files"]] == [
        "console/mon-operator-console.zip",
        "mon-console.cdx.json",
        "mon-python.cdx.json",
        "python/mon_security_fabric-0.1.0-py3-none-any.whl",
        "python/mon_security_fabric-0.1.0.tar.gz",
    ]


def test_required_release_artifact_set_is_explicit() -> None:
    assert required_release_artifacts() == (
        "console/mon-operator-console.zip",
        "manifest.json",
        "mon-console.cdx.json",
        "mon-python.cdx.json",
        "python/mon_security_fabric-0.1.0-py3-none-any.whl",
        "python/mon_security_fabric-0.1.0.tar.gz",
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
