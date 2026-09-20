from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mon.release_candidate import (
    ReleaseCandidateError,
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
    ]


def test_release_candidate_workflow_is_controlled_and_manifest_is_last() -> None:
    workflow = Path(".github/workflows/release-candidate.yml").read_text(
        encoding="utf-8"
    )

    assert "workflow_dispatch:" in workflow
    assert "contents: read" in workflow
    assert "pull_request:" not in workflow
    assert "id-token: write" not in workflow
    assert "cyclonedx-py environment" in workflow
    assert "@cyclonedx/cyclonedx-npm" in workflow
    assert "python -m build --sdist --wheel" in workflow
    assert "python tools/release_candidate_gate.py release-artifacts" in workflow
    assert "retention-days: 14" in workflow

    gate = workflow.index("Gate release-candidate evidence")
    manifest = workflow.index("Generate final release manifest")
    verify = workflow.index("Verify final release manifest")
    upload = workflow.index("Upload release-candidate evidence bundle")
    assert gate < manifest < verify < upload
