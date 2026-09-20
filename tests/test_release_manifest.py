from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from mon.release_manifest import (
    ReleaseManifestError,
    ReleaseManifestVerificationError,
    build_manifest,
    manifest_bytes,
    verify_manifest,
    write_manifest,
)

SOURCE_SHA = "a" * 40


def test_manifest_is_sorted_and_hashes_exact_final_bytes(tmp_path: Path) -> None:
    (tmp_path / "z.bin").write_bytes(b"\x00final\xff")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "a.txt").write_bytes(b"exact bytes\n")

    manifest = build_manifest(tmp_path, SOURCE_SHA)

    assert manifest["schema_version"] == 1
    assert manifest["source_sha"] == SOURCE_SHA
    assert [entry["path"] for entry in manifest["files"]] == ["nested/a.txt", "z.bin"]
    assert manifest["files"][0]["sha256"] == hashlib.sha256(b"exact bytes\n").hexdigest()
    assert manifest["files"][1]["sha256"] == hashlib.sha256(b"\x00final\xff").hexdigest()
    assert all("\\" not in entry["path"] for entry in manifest["files"])
    assert str(tmp_path) not in json.dumps(manifest)


def test_manifest_output_is_deterministic_and_excludes_itself(tmp_path: Path) -> None:
    (tmp_path / "artifact.whl").write_bytes(b"wheel")
    first_path = write_manifest(tmp_path, SOURCE_SHA)
    first = first_path.read_bytes()
    second = write_manifest(tmp_path, SOURCE_SHA).read_bytes()

    assert first == second
    assert first == manifest_bytes(build_manifest(tmp_path, SOURCE_SHA))
    payload = json.loads(first)
    assert [entry["path"] for entry in payload["files"]] == ["artifact.whl"]


def test_empty_release_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ReleaseManifestError, match="empty"):
        build_manifest(tmp_path, SOURCE_SHA)


@pytest.mark.parametrize(
    "source_sha",
    ["", "abc123", "main", "g" * 40, "a" * 39],
)
def test_source_identity_must_be_full_git_sha(tmp_path: Path, source_sha: str) -> None:
    (tmp_path / "artifact.whl").write_bytes(b"wheel")
    with pytest.raises(ReleaseManifestError, match="source_sha"):
        build_manifest(tmp_path, source_sha)


def test_manifest_verification_succeeds_for_unchanged_artifacts(tmp_path: Path) -> None:
    (tmp_path / "artifact.whl").write_bytes(b"wheel")
    (tmp_path / "sbom.json").write_bytes(b'{"bomFormat":"CycloneDX"}\n')
    write_manifest(tmp_path, SOURCE_SHA)

    verify_manifest(tmp_path)


def test_manifest_verification_fails_after_byte_mutation(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.whl"
    artifact.write_bytes(b"wheel")
    write_manifest(tmp_path, SOURCE_SHA)
    artifact.write_bytes(b"wheel-mutated")

    with pytest.raises(ReleaseManifestVerificationError, match="size|sha256"):
        verify_manifest(tmp_path)


def test_manifest_verification_fails_for_missing_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.whl"
    artifact.write_bytes(b"wheel")
    write_manifest(tmp_path, SOURCE_SHA)
    artifact.unlink()

    with pytest.raises(ReleaseManifestVerificationError, match="missing"):
        verify_manifest(tmp_path)


def test_manifest_verification_fails_for_unexpected_artifact(tmp_path: Path) -> None:
    (tmp_path / "artifact.whl").write_bytes(b"wheel")
    write_manifest(tmp_path, SOURCE_SHA)
    (tmp_path / "late-file.txt").write_text("not covered\n", encoding="utf-8")

    with pytest.raises(ReleaseManifestVerificationError, match="artifact set"):
        verify_manifest(tmp_path)


def test_manifest_rejects_path_escape_manifest_location(tmp_path: Path) -> None:
    (tmp_path / "artifact.whl").write_bytes(b"wheel")
    write_manifest(tmp_path, SOURCE_SHA)
    outside = tmp_path.parent / "manifest.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ReleaseManifestVerificationError, match="escapes"):
        verify_manifest(tmp_path, manifest_path=outside)


def test_cli_wrapper_generates_and_verifies_after_installable_import(tmp_path: Path) -> None:
    (tmp_path / "artifact.whl").write_bytes(b"wheel")
    wrapper = Path("tools/release_manifest.py").resolve()
    subprocess.run(
        [sys.executable, str(wrapper), str(tmp_path), "--source-sha", SOURCE_SHA],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        [sys.executable, str(wrapper), str(tmp_path), "--verify"],
        cwd=tmp_path,
        check=True,
    )
    assert (tmp_path / "manifest.json").is_file()
