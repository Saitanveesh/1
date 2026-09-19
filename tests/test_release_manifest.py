from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.release_manifest import build_manifest, write_manifest


def test_manifest_is_sorted_and_hashes_final_bytes(tmp_path: Path) -> None:
    (tmp_path / "z.bin").write_bytes(b"\x00final\xff")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "a.txt").write_bytes(b"exact bytes\n")

    manifest = build_manifest(tmp_path, "abc123")

    assert manifest["schema_version"] == 1
    assert manifest["source_sha"] == "abc123"
    assert [entry["path"] for entry in manifest["files"]] == ["nested/a.txt", "z.bin"]
    assert manifest["files"][0]["sha256"] == hashlib.sha256(b"exact bytes\n").hexdigest()
    assert manifest["files"][1]["sha256"] == hashlib.sha256(b"\x00final\xff").hexdigest()


def test_manifest_output_is_reproducible_and_excludes_itself(tmp_path: Path) -> None:
    (tmp_path / "artifact.whl").write_bytes(b"wheel")
    first = write_manifest(tmp_path, "deadbeef").read_bytes()
    second = write_manifest(tmp_path, "deadbeef").read_bytes()

    assert first == second
    payload = json.loads(first)
    assert [entry["path"] for entry in payload["files"]] == ["artifact.whl"]


def test_empty_release_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="empty"):
        build_manifest(tmp_path, "abc123")
