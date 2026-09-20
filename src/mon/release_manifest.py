from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA_VERSION = 1
MANIFEST_FILENAME = "manifest.json"
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")


class ReleaseManifestError(ValueError):
    pass


class ReleaseManifestVerificationError(ReleaseManifestError):
    pass


def validate_source_sha(source_sha: str) -> str:
    normalized = source_sha.strip().casefold()
    if not _GIT_SHA_RE.fullmatch(normalized):
        raise ReleaseManifestError(
            "source_sha must be a full immutable Git commit SHA "
            "(40-character SHA-1 or 64-character SHA-256 hex)"
        )
    return normalized


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_root(artifact_dir: Path) -> Path:
    root = artifact_dir.resolve()
    if not root.is_dir():
        raise ReleaseManifestError("release artifact directory does not exist")
    return root


def _relative_artifact_path(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ReleaseManifestError("release artifact path escapes artifact root") from exc
    text = relative.as_posix()
    if text in {"", "."} or text.startswith("../") or text.startswith("/"):
        raise ReleaseManifestError("release artifact path escapes artifact root")
    return text


def _artifact_files(root: Path) -> list[Path]:
    files = []
    for item in root.rglob("*"):
        if not item.is_file():
            continue
        relative = _relative_artifact_path(root, item)
        if relative == MANIFEST_FILENAME:
            continue
        files.append(item)
    return sorted(files, key=lambda path: _relative_artifact_path(root, path))


def build_manifest(artifact_dir: Path, source_sha: str) -> dict[str, object]:
    root = _artifact_root(artifact_dir)
    source = validate_source_sha(source_sha)
    files: list[dict[str, object]] = []
    for path in _artifact_files(root):
        files.append(
            {
                "path": _relative_artifact_path(root, path),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
        )
    if not files:
        raise ReleaseManifestError("release artifact directory is empty")
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "source_sha": source,
        "files": files,
    }


def manifest_bytes(manifest: dict[str, object]) -> bytes:
    return (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def write_manifest(artifact_dir: Path, source_sha: str) -> Path:
    output = _artifact_root(artifact_dir) / MANIFEST_FILENAME
    output.write_bytes(manifest_bytes(build_manifest(artifact_dir, source_sha)))
    return output


def _load_manifest(manifest_path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseManifestVerificationError("release manifest is unreadable") from exc
    if not isinstance(payload, dict):
        raise ReleaseManifestVerificationError("release manifest must be a JSON object")
    return payload


def verify_manifest(artifact_dir: Path, *, manifest_path: Path | None = None) -> None:
    root = _artifact_root(artifact_dir)
    manifest_file = manifest_path or (root / MANIFEST_FILENAME)
    resolved_manifest = manifest_file.resolve()
    try:
        resolved_manifest.relative_to(root)
    except ValueError as exc:
        raise ReleaseManifestVerificationError(
            "release manifest path escapes artifact root"
        ) from exc
    manifest = _load_manifest(resolved_manifest)
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ReleaseManifestVerificationError("unsupported release manifest schema")
    source_sha = manifest.get("source_sha")
    if not isinstance(source_sha, str):
        raise ReleaseManifestVerificationError("release manifest source_sha is invalid")
    validate_source_sha(source_sha)
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise ReleaseManifestVerificationError("release manifest has no files")

    previous_path = ""
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReleaseManifestVerificationError(
                "release manifest file entry is invalid"
            )
        relative = entry.get("path")
        expected_sha = entry.get("sha256")
        expected_size = entry.get("size")
        if not isinstance(relative, str) or relative in {"", MANIFEST_FILENAME}:
            raise ReleaseManifestVerificationError("release manifest path is invalid")
        if relative <= previous_path:
            raise ReleaseManifestVerificationError("release manifest files are not sorted")
        previous_path = relative
        if relative in seen:
            raise ReleaseManifestVerificationError(
                "release manifest contains duplicate path"
            )
        seen.add(relative)
        candidate = (root / relative).resolve()
        actual_relative = _relative_artifact_path(root, candidate)
        if actual_relative != relative:
            raise ReleaseManifestVerificationError("release manifest path is not canonical")
        if not candidate.is_file():
            raise ReleaseManifestVerificationError(f"release artifact is missing: {relative}")
        if not isinstance(expected_size, int) or expected_size < 0:
            raise ReleaseManifestVerificationError("release artifact size is invalid")
        if candidate.stat().st_size != expected_size:
            raise ReleaseManifestVerificationError(
                f"release artifact size changed: {relative}"
            )
        if not isinstance(expected_sha, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_sha
        ):
            raise ReleaseManifestVerificationError("release artifact sha256 is invalid")
        if sha256_file(candidate) != expected_sha:
            raise ReleaseManifestVerificationError(
                f"release artifact sha256 changed: {relative}"
            )

    actual_files = {
        _relative_artifact_path(root, path)
        for path in _artifact_files(root)
    }
    if actual_files != seen:
        raise ReleaseManifestVerificationError(
            "release artifact set differs from manifest"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate or verify MON release manifest")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="verify an existing manifest instead of generating one",
    )
    args = parser.parse_args(argv)
    if args.verify:
        verify_manifest(args.artifact_dir)
        return 0
    if args.source_sha is None:
        parser.error("--source-sha is required unless --verify is used")
    write_manifest(args.artifact_dir, args.source_sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
