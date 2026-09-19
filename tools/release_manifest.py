from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(artifact_dir: Path, source_sha: str) -> dict[str, object]:
    root = artifact_dir.resolve()
    files: list[dict[str, object]] = []
    artifact_paths = sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    for path in artifact_paths:
        relative = path.relative_to(root).as_posix()
        if relative == "manifest.json":
            continue
        files.append(
            {"path": relative, "sha256": sha256_file(path), "size": path.stat().st_size}
        )
    if not files:
        raise ValueError("release artifact directory is empty")
    return {"schema_version": 1, "source_sha": source_sha, "files": files}


def write_manifest(artifact_dir: Path, source_sha: str) -> Path:
    manifest = build_manifest(artifact_dir, source_sha)
    output = artifact_dir / "manifest.json"
    output.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate MON release SHA-256 manifest")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    if not args.source_sha.strip():
        parser.error("--source-sha must not be empty")
    write_manifest(args.artifact_dir, args.source_sha.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
