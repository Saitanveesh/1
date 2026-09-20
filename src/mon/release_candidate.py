from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

CYCLONEDX_FORMAT = "CycloneDX"
SUPPORTED_CYCLONEDX_VERSIONS = {"1.5", "1.6", "1.7"}


class ReleaseCandidateError(ValueError):
    pass


def load_json_file(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseCandidateError(f"release candidate JSON is unreadable: {path}") from exc
    if not isinstance(payload, dict):
        raise ReleaseCandidateError("release candidate JSON must be an object")
    return payload


def validate_cyclonedx_sbom(path: Path) -> None:
    payload = load_json_file(path)
    if payload.get("bomFormat") != CYCLONEDX_FORMAT:
        raise ReleaseCandidateError("SBOM must use CycloneDX bomFormat")
    spec_version = payload.get("specVersion")
    if spec_version not in SUPPORTED_CYCLONEDX_VERSIONS:
        raise ReleaseCandidateError("SBOM CycloneDX specVersion is unsupported")
    components = payload.get("components")
    if not isinstance(components, list) or not components:
        raise ReleaseCandidateError("SBOM must contain at least one component")
    for component in components:
        if not isinstance(component, dict):
            raise ReleaseCandidateError("SBOM component entry must be an object")
        name = component.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ReleaseCandidateError("SBOM component must include a name")


def validate_release_candidate_directory(
    artifact_dir: Path,
    *,
    required_sboms: tuple[str, ...] = ("mon-python.cdx.json", "mon-console.cdx.json"),
) -> None:
    root = artifact_dir.resolve()
    if not root.is_dir():
        raise ReleaseCandidateError("release candidate artifact directory does not exist")
    for sbom_name in required_sboms:
        sbom_path = (root / sbom_name).resolve()
        try:
            sbom_path.relative_to(root)
        except ValueError as exc:
            raise ReleaseCandidateError("SBOM path escapes artifact directory") from exc
        if not sbom_path.is_file():
            raise ReleaseCandidateError(f"required SBOM is missing: {sbom_name}")
        validate_cyclonedx_sbom(sbom_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate MON release-candidate evidence")
    parser.add_argument("artifact_dir", type=Path)
    args = parser.parse_args(argv)
    validate_release_candidate_directory(args.artifact_dir)
    return 0
