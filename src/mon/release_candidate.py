from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Protocol

from mon.release_manifest import (
    MANIFEST_FILENAME,
    ReleaseManifestError,
    ReleaseManifestVerificationError,
    validate_source_sha,
    verify_manifest,
)

CYCLONEDX_FORMAT = "CycloneDX"
SUPPORTED_CYCLONEDX_VERSIONS = {"1.5", "1.6", "1.7"}
REQUIRED_RELEASE_ARTIFACTS = (
    "console/mon-operator-console.zip",
    "manifest.json",
    "mon-console.cdx.json",
    "mon-python.cdx.json",
    "python/mon_security_fabric-0.1.0-py3-none-any.whl",
    "python/mon_security_fabric-0.1.0.tar.gz",
)
REQUIRED_SBOMS = ("mon-python.cdx.json", "mon-console.cdx.json")


class ReleaseCandidateError(ValueError):
    pass


class ReleaseCandidateVerificationError(ReleaseCandidateError):
    pass


class AttestationRunner(Protocol):
    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[str]:
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
    required_sboms: tuple[str, ...] = REQUIRED_SBOMS,
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


def required_release_artifacts() -> tuple[str, ...]:
    return REQUIRED_RELEASE_ARTIFACTS


def _artifact_root(artifact_dir: Path) -> Path:
    root = artifact_dir.resolve()
    if not root.is_dir():
        raise ReleaseCandidateVerificationError(
            "release candidate artifact directory does not exist"
        )
    return root


def _relative_candidate_path(root: Path, path: Path) -> str:
    if path.is_symlink():
        raise ReleaseCandidateVerificationError("release candidate contains symlink")
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ReleaseCandidateVerificationError(
            "release candidate path escapes artifact directory"
        ) from exc
    text = relative.as_posix()
    if text in {"", "."} or text.startswith("../") or text.startswith("/"):
        raise ReleaseCandidateVerificationError(
            "release candidate path escapes artifact directory"
        )
    return text


def _candidate_files(root: Path) -> set[str]:
    files: set[str] = set()
    for item in root.rglob("*"):
        if item.is_symlink():
            raise ReleaseCandidateVerificationError("release candidate contains symlink")
        if item.is_file():
            files.add(_relative_candidate_path(root, item))
    return files


def verify_release_candidate_offline(artifact_dir: Path, expected_source_sha: str) -> None:
    root = _artifact_root(artifact_dir)
    source_sha = validate_source_sha(expected_source_sha)
    files = _candidate_files(root)
    try:
        verify_manifest(root)
    except (ReleaseManifestError, ReleaseManifestVerificationError) as exc:
        raise ReleaseCandidateVerificationError(str(exc)) from exc

    manifest = load_json_file(root / MANIFEST_FILENAME)
    if manifest.get("source_sha") != source_sha:
        raise ReleaseCandidateVerificationError("release manifest source_sha mismatch")

    required = set(REQUIRED_RELEASE_ARTIFACTS)
    if files != required:
        missing = sorted(required - files)
        extra = sorted(files - required)
        details = []
        if missing:
            details.append(f"missing={missing}")
        if extra:
            details.append(f"extra={extra}")
        raise ReleaseCandidateVerificationError(
            "release candidate artifact set mismatch: " + ", ".join(details)
        )

    try:
        validate_release_candidate_directory(root)
    except ReleaseCandidateError as exc:
        raise ReleaseCandidateVerificationError(str(exc)) from exc


def _default_attestation_runner(
    args: list[str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, text=True, capture_output=True)


def verify_release_candidate_attestations(
    artifact_dir: Path,
    expected_source_sha: str,
    *,
    repository: str = "Saitanveesh/1",
    signer_workflow: str = "github.com/Saitanveesh/1/.github/workflows/release-candidate.yml",
    runner: AttestationRunner = _default_attestation_runner,
) -> None:
    root = _artifact_root(artifact_dir)
    try:
        source_sha = validate_source_sha(expected_source_sha)
    except ReleaseManifestError as exc:
        raise ReleaseCandidateVerificationError(str(exc)) from exc
    for artifact in REQUIRED_RELEASE_ARTIFACTS:
        result = runner(
            [
                "gh",
                "attestation",
                "verify",
                str(root / artifact),
                "--repo",
                repository,
                "--signer-workflow",
                signer_workflow,
                "--source-digest",
                source_sha,
            ]
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            detail = f": {stderr}" if stderr else ""
            raise ReleaseCandidateVerificationError(
                f"release candidate attestation verification failed for {artifact}{detail}"
            )


def verify_release_candidate(
    artifact_dir: Path,
    expected_source_sha: str,
    *,
    online_attestations: bool = False,
    repository: str = "Saitanveesh/1",
    signer_workflow: str = "github.com/Saitanveesh/1/.github/workflows/release-candidate.yml",
    runner: AttestationRunner = _default_attestation_runner,
) -> None:
    verify_release_candidate_offline(artifact_dir, expected_source_sha)
    if online_attestations:
        verify_release_candidate_attestations(
            artifact_dir,
            expected_source_sha,
            repository=repository,
            signer_workflow=signer_workflow,
            runner=runner,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate MON release-candidate evidence")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument(
        "--online-attestations",
        action="store_true",
        help="verify GitHub artifact attestations using gh and the GitHub API",
    )
    parser.add_argument("--repo", default="Saitanveesh/1")
    parser.add_argument(
        "--signer-workflow",
        default="github.com/Saitanveesh/1/.github/workflows/release-candidate.yml",
    )
    args = parser.parse_args(argv)
    if args.source_sha:
        verify_release_candidate(
            args.artifact_dir,
            args.source_sha,
            online_attestations=args.online_attestations,
            repository=args.repo,
            signer_workflow=args.signer_workflow,
        )
    else:
        validate_release_candidate_directory(args.artifact_dir)
    return 0
