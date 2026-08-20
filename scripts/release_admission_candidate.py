#!/usr/bin/env python3
"""Verify PyPI parity and emit a non-admitted release-candidate record.

PyPI is an artifact authority. It is not the OpenAdapt Production selector.
Only an active record in the canonical OpenAdaptAI/.github admission ledger can
select a Production release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.candidate_lifecycle import verify_manifest
except ModuleNotFoundError:  # Direct ``python scripts/...`` execution.
    from candidate_lifecycle import verify_manifest

SCHEMA_VERSION = "openadapt.production-release-admission-candidate/v1"
POLICY_SCHEMA = "openadapt.production-lifecycle-policy/v1"
AUTHORITY_REPOSITORY = "OpenAdaptAI/.github"
POLICY_PATH = "production-lifecycle-policy.json"
ADMISSIONS_PATH = "production-lifecycle-admissions.json"
TARGET_ID = "capture"
SOURCE_REPOSITORY = "OpenAdaptAI/openadapt-capture"
PROJECT = "openadapt-capture"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
STABLE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class AdmissionCandidateError(RuntimeError):
    """The published release cannot become an admission candidate."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fetch_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "openadapt-capture-release-parity/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(4 * 1024 * 1024)
        value = json.loads(body)
    except (OSError, urllib.error.URLError, ValueError, TypeError) as exc:
        raise AdmissionCandidateError(f"PyPI parity request failed: {exc}") from exc
    if not isinstance(value, dict):
        raise AdmissionCandidateError("PyPI returned a non-object response")
    return value


def _capture_target(policy: Mapping[str, Any]) -> dict[str, Any]:
    if policy.get("schema_version") != POLICY_SCHEMA:
        raise AdmissionCandidateError("the lifecycle policy schema is not supported")
    revision = policy.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise AdmissionCandidateError("the lifecycle policy revision is invalid")
    targets = policy.get("targets")
    if not isinstance(targets, list):
        raise AdmissionCandidateError("the lifecycle policy target list is invalid")
    matches = [item for item in targets if isinstance(item, dict) and item.get("id") == TARGET_ID]
    if len(matches) != 1:
        raise AdmissionCandidateError("the lifecycle policy must contain one Capture target")
    target = matches[0]
    expected = {
        "source_repository": SOURCE_REPOSITORY,
        "release_kind": "public_package",
        "required_claim_scope": "qualified_native_recorder_release",
        "required_artifact_kinds": ["sdist", "wheel"],
        "package_index_project": PROJECT,
        "artifact_authority_by_kind": {"sdist": "pypi", "wheel": "pypi"},
    }
    for key, value in expected.items():
        if target.get(key) != value:
            raise AdmissionCandidateError(f"the Capture lifecycle policy {key} differs")
    return target


def _artifact_kind(name: str) -> str:
    if name.endswith(".whl"):
        return "wheel"
    if name.endswith(".tar.gz"):
        return "sdist"
    raise AdmissionCandidateError(f"unsupported release archive: {name}")


def verify_registry_parity(
    *,
    dist_dir: Path,
    manifest_path: Path,
    version: str,
    get_json: Callable[[str], dict[str, Any]] = _fetch_json,
) -> tuple[str, list[dict[str, Any]]]:
    """Require exact local/PyPI parity for one explicit version endpoint."""

    if STABLE_VERSION.fullmatch(version) is None:
        raise AdmissionCandidateError("the candidate version is not stable SemVer")
    hashes = verify_manifest(dist_dir, manifest_path)
    endpoint = (
        "https://pypi.org/pypi/"
        f"{urllib.parse.quote(PROJECT, safe='')}/{urllib.parse.quote(version, safe='')}/json"
    )
    metadata = get_json(endpoint)
    info = metadata.get("info")
    if not isinstance(info, dict) or info.get("name") != PROJECT or info.get("version") != version:
        raise AdmissionCandidateError("PyPI project or version metadata differs")
    files = metadata.get("urls")
    if not isinstance(files, list):
        raise AdmissionCandidateError("PyPI release files are invalid")

    expected_names = set(hashes)
    published_names = {str(item.get("filename")) for item in files if isinstance(item, dict)}
    if published_names != expected_names:
        raise AdmissionCandidateError(
            "PyPI and the exact candidate archive set differ: "
            f"candidate={sorted(expected_names)}, pypi={sorted(published_names)}"
        )

    artifacts: list[dict[str, Any]] = []
    for name in sorted(expected_names):
        local_path = dist_dir / name
        matches = [
            item
            for item in files
            if isinstance(item, dict)
            and item.get("filename") == name
            and item.get("digests", {}).get("sha256") == hashes[name]
            and item.get("size") == local_path.stat().st_size
            and item.get("yanked") is False
        ]
        if len(matches) != 1:
            raise AdmissionCandidateError(f"PyPI does not verify exact archive {name}")
        item = matches[0]
        url = item.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise AdmissionCandidateError(f"PyPI archive URL is invalid for {name}")
        kind = _artifact_kind(name)
        expected_package_type = "bdist_wheel" if kind == "wheel" else "sdist"
        if item.get("packagetype") != expected_package_type:
            raise AdmissionCandidateError(f"PyPI archive type differs for {name}")
        if _sha256(local_path) != hashes[name]:
            raise AdmissionCandidateError(
                f"the local archive changed after manifest verification: {name}"
            )
        artifacts.append(
            {
                "name": name,
                "kind": kind,
                "authority": "pypi",
                "url": url,
                "sha256": f"sha256:{hashes[name]}",
                "size_bytes": local_path.stat().st_size,
            }
        )
    return endpoint, artifacts


def build_admission_candidate(
    *,
    policy_path: Path,
    policy_commit: str,
    source_commit: str,
    version: str,
    endpoint: str,
    artifacts: list[dict[str, Any]],
    verified_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a record that cannot select or claim a Production default."""

    if HEX40.fullmatch(policy_commit) is None or HEX40.fullmatch(source_commit) is None:
        raise AdmissionCandidateError("policy and source commits must be lowercase SHAs")
    if STABLE_VERSION.fullmatch(version) is None:
        raise AdmissionCandidateError("the candidate version is not stable SemVer")
    expected_endpoint = f"https://pypi.org/pypi/{PROJECT}/{version}/json"
    if endpoint != expected_endpoint:
        raise AdmissionCandidateError("the registry parity endpoint is not the exact version")
    kinds = [item.get("kind") for item in artifacts if isinstance(item, dict)]
    if set(kinds) != {"sdist", "wheel"} or len(kinds) != 2 or len(kinds) != len(artifacts):
        raise AdmissionCandidateError("the admission candidate requires one wheel and one sdist")
    if any(item.get("authority") != "pypi" for item in artifacts):
        raise AdmissionCandidateError("the admission candidate artifact authority differs")
    try:
        policy_bytes = policy_path.read_bytes()
        policy = json.loads(policy_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionCandidateError("the lifecycle policy is not valid JSON") from exc
    if not isinstance(policy, dict):
        raise AdmissionCandidateError("the lifecycle policy must be a JSON object")
    target = _capture_target(policy)
    now = (verified_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    timestamp = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": SCHEMA_VERSION,
        "target": TARGET_ID,
        "claim_scope": target["required_claim_scope"],
        "release_status": "not_admitted",
        "production_default": None,
        "production_authority": {
            "repository": AUTHORITY_REPOSITORY,
            "source_commit": policy_commit,
            "policy_path": POLICY_PATH,
            "policy_revision": policy["revision"],
            "policy_sha256": f"sha256:{hashlib.sha256(policy_bytes).hexdigest()}",
            "admissions_path": ADMISSIONS_PATH,
            "activation_required": True,
            "pypi_latest_is_authority": False,
        },
        "release": {
            "kind": "public_package",
            "version": version,
            "tag": f"v{version}",
            "source_commit": source_commit,
            "immutable_release_url": (
                f"https://github.com/{SOURCE_REPOSITORY}/commit/{source_commit}"
            ),
            "artifacts": artifacts,
        },
        "registry_parity": {
            "project": PROJECT,
            "version_endpoint": endpoint,
            "verified_at": timestamp,
            "exact_archive_set": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    endpoint, artifacts = verify_registry_parity(
        dist_dir=args.dist,
        manifest_path=args.manifest,
        version=args.version,
    )
    candidate = build_admission_candidate(
        policy_path=args.policy,
        policy_commit=args.policy_commit,
        source_commit=args.source_commit,
        version=args.version,
        endpoint=endpoint,
        artifacts=artifacts,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(candidate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"verified PyPI parity for {PROJECT} {args.version}; wrote a not-admitted release candidate"
    )


if __name__ == "__main__":
    main()
