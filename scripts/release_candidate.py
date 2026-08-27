#!/usr/bin/env python3
"""Build and verify the closed Capture release artifact inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path, PurePath
from typing import Any

INVENTORY_SCHEMA_VERSION = "openadapt.production-release-artifact-inventory/v1"
TAG_BINDING_SCHEMA_VERSION = "openadapt.production-release-tag-binding/v1"
TARGET = "capture"
CLAIM_SCOPE = "production_capture"
ARTIFACT_FIELDS = frozenset({"name", "kind", "sha256", "size_bytes", "media_type"})
INVENTORY_FIELDS = frozenset({"schema_version", "target", "claim_scope", "artifacts"})
REFERENCE_FIELDS = frozenset(
    {
        "schema_version",
        "repository",
        "repository_id",
        "repository_owner_id",
        "registry_source_commit",
        "registry_revision",
        "registry_head_sha256",
        "registry_entry_sha256",
        "kind",
        "object_schema_version",
        "object_path",
        "object_sha256",
        "size_bytes",
        "object_media_type",
        "semantic_identity_sha256",
        "subject_sha256",
    }
)
TAG_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "admission_reference",
        "admission_reference_sha256",
        "artifact_inventory_sha256",
    }
)
REFERENCE_DIGEST_DOMAIN = b"OpenAdapt production release tag admission reference v1\0"
INVENTORY_DIGEST_DOMAIN = b"OpenAdapt production release artifact inventory v1\0"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


class CandidateInventoryError(ValueError):
    """The candidate files or inventory do not satisfy the release contract."""


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as candidate:
        while chunk := candidate.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _artifact_kind(path: Path) -> tuple[str, str] | None:
    if path.name.endswith(".tar.gz"):
        return "python-sdist", "application/gzip"
    if path.name.endswith(".whl"):
        return "python-wheel", "application/zip"
    return None


def _candidate_files(dist: Path) -> list[Path]:
    if not dist.is_dir():
        raise CandidateInventoryError(f"candidate directory does not exist: {dist}")
    files: list[Path] = []
    for path in dist.iterdir():
        details = path.lstat()
        if stat.S_ISDIR(details.st_mode):
            raise CandidateInventoryError(f"candidate directory contains a subdirectory: {path.name}")
        if not stat.S_ISREG(details.st_mode) or path.is_symlink():
            raise CandidateInventoryError(f"candidate artifact is not a regular file: {path.name}")
        files.append(path)
    names = [path.name for path in files]
    if len(names) != len(set(names)) or len(names) != len({name.casefold() for name in names}):
        raise CandidateInventoryError("candidate artifact names are not unique")
    unsupported = sorted(path.name for path in files if _artifact_kind(path) is None)
    if unsupported:
        raise CandidateInventoryError(f"candidate directory contains unlisted files: {unsupported}")
    if len(files) != 2:
        raise CandidateInventoryError("candidate must contain exactly one wheel and one sdist")
    kinds = [_artifact_kind(path)[0] for path in files if _artifact_kind(path) is not None]
    if kinds.count("python-wheel") != 1 or kinds.count("python-sdist") != 1:
        raise CandidateInventoryError("candidate must contain exactly one wheel and one sdist")
    return files


def build_inventory(dist: Path) -> dict[str, Any]:
    """Return the closed inventory for exactly one wheel and one sdist."""
    artifacts: list[dict[str, Any]] = []
    for path in _candidate_files(dist):
        kind_and_media = _artifact_kind(path)
        assert kind_and_media is not None
        kind, media_type = kind_and_media
        artifacts.append(
            {
                "name": path.name,
                "kind": kind,
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
                "media_type": media_type,
            }
        )
    artifacts.sort(key=lambda artifact: (artifact["kind"], artifact["name"], artifact["sha256"]))
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "target": TARGET,
        "claim_scope": CLAIM_SCOPE,
        "artifacts": artifacts,
    }


def _load_canonical_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CandidateInventoryError(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise CandidateInventoryError(f"{label} must be a JSON object")
    if raw != _canonical_json_bytes(value) + b"\n":
        raise CandidateInventoryError(f"{label} is not canonical JSON")
    return value


def _load_inventory(path: Path) -> dict[str, Any]:
    return _load_canonical_object(path, label="release inventory")


def verify_inventory(dist: Path, inventory_path: Path) -> dict[str, Any]:
    """Verify canonical inventory bytes and every local candidate file."""
    inventory = _load_inventory(inventory_path)
    if set(inventory) != INVENTORY_FIELDS:
        raise CandidateInventoryError("release inventory has an unexpected field set")
    if inventory.get("schema_version") != INVENTORY_SCHEMA_VERSION:
        raise CandidateInventoryError("release inventory schema is not supported")
    if inventory.get("target") != TARGET or inventory.get("claim_scope") != CLAIM_SCOPE:
        raise CandidateInventoryError("release inventory names a different target or claim scope")
    artifacts = inventory.get("artifacts")
    if not isinstance(artifacts, list):
        raise CandidateInventoryError("release inventory artifacts must be an array")
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != ARTIFACT_FIELDS:
            raise CandidateInventoryError("release inventory has an invalid artifact field set")
        name = artifact.get("name")
        if not isinstance(name, str) or not name or PurePath(name).name != name:
            raise CandidateInventoryError("release inventory has an unsafe artifact name")
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            raise CandidateInventoryError("release inventory has an invalid artifact SHA-256")
        if not isinstance(artifact.get("size_bytes"), int) or artifact["size_bytes"] < 0:
            raise CandidateInventoryError("release inventory has an invalid artifact size")
    expected = build_inventory(dist)
    if inventory != expected:
        raise CandidateInventoryError("local candidate files differ from the release inventory")
    return inventory


def _prefixed_digest(domain: bytes, value: object) -> str:
    return f"sha256:{hashlib.sha256(domain + _canonical_json_bytes(value)).hexdigest()}"


def build_tag_binding(
    admission_reference_path: Path,
    inventory_path: Path,
) -> dict[str, Any]:
    """Bind the parsed admission reference and exact inventory into a tag message."""
    reference = _load_canonical_object(
        admission_reference_path,
        label="admission reference",
    )
    if set(reference) != REFERENCE_FIELDS:
        raise CandidateInventoryError("admission reference has an unexpected field set")
    inventory = _load_inventory(inventory_path)
    if set(inventory) != INVENTORY_FIELDS:
        raise CandidateInventoryError("release inventory has an unexpected field set")
    if inventory.get("schema_version") != INVENTORY_SCHEMA_VERSION:
        raise CandidateInventoryError("release inventory schema is not supported")
    if inventory.get("target") != TARGET or inventory.get("claim_scope") != CLAIM_SCOPE:
        raise CandidateInventoryError("release inventory names a different target or claim scope")
    inventory_projection = {
        "target": inventory["target"],
        "claim_scope": inventory["claim_scope"],
        "artifacts": inventory["artifacts"],
    }
    return {
        "schema_version": TAG_BINDING_SCHEMA_VERSION,
        "admission_reference": reference,
        "admission_reference_sha256": _prefixed_digest(
            REFERENCE_DIGEST_DOMAIN,
            reference,
        ),
        "artifact_inventory_sha256": _prefixed_digest(
            INVENTORY_DIGEST_DOMAIN,
            inventory_projection,
        ),
    }


def verify_tag_binding(
    tag_message_path: Path,
    admission_reference_path: Path,
    inventory_path: Path,
) -> dict[str, Any]:
    """Require the exact canonical tag message for the reference and inventory."""
    actual = _load_canonical_object(tag_message_path, label="release tag binding")
    if set(actual) != TAG_BINDING_FIELDS:
        raise CandidateInventoryError("release tag binding has an unexpected field set")
    expected = build_tag_binding(admission_reference_path, inventory_path)
    if actual != expected:
        raise CandidateInventoryError("release tag binding differs from the expected binding")
    return actual


def _write_inventory(path: Path, inventory: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical_json_bytes(inventory) + b"\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inventory_parser = subparsers.add_parser("inventory")
    inventory_parser.add_argument("--dist", type=Path, required=True)
    inventory_parser.add_argument("--output", type=Path, required=True)
    inventory_parser.add_argument("--github-output", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--dist", type=Path, required=True)
    verify_parser.add_argument("--inventory", type=Path, required=True)
    binding_parser = subparsers.add_parser("tag-binding")
    binding_parser.add_argument("--admission-reference", type=Path, required=True)
    binding_parser.add_argument("--inventory", type=Path, required=True)
    binding_parser.add_argument("--output", type=Path, required=True)
    verify_binding_parser = subparsers.add_parser("verify-tag-binding")
    verify_binding_parser.add_argument("--tag-message", type=Path, required=True)
    verify_binding_parser.add_argument("--admission-reference", type=Path, required=True)
    verify_binding_parser.add_argument("--inventory", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.command == "inventory":
            inventory = build_inventory(args.dist)
            _write_inventory(args.output, inventory)
            if args.github_output is not None:
                with args.github_output.open("a", encoding="utf-8") as output:
                    output.write(
                        "artifact_inventory_json="
                        + _canonical_json_bytes(inventory).decode("utf-8")
                        + "\n"
                    )
            print(_canonical_json_bytes(inventory).decode("utf-8"))
        elif args.command == "verify":
            verify_inventory(args.dist, args.inventory)
            print(f"verified release candidate against {args.inventory}")
        elif args.command == "tag-binding":
            binding = build_tag_binding(args.admission_reference, args.inventory)
            _write_inventory(args.output, binding)
            print(_canonical_json_bytes(binding).decode("utf-8"))
        else:
            verify_tag_binding(
                args.tag_message,
                args.admission_reference,
                args.inventory,
            )
            print(f"verified release tag binding in {args.tag_message}")
    except CandidateInventoryError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
