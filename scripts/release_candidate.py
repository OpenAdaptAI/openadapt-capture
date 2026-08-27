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
TARGET = "capture"
CLAIM_SCOPE = "production_capture"
ARTIFACT_FIELDS = frozenset({"name", "kind", "sha256", "size_bytes", "media_type"})
INVENTORY_FIELDS = frozenset({"schema_version", "target", "claim_scope", "artifacts"})
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


def _load_inventory(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CandidateInventoryError(f"release inventory is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise CandidateInventoryError("release inventory must be a JSON object")
    if raw != _canonical_json_bytes(value) + b"\n":
        raise CandidateInventoryError("release inventory is not canonical JSON")
    return value


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
        else:
            verify_inventory(args.dist, args.inventory)
            print(f"verified release candidate against {args.inventory}")
    except CandidateInventoryError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
