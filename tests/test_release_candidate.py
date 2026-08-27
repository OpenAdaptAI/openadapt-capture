"""Closed production release artifact inventory tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.release_candidate import (
    CandidateInventoryError,
    build_inventory,
    build_tag_binding,
    verify_inventory,
    verify_tag_binding,
)


def _candidate(dist: Path) -> None:
    dist.mkdir()
    (dist / "openadapt_capture-1.2.3.tar.gz").write_bytes(b"source")
    (dist / "openadapt_capture-1.2.3-py3-none-any.whl").write_bytes(b"wheel")


def _write_inventory(path: Path, inventory: dict) -> None:
    path.write_text(
        json.dumps(
            inventory,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )


def _admission_reference() -> dict:
    return {
        "schema_version": "openadapt.production-evidence-reference/v2",
        "repository": "OpenAdaptAI/.github",
        "repository_id": "858454062",
        "repository_owner_id": "132681217",
        "registry_source_commit": "a" * 40,
        "registry_revision": 1,
        "registry_head_sha256": "sha256:" + "b" * 64,
        "registry_entry_sha256": "sha256:" + "c" * 64,
        "kind": "qualification-release",
        "object_schema_version": "openadapt.qualification-release/v1",
        "object_path": (
            "production-evidence/objects/sha256/dd/"
            + "d" * 64
            + ".qualification-release.json"
        ),
        "object_sha256": "sha256:" + "d" * 64,
        "size_bytes": 1234,
        "object_media_type": (
            "application/vnd.openadapt.qualification-release+json;version=1"
        ),
        "semantic_identity_sha256": "sha256:" + "e" * 64,
        "subject_sha256": None,
    }


def test_builds_and_verifies_the_closed_sorted_inventory(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _candidate(dist)

    inventory = build_inventory(dist)
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, inventory)

    assert inventory["schema_version"] == "openadapt.production-release-artifact-inventory/v1"
    assert inventory["target"] == "capture"
    assert inventory["claim_scope"] == "production_capture"
    assert [artifact["kind"] for artifact in inventory["artifacts"]] == [
        "python-sdist",
        "python-wheel",
    ]
    assert all(artifact["sha256"].startswith("sha256:") for artifact in inventory["artifacts"])
    assert verify_inventory(dist, inventory_path) == inventory


@pytest.mark.parametrize("extra_name", ["SHA256SUMS", "metadata.json", "nested"])
def test_rejects_every_unlisted_candidate_entry(tmp_path: Path, extra_name: str) -> None:
    dist = tmp_path / "dist"
    _candidate(dist)
    extra = dist / extra_name
    if extra_name == "nested":
        extra.mkdir()
    else:
        extra.write_text("not publishable", encoding="utf-8")

    with pytest.raises(CandidateInventoryError, match="subdirectory|unlisted"):
        build_inventory(dist)


def test_rejects_noncanonical_inventory_bytes(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _candidate(dist)
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps(build_inventory(dist), indent=2), encoding="utf-8")

    with pytest.raises(CandidateInventoryError, match="not canonical"):
        verify_inventory(dist, inventory_path)


def test_rejects_changed_candidate_bytes(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _candidate(dist)
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, build_inventory(dist))
    (dist / "openadapt_capture-1.2.3-py3-none-any.whl").write_bytes(b"changed")

    with pytest.raises(CandidateInventoryError, match="differ"):
        verify_inventory(dist, inventory_path)


def test_builds_and_verifies_exact_canonical_tag_binding(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _candidate(dist)
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, build_inventory(dist))
    reference_path = tmp_path / "reference.json"
    _write_inventory(reference_path, _admission_reference())

    binding = build_tag_binding(reference_path, inventory_path)
    binding_path = tmp_path / "tag-message.txt"
    _write_inventory(binding_path, binding)

    assert binding["schema_version"] == "openadapt.production-release-tag-binding/v1"
    assert binding["admission_reference"] == _admission_reference()
    assert binding["admission_reference_sha256"].startswith("sha256:")
    assert binding["artifact_inventory_sha256"].startswith("sha256:")
    assert verify_tag_binding(binding_path, reference_path, inventory_path) == binding


def test_rejects_tag_binding_with_a_second_newline(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _candidate(dist)
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, build_inventory(dist))
    reference_path = tmp_path / "reference.json"
    _write_inventory(reference_path, _admission_reference())
    binding_path = tmp_path / "tag-message.txt"
    _write_inventory(binding_path, build_tag_binding(reference_path, inventory_path))
    binding_path.write_bytes(binding_path.read_bytes() + b"\n")

    with pytest.raises(CandidateInventoryError, match="not canonical"):
        verify_tag_binding(binding_path, reference_path, inventory_path)


def test_rejects_tag_binding_when_inventory_changes(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _candidate(dist)
    inventory_path = tmp_path / "inventory.json"
    _write_inventory(inventory_path, build_inventory(dist))
    reference_path = tmp_path / "reference.json"
    _write_inventory(reference_path, _admission_reference())
    binding_path = tmp_path / "tag-message.txt"
    _write_inventory(binding_path, build_tag_binding(reference_path, inventory_path))
    inventory = build_inventory(dist)
    inventory["artifacts"][0]["size_bytes"] += 1
    _write_inventory(inventory_path, inventory)

    with pytest.raises(CandidateInventoryError, match="differs"):
        verify_tag_binding(binding_path, reference_path, inventory_path)
