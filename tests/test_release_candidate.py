"""Closed production release artifact inventory tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.release_candidate import (
    CandidateInventoryError,
    build_inventory,
    verify_inventory,
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
