"""Durable App-authored GitHub release staging contract tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.github_release_staging import (
    RELEASE_APP_ID,
    RELEASE_BOT_LOGIN,
    RELEASE_BOT_USER_ID,
    REPOSITORY_ID,
    GitHubClient,
    ReleaseStagingError,
    _load_canonical_staging,
    select_tag_rulesets,
    stage_release,
)
from scripts.release_candidate import build_inventory

REPOSITORY = "OpenAdaptAI/openadapt-capture"
SOURCE_COMMIT = "a" * 40
TAG = "v1.2.3"


def _ruleset(
    ruleset_id: int,
    name: str,
    rule_types: list[str],
    bypass_actors: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "id": ruleset_id,
        "name": name,
        "target": "tag",
        "enforcement": "active",
        "bypass_actors": bypass_actors,
        "conditions": {
            "ref_name": {
                "include": ["refs/tags/v*"],
                "exclude": [],
            }
        },
        "rules": [{"type": value} for value in rule_types],
        "node_id": "mutable-noise",
        "current_user_can_bypass": True,
    }


def _creation_ruleset() -> dict[str, Any]:
    return _ruleset(
        1001,
        "Release App creates immutable tags",
        ["creation"],
        [
            {
                "actor_id": RELEASE_APP_ID,
                "actor_type": "Integration",
                "bypass_mode": "always",
            }
        ],
    )


def _immutable_ruleset() -> dict[str, Any]:
    return _ruleset(
        1002,
        "Release tags cannot change",
        ["update", "deletion", "non_fast_forward"],
        [],
    )


def _candidate(tmp_path: Path) -> tuple[Path, Path]:
    dist = tmp_path / "candidate"
    dist.mkdir()
    (dist / "openadapt_capture-1.2.3.tar.gz").write_bytes(b"source")
    (dist / "openadapt_capture-1.2.3-py3-none-any.whl").write_bytes(b"wheel")
    inventory = build_inventory(dist)
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return dist, inventory_path


def test_normalizes_exact_creation_and_immutability_rulesets() -> None:
    rulesets = select_tag_rulesets(
        [_immutable_ruleset(), _creation_ruleset()],
        repository=REPOSITORY,
        repository_id=REPOSITORY_ID,
        tag=TAG,
    )

    assert [ruleset["role"] for ruleset in rulesets] == [
        "creation_authority",
        "immutability",
    ]
    assert rulesets[0]["bypass_actors"] == [
        {
            "actor_id": RELEASE_APP_ID,
            "actor_type": "Integration",
            "bypass_mode": "always",
        }
    ]
    assert rulesets[1]["bypass_actors"] == []
    assert [rule["type"] for rule in rulesets[1]["rules"]] == [
        "deletion",
        "non_fast_forward",
        "update",
    ]
    assert "node_id" not in rulesets[0]
    assert "current_user_can_bypass" not in rulesets[0]


def test_rejects_immutability_ruleset_with_any_bypass() -> None:
    immutable = _immutable_ruleset()
    immutable["bypass_actors"] = _creation_ruleset()["bypass_actors"]

    with pytest.raises(ReleaseStagingError, match="one tag ruleset per role"):
        select_tag_rulesets(
            [_creation_ruleset(), immutable],
            repository=REPOSITORY,
            repository_id=REPOSITORY_ID,
            tag=TAG,
        )


class _FakeClient:
    def __init__(self, dist: Path) -> None:
        self.dist = dist
        self.assets: list[dict[str, Any]] = []
        self.release = {
            "id": 2001,
            "tag_name": TAG,
            "target_commitish": SOURCE_COMMIT,
            "draft": True,
            "prerelease": False,
            "author": {"id": int(RELEASE_BOT_USER_ID), "login": RELEASE_BOT_LOGIN},
            "assets": self.assets,
            "upload_url": (
                "https://uploads.github.com/repos/OpenAdaptAI/openadapt-capture/"
                "releases/2001/assets{?name,label}"
            ),
            "url": (
                "https://api.github.com/repos/OpenAdaptAI/openadapt-capture/"
                "releases/2001"
            ),
        }

    def request_json(
        self,
        url: str,
        *,
        method: str = "GET",
        payload: object | None = None,
    ) -> Any:
        if url == "https://api.github.com/installation":
            return {"id": 156835568, "app_id": int(RELEASE_APP_ID)}
        if url == f"https://api.github.com/repos/{REPOSITORY}":
            return {"id": int(REPOSITORY_ID)}
        if url.endswith("/immutable-releases"):
            return {"enabled": True}
        if "/rulesets?" in url:
            return [
                {"id": 1001, "target": "tag"},
                {"id": 1002, "target": "tag"},
            ]
        if url.endswith("/rulesets/1001"):
            return _creation_ruleset()
        if url.endswith("/rulesets/1002"):
            return _immutable_ruleset()
        if "/releases?" in url:
            return []
        if url.endswith("/releases") and method == "POST":
            assert isinstance(payload, dict) and payload["draft"] is True
            return self.release
        if url.endswith("/releases/2001"):
            return self.release
        raise AssertionError((method, url, payload))

    def upload_asset(self, upload_url: str, path: Path, *, media_type: str) -> dict[str, Any]:
        assert upload_url.startswith("https://uploads.github.com/")
        assert media_type in {"application/gzip", "application/zip"}
        asset = {
            "id": 3000 + len(self.assets),
            "name": path.name,
            "url": f"https://api.github.com/assets/{path.name}",
            "uploader": {"id": int(RELEASE_BOT_USER_ID), "login": RELEASE_BOT_LOGIN},
        }
        self.assets.append(asset)
        return asset

    def request_bytes(self, url: str) -> bytes:
        return (self.dist / url.rsplit("/", 1)[-1]).read_bytes()


def test_stages_exact_assets_and_emits_closed_evidence(tmp_path: Path) -> None:
    dist, inventory_path = _candidate(tmp_path)
    client = _FakeClient(dist)

    staging = stage_release(
        client,  # type: ignore[arg-type]
        repository=REPOSITORY,
        repository_id=REPOSITORY_ID,
        source_commit=SOURCE_COMMIT,
        tag=TAG,
        dist=dist,
        inventory_path=inventory_path,
        observed_at="2026-08-27T17:30:00Z",
    )

    assert staging["schema_version"] == "openadapt.production-release-staging-evidence/v1"
    assert staging["draft_release_id"] == "2001"
    assert staging["draft"] is True
    assert staging["immutable_releases_enabled"] is True
    assert [asset["name"] for asset in staging["assets"]] == sorted(
        path.name for path in dist.iterdir()
    )
    assert all(asset["uploader_id"] == RELEASE_BOT_USER_ID for asset in staging["assets"])
    assert staging["tag_rulesets_sha256"].startswith("sha256:")

    staging_path = tmp_path / "staging.json"
    staging_path.write_text(
        json.dumps(staging, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    assert _load_canonical_staging(staging_path) == staging


def test_rejects_noncanonical_staging_evidence(tmp_path: Path) -> None:
    path = tmp_path / "staging.json"
    path.write_text("{}\n\n", encoding="utf-8")

    with pytest.raises(ReleaseStagingError, match="field set|canonical"):
        _load_canonical_staging(path)


def test_requires_a_release_app_token() -> None:
    with pytest.raises(ReleaseStagingError, match="release App token"):
        GitHubClient("")
