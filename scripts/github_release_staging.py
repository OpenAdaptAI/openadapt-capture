#!/usr/bin/env python3
"""Stage and verify durable Capture release candidates on GitHub."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.release_candidate import _canonical_json_bytes, verify_inventory
except ModuleNotFoundError:  # Direct execution adds scripts/, not the repository root.
    from release_candidate import _canonical_json_bytes, verify_inventory

STAGING_SCHEMA_VERSION = "openadapt.production-release-staging-evidence/v1"
RULESET_SCHEMA_VERSION = "openadapt.production-release-tag-ruleset/v1"
RULESETS_DIGEST_DOMAIN = b"OpenAdapt production release tag rulesets v1\0"
STAGING_DIGEST_DOMAIN = b"OpenAdapt production release staging evidence v1\0"
RELEASE_APP_ID = "4730708"
RELEASE_APP_INSTALLATION_ID = "156835568"
RELEASE_BOT_USER_ID = "321543906"
RELEASE_BOT_LOGIN = "openadapt-release[bot]"
REPOSITORY_ID = "1115283835"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
STAGING_FIELDS = frozenset(
    {
        "schema_version",
        "repository",
        "repository_id",
        "draft_release_id",
        "tag",
        "target_commitish",
        "draft",
        "prerelease",
        "release_app_id",
        "release_app_installation_id",
        "release_app_bot_user_id",
        "release_author_login",
        "assets",
        "immutable_releases_enabled",
        "tag_rulesets",
        "tag_rulesets_sha256",
        "observed_at",
    }
)
ASSET_FIELDS = frozenset(
    {"asset_id", "name", "sha256", "size_bytes", "uploader_id", "uploader_login"}
)
RULESET_FIELDS = frozenset(
    {
        "schema_version",
        "role",
        "repository",
        "repository_id",
        "ruleset_id",
        "name",
        "target",
        "enforcement",
        "bypass_actors",
        "conditions",
        "rules",
    }
)


class ReleaseStagingError(RuntimeError):
    """GitHub release staging does not match the admitted contract."""


class GitHubClient:
    """Narrow GitHub API client for one release transaction."""

    def __init__(self, token: str) -> None:
        if not token:
            raise ReleaseStagingError("GH_TOKEN must contain the exact release App token")
        self.token = token

    def request_json(
        self,
        url: str,
        *,
        method: str = "GET",
        payload: object | None = None,
    ) -> Any:
        data = None if payload is None else _canonical_json_bytes(payload)
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "openadapt-capture-release-staging/1",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(32 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            raise ReleaseStagingError(f"GitHub API {method} {url} failed with HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ReleaseStagingError(f"GitHub API {method} {url} failed: {exc}") from exc
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReleaseStagingError(f"GitHub API {method} {url} returned invalid JSON") from exc

    def request_bytes(self, url: str) -> bytes:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/octet-stream",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "openadapt-capture-release-staging/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read(256 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            raise ReleaseStagingError(f"GitHub asset download failed with HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ReleaseStagingError(f"GitHub asset download failed: {exc}") from exc

    def upload_asset(
        self,
        upload_url: str,
        path: Path,
        *,
        media_type: str,
    ) -> dict[str, Any]:
        base_url = upload_url.split("{", 1)[0]
        url = f"{base_url}?{urllib.parse.urlencode({'name': path.name})}"
        request = urllib.request.Request(
            url,
            data=path.read_bytes(),
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": media_type,
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "openadapt-capture-release-staging/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                value = json.loads(response.read(4 * 1024 * 1024))
        except urllib.error.HTTPError as exc:
            raise ReleaseStagingError(f"GitHub asset upload failed with HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise ReleaseStagingError(f"GitHub asset upload failed: {exc}") from exc
        if not isinstance(value, dict):
            raise ReleaseStagingError("GitHub asset upload returned a non-object")
        return value


def _decimal_id(value: Any, *, label: str) -> str:
    if isinstance(value, bool):
        raise ReleaseStagingError(f"{label} is not a decimal GitHub ID")
    text = str(value)
    if not text.isdigit() or int(text) <= 0:
        raise ReleaseStagingError(f"{label} is not a decimal GitHub ID")
    return text


def _canonical_digest(domain: bytes, value: object) -> str:
    return f"sha256:{hashlib.sha256(domain + _canonical_json_bytes(value)).hexdigest()}"


def _ref_matches(pattern: str, ref: str) -> bool:
    if pattern == "~ALL":
        return True
    return fnmatch.fnmatchcase(ref, pattern)


def _conditions_match_tag(conditions: dict[str, Any], tag: str) -> bool:
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict) or set(ref_name) != {"include", "exclude"}:
        return False
    include = ref_name.get("include")
    exclude = ref_name.get("exclude")
    if not isinstance(include, list) or not isinstance(exclude, list):
        return False
    ref = f"refs/tags/{tag}"
    return any(isinstance(pattern, str) and _ref_matches(pattern, ref) for pattern in include) and not any(
        isinstance(pattern, str) and _ref_matches(pattern, ref) for pattern in exclude
    )


def _normalized_ruleset(
    raw: dict[str, Any],
    *,
    role: str,
    repository: str,
    repository_id: str,
) -> dict[str, Any]:
    bypass_raw = raw.get("bypass_actors")
    rules_raw = raw.get("rules")
    conditions_raw = raw.get("conditions")
    if not isinstance(bypass_raw, list) or not isinstance(rules_raw, list):
        raise ReleaseStagingError("tag ruleset has invalid bypass actors or rules")
    if not isinstance(conditions_raw, dict):
        raise ReleaseStagingError("tag ruleset has invalid conditions")
    ref_name = conditions_raw.get("ref_name")
    if not isinstance(ref_name, dict):
        raise ReleaseStagingError("tag ruleset has no ref_name condition")
    include = ref_name.get("include")
    exclude = ref_name.get("exclude")
    if not isinstance(include, list) or not all(isinstance(value, str) for value in include):
        raise ReleaseStagingError("tag ruleset has invalid include conditions")
    if not isinstance(exclude, list) or not all(isinstance(value, str) for value in exclude):
        raise ReleaseStagingError("tag ruleset has invalid exclude conditions")
    bypass_actors = []
    for actor in bypass_raw:
        if not isinstance(actor, dict):
            raise ReleaseStagingError("tag ruleset has an invalid bypass actor")
        actor_type = actor.get("actor_type")
        bypass_mode = actor.get("bypass_mode")
        if not isinstance(actor_type, str) or not isinstance(bypass_mode, str):
            raise ReleaseStagingError("tag ruleset has an invalid bypass actor")
        bypass_actors.append(
            {
                "actor_id": _decimal_id(actor.get("actor_id"), label="ruleset bypass actor"),
                "actor_type": actor_type,
                "bypass_mode": bypass_mode,
            }
        )
    bypass_actors.sort(
        key=lambda actor: (actor["actor_type"], actor["actor_id"], actor["bypass_mode"])
    )
    rules = []
    for rule in rules_raw:
        if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
            raise ReleaseStagingError("tag ruleset has an invalid rule")
        rules.append({"type": rule["type"]})
    rules.sort(key=lambda rule: rule["type"])
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise ReleaseStagingError("tag ruleset has no stable name")
    return {
        "schema_version": RULESET_SCHEMA_VERSION,
        "role": role,
        "repository": repository,
        "repository_id": repository_id,
        "ruleset_id": _decimal_id(raw.get("id"), label="tag ruleset"),
        "name": name,
        "target": raw.get("target"),
        "enforcement": raw.get("enforcement"),
        "bypass_actors": bypass_actors,
        "conditions": {
            "ref_name": {
                "include": sorted(set(include)),
                "exclude": sorted(set(exclude)),
            }
        },
        "rules": rules,
    }


def select_tag_rulesets(
    raw_rulesets: list[dict[str, Any]],
    *,
    repository: str,
    repository_id: str,
    tag: str,
) -> list[dict[str, Any]]:
    """Select exactly one creation authority and one immutable tag ruleset."""
    candidates: dict[str, list[dict[str, Any]]] = {
        "creation_authority": [],
        "immutability": [],
    }
    for raw in raw_rulesets:
        if not isinstance(raw, dict):
            raise ReleaseStagingError("GitHub returned a non-object tag ruleset")
        if raw.get("target") != "tag" or raw.get("enforcement") != "active":
            continue
        conditions = raw.get("conditions")
        if not isinstance(conditions, dict) or not _conditions_match_tag(conditions, tag):
            continue
        types = sorted(
            rule.get("type")
            for rule in raw.get("rules", [])
            if isinstance(rule, dict) and isinstance(rule.get("type"), str)
        )
        bypass = raw.get("bypass_actors")
        if not isinstance(bypass, list):
            continue
        normalized_bypass = []
        for actor in bypass:
            if not isinstance(actor, dict):
                break
            try:
                normalized_bypass.append(
                    {
                        "actor_id": _decimal_id(
                            actor.get("actor_id"),
                            label="ruleset bypass actor",
                        ),
                        "actor_type": actor.get("actor_type"),
                        "bypass_mode": actor.get("bypass_mode"),
                    }
                )
            except ReleaseStagingError:
                break
        else:
            normalized_bypass.sort(
                key=lambda actor: (
                    str(actor["actor_type"]),
                    actor["actor_id"],
                    str(actor["bypass_mode"]),
                )
            )
        if types == ["creation"] and normalized_bypass == [
            {
                "actor_id": RELEASE_APP_ID,
                "actor_type": "Integration",
                "bypass_mode": "always",
            }
        ]:
            role = "creation_authority"
        elif types == ["deletion", "non_fast_forward", "update"] and not normalized_bypass:
            role = "immutability"
        else:
            continue
        candidates[role].append(
            _normalized_ruleset(
                raw,
                role=role,
                repository=repository,
                repository_id=repository_id,
            )
        )
    if any(len(values) != 1 for values in candidates.values()):
        counts = {role: len(values) for role, values in candidates.items()}
        raise ReleaseStagingError(f"expected one tag ruleset per role, got {counts}")
    return [candidates["creation_authority"][0], candidates["immutability"][0]]


def _verify_identity_and_settings(
    client: GitHubClient,
    *,
    repository: str,
    repository_id: str,
    tag: str,
) -> list[dict[str, Any]]:
    installation = client.request_json("https://api.github.com/installation")
    if not isinstance(installation, dict):
        raise ReleaseStagingError("release App token has no installation identity")
    if _decimal_id(installation.get("id"), label="release App installation") != RELEASE_APP_INSTALLATION_ID:
        raise ReleaseStagingError("release App installation differs from the production authority")
    if _decimal_id(installation.get("app_id"), label="release App") != RELEASE_APP_ID:
        raise ReleaseStagingError("release App identity differs from the production authority")
    repository_value = client.request_json(f"https://api.github.com/repos/{repository}")
    if not isinstance(repository_value, dict):
        raise ReleaseStagingError("GitHub returned no repository identity")
    if _decimal_id(repository_value.get("id"), label="repository") != repository_id:
        raise ReleaseStagingError("repository ID differs from the production target")
    immutable = client.request_json(f"https://api.github.com/repos/{repository}/immutable-releases")
    if not isinstance(immutable, dict) or immutable.get("enabled") is not True:
        raise ReleaseStagingError("immutable GitHub Releases are not enabled")
    summaries = client.request_json(
        f"https://api.github.com/repos/{repository}/rulesets?includes_parents=false&per_page=100"
    )
    if not isinstance(summaries, list):
        raise ReleaseStagingError("GitHub returned no repository ruleset list")
    detailed = []
    for summary in summaries:
        if not isinstance(summary, dict) or summary.get("target") != "tag":
            continue
        ruleset_id = _decimal_id(summary.get("id"), label="tag ruleset")
        value = client.request_json(f"https://api.github.com/repos/{repository}/rulesets/{ruleset_id}")
        if not isinstance(value, dict):
            raise ReleaseStagingError("GitHub returned a non-object tag ruleset")
        detailed.append(value)
    return select_tag_rulesets(
        detailed,
        repository=repository,
        repository_id=repository_id,
        tag=tag,
    )


def _asset_evidence(
    client: GitHubClient,
    asset: dict[str, Any],
    expected: dict[str, Any],
) -> dict[str, Any]:
    if asset.get("name") != expected.get("name"):
        raise ReleaseStagingError("draft release asset name differs from the inventory")
    uploader = asset.get("uploader")
    if not isinstance(uploader, dict):
        raise ReleaseStagingError("draft release asset has no uploader identity")
    uploader_id = _decimal_id(uploader.get("id"), label="release asset uploader")
    uploader_login = uploader.get("login")
    if uploader_id != RELEASE_BOT_USER_ID or uploader_login != RELEASE_BOT_LOGIN:
        raise ReleaseStagingError("draft release asset was not uploaded by the release App")
    asset_url = asset.get("url")
    if not isinstance(asset_url, str):
        raise ReleaseStagingError("draft release asset has no API URL")
    raw = client.request_bytes(asset_url)
    digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    if digest != expected.get("sha256") or len(raw) != expected.get("size_bytes"):
        raise ReleaseStagingError("draft release asset bytes differ from the inventory")
    return {
        "asset_id": _decimal_id(asset.get("id"), label="release asset"),
        "name": asset["name"],
        "sha256": digest,
        "size_bytes": len(raw),
        "uploader_id": uploader_id,
        "uploader_login": uploader_login,
    }


def _find_release(client: GitHubClient, repository: str, tag: str) -> dict[str, Any] | None:
    releases: list[Any] = []
    for page in range(1, 11):
        batch = client.request_json(
            f"https://api.github.com/repos/{repository}/releases?per_page=100&page={page}"
        )
        if not isinstance(batch, list):
            raise ReleaseStagingError("GitHub returned no release list")
        releases.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise ReleaseStagingError("GitHub release list exceeded the search bound")
    matches = [
        release
        for release in releases
        if isinstance(release, dict) and release.get("tag_name") == tag
    ]
    if len(matches) > 1:
        raise ReleaseStagingError("GitHub returned duplicate releases for the candidate tag")
    return matches[0] if matches else None


def _verify_release_shape(
    release: dict[str, Any],
    *,
    tag: str,
    source_commit: str,
    require_draft: bool,
) -> None:
    if release.get("tag_name") != tag or release.get("target_commitish") != source_commit:
        raise ReleaseStagingError("draft release tag or target commit differs")
    if release.get("draft") is not require_draft or release.get("prerelease") is not False:
        raise ReleaseStagingError("GitHub release state differs from the release transaction")
    author = release.get("author")
    if not isinstance(author, dict):
        raise ReleaseStagingError("GitHub release has no author identity")
    if _decimal_id(author.get("id"), label="release author") != RELEASE_BOT_USER_ID:
        raise ReleaseStagingError("GitHub release author is not the release App")
    if author.get("login") != RELEASE_BOT_LOGIN:
        raise ReleaseStagingError("GitHub release author login is not the release App")


def _ensure_assets(
    client: GitHubClient,
    release: dict[str, Any],
    *,
    repository: str,
    dist: Path,
    inventory: dict[str, Any],
    upload_missing: bool,
) -> list[dict[str, Any]]:
    expected_by_name = {artifact["name"]: artifact for artifact in inventory["artifacts"]}
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ReleaseStagingError("GitHub release has no asset list")
    actual_by_name = {
        asset.get("name"): asset
        for asset in assets
        if isinstance(asset, dict) and isinstance(asset.get("name"), str)
    }
    if len(actual_by_name) != len(assets):
        raise ReleaseStagingError("GitHub release has duplicate or invalid asset names")
    extra = sorted(set(actual_by_name) - set(expected_by_name))
    if extra:
        raise ReleaseStagingError(f"GitHub release has unlisted assets: {extra}")
    missing = sorted(set(expected_by_name) - set(actual_by_name))
    if missing and not upload_missing:
        raise ReleaseStagingError(f"GitHub release is missing admitted assets: {missing}")
    upload_url = release.get("upload_url")
    if missing and not isinstance(upload_url, str):
        raise ReleaseStagingError("GitHub draft release has no upload URL")
    for name in missing:
        expected = expected_by_name[name]
        client.upload_asset(
            upload_url,
            dist / name,
            media_type=expected["media_type"],
        )
    if missing:
        release_id = _decimal_id(release.get("id"), label="draft release")
        refreshed = client.request_json(
            f"https://api.github.com/repos/{repository}/releases/{release_id}"
        )
        if not isinstance(refreshed, dict) or not isinstance(refreshed.get("assets"), list):
            raise ReleaseStagingError("GitHub returned no refreshed draft assets")
        assets = refreshed["assets"]
        actual_by_name = {
            asset.get("name"): asset
            for asset in assets
            if isinstance(asset, dict) and isinstance(asset.get("name"), str)
        }
    if set(actual_by_name) != set(expected_by_name):
        raise ReleaseStagingError("GitHub draft asset set differs from the inventory")
    evidence = [
        _asset_evidence(client, actual_by_name[name], expected_by_name[name])
        for name in sorted(expected_by_name)
    ]
    evidence.sort(key=lambda item: (item["name"], item["asset_id"]))
    return evidence


def _staging_object(
    *,
    repository: str,
    repository_id: str,
    release: dict[str, Any],
    tag: str,
    source_commit: str,
    assets: list[dict[str, Any]],
    tag_rulesets: list[dict[str, Any]],
    observed_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": STAGING_SCHEMA_VERSION,
        "repository": repository,
        "repository_id": repository_id,
        "draft_release_id": _decimal_id(release.get("id"), label="draft release"),
        "tag": tag,
        "target_commitish": source_commit,
        "draft": True,
        "prerelease": False,
        "release_app_id": RELEASE_APP_ID,
        "release_app_installation_id": RELEASE_APP_INSTALLATION_ID,
        "release_app_bot_user_id": RELEASE_BOT_USER_ID,
        "release_author_login": RELEASE_BOT_LOGIN,
        "assets": assets,
        "immutable_releases_enabled": True,
        "tag_rulesets": tag_rulesets,
        "tag_rulesets_sha256": _canonical_digest(RULESETS_DIGEST_DOMAIN, tag_rulesets),
        "observed_at": observed_at,
    }


def stage_release(
    client: GitHubClient,
    *,
    repository: str,
    repository_id: str,
    source_commit: str,
    tag: str,
    dist: Path,
    inventory_path: Path,
    observed_at: str,
) -> dict[str, Any]:
    inventory = verify_inventory(dist, inventory_path)
    tag_rulesets = _verify_identity_and_settings(
        client,
        repository=repository,
        repository_id=repository_id,
        tag=tag,
    )
    release = _find_release(client, repository, tag)
    if release is None:
        release = client.request_json(
            f"https://api.github.com/repos/{repository}/releases",
            method="POST",
            payload={
                "tag_name": tag,
                "target_commitish": source_commit,
                "name": tag,
                "body": "Release candidate awaiting signed production admission.",
                "draft": True,
                "prerelease": False,
                "generate_release_notes": False,
                "make_latest": "false",
            },
        )
        if not isinstance(release, dict):
            raise ReleaseStagingError("GitHub did not return the created draft release")
    _verify_release_shape(release, tag=tag, source_commit=source_commit, require_draft=True)
    assets = _ensure_assets(
        client,
        release,
        repository=repository,
        dist=dist,
        inventory=inventory,
        upload_missing=True,
    )
    return _staging_object(
        repository=repository,
        repository_id=repository_id,
        release=release,
        tag=tag,
        source_commit=source_commit,
        assets=assets,
        tag_rulesets=tag_rulesets,
        observed_at=observed_at,
    )


def verify_staged_release(
    client: GitHubClient,
    *,
    dist: Path,
    inventory_path: Path,
    staging_path: Path,
    require_draft: bool,
) -> dict[str, Any]:
    expected = _load_canonical_staging(staging_path)
    inventory = verify_inventory(dist, inventory_path)
    repository = expected["repository"]
    repository_id = expected["repository_id"]
    tag = expected["tag"]
    source_commit = expected["target_commitish"]
    tag_rulesets = _verify_identity_and_settings(
        client,
        repository=repository,
        repository_id=repository_id,
        tag=tag,
    )
    release_id = expected["draft_release_id"]
    release = client.request_json(f"https://api.github.com/repos/{repository}/releases/{release_id}")
    if not isinstance(release, dict):
        raise ReleaseStagingError("GitHub returned no bound release")
    _verify_release_shape(
        release,
        tag=tag,
        source_commit=source_commit,
        require_draft=require_draft,
    )
    if not require_draft and release.get("immutable") is not True:
        raise ReleaseStagingError("published GitHub release is not immutable")
    assets = _ensure_assets(
        client,
        release,
        repository=repository,
        dist=dist,
        inventory=inventory,
        upload_missing=False,
    )
    actual = _staging_object(
        repository=repository,
        repository_id=repository_id,
        release=release,
        tag=tag,
        source_commit=source_commit,
        assets=assets,
        tag_rulesets=tag_rulesets,
        observed_at=expected["observed_at"],
    )
    if actual != expected:
        raise ReleaseStagingError("live GitHub staging state differs from the admitted object")
    return expected


def publish_staged_release(
    client: GitHubClient,
    *,
    dist: Path,
    inventory_path: Path,
    staging_path: Path,
) -> dict[str, Any]:
    """Publish the one admitted draft, or verify its prior publication."""
    expected = _load_canonical_staging(staging_path)
    repository = expected["repository"]
    release_id = expected["draft_release_id"]
    release = client.request_json(f"https://api.github.com/repos/{repository}/releases/{release_id}")
    if not isinstance(release, dict):
        raise ReleaseStagingError("GitHub returned no bound release")
    if release.get("draft") is False:
        return verify_staged_release(
            client,
            dist=dist,
            inventory_path=inventory_path,
            staging_path=staging_path,
            require_draft=False,
        )
    verify_staged_release(
        client,
        dist=dist,
        inventory_path=inventory_path,
        staging_path=staging_path,
        require_draft=True,
    )
    published = client.request_json(
        f"https://api.github.com/repos/{repository}/releases/{release_id}",
        method="PATCH",
        payload={
            "draft": False,
            "prerelease": False,
            "make_latest": "legacy",
            "name": expected["tag"],
            "body": f"OpenAdapt Capture {expected['tag']}.",
        },
    )
    if not isinstance(published, dict):
        raise ReleaseStagingError("GitHub did not return the published release")
    return verify_staged_release(
        client,
        dist=dist,
        inventory_path=inventory_path,
        staging_path=staging_path,
        require_draft=False,
    )


def _load_canonical_staging(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReleaseStagingError(f"publication staging evidence is unreadable: {exc}") from exc
    if not isinstance(value, dict) or set(value) != STAGING_FIELDS:
        raise ReleaseStagingError("publication staging evidence has an unexpected field set")
    if raw != _canonical_json_bytes(value) + b"\n":
        raise ReleaseStagingError("publication staging evidence is not canonical JSON")
    if value.get("schema_version") != STAGING_SCHEMA_VERSION:
        raise ReleaseStagingError("publication staging evidence schema is not supported")
    fixed = {
        "repository": "OpenAdaptAI/openadapt-capture",
        "repository_id": REPOSITORY_ID,
        "draft": True,
        "prerelease": False,
        "release_app_id": RELEASE_APP_ID,
        "release_app_installation_id": RELEASE_APP_INSTALLATION_ID,
        "release_app_bot_user_id": RELEASE_BOT_USER_ID,
        "release_author_login": RELEASE_BOT_LOGIN,
        "immutable_releases_enabled": True,
    }
    if any(value.get(key) != expected for key, expected in fixed.items()):
        raise ReleaseStagingError("publication staging evidence has an invalid fixed value")
    _decimal_id(value.get("draft_release_id"), label="draft release")
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", str(value.get("tag"))) is None:
        raise ReleaseStagingError("publication staging evidence has an invalid tag")
    if re.fullmatch(r"[0-9a-f]{40}", str(value.get("target_commitish"))) is None:
        raise ReleaseStagingError("publication staging evidence has an invalid source commit")
    assets = value.get("assets")
    if not isinstance(assets, list) or any(
        not isinstance(asset, dict) or set(asset) != ASSET_FIELDS for asset in assets
    ):
        raise ReleaseStagingError("publication staging evidence has an invalid asset set")
    if len(assets) != 2:
        raise ReleaseStagingError("publication staging evidence must contain two assets")
    asset_order = [(asset["name"], asset["asset_id"]) for asset in assets]
    if asset_order != sorted(asset_order) or len(asset_order) != len(set(asset_order)):
        raise ReleaseStagingError("publication staging evidence assets are not sorted and unique")
    if len({asset["name"] for asset in assets}) != len(assets):
        raise ReleaseStagingError("publication staging evidence repeats an asset name")
    for asset in assets:
        _decimal_id(asset.get("asset_id"), label="release asset")
        if asset.get("uploader_id") != RELEASE_BOT_USER_ID or asset.get(
            "uploader_login"
        ) != RELEASE_BOT_LOGIN:
            raise ReleaseStagingError("publication staging evidence has an invalid uploader")
        if not isinstance(asset.get("name"), str) or Path(asset["name"]).name != asset["name"]:
            raise ReleaseStagingError("publication staging evidence has an unsafe asset name")
        if not isinstance(asset.get("sha256"), str) or SHA256_PATTERN.fullmatch(
            asset["sha256"]
        ) is None:
            raise ReleaseStagingError("publication staging evidence has an invalid asset digest")
        if not isinstance(asset.get("size_bytes"), int) or asset["size_bytes"] < 0:
            raise ReleaseStagingError("publication staging evidence has an invalid asset size")
    rulesets = value.get("tag_rulesets")
    if not isinstance(rulesets, list) or any(
        not isinstance(ruleset, dict) or set(ruleset) != RULESET_FIELDS for ruleset in rulesets
    ):
        raise ReleaseStagingError("publication staging evidence has an invalid ruleset set")
    if len(rulesets) != 2 or [ruleset.get("role") for ruleset in rulesets] != [
        "creation_authority",
        "immutability",
    ]:
        raise ReleaseStagingError("publication staging evidence has an invalid ruleset role set")
    if value.get("tag_rulesets_sha256") != _canonical_digest(
        RULESETS_DIGEST_DOMAIN,
        rulesets,
    ):
        raise ReleaseStagingError("publication staging evidence has an invalid ruleset digest")
    for ruleset in rulesets:
        if (
            ruleset.get("schema_version") != RULESET_SCHEMA_VERSION
            or ruleset.get("repository") != fixed["repository"]
            or ruleset.get("repository_id") != REPOSITORY_ID
            or ruleset.get("target") != "tag"
            or ruleset.get("enforcement") != "active"
        ):
            raise ReleaseStagingError("publication staging evidence has an invalid ruleset")
        _decimal_id(ruleset.get("ruleset_id"), label="tag ruleset")
    _observed_at(value.get("observed_at"))
    return value


def _observed_at(value: str | None) -> str:
    if value is not None:
        if not isinstance(value, str):
            raise ReleaseStagingError("--observed-at must be an RFC 3339 timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ReleaseStagingError("--observed-at must be an RFC 3339 timestamp") from exc
        if parsed.tzinfo is None:
            raise ReleaseStagingError("--observed-at must include a timezone")
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_canonical(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical_json_bytes(value) + b"\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage = subparsers.add_parser("stage")
    stage.add_argument("--repository", required=True)
    stage.add_argument("--repository-id", default=REPOSITORY_ID)
    stage.add_argument("--source-commit", required=True)
    stage.add_argument("--tag", required=True)
    stage.add_argument("--dist", type=Path, required=True)
    stage.add_argument("--inventory", type=Path, required=True)
    stage.add_argument("--observed-at")
    stage.add_argument("--output", type=Path, required=True)
    stage.add_argument("--github-output", type=Path)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--dist", type=Path, required=True)
    verify.add_argument("--inventory", type=Path, required=True)
    verify.add_argument("--staging", type=Path, required=True)
    verify.add_argument("--published", action="store_true")
    publish = subparsers.add_parser("publish")
    publish.add_argument("--dist", type=Path, required=True)
    publish.add_argument("--inventory", type=Path, required=True)
    publish.add_argument("--staging", type=Path, required=True)
    args = parser.parse_args()
    token = os.environ.get("GH_TOKEN")
    try:
        client = GitHubClient(token or "")
        if args.command == "stage":
            if args.repository != "OpenAdaptAI/openadapt-capture":
                raise ReleaseStagingError("repository differs from the Capture production target")
            if args.repository_id != REPOSITORY_ID:
                raise ReleaseStagingError("repository ID differs from the Capture production target")
            if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
                raise ReleaseStagingError("source commit must be a lowercase 40-character SHA")
            if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.tag) is None:
                raise ReleaseStagingError("tag must be an exact stable semantic version")
            staging = stage_release(
                client,
                repository=args.repository,
                repository_id=args.repository_id,
                source_commit=args.source_commit,
                tag=args.tag,
                dist=args.dist,
                inventory_path=args.inventory,
                observed_at=_observed_at(args.observed_at),
            )
            _write_canonical(args.output, staging)
            if args.github_output is not None:
                with args.github_output.open("a", encoding="utf-8") as output:
                    output.write(
                        "publication_staging_json="
                        + _canonical_json_bytes(staging).decode("utf-8")
                        + "\n"
                    )
                    output.write(
                        "publication_staging_sha256="
                        + _canonical_digest(STAGING_DIGEST_DOMAIN, staging)
                        + "\n"
                    )
                    output.write(f"draft_release_id={staging['draft_release_id']}\n")
            print(_canonical_json_bytes(staging).decode("utf-8"))
        elif args.command == "verify":
            verify_staged_release(
                client,
                dist=args.dist,
                inventory_path=args.inventory,
                staging_path=args.staging,
                require_draft=not args.published,
            )
            print(f"verified durable release staging in {args.staging}")
        else:
            publish_staged_release(
                client,
                dist=args.dist,
                inventory_path=args.inventory,
                staging_path=args.staging,
            )
            print(f"published the admitted durable release in {args.staging}")
    except ReleaseStagingError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
