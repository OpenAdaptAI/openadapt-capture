"""Built archives use the same content rules as the public source tree."""

from __future__ import annotations

import json
import re
import stat
import zipfile
from pathlib import Path

import pytest

from scripts.check_source_boundary import BoundaryError, Policy, load_policy, scan_archive


def _policy() -> Policy:
    return Policy(
        path_tokens=("forbidden_path_token",),
        private_segments=frozenset({"private"}),
        path_prefixes=("forbidden/prefix",),
        content_patterns=re.compile(r"oracle[_-]recipe[_-]id\s*[:=]", re.IGNORECASE),
        archive_content_patterns=re.compile(
            r"deployment[-_]derived\s+threshold\s*=", re.IGNORECASE
        ),
        signatures=(b"OPENADAPT-CORPUS-PRIVATE-DO-NOT-PACKAGE",),
        repository="openadapt-capture",
        digest="sha256:" + "a" * 64,
    )


def test_policy_loads_the_archive_specific_content_patterns(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "policy_digest": "sha256:" + "a" * 64,
                "crown_jewel_categories": ["grown_corpus"],
                "public_repositories": {
                    "openadapt-capture": {
                        "classification": "public",
                        "must_not_contain": ["grown_corpus"],
                    }
                },
                "enforcement": {
                    "path_tokens": ["grown_corpus"],
                    "private_path_segments": ["private"],
                    "content_signature_parts": [["PRIVATE", "-SIGNATURE"]],
                    "repository_tree": {"content_patterns": ["tree_only_pattern"]},
                    "built_artifacts": {
                        "path_prefixes": ["forbidden/prefix"],
                        "content_patterns": ["archive_only_pattern"],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path, "openadapt-capture")

    assert policy.content_patterns.search("tree_only_pattern")
    assert not policy.content_patterns.search("archive_only_pattern")
    assert policy.archive_content_patterns.search("archive_only_pattern")


def test_archive_scan_applies_the_canonical_content_pattern(tmp_path: Path) -> None:
    wheel = tmp_path / "candidate.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "openadapt_capture/innocent_name.py",
            "deployment-derived threshold = 0.91\n",
        )

    assert scan_archive(wheel, _policy()) == [
        "candidate.whl:openadapt_capture/innocent_name.py:1: "
        "content matches a forbidden pattern"
    ]


def test_archive_scan_accepts_unrelated_public_text(tmp_path: Path) -> None:
    wheel = tmp_path / "candidate.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("openadapt_capture/module.py", "CAPTURE_SCHEMA = 'v1'\n")

    assert scan_archive(wheel, _policy()) == []


def test_archive_scan_rejects_an_unsafe_member_path(tmp_path: Path) -> None:
    wheel = tmp_path / "candidate.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("../outside.py", "safe = True\n")

    with pytest.raises(BoundaryError, match="unsafe archive member path"):
        scan_archive(wheel, _policy())


def test_archive_scan_rejects_duplicate_members(tmp_path: Path) -> None:
    wheel = tmp_path / "candidate.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("openadapt_capture/module.py", "first = True\n")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("openadapt_capture/module.py", "second = True\n")

    with pytest.raises(BoundaryError, match="duplicate archive member"):
        scan_archive(wheel, _policy())


def test_archive_scan_rejects_links(tmp_path: Path) -> None:
    wheel = tmp_path / "candidate.whl"
    link = zipfile.ZipInfo("openadapt_capture/link.py")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(link, "module.py")

    with pytest.raises(BoundaryError, match="non-regular archive member"):
        scan_archive(wheel, _policy())


def test_archive_scan_bounds_expanded_member_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "candidate.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("openadapt_capture/module.py", "safe = True\n")
    monkeypatch.setattr("scripts.check_source_boundary.ARCHIVE_MEMBER_SIZE_LIMIT", 4)

    with pytest.raises(BoundaryError, match="archive member .* is too large"):
        scan_archive(wheel, _policy())
