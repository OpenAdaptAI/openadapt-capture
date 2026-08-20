#!/usr/bin/env python3
"""Verify that one exact commit is a prepared, versioned release candidate."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 test matrix.
    import tomli as tomllib

try:
    from scripts.check_changelog import validate_documents
except ModuleNotFoundError:  # Direct ``python scripts/...`` execution.
    from check_changelog import validate_documents

HEX40 = re.compile(r"^[0-9a-f]{40}$")
STABLE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class PreparedReleaseError(RuntimeError):
    """The checked-out commit is not the exact prepared release candidate."""


def _git(repository: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PreparedReleaseError(f"git {' '.join(args)} failed") from exc
    return result.stdout.strip()


def validate_prepared_release(
    repository: Path,
    *,
    expected_sha: str,
    expected_version: str,
) -> dict[str, str]:
    """Bind the release commit, package version, and maintained changelog."""

    if HEX40.fullmatch(expected_sha) is None:
        raise PreparedReleaseError("the expected source commit is not a lowercase SHA")
    if STABLE_VERSION.fullmatch(expected_version) is None:
        raise PreparedReleaseError("the expected release version is not stable SemVer")

    actual_sha = _git(repository, "rev-parse", "HEAD")
    if actual_sha != expected_sha:
        raise PreparedReleaseError(
            f"the checkout is {actual_sha}, not prepared source commit {expected_sha}"
        )
    if _git(repository, "status", "--porcelain"):
        raise PreparedReleaseError("the prepared release checkout is not clean")

    subject = _git(repository, "log", "-1", "--pretty=format:%s")
    expected_subject = f"chore: release {expected_version}"
    if subject != expected_subject:
        raise PreparedReleaseError(
            f"the prepared release subject is {subject!r}, not {expected_subject!r}"
        )
    author = _git(repository, "log", "-1", "--pretty=format:%an")
    if author != "semantic-release":
        raise PreparedReleaseError(
            f"the prepared release author is {author!r}, not 'semantic-release'"
        )

    try:
        project = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise PreparedReleaseError("pyproject.toml has no valid project metadata") from exc
    if project.get("name") != "openadapt-capture":
        raise PreparedReleaseError("the prepared package name is not openadapt-capture")
    if project.get("version") != expected_version:
        raise PreparedReleaseError("the prepared package version differs from the request")

    try:
        releases = validate_documents(
            (repository / "CHANGELOG.md").read_text(encoding="utf-8"),
            (repository / "pyproject.toml").read_text(encoding="utf-8"),
        )
    except (OSError, ValueError) as exc:
        raise PreparedReleaseError("the maintained changelog is invalid") from exc
    if releases[0].version != expected_version:
        raise PreparedReleaseError("the newest changelog release differs from the request")

    return {
        "source_commit": actual_sha,
        "version": expected_version,
        "tag": f"v{expected_version}",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    result = validate_prepared_release(
        args.repository.resolve(),
        expected_sha=args.expected_sha,
        expected_version=args.expected_version,
    )
    print(f"verified prepared release {result['tag']} at {result['source_commit']}")


if __name__ == "__main__":
    main()
