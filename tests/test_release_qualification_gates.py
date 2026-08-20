"""Tests for the fail-closed production qualification and release gates."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.candidate_lifecycle import CandidateLifecycleError, verify_manifest
from scripts.check_display_topology import DisplayTopologyError, qualify_topology
from scripts.check_junit_no_skips import JUnitQualificationError, check_reports
from scripts.check_prepared_release import (
    PreparedReleaseError,
    validate_prepared_release,
)
from scripts.check_release_ci import (
    EXPECTED_QUALIFICATION_JOBS,
    ReleaseEvidenceError,
    check_once,
    validate_qualification_jobs,
)
from scripts.release_admission_candidate import (
    AdmissionCandidateError,
    build_admission_candidate,
    verify_registry_parity,
)


def _write_manifest(dist: Path, archives: list[Path]) -> Path:
    manifest = dist / "SHA256SUMS"
    manifest.write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in archives
        ),
        encoding="utf-8",
    )
    return manifest


def test_candidate_manifest_accounts_for_exact_wheel_and_sdist(tmp_path: Path) -> None:
    wheel = tmp_path / "openadapt_capture-1.2.2-py3-none-any.whl"
    sdist = tmp_path / "openadapt_capture-1.2.2.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    manifest = _write_manifest(tmp_path, [wheel, sdist])

    assert set(verify_manifest(tmp_path, manifest)) == {wheel.name, sdist.name}


def test_candidate_manifest_rejects_unaccounted_archive(tmp_path: Path) -> None:
    wheel = tmp_path / "openadapt_capture-1.2.2-py3-none-any.whl"
    sdist = tmp_path / "openadapt_capture-1.2.2.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    manifest = _write_manifest(tmp_path, [wheel])

    with pytest.raises(CandidateLifecycleError, match="manifest and candidate archives differ"):
        verify_manifest(tmp_path, manifest)


def _policy(path: Path) -> Path:
    policy = {
        "schema_version": "openadapt.production-lifecycle-policy/v1",
        "revision": 1,
        "targets": [
            {
                "id": "capture",
                "source_repository": "OpenAdaptAI/openadapt-capture",
                "release_kind": "public_package",
                "required_claim_scope": "qualified_native_recorder_release",
                "required_artifact_kinds": ["sdist", "wheel"],
                "package_index_project": "openadapt-capture",
                "artifact_authority_by_kind": {"sdist": "pypi", "wheel": "pypi"},
            }
        ],
    }
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def test_registry_parity_emits_only_an_explicit_not_admitted_candidate(
    tmp_path: Path,
) -> None:
    version = "1.3.0"
    wheel = tmp_path / f"openadapt_capture-{version}-py3-none-any.whl"
    sdist = tmp_path / f"openadapt_capture-{version}.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    manifest = _write_manifest(tmp_path, [wheel, sdist])

    def get_json(url: str) -> dict:
        assert url == f"https://pypi.org/pypi/openadapt-capture/{version}/json"
        return {
            "info": {"name": "openadapt-capture", "version": version},
            # A newer index version is deliberately irrelevant. PyPI latest is
            # not a Production selector.
            "releases": {"99.0.0": []},
            "urls": [
                {
                    "filename": path.name,
                    "url": f"https://files.pythonhosted.org/{path.name}",
                    "size": path.stat().st_size,
                    "digests": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
                    "yanked": False,
                    "packagetype": "bdist_wheel" if path.suffix == ".whl" else "sdist",
                }
                for path in (wheel, sdist)
            ],
        }

    endpoint, artifacts = verify_registry_parity(
        dist_dir=tmp_path,
        manifest_path=manifest,
        version=version,
        get_json=get_json,
    )
    candidate = build_admission_candidate(
        policy_path=_policy(tmp_path / "policy.json"),
        policy_commit="a" * 40,
        source_commit="b" * 40,
        version=version,
        endpoint=endpoint,
        artifacts=artifacts,
        verified_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
    )

    assert candidate["release_status"] == "not_admitted"
    assert candidate["production_default"] is None
    assert candidate["production_authority"]["activation_required"] is True
    assert candidate["production_authority"]["pypi_latest_is_authority"] is False
    assert candidate["release"]["version"] == version
    assert {item["kind"] for item in candidate["release"]["artifacts"]} == {
        "sdist",
        "wheel",
    }


def test_registry_parity_rejects_changed_published_bytes(tmp_path: Path) -> None:
    version = "1.3.0"
    wheel = tmp_path / f"openadapt_capture-{version}-py3-none-any.whl"
    sdist = tmp_path / f"openadapt_capture-{version}.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    manifest = _write_manifest(tmp_path, [wheel, sdist])

    def get_json(_url: str) -> dict:
        return {
            "info": {"name": "openadapt-capture", "version": version},
            "urls": [
                {
                    "filename": path.name,
                    "url": f"https://files.pythonhosted.org/{path.name}",
                    "size": path.stat().st_size,
                    "digests": {"sha256": "0" * 64},
                    "yanked": False,
                    "packagetype": "bdist_wheel" if path.suffix == ".whl" else "sdist",
                }
                for path in (wheel, sdist)
            ],
        }

    with pytest.raises(AdmissionCandidateError, match="does not verify exact archive"):
        verify_registry_parity(
            dist_dir=tmp_path,
            manifest_path=manifest,
            version=version,
            get_json=get_json,
        )


def test_prepared_release_binds_commit_version_and_changelog(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    for name in ("pyproject.toml", "CHANGELOG.md"):
        (repository / name).write_bytes((Path(__file__).parents[1] / name).read_bytes())
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(["git", "config", "user.name", "semantic-release"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "bot@openadapt.ai"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "add", "pyproject.toml", "CHANGELOG.md"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "chore: release 1.2.2"],
        cwd=repository,
        check=True,
    )
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    assert (
        validate_prepared_release(
            repository,
            expected_sha=sha,
            expected_version="1.2.2",
        )["tag"]
        == "v1.2.2"
    )

    with pytest.raises(PreparedReleaseError, match="subject"):
        validate_prepared_release(
            repository,
            expected_sha=sha,
            expected_version="1.2.3",
        )


def test_display_topology_requires_stable_multiple_monitors() -> None:
    snapshot = {
        "coordinate_space": "virtual_desktop_pixels",
        "origin": [-1920, 0],
        "viewport": [4480, 1440],
        "monitor_count": 2,
        "monitors": [[-1920, 0, 1920, 1080], [0, 0, 2560, 1440]],
    }

    evidence = qualify_topology(
        lambda: snapshot,
        minimum_monitors=2,
        samples=3,
        interval_seconds=0,
    )

    assert evidence["stable"] is True
    assert evidence["topology"] == snapshot


def test_display_topology_rejects_change_during_qualification() -> None:
    snapshots = iter(
        [
            {
                "coordinate_space": "virtual_desktop_pixels",
                "monitor_count": 2,
                "monitors": [[0, 0, 10, 10], [10, 0, 10, 10]],
            },
            {
                "coordinate_space": "virtual_desktop_pixels",
                "monitor_count": 2,
                "monitors": [[0, 0, 10, 10], [10, 0, 20, 10]],
            },
        ]
    )

    with pytest.raises(DisplayTopologyError, match="changed during qualification"):
        qualify_topology(
            lambda: next(snapshots),
            minimum_monitors=2,
            samples=2,
            interval_seconds=0,
        )


def test_junit_gate_rejects_a_skipped_test(tmp_path: Path) -> None:
    report = tmp_path / "qualification.xml"
    report.write_text(
        "<testsuites><testsuite><testcase name='ok'/><testcase name='no'>"
        "<skipped message='no display'/></testcase></testsuite></testsuites>",
        encoding="utf-8",
    )

    with pytest.raises(JUnitQualificationError, match="skipped 1 of 2"):
        check_reports([report])


def test_junit_gate_accepts_complete_tests(tmp_path: Path) -> None:
    report = tmp_path / "qualification.xml"
    report.write_text(
        "<testsuites><testsuite><testcase name='one'/><testcase name='two'/>"
        "</testsuite></testsuites>",
        encoding="utf-8",
    )

    assert check_reports([report]) == {
        "tests": 2,
        "skipped": 0,
        "failures": 0,
        "errors": 0,
    }


def _successful_jobs() -> list[dict[str, str]]:
    return [
        {"name": name, "status": "completed", "conclusion": "success"}
        for name in sorted(EXPECTED_QUALIFICATION_JOBS)
    ]


def test_release_gate_rejects_missing_qualification_job() -> None:
    jobs = _successful_jobs()[:-1]

    with pytest.raises(ReleaseEvidenceError, match="job set differs"):
        validate_qualification_jobs(jobs)


def test_release_gate_rejects_skipped_qualification_job() -> None:
    jobs = _successful_jobs()
    jobs[0] = {**jobs[0], "conclusion": "skipped"}

    with pytest.raises(ReleaseEvidenceError, match="incomplete jobs"):
        validate_qualification_jobs(jobs)


def test_release_gate_binds_both_workflows_and_jobs_to_exact_sha() -> None:
    sha = "a" * 40

    def get_json(url: str, _token: str):
        if "/test.yml/runs?" in url:
            return {
                "workflow_runs": [
                    {
                        "id": 10,
                        "head_sha": sha,
                        "event": "push",
                        "created_at": "2026-08-18T00:00:00Z",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
            }
        if "/production-qualification.yml/runs?" in url:
            return {
                "workflow_runs": [
                    {
                        "id": 20,
                        "head_sha": sha,
                        "event": "workflow_dispatch",
                        "created_at": "2026-08-18T00:01:00Z",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
            }
        if "/actions/runs/20/jobs?" in url:
            return {"jobs": _successful_jobs()}
        raise AssertionError(f"unexpected URL {url}")

    assert check_once(
        repository="OpenAdaptAI/openadapt-capture",
        sha=sha,
        token="test",
        get_json=get_json,
    ) == {"test.yml": 10, "production-qualification.yml": 20}
