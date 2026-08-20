"""Static security contracts for the exact-artifact release transaction."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
FULL_ACTION_SHA = re.compile(r"(?:-\s+)?uses:\s+[^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$")


def _workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def test_every_release_bound_action_uses_an_immutable_commit() -> None:
    for name in (
        "control-contract.yml",
        "production-qualification.yml",
        "release.yml",
        "test.yml",
    ):
        action_lines = [line.strip() for line in _workflow(name).splitlines() if "uses:" in line]
        assert action_lines, name
        assert all(FULL_ACTION_SHA.fullmatch(line) for line in action_lines), (name, action_lines)


def test_release_transaction_never_rebuilds_the_qualified_archives() -> None:
    workflow = _workflow("release.yml")
    prepare = workflow.index("Prepare the versioned release commit")
    evidence = workflow.index("Wait for exact prepared-commit qualification")
    download = workflow.index("Download the exact qualified archives")
    publish = workflow.index("Publish the exact qualified archives to PyPI")
    parity = workflow.index("Verify PyPI parity and write the admission candidate")
    assert prepare < evidence < download < publish < parity
    assert "uv build" not in workflow
    assert "release_status" not in workflow


def test_pypi_token_isolated_from_manifest_and_candidate_finalization() -> None:
    workflow = _workflow("release.yml")
    publish_job = workflow[workflow.index("  publish-pypi:") : workflow.index("  finalize-candidate:")]
    assert "id-token: write" in publish_job
    assert "contents: write" not in publish_job
    assert "issues: write" not in publish_job
    assert "packages-dir: release-bundle/dist/" in publish_job
    assert "SHA256SUMS" not in publish_job
    assert "scripts/" not in publish_job
    assert "mv dist/SHA256SUMS evidence/SHA256SUMS" in workflow


def test_qualification_builds_once_after_version_preparation() -> None:
    workflow = _workflow("production-qualification.yml")
    prepared = workflow.index("Require a prepared versioned release commit")
    build = workflow.index("Build the candidate once")
    assert prepared < build
    assert workflow.count("uv build --wheel --sdist") == 1
    assert "Candidate control contract (${{ matrix.os }})" in workflow
    assert '"${wheel[0]}[linux]"' in workflow
    assert "gi.require_version('Atspi', '2.0')" in workflow
    assert workflow.count('"${GITHUB_WORKSPACE}/tests/test_structural_observation.py"') == 2
    assert workflow.count('"${GITHUB_WORKSPACE}/tests/test_window_capture.py"') == 2
    assert '"$env:GITHUB_WORKSPACE/tests/test_structural_observation.py"' in workflow


def test_pypi_latest_never_selects_a_production_default() -> None:
    source = (ROOT / "scripts" / "release_admission_candidate.py").read_text(encoding="utf-8")
    assert 'pypi_latest_is_authority": False' in source
    assert '"production_default": None' in source
    assert "/{urllib.parse.quote(version, safe='')}/json" in source
