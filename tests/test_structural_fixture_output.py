"""Contract tests for structural qualification fixture producer outputs."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.read_structural_fixture_output import (
    FixtureOutputError,
    read_fixture_output,
)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_reads_the_exact_fixture_output(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.json"
    output = _write(
        tmp_path / "producer.out",
        f"structural_fixture_path={fixture}\n"
        "structural_fixture_instance_uuid=293e3c26-90c2-47fc-89c8-181a538b1693\n",
    )
    assert read_fixture_output(output) == {
        "structural_fixture_path": str(fixture),
        "structural_fixture_instance_uuid": (
            "293e3c26-90c2-47fc-89c8-181a538b1693"
        ),
    }


@pytest.mark.parametrize(
    "text",
    [
        "structural_fixture_path=relative.json\n"
        "structural_fixture_instance_uuid=293e3c26-90c2-47fc-89c8-181a538b1693\n",
        "structural_fixture_path=/tmp/fixture.json\n"
        "structural_fixture_path=/tmp/second.json\n"
        "structural_fixture_instance_uuid=293e3c26-90c2-47fc-89c8-181a538b1693\n",
        "structural_fixture_path=/tmp/fixture.json\n"
        "structural_fixture_instance_uuid=not-a-uuid\n",
        "structural_fixture_path=/tmp/fixture.json\n"
        "structural_fixture_instance_uuid=293e3c26-90c2-47fc-89c8-181a538b1693\n"
        "unexpected=value\n",
    ],
)
def test_rejects_ambiguous_or_unsafe_output(tmp_path: Path, text: str) -> None:
    output = _write(tmp_path / "producer.out", text)
    with pytest.raises(FixtureOutputError):
        read_fixture_output(output)
