"""Immutable capture terminal and verified-consumer snapshot tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import openadapt_capture.terminal as terminal_module
from openadapt_capture.capture import CaptureSession
from openadapt_capture.db import create_db, crud
from openadapt_capture.terminal import (
    ARTIFACT_MANIFEST_FILENAME,
    CAPTURE_TERMINAL_FILENAME,
    CaptureSealError,
    seal_capture,
    verify_capture_artifacts,
)


def _capture_directory(root: Path) -> Path:
    capture_dir = root / "capture"
    capture_dir.mkdir(parents=True)
    engine, session_factory = create_db(str(capture_dir / "recording.db"))
    session = session_factory()
    crud.insert_recording(
        session,
        {
            "timestamp": 10.0,
            "monitor_width": 800,
            "monitor_height": 600,
            "double_click_interval_seconds": 0.5,
            "double_click_distance_pixels": 5,
            "platform": "test",
            "task_description": "sealed capture",
        },
    )
    session.close()
    engine.dispose()
    (capture_dir / "artifact.bin").write_bytes(b"artifact")
    (capture_dir / "capture-state.json").write_text('{"phase":"finalizing"}\n')
    return capture_dir


def _seal(capture_dir: Path):
    return seal_capture(
        capture_dir,
        session_id="session-1",
        process_started_at=9.0,
        capture_started_at=10.0,
        capture_ended_at=12.0,
        event_counts={
            "action": 0,
            "screen": 0,
            "window": 0,
            "browser": 0,
            "video": 0,
        },
        last_source_ordinal=None,
    )


def test_terminal_binds_canonical_manifest_bytes_including_newline(tmp_path) -> None:
    capture_dir = _capture_directory(tmp_path)
    terminal = _seal(capture_dir)
    manifest_raw = (capture_dir / ARTIFACT_MANIFEST_FILENAME).read_bytes()

    assert manifest_raw.endswith(b"\n")
    assert terminal.artifact_manifest_size_bytes == len(manifest_raw)
    assert terminal.artifact_manifest_sha256 == hashlib.sha256(
        b"openadapt.capture-artifact-manifest.v1\0" + manifest_raw
    ).hexdigest()
    assert (capture_dir / CAPTURE_TERMINAL_FILENAME).read_bytes().endswith(b"\n")
    verified_terminal, manifest = verify_capture_artifacts(capture_dir)
    assert verified_terminal == terminal
    assert [artifact.path for artifact in manifest.artifacts] == [
        "artifact.bin",
        "recording.db",
    ]


def test_mutable_control_state_is_not_part_of_the_immutable_inventory(tmp_path) -> None:
    capture_dir = _capture_directory(tmp_path)
    _seal(capture_dir)

    (capture_dir / "capture-state.json").write_text('{"phase":"complete"}\n')

    verify_capture_artifacts(capture_dir)


def test_terminal_rejects_artifact_tamper_and_uninventoried_files(tmp_path) -> None:
    capture_dir = _capture_directory(tmp_path)
    _seal(capture_dir)
    (capture_dir / "artifact.bin").write_bytes(b"changed")
    with pytest.raises(CaptureSealError, match="differs from its seal"):
        verify_capture_artifacts(capture_dir)

    other = _capture_directory(tmp_path / "other")
    _seal(other)
    (other / "late.txt").write_text("late")
    with pytest.raises(CaptureSealError, match="sealed inventory"):
        verify_capture_artifacts(other)


def test_manifest_rejects_symbolic_links(tmp_path) -> None:
    capture_dir = _capture_directory(tmp_path)
    (capture_dir / "linked.bin").symlink_to(capture_dir / "artifact.bin")

    with pytest.raises(CaptureSealError, match="not a regular file"):
        _seal(capture_dir)


def test_verifier_rejects_an_intermediate_directory_replaced_during_read(
    tmp_path,
    monkeypatch,
) -> None:
    capture_dir = _capture_directory(tmp_path)
    nested = capture_dir / "nested"
    nested.mkdir()
    (nested / "evidence.bin").write_bytes(b"evidence")
    _seal(capture_dir)
    moved = tmp_path / "moved-nested"
    original_hash = terminal_module._hash_relative_regular_file
    replaced = False

    def replace_then_hash(root, relative_path):
        nonlocal replaced
        if relative_path == "nested/evidence.bin" and not replaced:
            replaced = True
            nested.rename(moved)
            nested.symlink_to(moved, target_is_directory=True)
        return original_hash(root, relative_path)

    monkeypatch.setattr(
        terminal_module,
        "_hash_relative_regular_file",
        replace_then_hash,
    )

    with pytest.raises(CaptureSealError, match="path changed"):
        verify_capture_artifacts(capture_dir)


def test_verified_loader_uses_a_private_snapshot_without_migrating_source(tmp_path) -> None:
    capture_dir = _capture_directory(tmp_path)
    terminal = _seal(capture_dir)
    source_db = capture_dir / "recording.db"
    before = (source_db.stat().st_mtime_ns, hashlib.sha256(source_db.read_bytes()).hexdigest())

    with CaptureSession.load_verified(capture_dir) as capture:
        assert capture.task_description == "sealed capture"
        assert capture.capture_dir != capture_dir
        assert capture.capture_dir.parent != capture_dir.parent
        assert json.loads(
            (capture.capture_dir / CAPTURE_TERMINAL_FILENAME).read_text()
        )["terminal_sha256"] == terminal.terminal_sha256

    after = (source_db.stat().st_mtime_ns, hashlib.sha256(source_db.read_bytes()).hexdigest())
    assert after == before


def test_verified_loader_rejects_terminal_counts_that_differ_from_database(tmp_path) -> None:
    capture_dir = _capture_directory(tmp_path)
    seal_capture(
        capture_dir,
        session_id="session-1",
        process_started_at=9.0,
        capture_started_at=10.0,
        capture_ended_at=12.0,
        event_counts={
            "action": 1,
            "screen": 0,
            "window": 0,
            "browser": 0,
            "video": 0,
        },
        last_source_ordinal=None,
    )

    with pytest.raises(ValueError, match="action count"):
        CaptureSession.load_verified(capture_dir)


def test_verified_loader_rejects_multiple_recordings(tmp_path) -> None:
    capture_dir = _capture_directory(tmp_path)
    engine, session_factory = create_db(str(capture_dir / "recording.db"))
    session = session_factory()
    crud.insert_recording(
        session,
        {
            "timestamp": 20.0,
            "monitor_width": 800,
            "monitor_height": 600,
            "double_click_interval_seconds": 0.5,
            "double_click_distance_pixels": 5,
            "platform": "test",
            "task_description": "second recording",
        },
    )
    session.close()
    engine.dispose()
    _seal(capture_dir)

    with pytest.raises(ValueError, match="exactly one recording"):
        CaptureSession.load_verified(capture_dir)


def test_verified_loader_rejects_duplicate_source_ordinals(tmp_path) -> None:
    capture_dir = _capture_directory(tmp_path)
    engine, session_factory = create_db(str(capture_dir / "recording.db"))
    session = session_factory()
    recording = session.query(crud.Recording).one()
    for timestamp in (11.0, 12.0):
        crud.insert_screenshot(
            session,
            recording,
            timestamp,
            {"source_ordinal": 1, "png_sha256": None},
        )
    session.close()
    engine.dispose()
    seal_capture(
        capture_dir,
        session_id="session-1",
        process_started_at=9.0,
        capture_started_at=10.0,
        capture_ended_at=12.0,
        event_counts={
            "action": 0,
            "screen": 2,
            "window": 0,
            "browser": 0,
            "video": 0,
        },
        last_source_ordinal=1,
    )

    with pytest.raises(ValueError, match="reuse a source ordinal"):
        CaptureSession.load_verified(capture_dir)


def test_verified_loader_opens_an_encoded_immutable_database_uri(tmp_path) -> None:
    capture_dir = _capture_directory(tmp_path / "capture#fragment")
    _seal(capture_dir)

    with CaptureSession.load_verified(capture_dir) as capture:
        assert capture.task_description == "sealed capture"
