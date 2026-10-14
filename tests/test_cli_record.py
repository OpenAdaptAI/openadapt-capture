"""Behavior tests for the public capture CLI recording path."""

from __future__ import annotations

import pytest

from openadapt_capture.cli import record, status, stop
from openadapt_capture.control import CaptureControlUnavailable, RecorderStatus
from openadapt_capture.input_observer import (
    InputObserverPermissionError,
    InputObserverUnavailableError,
)
from openadapt_capture.video import FFmpegUnavailableError


class _RecorderThatNeverBecomesReady:
    """Small recorder double for startup-failure behavior."""

    def __init__(self, *args, **kwargs):
        self.event_count = 0
        self.exited = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.exited = True
        return False

    def wait_for_ready(self):
        return False


def test_record_refuses_when_recorder_never_becomes_ready(monkeypatch, tmp_path, capsys):
    import openadapt_capture.recorder as recorder_module

    recorder = None

    def recorder_factory(*args, **kwargs):
        nonlocal recorder
        recorder = _RecorderThatNeverBecomesReady(*args, **kwargs)
        return recorder

    monkeypatch.setattr(recorder_module, "Recorder", recorder_factory)

    with pytest.raises(SystemExit) as raised:
        record(str(tmp_path / "capture"), video=False)

    assert raised.value.code == 1
    assert recorder is not None and recorder.exited
    output = capsys.readouterr().out
    assert "did not become ready" in output
    assert "Recorded 0 events" not in output
    assert "Saved to:" not in output


class _RecorderThatFailsStartup(_RecorderThatNeverBecomesReady):
    """Recorder double whose startup surfaces a worker setup error."""

    error: BaseException

    def wait_for_ready(self):
        raise self.error


@pytest.mark.parametrize(
    "error",
    [
        FFmpegUnavailableError(
            "Video capture needs an FFmpeg executable, and none is installed."
        ),
        InputObserverPermissionError(
            "macOS denied global input observation. In System Settings > "
            "Privacy & Security > Input Monitoring, allow the app that runs "
            "the recorder."
        ),
        InputObserverUnavailableError(
            "X RECORD requires an X11 desktop and DISPLAY is not set"
        ),
    ],
)
def test_record_prints_the_setup_fix_instead_of_a_traceback(
    monkeypatch, tmp_path, capsys, error
):
    import openadapt_capture.recorder as recorder_module

    recorder = None

    def recorder_factory(*args, **kwargs):
        nonlocal recorder
        recorder = _RecorderThatFailsStartup(*args, **kwargs)
        recorder.error = error
        return recorder

    monkeypatch.setattr(recorder_module, "Recorder", recorder_factory)

    with pytest.raises(SystemExit) as raised:
        record(str(tmp_path / "capture"), video=False)

    assert raised.value.code == 1
    assert raised.value.__cause__ is error
    assert recorder is not None and recorder.exited
    output = capsys.readouterr().out
    assert f"Recording did not start: {error}" in output
    assert "No successful capture was saved." in output
    assert "Saved to:" not in output


def test_record_names_the_configured_stop_sequences(monkeypatch, tmp_path, capsys):
    import openadapt_capture.recorder as recorder_module
    from openadapt_capture.config import settings

    monkeypatch.setattr(recorder_module, "Recorder", _RecorderThatNeverBecomesReady)
    monkeypatch.setattr(
        settings,
        "STOP_SEQUENCES",
        [list("oa.stop"), ["ctrl", "ctrl", "ctrl"], ["ctrl", "alt"], []],
    )

    with pytest.raises(SystemExit):
        record(str(tmp_path / "capture"), video=False)

    output = capsys.readouterr().out
    assert (
        "To stop, press Ctrl+C here. In any app, you can also type oa.stop, "
        "press Ctrl 3 times, or press ctrl alt."
    ) in output

    monkeypatch.setattr(settings, "STOP_SEQUENCES", [list("oa.stop")])
    with pytest.raises(SystemExit):
        record(str(tmp_path / "capture"), video=False)
    assert (
        "To stop, press Ctrl+C here. In any app, you can also type oa.stop.\n"
    ) in capsys.readouterr().out

    monkeypatch.setattr(settings, "STOP_SEQUENCES", [])
    with pytest.raises(SystemExit):
        record(str(tmp_path / "capture"), video=False)
    assert "To stop, press Ctrl+C here.\n" in capsys.readouterr().out


def _status_result() -> RecorderStatus:
    return RecorderStatus(
        session_id="7fce2c55-5391-47d4-96bf-b3c90feaa69f",
        pid=42,
        process_started_at=100.0,
        capture_dir="/capture",
        phase="complete",
        ready=True,
        complete=True,
        integrity_verified=True,
        event_counts={"action": 1},
    )


def test_status_cli_calls_the_public_control_api(monkeypatch, capsys):
    import openadapt_capture.control as control_module

    monkeypatch.setattr(control_module, "status_recording", lambda *args, **kwargs: _status_result())
    status("7fce2c55-5391-47d4-96bf-b3c90feaa69f")
    output = capsys.readouterr().out
    assert '"phase": "complete"' in output
    assert '"integrity_verified": true' in output


def test_stop_cli_returns_non_success_when_no_recorder_exists(monkeypatch, capsys):
    import openadapt_capture.control as control_module

    def unavailable(*args, **kwargs):
        raise CaptureControlUnavailable("No live Capture recorder was found.")

    monkeypatch.setattr(control_module, "stop_recording", unavailable)
    with pytest.raises(SystemExit) as raised:
        stop()
    assert raised.value.code == 1
    assert "No live Capture recorder" in capsys.readouterr().out
