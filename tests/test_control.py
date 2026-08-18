"""Security and lifecycle tests for cross-process Capture control."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import psutil
import pytest

from openadapt_capture import control
from openadapt_capture import recorder as recorder_module
from openadapt_capture.control import (
    CaptureControlError,
    CaptureControlUnavailable,
    RecorderControlServer,
    discover_recorders,
    status_recording,
    stop_recording,
)


def _terminal_payload(capture_dir: Path, session_id: str) -> dict:
    return {
        "schema_version": control.TERMINAL_STATE_SCHEMA_VERSION,
        "session_id": session_id,
        "pid": os.getpid(),
        "process_started_at": psutil.Process().create_time(),
        "capture_dir": str(capture_dir),
        "phase": "recording",
        "ready": True,
        "complete": False,
        "integrity_verified": False,
        "error_code": None,
        "started_at": time.time(),
        "finalized_at": None,
        "event_counts": {
            "action": 0,
            "screen": 0,
            "window": 0,
            "browser": 0,
            "video": 0,
        },
    }


def _wait_for_session(runtime_dir: Path, timeout: float = 15.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sessions = discover_recorders(runtime_dir)
        if len(sessions) == 1:
            try:
                if status_recording(sessions[0], runtime_dir=runtime_dir, timeout=1).ready:
                    return sessions[0]
            except CaptureControlError:
                pass
        time.sleep(0.05)
    raise AssertionError("the subprocess recorder did not publish its control session")


def _start_child(
    tmp_path: Path,
    *,
    stall: bool = False,
) -> tuple[subprocess.Popen[str], Path, Path]:
    capture_dir = tmp_path / "capture"
    runtime_dir = tmp_path / "runtime"
    env = os.environ.copy()
    if stall:
        env["OPENADAPT_CONTROL_TEST_STALL"] = "1"
    child = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).with_name("control_recorder_process.py")),
            str(capture_dir),
            str(runtime_dir),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    return child, capture_dir, runtime_dir


def _finish_child(child: subprocess.Popen[str]) -> tuple[str, str]:
    try:
        stdout, stderr = child.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        child.kill()
        stdout, stderr = child.communicate(timeout=5)
        raise AssertionError(f"recorder child did not exit\nstdout={stdout}\nstderr={stderr}")
    return stdout, stderr


def test_subprocess_ready_status_stop_and_complete(tmp_path: Path) -> None:
    """The same public contract runs on the macOS, Windows, and Linux matrix."""
    child, capture_dir, runtime_dir = _start_child(tmp_path)
    try:
        session_id = _wait_for_session(runtime_dir)
        current = status_recording(session_id, runtime_dir=runtime_dir)
        assert current.phase == "recording"
        assert current.ready
        assert not current.complete

        completed = stop_recording(session_id, runtime_dir=runtime_dir, timeout=10)
        assert completed.phase == "complete"
        assert completed.complete
        assert completed.integrity_verified
        stdout, stderr = _finish_child(child)
        assert child.returncode == 0, f"stdout={stdout}\nstderr={stderr}"
        terminal = json.loads(
            (capture_dir / control.TERMINAL_STATE_FILENAME).read_text(encoding="utf-8")
        )
        assert terminal["session_id"] == session_id
        assert terminal["complete"] is True
        assert terminal["integrity_verified"] is True
        assert "token" not in terminal
        assert "capture_dir" not in terminal
        assert discover_recorders(runtime_dir) == []
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_concurrent_repeated_stop_is_idempotent(tmp_path: Path) -> None:
    child, _capture_dir, runtime_dir = _start_child(tmp_path)
    try:
        session_id = _wait_for_session(runtime_dir)
        results: list[object] = []

        def request_stop() -> None:
            try:
                results.append(stop_recording(session_id, runtime_dir=runtime_dir, timeout=10))
            except BaseException as exc:  # retained for an exact assertion below
                results.append(exc)

        callers = [threading.Thread(target=request_stop) for _ in range(2)]
        for caller in callers:
            caller.start()
        for caller in callers:
            caller.join(timeout=15)
        assert len(results) == 2
        assert all(not isinstance(result, BaseException) for result in results), repr(results)
        assert all(result.complete for result in results)  # type: ignore[union-attr]
        _finish_child(child)
        assert child.returncode == 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_crash_recovery_removes_only_proven_stale_endpoint(tmp_path: Path) -> None:
    child, capture_dir, runtime_dir = _start_child(tmp_path)
    session_id = _wait_for_session(runtime_dir)
    child.kill()
    _finish_child(child)

    assert discover_recorders(runtime_dir) == []
    assert not (runtime_dir / f"{session_id}.json").exists()
    terminal = json.loads(
        (capture_dir / control.TERMINAL_STATE_FILENAME).read_text(encoding="utf-8")
    )
    assert terminal["phase"] == "crashed"
    assert terminal["complete"] is False
    assert terminal["error_code"] == "recorder_process_exited"


def test_finalization_timeout_is_not_success(tmp_path: Path) -> None:
    child, capture_dir, runtime_dir = _start_child(tmp_path, stall=True)
    try:
        session_id = _wait_for_session(runtime_dir)
        with pytest.raises(CaptureControlError, match="finalization_timeout"):
            stop_recording(session_id, runtime_dir=runtime_dir, timeout=0.05)
        terminal = json.loads(
            (capture_dir / control.TERMINAL_STATE_FILENAME).read_text(encoding="utf-8")
        )
        assert terminal["complete"] is False
        assert terminal["integrity_verified"] is False
        assert terminal["error_code"] == "finalization_timeout"
        stdout, stderr = _finish_child(child)
        assert child.returncode == 0, f"stdout={stdout}\nstderr={stderr}"
        terminal = json.loads(
            (capture_dir / control.TERMINAL_STATE_FILENAME).read_text(encoding="utf-8")
        )
        assert terminal["complete"] is True
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_wrong_token_and_replaced_instance_fail_closed(tmp_path: Path) -> None:
    state = _terminal_payload(tmp_path / "capture", str(uuid.uuid4()))
    stop_calls = 0

    def snapshot() -> dict:
        return dict(state)

    def stop(_timeout: float) -> dict:
        nonlocal stop_calls
        stop_calls += 1
        return dict(state)

    server = RecorderControlServer(
        capture_dir=state["capture_dir"],
        snapshot=snapshot,
        stop=stop,
        session_id=state["session_id"],
        runtime_dir=tmp_path / "runtime",
    ).start()
    try:
        descriptor = control._parse_descriptor(server.descriptor_path)  # type: ignore[arg-type]
        request = {
            "schema_version": control.CONTROL_SCHEMA_VERSION,
            "command": "status",
            "session_id": descriptor.session_id,
            "pid": descriptor.pid,
            "process_started_at": descriptor.process_started_at,
            "request_id": str(uuid.uuid4()),
            "issued_at": time.time(),
            "timeout_seconds": 1.0,
        }
        request["mac"] = control._message_mac("x" * 64, request)
        with socket.create_connection((descriptor.host, descriptor.port), timeout=2) as peer:
            peer.sendall(control._canonical_json(request) + b"\n")
            response = json.loads(control._recv_line(peer))
        assert response["ok"] is False
        assert response["error_code"] == "authentication_failed"
        assert "token" not in response

        request["request_id"] = str(uuid.uuid4())
        request["mac"] = control._message_mac(descriptor.token, request)
        with socket.create_connection((descriptor.host, descriptor.port), timeout=2) as peer:
            peer.sendall(control._canonical_json(request) + b"\n")
            first_response = json.loads(control._recv_line(peer))
        assert first_response["ok"] is True
        with socket.create_connection((descriptor.host, descriptor.port), timeout=2) as peer:
            peer.sendall(control._canonical_json(request) + b"\n")
            replay_response = json.loads(control._recv_line(peer))
        assert replay_response["ok"] is False
        assert replay_response["error_code"] == "authentication_failed"

        request["request_id"] = str(uuid.uuid4())
        request["process_started_at"] += 10
        request["mac"] = control._message_mac(descriptor.token, request)
        with socket.create_connection((descriptor.host, descriptor.port), timeout=2) as peer:
            peer.sendall(control._canonical_json(request) + b"\n")
            response = json.loads(control._recv_line(peer))
        assert response["ok"] is False
        assert response["error_code"] == "authentication_failed"
        assert stop_calls == 0
    finally:
        server.close()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode assertion")
def test_runtime_secret_is_owner_only_and_wrong_owner_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _terminal_payload(tmp_path / "capture", str(uuid.uuid4()))
    server = RecorderControlServer(
        capture_dir=state["capture_dir"],
        snapshot=lambda: dict(state),
        stop=lambda _timeout: dict(state),
        session_id=state["session_id"],
        runtime_dir=tmp_path / "runtime",
    ).start()
    try:
        assert stat.S_IMODE((tmp_path / "runtime").stat().st_mode) == 0o700
        assert server.descriptor_path is not None
        assert stat.S_IMODE(server.descriptor_path.stat().st_mode) == 0o600
        raw = server.descriptor_path.read_text(encoding="utf-8")
        token = json.loads(raw)["token"]
        assert token not in repr(control._parse_descriptor(server.descriptor_path))

        actual_uid = os.getuid()
        monkeypatch.setattr(os, "getuid", lambda: actual_uid + 1)
        with pytest.raises(PermissionError, match="does not own"):
            control._parse_descriptor(server.descriptor_path)
    finally:
        server.close()


def test_multiple_sessions_require_exact_selection(tmp_path: Path) -> None:
    state_one = _terminal_payload(tmp_path / "one", str(uuid.uuid4()))
    state_two = _terminal_payload(tmp_path / "two", str(uuid.uuid4()))
    servers = [
        RecorderControlServer(
            capture_dir=state["capture_dir"],
            snapshot=lambda state=state: dict(state),
            stop=lambda _timeout, state=state: dict(state),
            session_id=state["session_id"],
            runtime_dir=tmp_path / "runtime",
        ).start()
        for state in (state_one, state_two)
    ]
    try:
        with pytest.raises(CaptureControlUnavailable, match="More than one"):
            status_recording(runtime_dir=tmp_path / "runtime")
        assert (
            status_recording(state_one["session_id"], runtime_dir=tmp_path / "runtime").session_id
            == state_one["session_id"]
        )
    finally:
        for server in servers:
            server.close()


def test_unauthenticated_descriptor_is_never_deleted(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    invalid = runtime_dir / f"{uuid.uuid4()}.json"
    invalid.write_text('{"pid": 999999}\n', encoding="utf-8")
    if sys.platform != "win32":
        invalid.chmod(0o600)
    assert discover_recorders(runtime_dir) == []
    assert invalid.exists()


def test_pid_reuse_descriptor_is_marked_crashed_and_removed(tmp_path: Path) -> None:
    runtime_dir = control._secure_runtime_dir(tmp_path / "runtime")
    capture_dir = tmp_path / "capture"
    session_id = str(uuid.uuid4())
    stale_start = psutil.Process().create_time() - 100.0
    terminal = _terminal_payload(capture_dir, session_id)
    terminal["process_started_at"] = stale_start
    control.write_terminal_state(capture_dir, terminal)
    descriptor = control._ControlDescriptor(
        session_id=session_id,
        pid=os.getpid(),
        process_started_at=stale_start,
        capture_dir=str(capture_dir),
        host="127.0.0.1",
        port=65534,
        created_at=time.time(),
        path=runtime_dir / f"{session_id}.json",
        token="x" * 64,
    )
    control._write_json_atomic(
        descriptor.path,
        descriptor.serialized(),
        owner_only=True,
    )

    assert discover_recorders(runtime_dir) == []
    assert not descriptor.path.exists()
    recovered = json.loads(
        (capture_dir / control.TERMINAL_STATE_FILENAME).read_text(encoding="utf-8")
    )
    assert recovered["phase"] == "crashed"
    assert recovered["complete"] is False


def test_recorder_failure_keeps_incomplete_state_and_removes_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture_dir = tmp_path / "capture"
    runtime_dir = tmp_path / "runtime"

    def fail_after_ready(*, status_pipe, **_kwargs) -> None:
        status_pipe.send({"type": "record.started"})
        raise RuntimeError("synthetic recorder failure")

    monkeypatch.setattr(recorder_module, "record", fail_after_ready)
    recorder = recorder_module.Recorder(
        str(capture_dir),
        capture_video=False,
        capture_images=True,
        control_runtime_dir=str(runtime_dir),
    )
    with pytest.raises(RuntimeError, match="synthetic recorder failure"):
        with recorder:
            recorder.wait_for_ready(timeout=2)

    assert discover_recorders(runtime_dir) == []
    terminal = json.loads(
        (capture_dir / control.TERMINAL_STATE_FILENAME).read_text(encoding="utf-8")
    )
    assert terminal["phase"] == "failed"
    assert terminal["complete"] is False
    assert terminal["integrity_verified"] is False
    assert terminal["error_code"] == "recording_or_finalization_failed"
