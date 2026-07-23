"""Platform-neutral and Linux contracts for native input observation."""

from __future__ import annotations

import ctypes
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from openadapt_capture import recorder as recorder_module
from openadapt_capture.capture import _convert_action_event
from openadapt_capture.events import MouseClickEvent, MouseDownEvent, MouseUpEvent
from openadapt_capture.input_observer import (
    InputObserverError,
    InputObserverUnavailableError,
    ObservedKey,
    ObservedMouseButton,
    ObservedMouseScroll,
    ThreadedInputObserver,
    add_exception_note,
    create_input_observer,
)
from openadapt_capture.input_observer.linux import (
    LinuxXInputObserver,
    _XIRawEvent,
    normalize_xinput_button_event,
    normalize_xinput_key_event,
)
from openadapt_capture.processing import merge_consecutive_mouse_click_events


class _CooperativeNeverReadyObserver(ThreadedInputObserver):
    def __init__(self) -> None:
        super().__init__(
            lambda event: None,
            observe_keyboard=True,
            observe_mouse=False,
            capture_mouse_moves=False,
            startup_timeout=0.02,
            shutdown_timeout=0.2,
        )
        self.resource_open = False
        self.torn_down = threading.Event()

    def _setup(self) -> None:
        self.resource_open = True
        self._stop_requested.wait()

    def _run_loop(self) -> None:
        return

    def _teardown(self) -> None:
        self.resource_open = False
        self.torn_down.set()


class _StubbornNeverReadyObserver(_CooperativeNeverReadyObserver):
    def __init__(self) -> None:
        super().__init__()
        self.shutdown_timeout = 0.01
        self.release_setup = threading.Event()

    def _setup(self) -> None:
        self.resource_open = True
        self.release_setup.wait()


class _ReadyObserver(ThreadedInputObserver):
    def __init__(self, callback=lambda _event: None) -> None:
        super().__init__(
            callback,
            observe_keyboard=True,
            observe_mouse=False,
            capture_mouse_moves=False,
            startup_timeout=0.2,
            shutdown_timeout=0.02,
        )
        self.release_loop = threading.Event()

    def _setup(self) -> None:
        return

    def _run_loop(self) -> None:
        self.release_loop.wait()

    def _teardown(self) -> None:
        return

    def _wake(self) -> None:
        self.release_loop.set()


def test_failed_startup_joins_and_tears_down_before_raising() -> None:
    observer = _CooperativeNeverReadyObserver()

    with pytest.raises(InputObserverError, match="did not become ready"):
        observer.start()

    assert observer._thread is None
    assert observer._delivery_thread is None
    assert observer.torn_down.is_set()
    assert not observer.resource_open


def test_lingering_failed_startup_cannot_be_reused_as_success() -> None:
    observer = _StubbornNeverReadyObserver()
    try:
        with pytest.raises(InputObserverError, match="did not become ready"):
            observer.start()
        assert observer._thread is not None
        assert observer._thread.is_alive()
        assert observer._delivery_thread is None

        with pytest.raises(InputObserverError, match="live thread from a failed startup"):
            observer.start()
    finally:
        observer.release_setup.set()
        deadline = time.monotonic() + 1
        while observer._thread is not None and observer._thread.is_alive():
            if time.monotonic() >= deadline:
                pytest.fail("stubborn observer thread did not finish after release")
            time.sleep(0.01)
        observer.stop()
    assert observer.torn_down.is_set()
    assert not observer.resource_open


def test_event_thread_start_failure_cleans_delivery_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = _ReadyObserver()
    original_start = threading.Thread.start

    def fail_event_thread(thread: threading.Thread) -> None:
        if thread.name.endswith("-event-loop"):
            raise RuntimeError("event thread start failed")
        original_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_event_thread)

    with pytest.raises(RuntimeError, match="event thread start failed"):
        observer.start()

    assert observer._thread is None
    assert observer._delivery_thread is None


def test_delivery_thread_start_failure_is_transactional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = _ReadyObserver()

    def fail_start(_thread: threading.Thread) -> None:
        raise RuntimeError("delivery thread start failed")

    monkeypatch.setattr(threading.Thread, "start", fail_start)

    with pytest.raises(RuntimeError, match="delivery thread start failed"):
        observer.start()

    assert observer._thread is None
    assert observer._delivery_thread is None


def test_first_failure_is_preserved_when_wake_also_fails() -> None:
    observer = _ReadyObserver()
    primary = InputObserverError("primary observer failure")

    def fail_wake() -> None:
        raise RuntimeError("wake failed")

    observer._wake = fail_wake  # type: ignore[method-assign]
    observer._fail(primary)

    with pytest.raises(InputObserverError, match="primary observer failure") as caught:
        observer.check_health()
    assert caught.value is primary
    assert any("wake failed" in note for note in getattr(primary, "__notes__", []))


def test_idempotent_start_surfaces_live_delivery_consumer_failure() -> None:
    callback_entered = threading.Event()

    def fail_consumer(_event) -> None:
        callback_entered.set()
        raise RuntimeError("consumer failed")

    observer = _ReadyObserver(fail_consumer)
    observer.start()
    observer._emit(ObservedKey(pressed=True, key_char="a"))
    assert callback_entered.wait(timeout=1)

    with pytest.raises(InputObserverError, match="consumer failed"):
        observer.start()
    with pytest.raises(InputObserverError, match="consumer failed"):
        observer.stop()


def test_event_shutdown_timeout_still_cleans_delivery_thread() -> None:
    class StubbornLoopObserver(_ReadyObserver):
        def _wake(self) -> None:
            return

    observer = StubbornLoopObserver()
    observer.start()

    with pytest.raises(InputObserverError, match="did not stop"):
        observer.stop()

    assert observer._thread is not None
    assert observer._thread.is_alive()
    assert observer._delivery_thread is None
    observer.release_loop.set()
    observer._thread.join(timeout=1)
    observer.stop()


def test_repeated_stop_retries_lingering_delivery_cleanup() -> None:
    callback_entered = threading.Event()
    release_callback = threading.Event()

    def block_consumer(_event) -> None:
        callback_entered.set()
        release_callback.wait()

    observer = _ReadyObserver(block_consumer)
    observer.start()
    observer._emit(ObservedKey(pressed=True, key_char="a"))
    assert callback_entered.wait(timeout=1)

    with pytest.raises(InputObserverError, match="delivery thread did not stop"):
        observer.stop()
    assert observer._delivery_thread is not None
    assert observer._delivery_thread.is_alive()

    release_callback.set()
    observer._delivery_thread.join(timeout=1)
    with pytest.raises(InputObserverError, match="delivery thread did not stop"):
        observer.stop()
    assert observer._delivery_thread is None


@pytest.mark.parametrize(
    ("detail", "pressed", "expected"),
    [
        (
            1,
            True,
            ObservedMouseButton(
                x=12,
                y=34,
                button="left",
                pressed=True,
            ),
        ),
        (
            2,
            False,
            ObservedMouseButton(
                x=12,
                y=34,
                button="middle",
                pressed=False,
            ),
        ),
        (
            4,
            True,
            ObservedMouseScroll(x=12, y=34, dx=0, dy=1),
        ),
        (
            7,
            True,
            ObservedMouseScroll(x=12, y=34, dx=1, dy=0),
        ),
        (
            8,
            True,
            ObservedMouseButton(
                x=12,
                y=34,
                button="x1",
                pressed=True,
            ),
        ),
        (
            9,
            False,
            ObservedMouseButton(
                x=12,
                y=34,
                button="x2",
                pressed=False,
            ),
        ),
        (4, False, None),
        (0, True, None),
    ],
)
def test_xinput_button_normalization(
    detail: int,
    pressed: bool,
    expected: ObservedMouseButton | ObservedMouseScroll | None,
) -> None:
    assert (
        normalize_xinput_button_event(
            detail=detail,
            pressed=pressed,
            x=12,
            y=34,
        )
        == expected
    )


def test_xinput_key_normalization_preserves_physical_and_canonical_identity() -> None:
    letter = normalize_xinput_key_event(
        keycode=38,
        pressed=True,
        keysym_name="A",
    )
    assert letter == ObservedKey(
        pressed=True,
        key_char="A",
        key_vk="38",
        canonical_key_char="a",
        canonical_key_vk="38",
    )

    modifier = normalize_xinput_key_event(
        keycode=50,
        pressed=False,
        keysym_name="Shift_L",
        injected=True,
    )
    assert modifier.key_name == "shift"
    assert modifier.canonical_key_name == "shift"
    assert modifier.injected


@pytest.mark.parametrize("button", ["x1", "x2", "button4"])
def test_auxiliary_mouse_button_survives_storage_conversion_and_processing(
    button: str,
) -> None:
    down = _convert_action_event(
        SimpleNamespace(
            name="click",
            timestamp=1.0,
            mouse_x=12.5,
            mouse_y=34.5,
            mouse_button_name=button,
            mouse_pressed=True,
        )
    )
    up = _convert_action_event(
        SimpleNamespace(
            name="click",
            timestamp=1.1,
            mouse_x=12.5,
            mouse_y=34.5,
            mouse_button_name=button,
            mouse_pressed=False,
        )
    )

    assert isinstance(down, MouseDownEvent)
    assert isinstance(up, MouseUpEvent)
    assert down.button == button
    assert up.button == button
    processed = merge_consecutive_mouse_click_events([down, up])
    assert len(processed) == 1
    assert isinstance(processed[0], MouseClickEvent)
    assert processed[0].button == button


@pytest.mark.skipif(
    ctypes.sizeof(ctypes.c_void_p) != 8,
    reason="ABI offsets below describe the supported 64-bit Linux runners",
)
def test_xinput_raw_event_matches_64_bit_libxi_abi() -> None:
    assert ctypes.sizeof(_XIRawEvent) == 144
    assert _XIRawEvent.root.offset == 64
    assert _XIRawEvent.root_x.offset == 72
    assert _XIRawEvent.root_y.offset == 80
    assert _XIRawEvent.flags.offset == 88
    assert _XIRawEvent.buttons.offset == 96
    assert _XIRawEvent.valuators.offset == 112
    assert _XIRawEvent.raw_values.offset == 136


def test_wayland_refuses_instead_of_silently_observing_only_xwayland(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    observer = LinuxXInputObserver(
        lambda event: None,
        observe_keyboard=True,
        observe_mouse=True,
        capture_mouse_moves=True,
        environ={"XDG_SESSION_TYPE": "wayland", "DISPLAY": ":0"},
    )

    with pytest.raises(InputObserverUnavailableError, match="silently omit"):
        observer.start()
    assert observer._thread is None


def test_factory_refuses_unknown_platform() -> None:
    with pytest.raises(InputObserverUnavailableError, match="not implemented"):
        create_input_observer(lambda event: None, platform_name="plan9")


def test_exception_note_helper_is_safe_without_python_311_api() -> None:
    class LegacyException:
        pass

    add_exception_note(LegacyException(), "cleanup context")  # type: ignore[arg-type]


def test_record_boundary_reraises_setup_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail_scope(*args, **kwargs):
        raise RuntimeError("native observer setup failed")

    monkeypatch.setattr(recorder_module, "build_window_scope", fail_scope)
    with pytest.raises(RuntimeError, match="native observer setup failed"):
        recorder_module.record("test", capture_dir=str(tmp_path))


def test_post_readiness_worker_failure_reaches_recorder_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    release_failure = threading.Event()

    def fail_after_ready(
        *,
        terminate_processing,
        terminate_recording,
        status_pipe,
        **kwargs,
    ) -> None:
        status_pipe.send({"type": "record.started"})
        assert release_failure.wait(timeout=1)
        raise RuntimeError("native observer failed after readiness")

    monkeypatch.setattr(recorder_module, "record", fail_after_ready)
    recorder = recorder_module.Recorder(str(tmp_path / "late-failure"))

    with pytest.raises(
        RuntimeError,
        match="native observer failed after readiness",
    ):
        with recorder:
            assert recorder.wait_for_ready(timeout=1)
            release_failure.set()

    with pytest.raises(
        RuntimeError,
        match="native observer failed after readiness",
    ):
        _ = recorder.capture


def test_recorder_worker_error_does_not_mask_outer_exception(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    release_failure = threading.Event()

    def fail_after_ready(*, status_pipe, **kwargs) -> None:
        status_pipe.send({"type": "record.started"})
        assert release_failure.wait(timeout=1)
        raise RuntimeError("secondary recorder failure")

    monkeypatch.setattr(recorder_module, "record", fail_after_ready)
    recorder = recorder_module.Recorder(str(tmp_path / "outer-failure"))

    with pytest.raises(ValueError, match="primary caller failure") as caught:
        with recorder:
            assert recorder.wait_for_ready(timeout=1)
            release_failure.set()
            raise ValueError("primary caller failure")

    notes = getattr(caught.value, "__notes__", [])
    if notes:
        assert any("secondary recorder failure" in note for note in notes)
