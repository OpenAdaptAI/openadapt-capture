"""Focused contract tests for the stdlib Windows input observer."""

from __future__ import annotations

import ctypes
import threading

import pytest

from openadapt_capture.input_observer import (
    InputObserverError,
    InputObserverPermissionError,
    ObservedKey,
    ObservedMouseButton,
    ObservedMouseMove,
    ObservedMouseScroll,
)
from openadapt_capture.input_observer.windows import (
    ERROR_ACCESS_DENIED,
    HC_ACTION,
    KBDLLHOOKSTRUCT,
    LLKHF_INJECTED,
    LLMHF_INJECTED,
    MSLLHOOKSTRUCT,
    POINT,
    WM_KEYDOWN,
    WM_KEYUP,
    WM_LBUTTONDOWN,
    WM_MOUSEHWHEEL,
    WM_MOUSEMOVE,
    WM_MOUSEWHEEL,
    WM_XBUTTONUP,
    XBUTTON2,
    WindowsInputObserver,
    _key_identity,
    _mouse_event,
    _signed_high_word,
)


class FakeKernel32:
    def GetCurrentThreadId(self) -> int:
        return 4242

    def GetModuleHandleW(self, _name):
        return 99


class FakeUser32:
    def __init__(
        self,
        *,
        hook_results: list[int] | None = None,
        last_error: int = 0,
        unhook_failures: set[int] | None = None,
    ) -> None:
        self.hook_results = list(hook_results or [101, 102])
        self.last_error = last_error
        self.unhook_failures = unhook_failures or set()
        self.installed: list[int] = []
        self.unhooked: list[int] = []
        self.next_calls: list[tuple[object, int, int, int]] = []
        self.posted = threading.Event()

    def PeekMessageW(self, *_args) -> int:
        return 0

    def SetWindowsHookExW(self, hook_type, _callback, _module, _thread_id):
        result = self.hook_results.pop(0)
        if result:
            self.installed.append(hook_type)
        return result

    def UnhookWindowsHookEx(self, hook) -> int:
        self.unhooked.append(int(hook))
        return int(hook not in self.unhook_failures)

    def CallNextHookEx(self, hook, code, wparam, lparam) -> int:
        self.next_calls.append((hook, code, wparam, lparam))
        return 73

    def GetMessageW(self, *_args) -> int:
        self.posted.wait(timeout=2)
        return 0

    def TranslateMessage(self, *_args) -> int:
        return 1

    def DispatchMessageW(self, *_args) -> int:
        return 1

    def PostThreadMessageW(self, *_args) -> int:
        self.posted.set()
        return 1

    def GetKeyboardState(self, keyboard_state) -> int:
        for index in range(256):
            keyboard_state[index] = 0
        return 1

    def ToUnicodeEx(
        self,
        vk_code,
        _scan_code,
        keyboard_state,
        buffer,
        _buffer_size,
        flags,
        _layout,
    ) -> int:
        assert flags == 4
        character = chr(vk_code)
        if keyboard_state[0x10] & 0x80:
            character = character.upper()
        else:
            character = character.lower()
        buffer[0] = character
        return 1

    def GetKeyboardLayout(self, _thread_id):
        return 1


def make_observer(
    callback,
    *,
    user32: FakeUser32 | None = None,
    observe_keyboard: bool = True,
    observe_mouse: bool = True,
    capture_mouse_moves: bool = True,
) -> WindowsInputObserver:
    return WindowsInputObserver(
        callback,
        observe_keyboard=observe_keyboard,
        observe_mouse=observe_mouse,
        capture_mouse_moves=capture_mouse_moves,
        startup_timeout=1,
        shutdown_timeout=1,
        _user32=user32 or FakeUser32(),
        _kernel32=FakeKernel32(),
    )


def test_signed_wheel_delta_and_mouse_normalization() -> None:
    assert _signed_high_word(120 << 16) == 120
    assert _signed_high_word(((-240) & 0xFFFF) << 16) == -240

    vertical = MSLLHOOKSTRUCT(
        pt=POINT(-10, 25),
        mouseData=((-240) & 0xFFFF) << 16,
    )
    horizontal = MSLLHOOKSTRUCT(
        pt=POINT(30, 40),
        mouseData=(120 & 0xFFFF) << 16,
    )
    assert _mouse_event(
        WM_MOUSEWHEEL,
        vertical,
        capture_mouse_moves=True,
    ) == ObservedMouseScroll(x=-10.0, y=25.0, dx=0.0, dy=-2.0)
    assert _mouse_event(
        WM_MOUSEHWHEEL,
        horizontal,
        capture_mouse_moves=True,
    ) == ObservedMouseScroll(x=30.0, y=40.0, dx=1.0, dy=0.0)


def test_mouse_move_button_xbutton_and_injected_filtering() -> None:
    payload = MSLLHOOKSTRUCT(pt=POINT(12, 34))
    assert _mouse_event(
        WM_MOUSEMOVE,
        payload,
        capture_mouse_moves=True,
    ) == ObservedMouseMove(x=12.0, y=34.0)
    assert (
        _mouse_event(
            WM_MOUSEMOVE,
            payload,
            capture_mouse_moves=False,
        )
        is None
    )
    assert _mouse_event(
        WM_LBUTTONDOWN,
        payload,
        capture_mouse_moves=True,
    ) == ObservedMouseButton(x=12.0, y=34.0, button="left", pressed=True)

    payload.mouseData = XBUTTON2 << 16
    assert _mouse_event(
        WM_XBUTTONUP,
        payload,
        capture_mouse_moves=True,
    ) == ObservedMouseButton(x=12.0, y=34.0, button="x2", pressed=False)

    payload.flags = LLMHF_INJECTED
    assert (
        _mouse_event(
            WM_LBUTTONDOWN,
            payload,
            capture_mouse_moves=True,
        )
        is None
    )


def test_key_identity_preserves_physical_and_canonical_semantics() -> None:
    assert _key_identity(0x41, "A") == {
        "key_name": None,
        "key_char": "A",
        "key_vk": "65",
        "canonical_key_name": None,
        "canonical_key_char": "a",
        "canonical_key_vk": "65",
    }
    assert _key_identity(0xA1, None) == {
        "key_name": "shift_r",
        "key_char": None,
        "key_vk": "161",
        "canonical_key_name": "shift",
        "canonical_key_char": None,
        "canonical_key_vk": "16",
    }


def test_callbacks_emit_normalized_events_filter_injected_and_chain() -> None:
    events = []
    user32 = FakeUser32()
    observer = make_observer(events.append, user32=user32)
    observer._keyboard_hook = 101
    observer._mouse_hook = 102

    key_payload = KBDLLHOOKSTRUCT(vkCode=0x41, scanCode=30)
    assert (
        observer._keyboard_hook_callback(
            HC_ACTION,
            WM_KEYDOWN,
            ctypes.addressof(key_payload),
        )
        == 73
    )
    key_payload.flags = LLKHF_INJECTED
    observer._keyboard_hook_callback(
        HC_ACTION,
        WM_KEYUP,
        ctypes.addressof(key_payload),
    )

    mouse_payload = MSLLHOOKSTRUCT(pt=POINT(5, 7))
    observer._mouse_hook_callback(
        HC_ACTION,
        WM_LBUTTONDOWN,
        ctypes.addressof(mouse_payload),
    )
    mouse_payload.flags = LLMHF_INJECTED
    observer._mouse_hook_callback(
        HC_ACTION,
        WM_MOUSEMOVE,
        ctypes.addressof(mouse_payload),
    )

    assert events == [
        ObservedKey(
            pressed=True,
            key_char="a",
            key_vk="65",
            canonical_key_char="a",
            canonical_key_vk="65",
        ),
        ObservedMouseButton(x=5.0, y=7.0, button="left", pressed=True),
    ]
    assert len(user32.next_calls) == 4


def test_partial_setup_permission_failure_rolls_back_installed_hook() -> None:
    user32 = FakeUser32(
        hook_results=[501, 0],
        last_error=ERROR_ACCESS_DENIED,
    )
    observer = make_observer(lambda _event: None, user32=user32)

    with pytest.raises(InputObserverPermissionError, match="mouse hook"):
        observer.start()

    assert user32.installed == [13]
    assert user32.unhooked == [501]


def test_threaded_lifecycle_wakes_and_unhooks_every_installed_hook() -> None:
    user32 = FakeUser32()
    observer = make_observer(lambda _event: None, user32=user32)

    observer.start()
    observer.stop()

    assert user32.installed == [13, 14]
    assert user32.posted.is_set()
    assert user32.unhooked == [101, 102]


def test_teardown_attempts_every_hook_and_surfaces_release_failure() -> None:
    user32 = FakeUser32(unhook_failures={101})
    observer = make_observer(lambda _event: None, user32=user32)
    observer._keyboard_hook = 101
    observer._mouse_hook = 102

    with pytest.raises(InputObserverError, match="keyboard hook"):
        observer._teardown()

    assert user32.unhooked == [101, 102]
    assert observer._keyboard_hook is None
    assert observer._mouse_hook is None


def test_callback_failure_is_surfaced_after_clean_teardown() -> None:
    user32 = FakeUser32()

    def fail(_event) -> None:
        raise ValueError("consumer failed")

    observer = make_observer(fail, user32=user32)
    observer._mouse_hook = 102
    payload = MSLLHOOKSTRUCT(pt=POINT(5, 7))

    observer._mouse_hook_callback(
        HC_ACTION,
        WM_LBUTTONDOWN,
        ctypes.addressof(payload),
    )

    with pytest.raises(InputObserverError, match="consumer failed"):
        observer.check_health()
