"""Native Windows global input observation using permissive stdlib ``ctypes``.

The implementation uses the documented ``WH_KEYBOARD_LL`` and ``WH_MOUSE_LL``
hooks.  It intentionally exposes observation only: input injection remains a
separate concern, and events marked as injected by Windows are discarded.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Any

from .base import (
    InputCallback,
    InputObserverError,
    InputObserverPermissionError,
    InputObserverUnavailableError,
    ObservedInput,
    ObservedKey,
    ObservedMouseButton,
    ObservedMouseMove,
    ObservedMouseScroll,
    ThreadedInputObserver,
)

# Hook and message constants from winuser.h.
WH_KEYBOARD_LL = 13
WH_MOUSE_LL = 14
HC_ACTION = 0

WM_QUIT = 0x0012
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105
WM_MOUSEMOVE = 0x0200
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202
WM_RBUTTONDOWN = 0x0204
WM_RBUTTONUP = 0x0205
WM_MBUTTONDOWN = 0x0207
WM_MBUTTONUP = 0x0208
WM_MOUSEWHEEL = 0x020A
WM_XBUTTONDOWN = 0x020B
WM_XBUTTONUP = 0x020C
WM_MOUSEHWHEEL = 0x020E
WM_USER = 0x0400

PM_NOREMOVE = 0x0000
WHEEL_DELTA = 120
XBUTTON1 = 0x0001
XBUTTON2 = 0x0002
TO_UNICODE_NO_STATE_CHANGE = 0x0004

LLKHF_LOWER_IL_INJECTED = 0x00000002
LLKHF_INJECTED = 0x00000010
LLMHF_INJECTED = 0x00000001
LLMHF_LOWER_IL_INJECTED = 0x00000002

ERROR_ACCESS_DENIED = 5
ERROR_PRIVILEGE_NOT_HELD = 1314

# Fixed-width aliases keep the structures testable off Windows as well as
# matching the Windows ABI on both 32- and 64-bit Python.
DWORD = ctypes.c_uint32
LONG = ctypes.c_int32
ULONG_PTR = ctypes.c_size_t
WPARAM = ctypes.c_size_t
LPARAM = ctypes.c_ssize_t
LRESULT = ctypes.c_ssize_t
HANDLE = ctypes.c_void_p
HWND = ctypes.c_void_p
HHOOK = ctypes.c_void_p
HINSTANCE = ctypes.c_void_p

WINFUNCTYPE = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
HOOKPROC = WINFUNCTYPE(LRESULT, ctypes.c_int, WPARAM, LPARAM)


class POINT(ctypes.Structure):
    """Windows screen coordinate."""

    _fields_ = [("x", LONG), ("y", LONG)]


class KBDLLHOOKSTRUCT(ctypes.Structure):
    """Payload delivered to a low-level keyboard hook."""

    _fields_ = [
        ("vkCode", DWORD),
        ("scanCode", DWORD),
        ("flags", DWORD),
        ("time", DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class MSLLHOOKSTRUCT(ctypes.Structure):
    """Payload delivered to a low-level mouse hook."""

    _fields_ = [
        ("pt", POINT),
        ("mouseData", DWORD),
        ("flags", DWORD),
        ("time", DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class MSG(ctypes.Structure):
    """Message-loop payload."""

    _fields_ = [
        ("hwnd", HWND),
        ("message", ctypes.c_uint32),
        ("wParam", WPARAM),
        ("lParam", LPARAM),
        ("time", DWORD),
        ("pt", POINT),
        ("lPrivate", DWORD),
    ]


_PHYSICAL_KEY_NAMES = {
    0x08: "backspace",
    0x09: "tab",
    0x0D: "enter",
    0x10: "shift",
    0x11: "ctrl",
    0x12: "alt",
    0x13: "pause",
    0x14: "caps_lock",
    0x1B: "esc",
    0x20: "space",
    0x21: "page_up",
    0x22: "page_down",
    0x23: "end",
    0x24: "home",
    0x25: "left",
    0x26: "up",
    0x27: "right",
    0x28: "down",
    0x2C: "print_screen",
    0x2D: "insert",
    0x2E: "delete",
    0x5B: "cmd_l",
    0x5C: "cmd_r",
    0x5D: "menu",
    0x70: "f1",
    0x71: "f2",
    0x72: "f3",
    0x73: "f4",
    0x74: "f5",
    0x75: "f6",
    0x76: "f7",
    0x77: "f8",
    0x78: "f9",
    0x79: "f10",
    0x7A: "f11",
    0x7B: "f12",
    0x7C: "f13",
    0x7D: "f14",
    0x7E: "f15",
    0x7F: "f16",
    0x80: "f17",
    0x81: "f18",
    0x82: "f19",
    0x83: "f20",
    0x84: "f21",
    0x85: "f22",
    0x86: "f23",
    0x87: "f24",
    0x90: "num_lock",
    0x91: "scroll_lock",
    0xA0: "shift_l",
    0xA1: "shift_r",
    0xA2: "ctrl_l",
    0xA3: "ctrl_r",
    0xA4: "alt_l",
    0xA5: "alt_r",
}

_CANONICAL_MODIFIERS = {
    0xA0: ("shift", 0x10),
    0xA1: ("shift", 0x10),
    0xA2: ("ctrl", 0x11),
    0xA3: ("ctrl", 0x11),
    0xA4: ("alt", 0x12),
    0xA5: ("alt", 0x12),
    0x5B: ("cmd", 0x5B),
    0x5C: ("cmd", 0x5B),
}

_BUTTON_MESSAGES = {
    WM_LBUTTONDOWN: ("left", True),
    WM_LBUTTONUP: ("left", False),
    WM_RBUTTONDOWN: ("right", True),
    WM_RBUTTONUP: ("right", False),
    WM_MBUTTONDOWN: ("middle", True),
    WM_MBUTTONUP: ("middle", False),
}


def _set_signature(function: Any, argtypes: list[Any], restype: Any) -> None:
    """Set a ctypes signature while allowing plain Python fakes in tests."""

    try:
        function.argtypes = argtypes
        function.restype = restype
    except (AttributeError, TypeError):
        return


def _handle_value(handle: object) -> int:
    """Return a stable integer value for a ctypes or fake Windows handle."""

    if handle is None:
        return 0
    if isinstance(handle, int):
        return handle
    value = getattr(handle, "value", None)
    return int(value or 0)


def _signed_high_word(value: int) -> int:
    """Extract a signed 16-bit wheel delta from ``mouseData``."""

    high_word = (int(value) >> 16) & 0xFFFF
    return high_word - 0x10000 if high_word & 0x8000 else high_word


def _key_identity(vk_code: int, character: str | None) -> dict[str, str | None]:
    """Normalize physical and canonical key identity like pynput's listener."""

    key_name = _PHYSICAL_KEY_NAMES.get(vk_code)
    canonical_name = key_name
    canonical_vk = vk_code
    canonical_character = character.lower() if character else None

    modifier = _CANONICAL_MODIFIERS.get(vk_code)
    if modifier is not None:
        canonical_name, canonical_vk = modifier
        character = None
        canonical_character = None
    elif key_name is not None:
        character = None
        canonical_character = None

    return {
        "key_name": key_name,
        "key_char": character,
        "key_vk": str(vk_code),
        "canonical_key_name": canonical_name,
        "canonical_key_char": canonical_character,
        "canonical_key_vk": str(canonical_vk),
    }


def _mouse_event(
    message: int,
    payload: MSLLHOOKSTRUCT,
    *,
    capture_mouse_moves: bool,
) -> ObservedInput | None:
    """Translate a Windows low-level mouse payload to the common contract."""

    injected = bool(payload.flags & (LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED))
    if injected:
        return None

    x = float(payload.pt.x)
    y = float(payload.pt.y)
    if message == WM_MOUSEMOVE:
        if not capture_mouse_moves:
            return None
        return ObservedMouseMove(x=x, y=y)

    button_transition = _BUTTON_MESSAGES.get(message)
    if button_transition is not None:
        button, pressed = button_transition
        return ObservedMouseButton(
            x=x,
            y=y,
            button=button,
            pressed=pressed,
        )

    if message in {WM_XBUTTONDOWN, WM_XBUTTONUP}:
        xbutton = (int(payload.mouseData) >> 16) & 0xFFFF
        button = "x1" if xbutton == XBUTTON1 else "x2" if xbutton == XBUTTON2 else None
        if button is None:
            return None
        return ObservedMouseButton(
            x=x,
            y=y,
            button=button,
            pressed=message == WM_XBUTTONDOWN,
        )

    if message == WM_MOUSEWHEEL:
        return ObservedMouseScroll(
            x=x,
            y=y,
            dx=0.0,
            dy=_signed_high_word(payload.mouseData) / WHEEL_DELTA,
        )
    if message == WM_MOUSEHWHEEL:
        return ObservedMouseScroll(
            x=x,
            y=y,
            dx=_signed_high_word(payload.mouseData) / WHEEL_DELTA,
            dy=0.0,
        )
    return None


class WindowsInputObserver(ThreadedInputObserver):
    """Observe global Windows keyboard and mouse input with low-level hooks."""

    def __init__(
        self,
        callback: InputCallback,
        *,
        observe_keyboard: bool,
        observe_mouse: bool,
        capture_mouse_moves: bool,
        startup_timeout: float = 5.0,
        shutdown_timeout: float = 5.0,
        _user32: Any | None = None,
        _kernel32: Any | None = None,
    ) -> None:
        super().__init__(
            callback,
            observe_keyboard=observe_keyboard,
            observe_mouse=observe_mouse,
            capture_mouse_moves=capture_mouse_moves,
            startup_timeout=startup_timeout,
            shutdown_timeout=shutdown_timeout,
        )
        self._user32 = _user32
        self._kernel32 = _kernel32
        self._keyboard_hook: object | None = None
        self._mouse_hook: object | None = None
        self._keyboard_proc: Any | None = None
        self._mouse_proc: Any | None = None
        self._thread_id: int | None = None

    def _load_apis(self) -> None:
        if self._user32 is not None and self._kernel32 is not None:
            return
        if sys.platform != "win32":
            raise InputObserverUnavailableError(
                "Windows input observation requires a native Windows session"
            )
        try:
            self._user32 = ctypes.WinDLL("user32", use_last_error=True)
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        except (AttributeError, OSError) as exc:
            raise InputObserverUnavailableError(
                f"Windows input APIs are unavailable: {exc}"
            ) from exc

    def _configure_apis(self) -> None:
        user32 = self._user32
        kernel32 = self._kernel32
        assert user32 is not None
        assert kernel32 is not None
        _set_signature(
            user32.SetWindowsHookExW,
            [ctypes.c_int, HOOKPROC, HINSTANCE, DWORD],
            HHOOK,
        )
        _set_signature(user32.UnhookWindowsHookEx, [HHOOK], ctypes.c_int)
        _set_signature(
            user32.CallNextHookEx,
            [HHOOK, ctypes.c_int, WPARAM, LPARAM],
            LRESULT,
        )
        _set_signature(
            user32.GetMessageW,
            [ctypes.POINTER(MSG), HWND, ctypes.c_uint32, ctypes.c_uint32],
            ctypes.c_int,
        )
        _set_signature(user32.TranslateMessage, [ctypes.POINTER(MSG)], ctypes.c_int)
        _set_signature(user32.DispatchMessageW, [ctypes.POINTER(MSG)], LRESULT)
        _set_signature(
            user32.PeekMessageW,
            [
                ctypes.POINTER(MSG),
                HWND,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
            ],
            ctypes.c_int,
        )
        _set_signature(
            user32.PostThreadMessageW,
            [DWORD, ctypes.c_uint32, WPARAM, LPARAM],
            ctypes.c_int,
        )
        _set_signature(
            user32.GetKeyboardState,
            [ctypes.POINTER(ctypes.c_ubyte)],
            ctypes.c_int,
        )
        _set_signature(
            user32.ToUnicodeEx,
            [
                ctypes.c_uint,
                ctypes.c_uint,
                ctypes.POINTER(ctypes.c_ubyte),
                ctypes.POINTER(ctypes.c_wchar),
                ctypes.c_int,
                ctypes.c_uint,
                HANDLE,
            ],
            ctypes.c_int,
        )
        _set_signature(user32.GetKeyboardLayout, [DWORD], HANDLE)
        _set_signature(kernel32.GetModuleHandleW, [ctypes.c_wchar_p], HINSTANCE)
        _set_signature(kernel32.GetCurrentThreadId, [], DWORD)

    def _last_error(self) -> int:
        for api in (self._user32, self._kernel32):
            value = getattr(api, "last_error", None)
            if value is not None:
                return int(value)
        get_last_error = getattr(ctypes, "get_last_error", None)
        return int(get_last_error()) if get_last_error is not None else 0

    def _hook_error(self, hook_name: str) -> InputObserverError:
        error_code = self._last_error()
        detail = f"Windows error {error_code}" if error_code else "unknown Windows error"
        message = f"could not install the global {hook_name} hook ({detail})"
        if error_code in {ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD}:
            return InputObserverPermissionError(message)
        return InputObserverUnavailableError(message)

    def _setup(self) -> None:
        self._load_apis()
        self._configure_apis()
        user32 = self._user32
        kernel32 = self._kernel32
        assert user32 is not None
        assert kernel32 is not None

        self._thread_id = int(kernel32.GetCurrentThreadId())
        # Force creation of the thread message queue before another thread can
        # request shutdown with PostThreadMessageW.
        message = MSG()
        user32.PeekMessageW(
            ctypes.byref(message),
            None,
            WM_USER,
            WM_USER,
            PM_NOREMOVE,
        )

        self._keyboard_proc = HOOKPROC(self._keyboard_hook_callback)
        self._mouse_proc = HOOKPROC(self._mouse_hook_callback)
        module = kernel32.GetModuleHandleW(None)

        if self.observe_keyboard:
            hook = user32.SetWindowsHookExW(
                WH_KEYBOARD_LL,
                self._keyboard_proc,
                module,
                0,
            )
            if not _handle_value(hook):
                raise self._hook_error("keyboard")
            self._keyboard_hook = hook

        if self.observe_mouse:
            hook = user32.SetWindowsHookExW(
                WH_MOUSE_LL,
                self._mouse_proc,
                module,
                0,
            )
            if not _handle_value(hook):
                raise self._hook_error("mouse")
            self._mouse_hook = hook

    def _run_loop(self) -> None:
        user32 = self._user32
        assert user32 is not None
        message = MSG()
        while not self._stop_requested.is_set():
            result = int(user32.GetMessageW(ctypes.byref(message), None, 0, 0))
            if result == 0:
                return
            if result == -1:
                error_code = self._last_error()
                raise InputObserverError(
                    "Windows input-observer message loop failed " f"(Windows error {error_code})"
                )
            user32.TranslateMessage(ctypes.byref(message))
            user32.DispatchMessageW(ctypes.byref(message))

    def _wake(self) -> None:
        user32 = self._user32
        thread_id = self._thread_id
        if user32 is None or thread_id is None:
            return
        user32.PostThreadMessageW(thread_id, WM_QUIT, 0, 0)

    def _teardown(self) -> None:
        user32 = self._user32
        failures: list[str] = []
        if user32 is not None:
            for name, attribute in (
                ("keyboard", "_keyboard_hook"),
                ("mouse", "_mouse_hook"),
            ):
                hook = getattr(self, attribute)
                if hook is None:
                    continue
                try:
                    released = user32.UnhookWindowsHookEx(hook)
                except BaseException as exc:
                    failures.append(f"{name} hook ({exc})")
                else:
                    if not released:
                        failures.append(f"{name} hook (Windows error {self._last_error()})")
                finally:
                    setattr(self, attribute, None)
        self._keyboard_proc = None
        self._mouse_proc = None
        self._thread_id = None
        if failures:
            raise InputObserverError(
                "could not release Windows input observer " + ", ".join(failures)
            )

    def _record_callback_failure(self, exc: BaseException) -> None:
        if self._failure is None:
            self._failure = exc
        self._stop_requested.set()
        try:
            self._wake()
        except BaseException as wake_exc:
            exc.add_note(f"waking the Windows input observer also failed: {wake_exc}")

    def _call_next(self, hook: object | None, code: int, wparam: int, lparam: int) -> int:
        user32 = self._user32
        assert user32 is not None
        return int(user32.CallNextHookEx(hook, code, wparam, lparam))

    def _keyboard_character(
        self,
        payload: KBDLLHOOKSTRUCT,
        *,
        pressed: bool,
    ) -> str | None:
        user32 = self._user32
        assert user32 is not None
        keyboard_state = (ctypes.c_ubyte * 256)()
        if not user32.GetKeyboardState(keyboard_state):
            return None
        vk_code = int(payload.vkCode)
        if vk_code < len(keyboard_state):
            if pressed:
                keyboard_state[vk_code] |= 0x80
            else:
                keyboard_state[vk_code] &= 0x7F
        buffer = ctypes.create_unicode_buffer(8)
        count = int(
            user32.ToUnicodeEx(
                vk_code,
                int(payload.scanCode),
                keyboard_state,
                buffer,
                len(buffer),
                TO_UNICODE_NO_STATE_CHANGE,
                user32.GetKeyboardLayout(0),
            )
        )
        if count == 0:
            return None
        character_count = abs(count)
        if ctypes.sizeof(ctypes.c_wchar) == 2:
            raw = ctypes.string_at(buffer, character_count * 2)
            return raw.decode("utf-16-le")
        return "".join(buffer[:character_count])

    def _keyboard_hook_callback(
        self,
        code: int,
        wparam: int,
        lparam: int,
    ) -> int:
        try:
            if code == HC_ACTION and wparam in {
                WM_KEYDOWN,
                WM_KEYUP,
                WM_SYSKEYDOWN,
                WM_SYSKEYUP,
            }:
                payload = ctypes.cast(
                    lparam,
                    ctypes.POINTER(KBDLLHOOKSTRUCT),
                ).contents
                injected = bool(payload.flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED))
                if not injected:
                    pressed = wparam in {WM_KEYDOWN, WM_SYSKEYDOWN}
                    identity = _key_identity(
                        int(payload.vkCode),
                        self._keyboard_character(payload, pressed=pressed),
                    )
                    self._emit(ObservedKey(pressed=pressed, **identity))
        except BaseException as exc:
            self._record_callback_failure(exc)
        return self._call_next(self._keyboard_hook, code, wparam, lparam)

    def _mouse_hook_callback(
        self,
        code: int,
        wparam: int,
        lparam: int,
    ) -> int:
        try:
            if code == HC_ACTION:
                payload = ctypes.cast(
                    lparam,
                    ctypes.POINTER(MSLLHOOKSTRUCT),
                ).contents
                event = _mouse_event(
                    wparam,
                    payload,
                    capture_mouse_moves=self.capture_mouse_moves,
                )
                if event is not None:
                    self._emit(event)
        except BaseException as exc:
            self._record_callback_failure(exc)
        return self._call_next(self._mouse_hook, code, wparam, lparam)
