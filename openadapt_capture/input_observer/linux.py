"""Linux global input observation through XInput2 raw events."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
import time
from typing import Any

from .base import (
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

_GENERIC_EVENT = 35
_XI_ALL_MASTER_DEVICES = 1
_XI_RAW_KEY_PRESS = 13
_XI_RAW_KEY_RELEASE = 14
_XI_RAW_BUTTON_PRESS = 15
_XI_RAW_BUTTON_RELEASE = 16
_XI_RAW_MOTION = 17
_XKB_USE_CORE_KBD = 0x0100
_XKB_GROUP_SHIFT = 13
_MAX_PENDING_BATCH = 256

_SPECIAL_KEY_NAMES = {
    "Alt_L": "alt",
    "Alt_R": "alt_r",
    "BackSpace": "backspace",
    "Caps_Lock": "caps_lock",
    "Control_L": "ctrl",
    "Control_R": "ctrl_r",
    "Delete": "delete",
    "Down": "down",
    "End": "end",
    "Escape": "esc",
    "Home": "home",
    "Left": "left",
    "Meta_L": "cmd",
    "Meta_R": "cmd_r",
    "Page_Down": "page_down",
    "Page_Up": "page_up",
    "Return": "enter",
    "Right": "right",
    "Shift_L": "shift",
    "Shift_R": "shift_r",
    "Super_L": "cmd",
    "Super_R": "cmd_r",
    "Tab": "tab",
    "Up": "up",
    "space": "space",
}
_KEYSYM_CHARACTERS = {
    "ampersand": "&",
    "apostrophe": "'",
    "asciicircum": "^",
    "asciitilde": "~",
    "asterisk": "*",
    "at": "@",
    "backslash": "\\",
    "bar": "|",
    "braceleft": "{",
    "braceright": "}",
    "bracketleft": "[",
    "bracketright": "]",
    "colon": ":",
    "comma": ",",
    "dollar": "$",
    "equal": "=",
    "exclam": "!",
    "greater": ">",
    "less": "<",
    "minus": "-",
    "numbersign": "#",
    "parenleft": "(",
    "parenright": ")",
    "percent": "%",
    "period": ".",
    "plus": "+",
    "question": "?",
    "quotedbl": '"',
    "semicolon": ";",
    "slash": "/",
    "underscore": "_",
}


class _XIEventMask(ctypes.Structure):
    _fields_ = [
        ("deviceid", ctypes.c_int),
        ("mask_len", ctypes.c_int),
        ("mask", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class _XIValuatorState(ctypes.Structure):
    _fields_ = [
        ("mask_len", ctypes.c_int),
        ("mask", ctypes.POINTER(ctypes.c_ubyte)),
        ("values", ctypes.POINTER(ctypes.c_double)),
    ]


class _XGenericEventCookie(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("serial", ctypes.c_ulong),
        ("send_event", ctypes.c_int),
        ("display", ctypes.c_void_p),
        ("extension", ctypes.c_int),
        ("evtype", ctypes.c_int),
        ("cookie", ctypes.c_uint),
        ("data", ctypes.c_void_p),
    ]


class _XEvent(ctypes.Union):
    _fields_ = [
        ("type", ctypes.c_int),
        ("xcookie", _XGenericEventCookie),
        ("pad", ctypes.c_long * 24),
    ]


class _XIRawEvent(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("serial", ctypes.c_ulong),
        ("send_event", ctypes.c_int),
        ("display", ctypes.c_void_p),
        ("extension", ctypes.c_int),
        ("evtype", ctypes.c_int),
        ("time", ctypes.c_ulong),
        ("deviceid", ctypes.c_int),
        ("sourceid", ctypes.c_int),
        ("detail", ctypes.c_int),
        ("flags", ctypes.c_int),
        ("valuators", _XIValuatorState),
        ("raw_values", ctypes.POINTER(ctypes.c_double)),
    ]


class _XkbStateRec(ctypes.Structure):
    _fields_ = [
        ("group", ctypes.c_ubyte),
        ("locked_group", ctypes.c_ubyte),
        ("base_group", ctypes.c_ushort),
        ("latched_group", ctypes.c_ushort),
        ("mods", ctypes.c_ubyte),
        ("base_mods", ctypes.c_ubyte),
        ("latched_mods", ctypes.c_ubyte),
        ("locked_mods", ctypes.c_ubyte),
        ("compat_state", ctypes.c_ubyte),
        ("grab_mods", ctypes.c_ubyte),
        ("compat_grab_mods", ctypes.c_ubyte),
        ("lookup_mods", ctypes.c_ubyte),
        ("compat_lookup_mods", ctypes.c_ubyte),
        ("ptr_buttons", ctypes.c_ushort),
    ]


def normalize_xinput_button_event(
    *,
    detail: int,
    pressed: bool,
    x: float,
    y: float,
    injected: bool = False,
    timestamp: float | None = None,
) -> ObservedInput | None:
    """Map X11 button numbers to a click or normalized wheel event."""
    if detail in {4, 5, 6, 7}:
        if not pressed:
            return None
        delta_by_button = {
            4: (0.0, 1.0),
            5: (0.0, -1.0),
            6: (-1.0, 0.0),
            7: (1.0, 0.0),
        }
        dx, dy = delta_by_button[detail]
        return ObservedMouseScroll(
            x=x,
            y=y,
            dx=dx,
            dy=dy,
            injected=injected,
            timestamp=timestamp,
        )
    button_by_detail = {
        1: "left",
        2: "middle",
        3: "right",
        8: "x1",
        9: "x2",
    }
    button = button_by_detail.get(detail)
    if button is None and detail > 0:
        button = f"button{detail}"
    if button is None:
        return None
    return ObservedMouseButton(
        x=x,
        y=y,
        button=button,
        pressed=pressed,
        injected=injected,
        timestamp=timestamp,
    )


def normalize_xinput_key_event(
    *,
    keycode: int,
    pressed: bool,
    keysym_name: str | None,
    injected: bool = False,
    character: str | None = None,
    derive_character: bool = True,
    timestamp: float | None = None,
) -> ObservedKey:
    """Normalize an XInput2 keycode and XKB keysym name."""
    key_name = _SPECIAL_KEY_NAMES.get(keysym_name or "")
    if derive_character and keysym_name:
        if len(keysym_name) == 1 and keysym_name.isprintable():
            character = keysym_name
        else:
            character = _KEYSYM_CHARACTERS.get(keysym_name)
    if key_name is None and character is None:
        key_name = keysym_name or f"keycode_{keycode}"
    virtual_key = str(keycode)
    return ObservedKey(
        pressed=pressed,
        key_name=key_name,
        key_char=character,
        key_vk=virtual_key,
        canonical_key_name=key_name,
        canonical_key_char=character.lower() if character else None,
        canonical_key_vk=virtual_key,
        injected=injected,
        timestamp=timestamp,
    )


class LinuxXInputObserver(ThreadedInputObserver):
    """Observe complete X11 desktop input with XInput2 raw events."""

    def __init__(self, *args, environ: dict[str, str] | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._environ = environ if environ is not None else os.environ
        self._x11: Any = None
        self._xi: Any = None
        self._xkbcommon: Any = None
        self._display: Any = None
        self._root = 0
        self._xi_opcode = 0
        self._event_mask_buffer: Any = None
        self._composition_mode: str | None = None
        self._unverifiable_keycodes: set[int] = set()

    @staticmethod
    def _set_mask(mask: ctypes.Array[ctypes.c_ubyte], event_type: int) -> None:
        mask[event_type >> 3] |= 1 << (event_type & 7)

    def _setup(self) -> None:
        if not sys.platform.startswith("linux"):
            raise InputObserverUnavailableError(
                "XInput2 input observation is available only on Linux"
            )
        session_type = self._environ.get("XDG_SESSION_TYPE", "").lower()
        if session_type == "wayland" or self._environ.get("WAYLAND_DISPLAY"):
            raise InputObserverUnavailableError(
                "native Wayland does not expose complete global input to XInput2. "
                "Run an X11 session; OpenAdapt refuses XWayland-only capture because "
                "it would silently omit input from native Wayland applications."
            )
        display_name = self._environ.get("DISPLAY")
        if not display_name:
            raise InputObserverUnavailableError(
                "XInput2 requires an X11 desktop and DISPLAY is not set"
            )

        x11_name = ctypes.util.find_library("X11")
        xi_name = ctypes.util.find_library("Xi")
        xkbcommon_name = ctypes.util.find_library("xkbcommon")
        if not x11_name or not xi_name or not xkbcommon_name:
            raise InputObserverUnavailableError(
                "Linux input observation requires the system libX11, libXi, "
                "and permissively licensed libxkbcommon runtime libraries"
            )
        try:
            self._x11 = ctypes.CDLL(x11_name)
            self._xi = ctypes.CDLL(xi_name)
            self._xkbcommon = ctypes.CDLL(xkbcommon_name)
        except OSError as exc:
            raise InputObserverUnavailableError(
                f"could not load X11 input libraries: {exc}"
            ) from exc
        self._configure_api()
        self._display = self._x11.XOpenDisplay(display_name.encode())
        if not self._display:
            raise InputObserverPermissionError(
                f"could not open X11 display {display_name!r}; authorize the "
                "recording user with the display server and retry"
            )
        self._root = int(self._x11.XDefaultRootWindow(self._display))

        opcode = ctypes.c_int()
        first_event = ctypes.c_int()
        first_error = ctypes.c_int()
        if not self._x11.XQueryExtension(
            self._display,
            b"XInputExtension",
            ctypes.byref(opcode),
            ctypes.byref(first_event),
            ctypes.byref(first_error),
        ):
            raise InputObserverUnavailableError(
                "the X11 server does not expose the XInput extension"
            )
        self._xi_opcode = opcode.value
        major = ctypes.c_int(2)
        minor = ctypes.c_int(0)
        status = self._xi.XIQueryVersion(
            self._display, ctypes.byref(major), ctypes.byref(minor)
        )
        if status != 0 or major.value < 2:
            raise InputObserverUnavailableError(
                f"XInput2 is required; server negotiation returned "
                f"{major.value}.{minor.value} with status {status}"
            )

        mask = (ctypes.c_ubyte * 4)()
        if self.observe_keyboard:
            self._set_mask(mask, _XI_RAW_KEY_PRESS)
            self._set_mask(mask, _XI_RAW_KEY_RELEASE)
        if self.observe_mouse:
            self._set_mask(mask, _XI_RAW_BUTTON_PRESS)
            self._set_mask(mask, _XI_RAW_BUTTON_RELEASE)
            if self.capture_mouse_moves:
                self._set_mask(mask, _XI_RAW_MOTION)
        event_mask = _XIEventMask(
            deviceid=_XI_ALL_MASTER_DEVICES,
            mask_len=len(mask),
            mask=ctypes.cast(mask, ctypes.POINTER(ctypes.c_ubyte)),
        )
        self._event_mask_buffer = mask
        if self._xi.XISelectEvents(
            self._display, self._root, ctypes.byref(event_mask), 1
        ) != 0:
            raise InputObserverPermissionError(
                "the X11 server refused XInput2 raw-event selection"
            )
        self._x11.XFlush(self._display)

    def _configure_api(self) -> None:
        self._x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
        self._x11.XOpenDisplay.restype = ctypes.c_void_p
        self._x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
        self._x11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
        self._x11.XDefaultRootWindow.restype = ctypes.c_ulong
        self._x11.XQueryExtension.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int),
        ]
        self._x11.XPending.argtypes = [ctypes.c_void_p]
        self._x11.XPending.restype = ctypes.c_int
        self._x11.XNextEvent.argtypes = [ctypes.c_void_p, ctypes.POINTER(_XEvent)]
        self._x11.XGetEventData.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_XGenericEventCookie),
        ]
        self._x11.XGetEventData.restype = ctypes.c_int
        self._x11.XFreeEventData.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_XGenericEventCookie),
        ]
        self._x11.XFlush.argtypes = [ctypes.c_void_p]
        self._x11.XQueryPointer.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_uint),
        ]
        self._x11.XQueryPointer.restype = ctypes.c_int
        self._x11.XkbGetState.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.POINTER(_XkbStateRec),
        ]
        self._x11.XkbGetState.restype = ctypes.c_int
        self._x11.XkbLookupKeySym.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ubyte,
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_ulong),
        ]
        self._x11.XkbLookupKeySym.restype = ctypes.c_int
        self._x11.XKeysymToString.argtypes = [ctypes.c_ulong]
        self._x11.XKeysymToString.restype = ctypes.c_char_p

        self._xi.XIQueryVersion.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int),
        ]
        self._xi.XIQueryVersion.restype = ctypes.c_int
        self._xi.XISelectEvents.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(_XIEventMask),
            ctypes.c_int,
        ]
        self._xi.XISelectEvents.restype = ctypes.c_int
        self._xkbcommon.xkb_keysym_to_utf8.argtypes = [
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_size_t,
        ]
        self._xkbcommon.xkb_keysym_to_utf8.restype = ctypes.c_int

    def _query_pointer(self) -> tuple[float, float]:
        root_return = ctypes.c_ulong()
        child_return = ctypes.c_ulong()
        root_x = ctypes.c_int()
        root_y = ctypes.c_int()
        window_x = ctypes.c_int()
        window_y = ctypes.c_int()
        mask = ctypes.c_uint()
        if not self._x11.XQueryPointer(
            self._display,
            self._root,
            ctypes.byref(root_return),
            ctypes.byref(child_return),
            ctypes.byref(root_x),
            ctypes.byref(root_y),
            ctypes.byref(window_x),
            ctypes.byref(window_y),
            ctypes.byref(mask),
        ):
            raise InputObserverError(
                "XInput2 delivered mouse input but XQueryPointer could not establish "
                "its global coordinates"
            )
        return float(root_x.value), float(root_y.value)

    def _lookup_keysym(self, keycode: int) -> tuple[int, str | None]:
        state = _XkbStateRec()
        if self._x11.XkbGetState(
            self._display,
            _XKB_USE_CORE_KBD,
            ctypes.byref(state),
        ) != 0:
            raise InputObserverError(
                "XKB could not read the active keyboard group and modifier state"
            )
        core_state = int(state.lookup_mods) | (int(state.group) << _XKB_GROUP_SHIFT)
        consumed_modifiers = ctypes.c_uint()
        keysym = ctypes.c_ulong()
        if not self._x11.XkbLookupKeySym(
            self._display,
            keycode,
            core_state,
            ctypes.byref(consumed_modifiers),
            ctypes.byref(keysym),
        ):
            raise InputObserverError(
                f"XKB could not resolve keycode {keycode} in active group "
                f"{int(state.group)}"
            )
        name_ptr = self._x11.XKeysymToString(keysym.value) if keysym.value else None
        name = name_ptr.decode(errors="replace") if name_ptr else None
        return int(keysym.value), name

    def _keysym_character(self, keysym: int) -> str | None:
        buffer = ctypes.create_string_buffer(64)
        length = int(
            self._xkbcommon.xkb_keysym_to_utf8(
                keysym,
                buffer,
                len(buffer),
            )
        )
        if length <= 1:
            return None
        return buffer.value.decode("utf-8", errors="strict")

    def _resolved_character(
        self,
        *,
        keycode: int,
        keysym: int,
        keysym_name: str | None,
        pressed: bool,
    ) -> str | None:
        if not pressed and keycode in self._unverifiable_keycodes:
            self._unverifiable_keycodes.discard(keycode)
            return None
        if keysym_name and (
            keysym_name.startswith("dead_")
            or keysym_name in {"Multi_key", "Compose"}
        ):
            if pressed:
                self._composition_mode = (
                    "dead" if keysym_name.startswith("dead_") else "multi"
                )
                self._unverifiable_keycodes.add(keycode)
            return None

        special_name = _SPECIAL_KEY_NAMES.get(keysym_name or "")
        if self._composition_mode is not None and special_name in {
            "enter",
            "esc",
            "space",
        }:
            if pressed:
                self._composition_mode = None
                self._unverifiable_keycodes.add(keycode)
            return None
        if self._composition_mode is not None and special_name is None:
            if pressed:
                self._unverifiable_keycodes.add(keycode)
                if self._composition_mode == "dead":
                    # A dead-key sequence resolves (or is rejected) on the
                    # next non-modifier key. Without the target app's IME
                    # result, that key's text is deliberately unverifiable.
                    self._composition_mode = None
            return None
        if special_name is not None:
            return None
        return self._keysym_character(keysym)

    def _handle_raw_event(self, raw: _XIRawEvent) -> None:
        injected = bool(raw.send_event)
        observed_at = time.time()
        if raw.evtype == _XI_RAW_MOTION:
            if self.observe_mouse and self.capture_mouse_moves:
                x, y = self._query_pointer()
                self._emit(
                    ObservedMouseMove(
                        x=x,
                        y=y,
                        injected=injected,
                        timestamp=observed_at,
                    )
                )
            return
        if raw.evtype in {_XI_RAW_BUTTON_PRESS, _XI_RAW_BUTTON_RELEASE}:
            if self.observe_mouse:
                x, y = self._query_pointer()
                event = normalize_xinput_button_event(
                    detail=raw.detail,
                    pressed=raw.evtype == _XI_RAW_BUTTON_PRESS,
                    x=x,
                    y=y,
                    injected=injected,
                    timestamp=observed_at,
                )
                if event is not None:
                    self._emit(event)
            return
        if raw.evtype in {_XI_RAW_KEY_PRESS, _XI_RAW_KEY_RELEASE}:
            if self.observe_keyboard:
                pressed = raw.evtype == _XI_RAW_KEY_PRESS
                keysym, keysym_name = self._lookup_keysym(raw.detail)
                self._emit(
                    normalize_xinput_key_event(
                        keycode=raw.detail,
                        pressed=pressed,
                        keysym_name=keysym_name,
                        injected=injected,
                        character=self._resolved_character(
                            keycode=raw.detail,
                            keysym=keysym,
                            keysym_name=keysym_name,
                            pressed=pressed,
                        ),
                        derive_character=False,
                        timestamp=observed_at,
                    )
                )

    def _run_loop(self) -> None:
        while not self._stop_requested.is_set():
            processed = 0
            while (
                not self._stop_requested.is_set()
                and processed < _MAX_PENDING_BATCH
                and self._x11.XPending(self._display)
            ):
                processed += 1
                event = _XEvent()
                self._x11.XNextEvent(self._display, ctypes.byref(event))
                cookie = event.xcookie
                if (
                    event.type != _GENERIC_EVENT
                    or cookie.extension != self._xi_opcode
                ):
                    continue
                if not self._x11.XGetEventData(
                    self._display, ctypes.byref(event.xcookie)
                ):
                    raise InputObserverError(
                        "XInput2 event cookie had no accessible event data"
                    )
                try:
                    if event.xcookie.data:
                        raw = ctypes.cast(
                            event.xcookie.data, ctypes.POINTER(_XIRawEvent)
                        ).contents
                        self._handle_raw_event(raw)
                finally:
                    self._x11.XFreeEventData(
                        self._display, ctypes.byref(event.xcookie)
                    )
            self._stop_requested.wait(0.01)

    def _teardown(self) -> None:
        if self._display and self._x11 is not None:
            self._x11.XCloseDisplay(self._display)
        self._display = None
        self._event_mask_buffer = None
        self._composition_mode = None
        self._unverifiable_keycodes.clear()


__all__ = [
    "LinuxXInputObserver",
    "normalize_xinput_button_event",
    "normalize_xinput_key_event",
]
