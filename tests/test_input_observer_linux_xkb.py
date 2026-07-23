"""Linux XInput2 ABI, XKB text semantics, and shutdown contracts."""

from __future__ import annotations

import ctypes

import pytest

from openadapt_capture.input_observer import ObservedKey
from openadapt_capture.input_observer import linux as linux_module
from openadapt_capture.input_observer.linux import (
    LinuxXInputObserver,
    _XIRawEvent,
    _XkbStateRec,
)


class FakeX11:
    def __init__(
        self,
        *,
        group: int = 0,
        lookup_mods: int = 0,
        keysym: int = 0x61,
        keysym_name: str = "a",
    ) -> None:
        self.group = group
        self.lookup_mods = lookup_mods
        self.keysym = keysym
        self.keysym_name = keysym_name
        self.lookup_states: list[int] = []

    def XkbGetState(self, _display, _device, state_pointer) -> int:
        state = ctypes.cast(
            state_pointer,
            ctypes.POINTER(_XkbStateRec),
        ).contents
        state.group = self.group
        state.lookup_mods = self.lookup_mods
        return 0

    def XkbLookupKeySym(
        self,
        _display,
        _keycode,
        state,
        _consumed_pointer,
        keysym_pointer,
    ) -> int:
        self.lookup_states.append(int(state))
        ctypes.cast(
            keysym_pointer,
            ctypes.POINTER(ctypes.c_ulong),
        ).contents.value = self.keysym
        return 1

    def XKeysymToString(self, _keysym):
        return self.keysym_name.encode()


class FakeXkbCommon:
    def __init__(self, text_by_keysym: dict[int, str]) -> None:
        self.text_by_keysym = text_by_keysym

    def xkb_keysym_to_utf8(self, keysym, buffer, size) -> int:
        encoded = self.text_by_keysym.get(int(keysym), "").encode()
        if not encoded:
            return 0
        assert len(encoded) + 1 <= int(size)
        ctypes.memmove(buffer, encoded + b"\0", len(encoded) + 1)
        return len(encoded) + 1


class FakeComposeXkbCommon(FakeXkbCommon):
    def __init__(self) -> None:
        super().__init__({0x65: "e", 0x78: "x"})
        self.statuses = iter(
            [
                linux_module._XKB_COMPOSE_COMPOSING,
                linux_module._XKB_COMPOSE_COMPOSED,
                0,
            ]
        )
        self.status = 0
        self.reset_count = 0

    def xkb_compose_state_feed(self, _state, _keysym) -> int:
        self.status = next(self.statuses)
        return 1

    def xkb_compose_state_get_status(self, _state) -> int:
        return self.status

    def xkb_compose_state_get_utf8(self, _state, buffer, size) -> int:
        encoded = "é".encode()
        assert len(encoded) + 1 <= int(size)
        ctypes.memmove(buffer, encoded + b"\0", len(encoded) + 1)
        return len(encoded)

    def xkb_compose_state_reset(self, _state) -> None:
        self.reset_count += 1


def make_observer() -> LinuxXInputObserver:
    return LinuxXInputObserver(
        lambda _event: None,
        observe_keyboard=True,
        observe_mouse=True,
        capture_mouse_moves=True,
        environ={"DISPLAY": ":0", "XDG_SESSION_TYPE": "x11"},
    )


@pytest.mark.skipif(
    ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_ulong) != 8,
    reason="ABI offsets below describe Linux's 64-bit LP64 data model",
)
def test_xinput_raw_event_matches_primary_header_lp64_abi() -> None:
    assert ctypes.sizeof(_XIRawEvent) == 96
    assert _XIRawEvent.flags.offset == 60
    assert _XIRawEvent.valuators.offset == 64
    assert _XIRawEvent.raw_values.offset == 88


def test_xkb_lookup_uses_active_group_caps_and_altgr_state() -> None:
    observer = make_observer()
    x11 = FakeX11(
        group=2,
        lookup_mods=0x82,
        keysym=0x20AC,
        keysym_name="EuroSign",
    )
    observer._display = object()
    observer._x11 = x11
    observer._xkbcommon = FakeXkbCommon({0x20AC: "€"})

    keysym, name = observer._lookup_keysym(26)

    assert (keysym, name) == (0x20AC, "EuroSign")
    assert x11.lookup_states == [0x82 | (2 << linux_module._XKB_GROUP_SHIFT)]
    assert (
        observer._resolved_character(
            keycode=26,
            keysym=keysym,
            keysym_name=name,
            pressed=True,
        )
        == "€"
    )


def test_dead_key_and_resolving_key_are_text_unverifiable() -> None:
    observer = make_observer()
    observer._xkbcommon = FakeXkbCommon({0x65: "e", 0x78: "x"})

    assert (
        observer._resolved_character(
            keycode=48,
            keysym=0xFE51,
            keysym_name="dead_acute",
            pressed=True,
        )
        is None
    )
    assert (
        observer._resolved_character(
            keycode=26,
            keysym=0x65,
            keysym_name="e",
            pressed=True,
        )
        is None
    )
    assert (
        observer._resolved_character(
            keycode=26,
            keysym=0x65,
            keysym_name="e",
            pressed=False,
        )
        is None
    )
    assert (
        observer._resolved_character(
            keycode=53,
            keysym=0x78,
            keysym_name="x",
            pressed=True,
        )
        == "x"
    )


def test_multi_key_sequence_never_guesses_application_compose_text() -> None:
    observer = make_observer()
    observer._xkbcommon = FakeXkbCommon({0x61: "a", 0x62: "b", 0x78: "x"})

    for keycode, keysym, name in [
        (65, 0xFF20, "Multi_key"),
        (38, 0x61, "a"),
        (56, 0x62, "b"),
    ]:
        assert (
            observer._resolved_character(
                keycode=keycode,
                keysym=keysym,
                keysym_name=name,
                pressed=True,
            )
            is None
        )

    assert (
        observer._resolved_character(
            keycode=53,
            keysym=0x78,
            keysym_name="x",
            pressed=True,
        )
        == "x"
    )


def test_locale_compose_state_commits_exact_text_then_resumes_normal_text() -> None:
    observer = make_observer()
    xkbcommon = FakeComposeXkbCommon()
    observer._xkbcommon = xkbcommon
    observer._compose_state = object()

    assert (
        observer._resolved_character(
            keycode=48,
            keysym=0xFE51,
            keysym_name="dead_acute",
            pressed=True,
        )
        is None
    )
    assert (
        observer._resolved_character(
            keycode=26,
            keysym=0x65,
            keysym_name="e",
            pressed=True,
        )
        == "é"
    )
    assert xkbcommon.reset_count == 1
    assert (
        observer._resolved_character(
            keycode=53,
            keysym=0x78,
            keysym_name="x",
            pressed=True,
        )
        == "x"
    )


def test_raw_event_stamps_receipt_time_before_delivery(
    monkeypatch,
) -> None:
    events = []
    observer = make_observer()
    observer._emit = events.append  # type: ignore[method-assign]
    observer._lookup_keysym = lambda _keycode: (0x61, "a")  # type: ignore[method-assign]
    observer._xkbcommon = FakeXkbCommon({0x61: "a"})
    monkeypatch.setattr(linux_module.time, "time", lambda: 321.5)
    raw = _XIRawEvent(
        evtype=linux_module._XI_RAW_KEY_PRESS,
        detail=38,
    )

    observer._handle_raw_event(raw)

    assert events == [
        ObservedKey(
            pressed=True,
            key_char="a",
            key_vk="38",
            canonical_key_char="a",
            canonical_key_vk="38",
            timestamp=321.5,
        )
    ]


def test_continuous_pending_events_cannot_prevent_stop() -> None:
    observer = make_observer()

    class AlwaysPendingX11:
        def __init__(self) -> None:
            self.next_count = 0

        def XPending(self, _display) -> int:
            return 1

        def XNextEvent(self, _display, event_pointer) -> None:
            self.next_count += 1
            event = ctypes.cast(
                event_pointer,
                ctypes.POINTER(linux_module._XEvent),
            ).contents
            event.type = 0
            if self.next_count == 5:
                observer._stop_requested.set()

    x11 = AlwaysPendingX11()
    observer._x11 = x11
    observer._display = object()

    observer._run_loop()

    assert x11.next_count == 5
