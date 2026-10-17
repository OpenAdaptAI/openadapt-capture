"""The input boundary of shadow mining: one normalized UI event.

A :class:`ShadowEvent` can still hold raw text (a typed value, a control
label, a URL). It exists only in memory, between an event source and the
:class:`~openadapt_capture.shadow.symbols.Tokenizer`. The tokenizer turns it
into a :class:`~openadapt_capture.shadow.symbols.ShadowSymbol`, which holds no
raw typed text, and only symbols reach the ring buffer.

The adapters below map Capture's existing event models onto this boundary.
They never read a window title, a screenshot, or the clipboard's contents.
Copy and paste are recognized from the key chord alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ShadowKind = Literal[
    "focus",
    "click",
    "double_click",
    "right_click",
    "type",
    "key",
    "shortcut",
    "copy",
    "paste",
    "navigate",
    "submit",
]

SHADOW_KINDS: frozenset[str] = frozenset(ShadowKind.__args__)  # type: ignore[attr-defined]

_COPY_KEYS = frozenset({"c", "x"})
_PASTE_KEYS = frozenset({"v"})
_CLIPBOARD_MODIFIERS = frozenset({"ctrl", "meta", "cmd", "command"})


@dataclass(frozen=True)
class ShadowEvent:
    """One user action, normalized across platforms and sources.

    Attributes:
        timestamp: Unix time in seconds.
        kind: What the person did.
        app: Process or bundle name of the application. Never a window title.
        window_class: Accessibility or toolkit class of the window, if known.
        role: Accessibility role of the target control, if known.
        label: Accessible name of the target control. Raw; never stored.
        text: Typed text. Raw; never stored.
        key: Named key for ``key`` and ``shortcut`` events.
        modifiers: Modifier keys held for ``shortcut``, ``copy``, and ``paste``.
        url: Page URL for browser events. Raw; only a pattern is stored.
        secure: True for a password or secure field. Its value is dropped,
            not hashed.
    """

    timestamp: float
    kind: ShadowKind
    app: str | None = None
    window_class: str | None = None
    role: str | None = None
    label: str | None = None
    text: str | None = None
    key: str | None = None
    modifiers: tuple[str, ...] = ()
    url: str | None = None
    secure: bool = False

    def __post_init__(self) -> None:
        if self.kind not in SHADOW_KINDS:
            raise ValueError(f"unknown shadow event kind {self.kind!r}")

    def __repr__(self) -> str:  # never echo raw text into logs
        return (
            f"ShadowEvent(t={self.timestamp:.3f}, kind={self.kind!r}, app={self.app!r}, "
            f"role={self.role!r})"
        )


def _attr(obj: Any, *names: str) -> Any:
    for name in names:
        if obj is None:
            return None
        obj = getattr(obj, name, None)
    return obj


def _structural_context(event: Any) -> dict[str, Any]:
    from openadapt_capture.structural import omit_tree_value

    obs = getattr(event, "structural_observation", None)
    role = _attr(obs, "element", "role") or _attr(obs, "element", "control_type")
    control_type = _attr(obs, "element", "control_type")
    return {
        "app": _attr(obs, "process", "process_name"),
        "window_class": _attr(obs, "window", "class_name"),
        "role": role,
        "label": _attr(obs, "element", "name"),
        "secure": omit_tree_value(role, control_type),
    }


def _chord_kind(modifiers: tuple[str, ...], key: str) -> ShadowKind:
    mods = {m.casefold() for m in modifiers}
    k = key.casefold()
    if mods & _CLIPBOARD_MODIFIERS and len(mods) == 1:
        if k in _COPY_KEYS:
            return "copy"
        if k in _PASTE_KEYS:
            return "paste"
    return "shortcut"


def from_capture_event(event: Any) -> ShadowEvent | None:
    """Map one merged Capture action event onto a :class:`ShadowEvent`.

    Supports ``mouse.singleclick``, ``mouse.doubleclick``, ``key.type`` and
    ``key.shortcut``. Raw mouse moves, key downs, scrolls, frames, and audio
    return ``None``; shadow mining does not use them.
    """

    etype = getattr(getattr(event, "type", None), "value", getattr(event, "type", None))
    ts = float(getattr(event, "timestamp", 0.0))
    if etype in ("mouse.singleclick", "mouse.click", "mouse.doubleclick"):
        ctx = _structural_context(event)
        button = str(getattr(event, "button", "left")).casefold()
        if etype == "mouse.doubleclick":
            kind: ShadowKind = "double_click"
        elif button == "right":
            kind = "right_click"
        else:
            kind = "click"
        return ShadowEvent(timestamp=ts, kind=kind, **ctx)
    if etype == "key.type":
        ctx = _structural_context(event)
        text = getattr(event, "text", "") or ""
        if not text:
            names = [
                getattr(c, "canonical_key_name", None) or getattr(c, "key_name", None)
                for c in getattr(event, "children", [])
            ]
            names = [n for n in names if n]
            return ShadowEvent(timestamp=ts, kind="key", key=names[0] if names else None, **ctx)
        return ShadowEvent(timestamp=ts, kind="type", text=text, **ctx)
    if etype == "key.shortcut":
        ctx = _structural_context(event)
        mods = tuple(getattr(event, "modifiers", ()) or ())
        key = str(getattr(event, "key", ""))
        return ShadowEvent(
            timestamp=ts, kind=_chord_kind(mods, key), key=key, modifiers=mods, **ctx
        )
    return None


def from_browser_event(event: Any, *, app: str | None = "browser") -> ShadowEvent | None:
    """Map one Capture browser event onto a :class:`ShadowEvent`."""

    etype = getattr(getattr(event, "type", None), "value", getattr(event, "type", None))
    ts = float(getattr(event, "timestamp", 0.0))
    url = getattr(event, "url", None)
    element = getattr(event, "element", None)
    role = getattr(element, "role", None)
    label = getattr(element, "name", None)
    tag = (getattr(element, "tag_name", "") or "").casefold()
    secure = tag == "input" and "password" in (getattr(element, "css_selector", "") or "")
    if etype == "navigate":
        nav = getattr(getattr(event, "navigation_type", None), "value", None)
        kind: ShadowKind = "submit" if nav == "form_submit" else "navigate"
        return ShadowEvent(timestamp=ts, kind=kind, app=app, url=url)
    if etype == "click":
        kind = "double_click" if getattr(event, "click_count", 1) == 2 else "click"
        return ShadowEvent(
            timestamp=ts, kind=kind, app=app, role=role, label=label, url=url, secure=secure
        )
    if etype == "input":
        return ShadowEvent(
            timestamp=ts,
            kind="type",
            app=app,
            role=role or "textfield",
            label=label,
            text=getattr(event, "data", None),
            url=url,
            secure=secure,
        )
    return None


def from_window_event(event: Any) -> ShadowEvent | None:
    """Map a Capture window event onto a ``focus`` event.

    Uses the owning application only. The window title is never read, since
    titles routinely carry document names, record names, and email subjects.
    """

    state = getattr(event, "state", None) or {}
    app = state.get("owner") or state.get("app") or state.get("process_name")
    if not app:
        return None
    return ShadowEvent(
        timestamp=float(getattr(event, "timestamp", 0.0)),
        kind="focus",
        app=str(app),
        window_class=state.get("class_name"),
    )
