"""Windows UI Automation observation without input injection.

``pywinauto`` is imported only when the Windows observer is instantiated.
Importing this module on macOS, Linux, or a headless host is side-effect free.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from openadapt_capture.structural import (
    StructuralAncestor,
    StructuralBounds,
    StructuralCandidateContext,
    StructuralElement,
    StructuralObservation,
    StructuralObservationRequest,
    StructuralProcessIdentity,
    StructuralWindowIdentity,
)

_SUPPORTED_PATTERN_ATTRIBUTES = (
    ("ExpandCollapse", "iface_expand_collapse"),
    ("Selection", "iface_selection"),
    ("SelectionItem", "iface_selection_item"),
    ("Invoke", "iface_invoke"),
    ("Toggle", "iface_toggle"),
    ("Text", "iface_text"),
    ("Value", "iface_value"),
    ("RangeValue", "iface_range_value"),
    ("Grid", "iface_grid"),
    ("GridItem", "iface_grid_item"),
    ("Table", "iface_table"),
    ("TableItem", "iface_table_item"),
    ("ScrollItem", "iface_scroll_item"),
    ("Scroll", "iface_scroll"),
    ("Transform", "iface_transform"),
    ("Window", "iface_window"),
)


def _present_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _present_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _safe_value(obj: Any, name: str) -> Any:
    try:
        return getattr(obj, name)
    except Exception:
        return None


def _safe_call(obj: Any, name: str) -> Any:
    value = _safe_value(obj, name)
    if not callable(value):
        return None
    try:
        return value()
    except Exception:
        return None


def _bounds(value: Any) -> StructuralBounds | None:
    if value is None:
        return None

    def read(name: str) -> Any:
        if isinstance(value, dict):
            return value.get(name)
        return _safe_value(value, name)

    raw = {name: read(name) for name in ("left", "top", "right", "bottom")}
    if any(item is None for item in raw.values()):
        return None
    try:
        return StructuralBounds(**raw)
    except (TypeError, ValueError):
        return None


def _element_info(wrapper: Any) -> Any:
    return _safe_value(wrapper, "element_info")


def _element_fields(wrapper: Any) -> dict[str, Any]:
    info = _element_info(wrapper)
    if info is None:
        return {}
    role = _present_string(_safe_call(wrapper, "friendly_class_name"))
    return {
        "automation_id": _present_string(
            _safe_value(info, "automation_id")
            or _safe_value(info, "auto_id")
        ),
        "role": role,
        "role_source": "pywinauto_friendly_class" if role else None,
        "control_type": _present_string(_safe_value(info, "control_type")),
        "name": _present_string(_safe_value(info, "name")),
        "class_name": _present_string(_safe_value(info, "class_name")),
        "framework_id": _present_string(_safe_value(info, "framework_id")),
        "native_window_handle": _present_int(
            _safe_value(info, "handle") or _safe_value(wrapper, "handle")
        ),
        "bounds": _bounds(_safe_value(info, "rectangle")),
    }


def _supported_patterns(wrapper: Any) -> list[str]:
    supported: list[str] = []
    for name, attribute in _SUPPORTED_PATTERN_ATTRIBUTES:
        try:
            if getattr(wrapper, attribute) is not None:
                supported.append(name)
        except Exception:
            continue
    return supported


def _as_element(wrapper: Any) -> StructuralElement:
    return StructuralElement(
        **_element_fields(wrapper),
        supported_patterns=_supported_patterns(wrapper),
    )


def _as_ancestor(wrapper: Any) -> StructuralAncestor | None:
    fields = _element_fields(wrapper)
    fields.pop("framework_id", None)
    fields.pop("native_window_handle", None)
    ancestor = StructuralAncestor(**fields)
    if not ancestor.model_dump(exclude_none=True):
        return None
    return ancestor


def _ancestry(wrapper: Any, *, maximum_depth: int) -> list[StructuralAncestor] | None:
    ancestors: list[StructuralAncestor] = []
    current = wrapper
    for _ in range(maximum_depth):
        parent = _safe_call(current, "parent")
        if parent is None:
            break
        ancestor = _as_ancestor(parent)
        if ancestor is not None:
            ancestors.append(ancestor)
        current = parent
    return ancestors or None


def _window_identity(wrapper: Any) -> StructuralWindowIdentity | None:
    top = _safe_call(wrapper, "top_level_parent")
    if top is None:
        return None
    fields = _element_fields(top)
    title = _present_string(_safe_call(top, "window_text")) or fields.get("name")
    identity = StructuralWindowIdentity(
        title=title,
        automation_id=fields.get("automation_id"),
        class_name=fields.get("class_name"),
        native_window_handle=fields.get("native_window_handle"),
        bounds=fields.get("bounds"),
    )
    if not identity.model_dump(exclude_none=True):
        return None
    return identity


def _candidate_cardinality(
    target: Any,
) -> tuple[int | None, StructuralCandidateContext | None]:
    target_fields = _element_fields(target)
    automation_id = target_fields.get("automation_id")
    control_type = target_fields.get("control_type")
    name = target_fields.get("name")

    search_kwargs: dict[str, str] = {}
    matched_fields: list[str] = []
    if automation_id:
        search_kwargs["auto_id"] = automation_id
        matched_fields.append("automation_id")
        if control_type:
            search_kwargs["control_type"] = control_type
            matched_fields.append("control_type")
    elif control_type and name:
        search_kwargs["control_type"] = control_type
        search_kwargs["title"] = name
        matched_fields.extend(("control_type", "name"))
    else:
        return None, None

    top = _safe_call(target, "top_level_parent")
    if top is None:
        return None, None
    try:
        candidates = list(top.descendants(**search_kwargs))
    except Exception:
        return None, None

    def exact_match(candidate: Any) -> bool:
        fields = _element_fields(candidate)
        return all(
            {
                "automation_id": fields.get("automation_id") == automation_id,
                "control_type": fields.get("control_type") == control_type,
                "name": fields.get("name") == name,
            }[field]
            for field in matched_fields
        )

    count = sum(1 for candidate in candidates if exact_match(candidate))
    if exact_match(top):
        count += 1
    return count, StructuralCandidateContext(
        scope="top_level_window",
        matched_fields=matched_fields,
    )


class WindowsUIAStructuralObserver:
    """Read Windows UIA evidence at a pointer or focused-element action."""

    def __init__(
        self,
        *,
        desktop_factory: Callable[[], Any] | None = None,
        process_name_resolver: Callable[[int], str | None] | None = None,
        clock: Callable[[], float] = time.time,
        maximum_ancestry_depth: int = 12,
    ) -> None:
        if desktop_factory is None:
            from pywinauto import Desktop

            def desktop_factory() -> Any:
                return Desktop(backend="uia")
        if process_name_resolver is None:
            process_name_resolver = self._resolve_process_name
        self._desktop_factory = desktop_factory
        self._process_name_resolver = process_name_resolver
        self._clock = clock
        self._maximum_ancestry_depth = maximum_ancestry_depth

    @staticmethod
    def _resolve_process_name(process_id: int) -> str | None:
        try:
            import psutil

            return _present_string(psutil.Process(process_id).name())
        except Exception:
            return None

    def observe(
        self,
        request: StructuralObservationRequest,
    ) -> StructuralObservation | None:
        desktop = self._desktop_factory()
        if request.x is not None and request.y is not None:
            target = desktop.from_point(request.x, request.y)
            query_kind = "point"
        else:
            target = desktop.get_active()
            query_kind = "focused"
        if target is None:
            return None

        element = _as_element(target)
        info = _element_info(target)
        process_id = _present_int(_safe_value(info, "process_id"))
        process = None
        if process_id is not None:
            process = StructuralProcessIdentity(
                process_id=process_id,
                process_name=self._process_name_resolver(process_id),
            )
        candidate_count, candidate_context = _candidate_cardinality(target)
        return StructuralObservation(
            provider="windows_uia",
            event_timestamp=request.event_timestamp,
            observed_at=self._clock(),
            query_kind=query_kind,
            element=element,
            process=process,
            window=_window_identity(target),
            ancestry=_ancestry(
                target,
                maximum_depth=self._maximum_ancestry_depth,
            ),
            candidate_count=candidate_count,
            candidate_context=candidate_context,
        )


__all__ = ["WindowsUIAStructuralObserver"]
