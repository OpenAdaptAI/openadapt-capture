"""Contract tests for optional native structural observations."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import sqlite3
import stat
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from openadapt_capture.capture import CaptureSession
from openadapt_capture.db import create_db, crud
from openadapt_capture.desktop_capture import DesktopCaptureScope
from openadapt_capture.recorder import (
    OrderedEventJournal,
    WindowActionReservation,
    _structural_observation_for_delivery,
    on_click,
    write_action_event,
)
from openadapt_capture.structural import (
    MAX_STRUCTURAL_ANCESTRY_DEPTH,
    MAX_STRUCTURAL_TEXT_LENGTH,
    BoundedStructuralObserver,
    StructuralBounds,
    StructuralCaptureWindowBinding,
    StructuralElement,
    StructuralObservation,
    StructuralObservationRequest,
    StructuralProcessIdentity,
    StructuralWindowIdentity,
    create_structural_observer,
)
from openadapt_capture.structural_observer.linux import (
    LinuxATSpiStructuralObserver,
    _GIAtspiRuntime,
)
from openadapt_capture.structural_observer.linux import (
    _fields as _atspi_fields,
)
from openadapt_capture.structural_observer.macos import (
    MacOSAXStructuralObserver,
    _AXRuntime,
)
from openadapt_capture.structural_observer.windows import (
    WindowsUIAStructuralObserver,
    _PywinautoRuntime,
)

_QUALIFICATION_FIXTURE_SCHEMA = (
    "openadapt.capture.structural-qualification-fixture/v1"
)
_QUALIFICATION_CLAIM_SCHEMA = (
    "openadapt.capture.structural-qualification-fixture-claim/v1"
)
_QUALIFICATION_FIXTURE_FIELDS = {
    "schema_version",
    "trial_uuid",
    "fixture_instance_uuid",
    "created_at",
    "output_owner_sha256",
    "provider",
    "process_id",
    "process_start_time",
    "native_window_handle",
    "window_bounds",
    "scale_x",
    "scale_y",
    "geometry_generation",
    "display_topology_sha256",
    "point",
    "focused_automation_id",
    "protected_point",
}
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
_LOWER_HEX_TOKEN = re.compile(r"[0-9a-f]{64}")


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_uuid(value: object, *, label: str) -> str:
    assert isinstance(value, str), f"{label} must be a UUID string"
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise AssertionError(f"{label} must be a canonical UUID") from exc
    assert str(parsed) == value, f"{label} must be a canonical lowercase UUID"
    return value


def _utc_timestamp(value: object, *, label: str) -> datetime:
    assert isinstance(value, str), f"{label} must be an RFC 3339 timestamp"
    assert value.endswith("Z"), f"{label} must use UTC Z form"
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AssertionError(f"{label} must be an RFC 3339 timestamp") from exc
    assert parsed.tzinfo is not None, f"{label} must include a timezone"
    return parsed.astimezone(timezone.utc)


def _load_and_claim_qualification_fixture() -> dict:
    """Read one fresh runner-owned fixture and claim it exactly once."""
    path_value = os.environ.get("OPENADAPT_CAPTURE_STRUCTURAL_FIXTURE_PATH")
    trial_uuid = _canonical_uuid(
        os.environ.get("OPENADAPT_CAPTURE_STRUCTURAL_TRIAL_UUID"),
        label="qualification trial UUID",
    )
    fixture_instance_uuid = _canonical_uuid(
        os.environ.get("OPENADAPT_CAPTURE_STRUCTURAL_FIXTURE_INSTANCE_UUID"),
        label="qualification fixture instance UUID",
    )
    trial_started_at = _utc_timestamp(
        os.environ.get("OPENADAPT_CAPTURE_STRUCTURAL_TRIAL_STARTED_AT"),
        label="qualification trial start",
    )
    owner_token = os.environ.get("OPENADAPT_CAPTURE_STRUCTURAL_OUTPUT_OWNER_TOKEN")
    runner_temp_value = os.environ.get("RUNNER_TEMP")
    assert path_value, "production qualification requires a fixture path"
    assert runner_temp_value, "production qualification requires RUNNER_TEMP"
    assert owner_token and _LOWER_HEX_TOKEN.fullmatch(owner_token), (
        "qualification output owner token must encode 32 random bytes"
    )

    path = Path(path_value)
    assert path.is_absolute(), "qualification fixture path must be absolute"
    expected_parent = (
        Path(runner_temp_value).resolve(strict=True)
        / "openadapt-capture-qualification"
        / trial_uuid
    )
    assert path.name == "structural-qualification-fixture.json"
    assert path.parent.resolve(strict=True) == expected_parent.resolve(strict=True), (
        "qualification fixture path is outside its exact private trial directory"
    )
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), (
        "qualification fixture must be a non-symlink regular file"
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened_metadata = os.fstat(descriptor)
        assert stat.S_ISREG(opened_metadata.st_mode), (
            "qualification fixture descriptor is not a regular file"
        )
        with os.fdopen(descriptor, "rb", closefd=False) as fixture_file:
            raw = fixture_file.read()
    finally:
        os.close(descriptor)
    try:
        fixture = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AssertionError("qualification fixture is not valid UTF-8 JSON") from exc
    assert isinstance(fixture, dict) and set(fixture) == _QUALIFICATION_FIXTURE_FIELDS
    assert raw == _canonical_json_bytes(fixture) + b"\n", (
        "qualification fixture must be exact canonical JSON plus LF"
    )
    assert fixture["schema_version"] == _QUALIFICATION_FIXTURE_SCHEMA
    assert fixture["trial_uuid"] == trial_uuid
    assert fixture["fixture_instance_uuid"] == fixture_instance_uuid
    expected_owner = hashlib.sha256(owner_token.encode("ascii")).hexdigest()
    assert fixture["output_owner_sha256"] == expected_owner
    assert _LOWER_SHA256.fullmatch(str(fixture["output_owner_sha256"]))
    created_at = _utc_timestamp(
        fixture["created_at"],
        label="qualification fixture creation time",
    )
    now = datetime.now(timezone.utc)
    assert trial_started_at <= created_at <= now, (
        "qualification fixture is stale or from the future"
    )

    fixture_sha256 = hashlib.sha256(raw).hexdigest()
    claim = {
        "schema_version": _QUALIFICATION_CLAIM_SCHEMA,
        "trial_uuid": trial_uuid,
        "fixture_instance_uuid": fixture_instance_uuid,
        "fixture_sha256": fixture_sha256,
        "claimed_at": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    claim_path = path.with_name("structural-qualification-fixture.claim.json")
    claim_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        claim_descriptor = os.open(claim_path, claim_flags, 0o600)
    except FileExistsError as exc:
        raise AssertionError("qualification fixture was already claimed") from exc
    try:
        claim_raw = _canonical_json_bytes(claim) + b"\n"
        with os.fdopen(claim_descriptor, "wb", closefd=False) as claim_file:
            claim_file.write(claim_raw)
            claim_file.flush()
            os.fsync(claim_file.fileno())
    finally:
        os.close(claim_descriptor)
    return fixture


class _Wrapper:
    def __init__(
        self,
        *,
        automation_id: str | None = None,
        control_type: str | None = None,
        name: str | None = None,
        role: str | None = None,
        process_id: int | None = None,
        parent: "_Wrapper | None" = None,
        top: "_Wrapper | None" = None,
        descendants: list["_Wrapper"] | None = None,
        title: str | None = None,
        patterns: tuple[str, ...] = (),
        is_password: bool = False,
    ) -> None:
        self.element_info = SimpleNamespace(
            automation_id=automation_id,
            control_type=control_type,
            name=name,
            class_name=None,
            framework_id=None,
            handle=None,
            process_id=process_id,
            rectangle=SimpleNamespace(left=10, top=20, right=110, bottom=60),
            is_password=is_password,
        )
        self._role = role
        self._parent = parent
        self._top = top
        self._descendants = descendants or []
        self._title = title
        self.descendant_queries: list[dict[str, object]] = []
        for pattern in patterns:
            setattr(self, f"iface_{pattern}", object())

    def friendly_class_name(self) -> str | None:
        return self._role

    def parent(self) -> "_Wrapper | None":
        return self._parent

    def top_level_parent(self) -> "_Wrapper":
        return self._top or self

    def descendants(self, **kwargs) -> list["_Wrapper"]:
        self.descendant_queries.append(kwargs)
        return self._descendants

    def window_text(self) -> str | None:
        return self._title


def _observation(request: StructuralObservationRequest) -> StructuralObservation:
    completed = request.receipt_monotonic_ns + 1_000_000
    return StructuralObservation(
        provider="windows_uia",
        event_timestamp=request.event_timestamp,
        receipt_monotonic_ns=request.receipt_monotonic_ns,
        completed_monotonic_ns=completed,
        completion_latency_ms=1.0,
        action_kind=request.action_kind,
        action_name=request.action_name,
        action_pressed=request.action_pressed,
        action_x=request.x,
        action_y=request.y,
        observer_phase=request.observer_phase,
        action_target_eligible=request.observer_phase == "pre_action",
        capture_window=request.capture_window,
        display_topology_sha256=request.display_topology_sha256,
        observed_at=request.event_timestamp + 0.001,
        query_kind="point" if request.x is not None else "focused",
        element=StructuralElement(
            automation_id="submit-order",
            role="Button",
            control_type="Button",
            name="Submit",
        ),
    )


class _Observer:
    def observe(
        self,
        request: StructuralObservationRequest,
    ) -> StructuralObservation:
        return _observation(request)


def _recording(capture_dir: Path):
    capture_dir.mkdir()
    engine, session_factory = create_db(str(capture_dir / "recording.db"))
    session = session_factory()
    recording = crud.insert_recording(
        session,
        {
            "timestamp": 100.0,
            "monitor_width": 1280,
            "monitor_height": 720,
            "double_click_interval_seconds": 0.5,
            "double_click_distance_pixels": 5,
            "platform": "win32",
            "task_description": "Structural observation test",
        },
    )
    return engine, session, recording


def test_windows_uia_observer_returns_exact_available_evidence() -> None:
    window = _Wrapper(
        automation_id="main-window",
        control_type="Window",
        name="Orders",
        role="Window",
        title="Orders - Example",
    )
    panel = _Wrapper(
        automation_id="order-panel",
        control_type="Pane",
        name="Order",
        role="Pane",
        parent=window,
        top=window,
    )
    target = _Wrapper(
        automation_id="submit-order",
        control_type="Button",
        name="Submit",
        role="Button",
        process_id=42,
        parent=panel,
        top=window,
        patterns=("invoke",),
    )
    duplicate = _Wrapper(
        automation_id="submit-order",
        control_type="Button",
        name="Other name",
        role="Button",
        top=window,
    )
    window._descendants = [target, duplicate]
    runtime = SimpleNamespace(
        from_point=lambda _x, _y: target,
        focused_element=lambda: target,
    )
    observer = WindowsUIAStructuralObserver(
        runtime=runtime,
        process_name_resolver=lambda process_id: "example.exe" if process_id == 42 else None,
        clock=lambda: 101.25,
    )

    observed = observer.observe(
        StructuralObservationRequest(
            event_timestamp=101.0,
            action_name="click",
            x=25,
            y=35,
        )
    )

    assert observed is not None
    assert observed.element.automation_id == "submit-order"
    assert observed.element.supported_patterns == ["Invoke"]
    assert observed.process is not None
    assert observed.process.process_name == "example.exe"
    assert observed.window is not None
    assert observed.window.title == "Orders - Example"
    assert [ancestor.automation_id for ancestor in observed.ancestry or []] == [
        "order-panel",
        "main-window",
    ]
    assert observed.candidate_count == 2
    assert observed.candidate_context is not None
    assert observed.candidate_context.matched_fields == [
        "automation_id",
        "control_type",
    ]
    assert window.descendant_queries == [{"control_type": "Button"}]
    assert "framework_id" not in observed.element.model_dump(exclude_none=True)


def test_windows_uia_omits_oversized_text_instead_of_truncating_identity() -> None:
    oversized = "x" * (MAX_STRUCTURAL_TEXT_LENGTH + 1)
    target = _Wrapper(
        automation_id="member-id",
        control_type="Edit",
        name=oversized,
        role="Edit",
        process_id=42,
        title=oversized,
    )
    target._top = target
    observer = WindowsUIAStructuralObserver(
        runtime=SimpleNamespace(
            from_point=lambda _x, _y: target,
            focused_element=lambda: target,
        ),
        process_name_resolver=lambda _process_id: oversized,
    )

    observed = observer.observe(
        StructuralObservationRequest(
            event_timestamp=101.0,
            action_name="click",
            x=25,
            y=35,
        )
    )

    assert observed is not None
    assert observed.element.automation_id == "member-id"
    assert observed.element.name is None
    assert observed.process is not None
    assert observed.process.process_name is None
    assert observed.window is not None
    assert observed.window.title is None


def test_structural_contract_accepts_namespaced_extension_provider() -> None:
    observation = StructuralObservation(
        provider="example_macos_ax",
        event_timestamp=101.0,
        receipt_monotonic_ns=1_000_000,
        completed_monotonic_ns=2_000_000,
        completion_latency_ms=1.0,
        action_kind="key",
        action_name="press",
        action_pressed=True,
        observer_phase="pre_action",
        action_target_eligible=True,
        observed_at=101.1,
        query_kind="focused",
        element=StructuralElement(role="AXTextField"),
    )

    assert observation.provider == "example_macos_ax"


def test_structural_bounds_reject_non_finite_or_inverted_provider_geometry() -> None:
    with pytest.raises(ValueError, match="finite"):
        StructuralBounds(left=0, top=0, right=float("nan"), bottom=10)
    with pytest.raises(ValueError, match="inverted"):
        StructuralBounds(left=10, top=0, right=5, bottom=10)


def test_windows_uia_ancestry_depth_is_bounded() -> None:
    with pytest.raises(ValueError, match="maximum_ancestry_depth"):
        WindowsUIAStructuralObserver(
            runtime=SimpleNamespace(),
            maximum_ancestry_depth=MAX_STRUCTURAL_ANCESTRY_DEPTH + 1,
        )


class _AXFakeRuntime:
    def __init__(self) -> None:
        self.window = object()
        self.parent = object()
        self.target = object()
        self.attributes = {
            (self.target, "AXIdentifier"): "submit-order",
            (self.target, "AXRole"): "AXButton",
            (self.target, "AXTitle"): "Submit",
            (self.target, "AXParent"): self.parent,
            (self.target, "AXWindow"): self.window,
            (self.parent, "AXRole"): "AXGroup",
            (self.parent, "AXTitle"): "Order",
            (self.parent, "AXParent"): self.window,
            (self.window, "AXRole"): "AXWindow",
            (self.window, "AXTitle"): "Orders",
            (self.window, "AXWindowNumber"): 44,
        }

    def attribute(self, element, name):
        return self.attributes.get((element, name))

    def element_at_point(self, x, y):
        assert (x, y) == (25, 35)
        return self.target

    def focused_element(self):
        return self.target

    def process_id(self, element):
        assert element is self.target
        return 42

    def actions(self, element):
        return ["AXPress"] if element is self.target else None

    def bounds(self, element):
        if element is self.target:
            from openadapt_capture.structural import StructuralBounds

            return StructuralBounds(left=10, top=20, right=110, bottom=60)
        return None


def test_macos_ax_observer_returns_action_time_evidence() -> None:
    observer = MacOSAXStructuralObserver(
        runtime=_AXFakeRuntime(),
        process_name_resolver=lambda pid: "Example" if pid == 42 else None,
        clock=lambda: 101.25,
    )

    observed = observer.observe(
        StructuralObservationRequest(
            event_timestamp=101.0,
            action_name="click",
            x=25,
            y=35,
        )
    )

    assert observed is not None
    assert observed.provider == "macos_ax"
    assert observed.query_kind == "point"
    assert observed.element.automation_id == "submit-order"
    assert observed.element.supported_patterns == ["AXPress"]
    assert observed.process is not None
    assert observed.process.process_name == "Example"
    assert observed.window is not None
    assert observed.window.native_window_handle == 44
    assert [item.role for item in observed.ancestry or []] == [
        "AXGroup",
        "AXWindow",
    ]


def test_macos_ax_runtime_falls_back_to_the_frontmost_application() -> None:
    system = object()
    application = object()
    focused = object()
    calls: list[tuple[object, str]] = []

    runtime = _AXRuntime.__new__(_AXRuntime)
    runtime.system = system
    runtime.frontmost_process_id = lambda: 42
    runtime.ax = SimpleNamespace(
        kAXErrorSuccess=0,
        AXUIElementCreateApplication=lambda process_id: (
            application if process_id == 42 else None
        ),
        AXUIElementCopyAttributeValue=lambda element, name, _output: (
            calls.append((element, name))
            or (0, focused if element is application else None)
        ),
    )

    assert runtime.focused_element() is focused
    assert calls == [
        (system, "AXFocusedUIElement"),
        (application, "AXFocusedUIElement"),
    ]


class _ATSpiElement:
    def __init__(self, name: str, parent=None) -> None:
        self.name = name
        self.parent = parent


class _ATSpiFakeRuntime:
    def __init__(self) -> None:
        self.application = _ATSpiElement("Example")
        self.window = _ATSpiElement("Orders", self.application)
        self.parent_element = _ATSpiElement("Order", self.window)
        self.target = _ATSpiElement("Submit", self.parent_element)

    def element_at_point(self, x, y):
        assert (x, y) == (25, 35)
        return self.target

    def focused_element(self):
        return self.target

    def parent(self, element):
        return element.parent

    def attributes(self, element):
        if element is self.target:
            return {"accessible-id": "submit-order", "class": "GtkButton"}
        return {}

    def role_name(self, element):
        return {
            self.target: "push button",
            self.parent_element: "panel",
            self.window: "frame",
            self.application: "application",
        }[element]

    def bounds(self, element):
        if element is self.target:
            from openadapt_capture.structural import StructuralBounds

            return StructuralBounds(left=10, top=20, right=110, bottom=60)
        return None

    def action_names(self, element):
        return ["click"] if element is self.target else None

    def process_id(self, element):
        assert element is self.target
        return 42


def test_linux_atspi_observer_returns_action_time_evidence() -> None:
    observer = LinuxATSpiStructuralObserver(
        runtime=_ATSpiFakeRuntime(),
        process_name_resolver=lambda pid: "example" if pid == 42 else None,
        clock=lambda: 101.5,
    )

    observed = observer.observe(
        StructuralObservationRequest(
            event_timestamp=101.0,
            action_name="press",
        )
    )

    assert observed is not None
    assert observed.provider == "linux_atspi"
    assert observed.query_kind == "focused"
    assert observed.element.automation_id == "submit-order"
    assert observed.element.class_name == "GtkButton"
    assert observed.element.supported_patterns == ["click"]
    assert observed.process is not None
    assert observed.process.process_name == "example"
    assert observed.window is not None
    assert observed.window.title == "Orders"
    assert [item.role for item in observed.ancestry or []] == [
        "panel",
        "frame",
        "application",
    ]


def test_gi_atspi_runtime_descends_from_desktop_point_query() -> None:
    class StateSet:
        def __init__(self, *states) -> None:
            self.states = set(states)

        def contains(self, state) -> bool:
            return state in self.states

    class Component:
        def __init__(self, child=None) -> None:
            self.child = child

        def get_accessible_at_point(self, x, y, coordinates):
            assert (x, y, coordinates) == (25, 35, "screen")
            return self.child

    class Node:
        def __init__(self, *, child=None, states=()) -> None:
            self.component = Component(child)
            self.states = StateSet(*states)

        def get_component_iface(self):
            return self.component

        def get_state_set(self):
            return self.states

    target = Node(states=("focused",))
    window = Node(child=target, states=("active",))
    application = Node(child=window)
    desktop = Node(child=application)
    runtime = _GIAtspiRuntime.__new__(_GIAtspiRuntime)
    runtime.atspi = SimpleNamespace(
        CoordType=SimpleNamespace(SCREEN="screen"),
        StateType=SimpleNamespace(ACTIVE="active", FOCUSED="focused"),
    )
    runtime.desktop = desktop

    assert runtime.element_at_point(25, 35) is target


def test_gi_atspi_runtime_omits_a_point_query_beyond_the_depth_bound() -> None:
    class Component:
        def __init__(self) -> None:
            self.child = None

        def get_accessible_at_point(self, _x, _y, _coordinates):
            return self.child

    class Node:
        def __init__(self) -> None:
            self.component = Component()

        def get_component_iface(self):
            return self.component

    nodes = [Node() for _ in range(MAX_STRUCTURAL_ANCESTRY_DEPTH + 3)]
    for current, child in zip(nodes, nodes[1:]):
        current.component.child = child
    runtime = _GIAtspiRuntime.__new__(_GIAtspiRuntime)
    runtime.atspi = SimpleNamespace(CoordType=SimpleNamespace(SCREEN="screen"))
    runtime.desktop = nodes[0]

    assert runtime.element_at_point(25, 35) is None


def test_gi_atspi_runtime_refuses_an_unbounded_child_list() -> None:
    node = SimpleNamespace(
        get_child_count=lambda: _GIAtspiRuntime._MAX_NODES + 1,
    )
    runtime = _GIAtspiRuntime.__new__(_GIAtspiRuntime)

    with pytest.raises(RuntimeError, match="child count"):
        runtime.children(node)


def test_gi_atspi_focused_search_refuses_a_truncated_tree() -> None:
    class Node:
        def __init__(self, *children, focused=False) -> None:
            self.children = list(children)
            self.focused = focused

        def get_child_count(self):
            return len(self.children)

        def get_child_at_index(self, index):
            return self.children[index]

        def get_state_set(self):
            return SimpleNamespace(contains=lambda state: state == "focused" and self.focused)

    first = Node(focused=True)
    second = Node()
    desktop = Node(first, second)
    runtime = _GIAtspiRuntime.__new__(_GIAtspiRuntime)
    runtime._MAX_NODES = 1
    runtime.atspi = SimpleNamespace(
        StateType=SimpleNamespace(FOCUSED="focused"),
    )
    runtime.desktop = desktop

    assert runtime.focused_element() is None


def test_gi_atspi_process_id_ascends_past_an_unowned_element() -> None:
    parent = SimpleNamespace(
        get_process_id=lambda: 42,
        parent=None,
    )
    target = SimpleNamespace(
        get_process_id=lambda: 0,
        parent=parent,
    )
    runtime = _GIAtspiRuntime.__new__(_GIAtspiRuntime)

    assert runtime.process_id(target) == 42


def test_atspi_fields_prefer_the_native_accessible_id() -> None:
    target = SimpleNamespace(
        name="Submit",
        get_accessible_id=lambda: "native-submit",
    )
    runtime = SimpleNamespace(
        attributes=lambda _element: {"accessible-id": "legacy-submit"},
        role_name=lambda _element: "push button",
        bounds=lambda _element: None,
        action_names=lambda _element: None,
    )

    fields = _atspi_fields(runtime, target)

    assert fields["automation_id"] == "native-submit"


@pytest.mark.parametrize(
    "observer_type",
    [MacOSAXStructuralObserver, LinuxATSpiStructuralObserver],
)
def test_cross_platform_runtime_is_owned_by_the_delivery_thread(observer_type) -> None:
    lifecycle: list[tuple[str, int]] = []
    fake = _AXFakeRuntime() if observer_type is MacOSAXStructuralObserver else _ATSpiFakeRuntime()

    class Runtime:
        def __getattr__(self, name):
            return getattr(fake, name)

        def close(self):
            lifecycle.append(("close", threading.get_ident()))

    def factory():
        lifecycle.append(("create", threading.get_ident()))
        return Runtime()

    observer = observer_type(runtime_factory=factory)

    def deliver() -> None:
        observer.open_current_thread()
        try:
            observation = observer.observe(
                StructuralObservationRequest(
                    event_timestamp=101.0,
                    action_name="press",
                )
            )
            assert observation is not None
        finally:
            observer.close_current_thread()

    thread = threading.Thread(target=deliver)
    thread.start()
    thread.join()

    assert [name for name, _thread_id in lifecycle] == ["create", "close"]
    assert len({thread_id for _name, thread_id in lifecycle}) == 1


def test_pywinauto_runtime_quantizes_points_and_uses_exact_focused_api() -> None:
    calls: list[tuple[str, object]] = []
    desktop = SimpleNamespace(
        from_point=lambda x, y: calls.append(("point", (x, y))) or "point-target",
        backend=SimpleNamespace(
            generic_wrapper_class=lambda info: calls.append(("wrap", info)) or "focused-target"
        ),
    )
    iui = SimpleNamespace(
        get_focused_element=lambda: calls.append(("focused", None)) or "raw-focused"
    )

    class ElementInfo:
        def __init__(self, raw: object) -> None:
            calls.append(("info", raw))

    runtime = _PywinautoRuntime.__new__(_PywinautoRuntime)
    runtime._desktop = desktop
    runtime._iui = iui
    runtime._element_info_type = ElementInfo

    assert runtime.from_point(25.49, -35.5) == "point-target"
    assert calls[0] == ("point", (25, -36))
    point = calls[0][1]
    assert isinstance(point, tuple)
    assert all(isinstance(value, int) for value in point)

    assert runtime.focused_element() == "focused-target"
    assert ("focused", None) in calls
    assert ("info", "raw-focused") in calls
    assert not hasattr(desktop, "get_active")


def test_uia_observer_owns_one_balanced_observation_thread() -> None:
    lifecycle: list[tuple[str, int]] = []
    observations: list[StructuralObservation | None] = []
    target = _Wrapper(
        automation_id="member-id",
        control_type="Edit",
        name="Member ID",
        role="Edit",
    )

    class Apartment:
        def __enter__(self):
            lifecycle.append(("enter", threading.get_ident()))
            return self

        def __exit__(self, _exc_type, _exc_val, _exc_tb) -> None:
            lifecycle.append(("exit", threading.get_ident()))

    class Runtime:
        def __init__(self) -> None:
            lifecycle.append(("runtime", threading.get_ident()))

        def from_point(self, _x: float, _y: float) -> _Wrapper:
            lifecycle.append(("point", threading.get_ident()))
            return target

        def focused_element(self) -> _Wrapper:
            lifecycle.append(("focused", threading.get_ident()))
            return target

        def close(self) -> None:
            lifecycle.append(("runtime-close", threading.get_ident()))

    observer = WindowsUIAStructuralObserver(
        runtime_factory=Runtime,
        apartment_factory=Apartment,
    )

    def observe_on_delivery_thread() -> None:
        observer.open_current_thread()
        try:
            observations.append(
                observer.observe(
                    StructuralObservationRequest(
                        event_timestamp=101.0,
                        action_name="click",
                        x=25.0,
                        y=35.0,
                    )
                )
            )
            observations.append(
                observer.observe(
                    StructuralObservationRequest(
                        event_timestamp=102.0,
                        action_name="press",
                    )
                )
            )
        finally:
            observer.close_current_thread()

    thread = threading.Thread(target=observe_on_delivery_thread)
    thread.start()
    thread.join()

    point, focused = observations
    assert point is not None and point.query_kind == "point"
    assert focused is not None and focused.query_kind == "focused"
    thread_ids = {thread_id for _name, thread_id in lifecycle}
    assert len(thread_ids) == 1
    assert [name for name, _thread_id in lifecycle] == [
        "enter",
        "runtime",
        "point",
        "focused",
        "runtime-close",
        "exit",
    ]


def test_structural_evidence_persists_through_capture_session(
    tmp_path: Path,
    monkeypatch,
) -> None:
    capture_dir = tmp_path / "capture"
    engine, session, recording = _recording(capture_dir)
    monkeypatch.setattr(
        "openadapt_capture.recorder.window.get_active_element_state",
        lambda _x, _y: {},
    )
    monkeypatch.setattr(
        "openadapt_capture.recorder.utils.get_timestamp",
        lambda: 101.2,
    )
    event_queue: queue.Queue = queue.Queue()
    perf_queue: queue.Queue = queue.Queue()

    on_click(
        event_queue,
        None,
        25,
        35,
        "left",
        True,
        timestamp=101.0,
        structural_observer=_Observer(),
    )
    on_click(
        event_queue,
        None,
        25,
        35,
        "left",
        False,
        timestamp=101.1,
        structural_observer=_Observer(),
    )
    write_action_event(session, recording, event_queue.get_nowait(), perf_queue)
    write_action_event(session, recording, event_queue.get_nowait(), perf_queue)
    session.close()
    engine.dispose()

    with CaptureSession.load(capture_dir) as capture:
        raw = capture.raw_events()
        actions = list(capture.actions())

        assert raw[0].structural_observation is not None
        assert raw[0].structural_observation.element.automation_id == "submit-order"
        assert raw[0].structural_observation.observer_phase == "post_action_unverified"
        assert raw[0].structural_observation.action_target_eligible is False
        assert raw[1].structural_observation is None
        assert len(actions) == 1
        assert actions[0].structural_observation is not None
        assert actions[0].structural_observation.element.name == "Submit"


def test_legacy_action_table_is_migrated_without_fabricated_evidence(
    tmp_path: Path,
) -> None:
    capture_dir = tmp_path / "legacy"
    engine, session, recording = _recording(capture_dir)
    crud.insert_action_event(
        session,
        recording,
        101.0,
        {
            "name": "scroll",
            "mouse_x": 25,
            "mouse_y": 35,
            "mouse_dx": 0,
            "mouse_dy": -1,
        },
    )
    session.close()
    engine.dispose()

    database_path = capture_dir / "recording.db"
    connection = sqlite3.connect(database_path)
    connection.execute("ALTER TABLE action_event DROP COLUMN structural_observation")
    connection.commit()
    connection.close()

    with CaptureSession.load(capture_dir) as capture:
        event = capture.raw_events()[0]
        assert event.structural_observation is None

    connection = sqlite3.connect(database_path)
    columns = {row[1] for row in connection.execute("PRAGMA table_info(action_event)")}
    connection.close()
    assert "structural_observation" in columns


@pytest.mark.parametrize(
    ("platform_name", "target"),
    [
        (
            "darwin",
            "openadapt_capture.structural_observer.macos.MacOSAXStructuralObserver",
        ),
        (
            "linux",
            "openadapt_capture.structural_observer.linux.LinuxATSpiStructuralObserver",
        ),
    ],
)
def test_factory_selects_each_native_structural_provider(
    monkeypatch, platform_name, target
) -> None:
    sentinel = object()
    monkeypatch.setattr(target, lambda: sentinel)
    assert create_structural_observer(platform_name=platform_name) is sentinel


def test_unsupported_platform_factory_is_headless_safe() -> None:
    assert create_structural_observer(platform_name="freebsd") is None


def test_windows_factory_omits_optional_evidence_when_uia_cannot_start(
    monkeypatch,
) -> None:
    def fail() -> None:
        raise RuntimeError("COM unavailable")

    monkeypatch.setattr(
        "openadapt_capture.structural_observer.windows.WindowsUIAStructuralObserver",
        fail,
    )
    assert create_structural_observer(platform_name="win32") is None


def test_lazy_uia_start_failure_does_not_abort_native_capture() -> None:
    attempts = 0

    def fail_runtime():
        nonlocal attempts
        attempts += 1
        raise RuntimeError("UIA unavailable")

    observer = WindowsUIAStructuralObserver(
        runtime_factory=fail_runtime,
        apartment_factory=lambda: SimpleNamespace(
            __enter__=lambda: None,
            __exit__=lambda *_args: None,
        ),
    )
    request = StructuralObservationRequest(
        event_timestamp=101.0,
        action_name="click",
        x=25.0,
        y=35.0,
    )
    assert observer.observe(request) is None
    assert observer.observe(request) is None
    assert attempts == 1


def _receipt_request(
    *,
    phase: str = "pre_action",
    action_name: str = "click",
    x: float | None = 25.0,
    y: float | None = 35.0,
    capture_window: StructuralCaptureWindowBinding | None = None,
) -> StructuralObservationRequest:
    return StructuralObservationRequest(
        event_timestamp=101.0,
        receipt_monotonic_ns=time.monotonic_ns(),
        action_kind="mouse_button" if x is not None else "key",
        action_name=action_name,
        action_pressed=True,
        x=x,
        y=y,
        observer_phase=phase,
        capture_window=capture_window,
        display_topology_sha256=(
            capture_window.display_topology_sha256 if capture_window else None
        ),
    )


def _write_qualification_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    created_at: str | None = None,
) -> tuple[Path, dict]:
    trial_uuid = "91ad0469-7282-474a-83ca-f68ad061f5aa"
    fixture_instance_uuid = "a77fcf06-9821-4d62-a538-b6f6cd2c62bf"
    owner_token = "ab" * 32
    timestamp = created_at or datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    fixture = {
        "schema_version": _QUALIFICATION_FIXTURE_SCHEMA,
        "trial_uuid": trial_uuid,
        "fixture_instance_uuid": fixture_instance_uuid,
        "created_at": timestamp,
        "output_owner_sha256": hashlib.sha256(owner_token.encode("ascii")).hexdigest(),
        "provider": "windows_uia",
        "process_id": os.getpid(),
        "process_start_time": psutil.Process().create_time(),
        "native_window_handle": 42,
        "window_bounds": {"left": -900, "top": 10, "right": -100, "bottom": 700},
        "scale_x": 1.25,
        "scale_y": 1.25,
        "geometry_generation": 3,
        "display_topology_sha256": "a" * 64,
        "point": {"x": -700, "y": 200, "automation_id": "normal"},
        "focused_automation_id": "focused",
        "protected_point": {
            "x": -700,
            "y": 300,
            "automation_id": "protected",
        },
    }
    fixture_dir = tmp_path / "openadapt-capture-qualification" / trial_uuid
    fixture_dir.mkdir(parents=True)
    fixture_path = fixture_dir / "structural-qualification-fixture.json"
    fixture_path.write_bytes(_canonical_json_bytes(fixture) + b"\n")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("OPENADAPT_CAPTURE_STRUCTURAL_FIXTURE_PATH", str(fixture_path))
    monkeypatch.setenv("OPENADAPT_CAPTURE_STRUCTURAL_TRIAL_UUID", trial_uuid)
    monkeypatch.setenv(
        "OPENADAPT_CAPTURE_STRUCTURAL_FIXTURE_INSTANCE_UUID",
        fixture_instance_uuid,
    )
    monkeypatch.setenv(
        "OPENADAPT_CAPTURE_STRUCTURAL_TRIAL_STARTED_AT",
        timestamp,
    )
    monkeypatch.setenv(
        "OPENADAPT_CAPTURE_STRUCTURAL_OUTPUT_OWNER_TOKEN",
        owner_token,
    )
    return fixture_path, fixture


@pytest.mark.structural_qualification_contract
def test_qualification_fixture_is_canonical_private_fresh_and_one_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_path, fixture = _write_qualification_fixture(tmp_path, monkeypatch)
    assert _load_and_claim_qualification_fixture() == fixture
    claim_path = fixture_path.with_name("structural-qualification-fixture.claim.json")
    claim_raw = claim_path.read_bytes()
    claim = json.loads(claim_raw)
    assert set(claim) == {
        "schema_version",
        "trial_uuid",
        "fixture_instance_uuid",
        "fixture_sha256",
        "claimed_at",
    }
    assert claim["schema_version"] == _QUALIFICATION_CLAIM_SCHEMA
    assert claim["fixture_sha256"] == hashlib.sha256(fixture_path.read_bytes()).hexdigest()
    assert claim_raw == _canonical_json_bytes(claim) + b"\n"
    assert stat.S_IMODE(claim_path.stat().st_mode) & 0o077 == 0
    with pytest.raises(AssertionError, match="already claimed"):
        _load_and_claim_qualification_fixture()


@pytest.mark.structural_qualification_contract
def test_qualification_fixture_refuses_stale_owner_and_noncanonical_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_path, fixture = _write_qualification_fixture(
        tmp_path,
        monkeypatch,
        created_at="2026-08-27T12:00:00Z",
    )
    monkeypatch.setenv(
        "OPENADAPT_CAPTURE_STRUCTURAL_TRIAL_STARTED_AT",
        "2026-08-27T12:00:01Z",
    )
    with pytest.raises(AssertionError, match="stale"):
        _load_and_claim_qualification_fixture()

    monkeypatch.setenv(
        "OPENADAPT_CAPTURE_STRUCTURAL_TRIAL_STARTED_AT",
        "2026-08-27T12:00:00Z",
    )
    fixture["output_owner_sha256"] = "b" * 64
    fixture_path.write_bytes(_canonical_json_bytes(fixture) + b"\n")
    with pytest.raises(AssertionError):
        _load_and_claim_qualification_fixture()

    fixture["output_owner_sha256"] = hashlib.sha256(
        ("ab" * 32).encode("ascii")
    ).hexdigest()
    fixture_path.write_bytes(json.dumps(fixture).encode("utf-8"))
    with pytest.raises(AssertionError, match="canonical"):
        _load_and_claim_qualification_fixture()


@pytest.mark.structural_qualification_contract
def test_qualification_fixture_refuses_a_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_path, _fixture = _write_qualification_fixture(tmp_path, monkeypatch)
    target = tmp_path / "outside.json"
    target.write_bytes(fixture_path.read_bytes())
    fixture_path.unlink()
    try:
        fixture_path.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"this host cannot create a test symlink: {exc}")
    with pytest.raises(AssertionError, match="non-symlink"):
        _load_and_claim_qualification_fixture()


@pytest.mark.structural_qualification_contract
def test_bounded_observer_timeout_cannot_stall_receipt_or_shutdown() -> None:
    entered = threading.Event()
    release = threading.Event()

    class HungObserver:
        def observe(self, _request):
            entered.set()
            release.wait()
            return None

    controller = BoundedStructuralObserver(
        HungObserver(),
        deadline_seconds=0.01,
        startup_timeout_seconds=0.01,
    )
    started = time.monotonic()
    assert controller.capture(_receipt_request()) is None
    assert entered.wait(timeout=0.1)
    assert time.monotonic() - started < 0.1
    assert controller.quarantined is True

    stopped = time.monotonic()
    controller.stop()
    assert time.monotonic() - stopped < 0.1
    release.set()


@pytest.mark.structural_qualification_contract
def test_bounded_observer_recovers_after_provider_failure() -> None:
    calls = 0

    class RecoveringObserver:
        def observe(self, request):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("provider restarted")
            return _observation(request)

    controller = BoundedStructuralObserver(
        RecoveringObserver(),
        deadline_seconds=0.1,
        startup_timeout_seconds=0.1,
    )
    try:
        assert controller.capture(_receipt_request()) is None
        observed = controller.capture(_receipt_request())
        assert observed is not None
        assert observed.element.automation_id == "submit-order"
    finally:
        controller.stop()
    assert calls == 2


@pytest.mark.structural_qualification_contract
def test_delivery_uses_the_reserved_snapshot_after_queue_delay_and_refuses_tab() -> None:
    journal = OrderedEventJournal()
    request = _receipt_request(
        phase="post_action_unverified",
        action_name="press",
        x=None,
        y=None,
    )
    reservation = journal.reserve(request.event_timestamp)
    reservation.set_structural_observation(_observation(request))
    time.sleep(0.01)

    event_data = {
        "name": "press",
        "canonical_key_name": "a",
    }
    observed = _structural_observation_for_delivery(
        reservation,
        event_timestamp=request.event_timestamp,
        event_data=event_data,
        raw_x=None,
        raw_y=None,
        coordinate_scope=None,
    )
    assert observed is not None
    assert observed.observer_phase == "post_action_unverified"
    assert observed.action_target_eligible is False

    event_data["canonical_key_name"] = "tab"
    assert (
        _structural_observation_for_delivery(
            reservation,
            event_timestamp=request.event_timestamp,
            event_data=event_data,
            raw_x=None,
            raw_y=None,
            coordinate_scope=None,
        )
        is None
    )


@pytest.mark.structural_qualification_contract
def test_delivery_refuses_action_coordinate_and_capture_window_mismatch() -> None:
    capture_window = StructuralCaptureWindowBinding(
        window_id="44",
        process_id=42,
        process_start_time=100.0,
        bounds=StructuralBounds(left=-1920, top=0, right=-920, bottom=800),
        scale_x=1.5,
        scale_y=1.5,
        geometry_generation=3,
        display_topology_sha256="a" * 64,
    )
    request = _receipt_request(
        x=-1500.5,
        y=200.25,
        capture_window=capture_window,
    )
    observation = _observation(request).model_copy(
        update={
            "process": StructuralProcessIdentity(process_id=99),
            "window": StructuralWindowIdentity(native_window_handle=45),
        }
    )
    journal = OrderedEventJournal()
    event_reservation = journal.reserve(request.event_timestamp)

    class Scope:
        def structural_binding_for_reserved_geometry(self, _geometry):
            return capture_window.model_dump(mode="json")

    reservation = WindowActionReservation(event_reservation, Scope(), ())
    reservation.set_structural_observation(observation)
    event_data = {"name": "click", "mouse_pressed": True}
    assert (
        _structural_observation_for_delivery(
            reservation,
            event_timestamp=request.event_timestamp,
            event_data=event_data,
            raw_x=request.x,
            raw_y=request.y,
            coordinate_scope=None,
        )
        is None
    )
    assert (
        _structural_observation_for_delivery(
            reservation,
            event_timestamp=request.event_timestamp,
            event_data=event_data,
            raw_x=request.x + 1,
            raw_y=request.y,
            coordinate_scope=None,
        )
        is None
    )


@pytest.mark.structural_qualification_contract
def test_protected_values_are_excluded_by_each_provider() -> None:
    secret = "correct horse battery staple"
    windows_target = _Wrapper(
        automation_id="password",
        control_type="Edit",
        name=secret,
        role="Edit",
        process_id=42,
        is_password=True,
    )
    windows_target._top = windows_target
    windows = WindowsUIAStructuralObserver(
        runtime=SimpleNamespace(
            from_point=lambda _x, _y: windows_target,
            focused_element=lambda: windows_target,
        )
    ).observe(_receipt_request())

    mac_runtime = _AXFakeRuntime()
    mac_runtime.attributes[(mac_runtime.target, "AXProtectedContent")] = True
    mac_runtime.attributes[(mac_runtime.target, "AXTitle")] = secret
    macos = MacOSAXStructuralObserver(runtime=mac_runtime).observe(_receipt_request())

    linux_runtime = _ATSpiFakeRuntime()
    linux_runtime.target.name = secret
    linux_runtime.is_protected = lambda element: element is linux_runtime.target
    linux = LinuxATSpiStructuralObserver(runtime=linux_runtime).observe(_receipt_request())

    for observation in (windows, macos, linux):
        assert observation is not None
        assert observation.element.protected_value is True
        assert observation.element.name is None
        assert secret not in observation.model_dump_json()


@pytest.mark.structural_qualification_contract
def test_post_action_observation_cannot_claim_action_target_identity() -> None:
    request = _receipt_request(phase="post_action_unverified")
    data = _observation(request).model_dump(mode="json")
    data["action_target_eligible"] = True
    with pytest.raises(ValueError, match="eligibility"):
        StructuralObservation.model_validate(data)


@pytest.mark.slow
@pytest.mark.skipif(
    os.environ.get("OPENADAPT_CAPTURE_PRODUCTION_QUALIFICATION") != "1",
    reason="requires the explicit interactive production qualification rig",
)
def test_live_native_structural_provider_matches_the_reviewed_fixture() -> None:
    fixture = _load_and_claim_qualification_fixture()
    observer = create_structural_observer()
    assert observer is not None, "the native structural provider is required"
    expected_provider = {
        "win32": "windows_uia",
        "darwin": "macos_ax",
        "linux": "linux_atspi",
    }["linux" if sys.platform.startswith("linux") else sys.platform]
    assert fixture["provider"] == expected_provider
    phase = "post_action_unverified" if sys.platform.startswith("linux") else "pre_action"
    window_bounds = StructuralBounds.model_validate(fixture["window_bounds"])
    capture_window = StructuralCaptureWindowBinding(
        window_id=str(fixture["native_window_handle"]),
        process_id=int(fixture["process_id"]),
        process_start_time=float(fixture["process_start_time"]),
        bounds=window_bounds,
        scale_x=float(fixture["scale_x"]),
        scale_y=float(fixture["scale_y"]),
        geometry_generation=int(fixture["geometry_generation"]),
        display_topology_sha256=str(fixture["display_topology_sha256"]),
    )
    assert psutil.Process(capture_window.process_id).create_time() == (
        capture_window.process_start_time
    )
    live_topology = DesktopCaptureScope.current().snapshot()
    assert live_topology["topology_sha256"] == (
        capture_window.display_topology_sha256
    )
    point = fixture["point"]
    protected_point = fixture["protected_point"]
    assert set(point) == {"x", "y", "automation_id"}
    assert set(protected_point) == {"x", "y", "automation_id"}
    assert min(float(point["x"]), float(point["y"])) < 0, (
        "the reviewed fixture must be on a negative-origin monitor"
    )
    assert capture_window.scale_x > 0 and capture_window.scale_y > 0

    controller = BoundedStructuralObserver(observer)
    try:
        requests = [
            StructuralObservationRequest(
                event_timestamp=101.0,
                receipt_monotonic_ns=time.monotonic_ns(),
                action_kind="mouse_button",
                action_name="click",
                action_pressed=True,
                x=float(point["x"]),
                y=float(point["y"]),
                observer_phase=phase,
                capture_window=capture_window,
                display_topology_sha256=capture_window.display_topology_sha256,
            ),
            StructuralObservationRequest(
                event_timestamp=102.0,
                receipt_monotonic_ns=time.monotonic_ns(),
                action_kind="key",
                action_name="press",
                action_pressed=True,
                observer_phase=phase,
                capture_window=capture_window,
                display_topology_sha256=capture_window.display_topology_sha256,
            ),
            StructuralObservationRequest(
                event_timestamp=103.0,
                receipt_monotonic_ns=time.monotonic_ns(),
                action_kind="mouse_button",
                action_name="click",
                action_pressed=True,
                x=float(protected_point["x"]),
                y=float(protected_point["y"]),
                observer_phase=phase,
                capture_window=capture_window,
                display_topology_sha256=capture_window.display_topology_sha256,
            ),
        ]
        point_observation, focused_observation, protected_observation = [
            controller.capture(request) for request in requests
        ]
    finally:
        controller.stop()

    assert point_observation is not None
    assert point_observation.provider == expected_provider
    assert point_observation.query_kind == "point"
    assert point_observation.element.automation_id == point["automation_id"]
    assert point_observation.process is not None
    assert point_observation.process.process_id == capture_window.process_id
    assert point_observation.window is not None
    assert point_observation.window.bounds == window_bounds
    if expected_provider != "linux_atspi":
        assert (
            point_observation.window.native_window_handle
            == int(capture_window.window_id)
        )
    assert point_observation.element.bounds is not None
    assert (
        point_observation.element.bounds.left
        <= float(point["x"])
        < point_observation.element.bounds.right
    )
    assert (
        point_observation.element.bounds.top
        <= float(point["y"])
        < point_observation.element.bounds.bottom
    )
    assert point_observation.completion_latency_ms <= 75

    assert focused_observation is not None
    assert focused_observation.query_kind == "focused"
    assert (
        focused_observation.element.automation_id
        == fixture["focused_automation_id"]
    )
    assert focused_observation.completion_latency_ms <= 75

    assert protected_observation is not None
    assert protected_observation.element.automation_id == protected_point["automation_id"]
    assert protected_observation.element.protected_value is True
    assert protected_observation.element.name is None
    assert protected_observation.completion_latency_ms <= 75
