"""Contract tests for optional native structural observations."""

from __future__ import annotations

import queue
import sqlite3
from pathlib import Path
from types import SimpleNamespace

from openadapt_capture.capture import CaptureSession
from openadapt_capture.db import create_db, crud
from openadapt_capture.recorder import on_click, write_action_event
from openadapt_capture.structural import (
    StructuralElement,
    StructuralObservation,
    StructuralObservationRequest,
    create_structural_observer,
)
from openadapt_capture.structural_observer.windows import (
    WindowsUIAStructuralObserver,
)


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
        )
        self._role = role
        self._parent = parent
        self._top = top
        self._descendants = descendants or []
        self._title = title
        for pattern in patterns:
            setattr(self, f"iface_{pattern}", object())

    def friendly_class_name(self) -> str | None:
        return self._role

    def parent(self) -> "_Wrapper | None":
        return self._parent

    def top_level_parent(self) -> "_Wrapper":
        return self._top or self

    def descendants(self, **_kwargs) -> list["_Wrapper"]:
        return self._descendants

    def window_text(self) -> str | None:
        return self._title


def _observation(event_timestamp: float) -> StructuralObservation:
    return StructuralObservation(
        provider="windows_uia",
        event_timestamp=event_timestamp,
        observed_at=event_timestamp + 0.001,
        query_kind="point",
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
        return _observation(request.event_timestamp)


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
    desktop = SimpleNamespace(
        from_point=lambda _x, _y: target,
        get_active=lambda: target,
    )
    observer = WindowsUIAStructuralObserver(
        desktop_factory=lambda: desktop,
        process_name_resolver=lambda process_id: (
            "example.exe" if process_id == 42 else None
        ),
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
    assert "framework_id" not in observed.element.model_dump(exclude_none=True)


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
    connection.execute(
        "ALTER TABLE action_event DROP COLUMN structural_observation"
    )
    connection.commit()
    connection.close()

    with CaptureSession.load(capture_dir) as capture:
        event = capture.raw_events()[0]
        assert event.structural_observation is None

    connection = sqlite3.connect(database_path)
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(action_event)")
    }
    connection.close()
    assert "structural_observation" in columns


def test_non_windows_factory_is_headless_safe() -> None:
    assert create_structural_observer(platform_name="linux") is None
