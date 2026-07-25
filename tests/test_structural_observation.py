"""Native structural evidence survives Capture's public action API."""

import time

from openadapt_capture.capture import CaptureSession
from openadapt_capture.config import RecordingConfig, config, config_override
from openadapt_capture.db import create_db, crud
from openadapt_capture.window import _windows

OBSERVATION = {
    "schema_version": 1,
    "observer": "windows_uia",
    "target": {
        "role": "Button",
        "name": "Submit",
        "automation_id": "submitButton",
        "class_name": "Button",
        "bounds": {"left": 10, "top": 20, "right": 110, "bottom": 50},
        "supported_patterns": ["invoke"],
    },
    "ancestors": [],
    "window_name": "Claims",
    "process_id": 1234,
}


def _capture_with_click(tmp_path, element_state):
    db_path = tmp_path / "recording.db"
    engine, session_factory = create_db(str(db_path))
    session = session_factory()
    recording = crud.insert_recording(
        session,
        {
            "timestamp": time.time(),
            "monitor_width": 1920,
            "monitor_height": 1080,
            "double_click_interval_seconds": 0.5,
            "double_click_distance_pixels": 5,
            "platform": "win32",
        },
    )
    for offset, pressed in ((0.001, True), (0.002, False)):
        crud.insert_action_event(
            session,
            recording,
            recording.timestamp + offset,
            {
                "name": "click",
                "mouse_x": 50,
                "mouse_y": 35,
                "mouse_button_name": "left",
                "mouse_pressed": pressed,
                "element_state": element_state if pressed else {},
            },
        )
    session.close()
    engine.dispose()
    return CaptureSession.load(tmp_path)


def test_versioned_uia_observation_round_trips_into_processed_click(tmp_path):
    with _capture_with_click(tmp_path, OBSERVATION) as capture:
        (action,) = list(capture.actions())

    observation = action.structural_observation
    assert observation is not None
    assert observation.target.automation_id == "submitButton"
    assert observation.window_name == "Claims"


def test_legacy_element_state_is_not_promoted_to_structural_evidence(tmp_path):
    with _capture_with_click(tmp_path, {"control_type": "Button"}) as capture:
        (action,) = list(capture.actions())

    assert action.structural_observation is None


def test_windows_observer_emits_json_safe_fingerprint(monkeypatch):
    class Rect:
        left, top, right, bottom = 10, 20, 110, 50

    class Info:
        process_id = 1234
        automation_id = "submitButton"
        class_name = "Button"
        control_type = "Button"

    class Element:
        element_info = Info()
        iface_invoke = object()

        def __init__(self, name, parent=None):
            self.name = name
            self._parent = parent

        def get_properties(self):
            return {
                "texts": [self.name],
                "control_type": "Button",
                "rectangle": Rect(),
            }

        def parent(self):
            return self._parent

    window = Element("Claims")
    target = Element("Submit", window)
    window.from_point = lambda _x, _y: target
    monkeypatch.setattr(_windows, "get_active_window", lambda: window)

    observation = _windows.get_active_element_observation(50, 35)
    assert observation["target"]["automation_id"] == "submitButton"
    assert observation["target"]["supported_patterns"] == ["invoke"]
    assert observation["ancestors"][0]["name"] == "Claims"


def test_recording_config_exposes_structural_observer_toggle():
    original = config.RECORD_READ_ACTIVE_ELEMENT_STATE
    with config_override(RecordingConfig(capture_structural_observations=True)):
        assert config.RECORD_READ_ACTIVE_ELEMENT_STATE is True
    assert config.RECORD_READ_ACTIVE_ELEMENT_STATE == original
