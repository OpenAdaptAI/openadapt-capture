"""Versioned structural observations captured beside native input events.

Structural observations are optional evidence.  They describe what the native
accessibility API exposed at action time; absent values stay absent rather than
being guessed from pixels, coordinates, or neighboring controls.
"""

from __future__ import annotations

import logging
import math
import queue
import sys
import threading
import time
from dataclasses import dataclass
from typing import Annotated, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

STRUCTURAL_OBSERVATION_SCHEMA_VERSION = "openadapt.capture.structural-observation/v1"
MAX_STRUCTURAL_TEXT_LENGTH = 512
MAX_STRUCTURAL_ANCESTRY_DEPTH = 32
DEFAULT_STRUCTURAL_OBSERVATION_DEADLINE_SECONDS = 0.075
DEFAULT_STRUCTURAL_OBSERVER_STARTUP_TIMEOUT_SECONDS = 1.0

_PROVIDER_PATTERN = r"^[a-z][a-z0-9_.-]*$"
_StructuralText = Annotated[str, Field(max_length=MAX_STRUCTURAL_TEXT_LENGTH)]
_ProviderIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=64, pattern=_PROVIDER_PATTERN),
]

_logger = logging.getLogger(__name__)


class StructuralBounds(BaseModel):
    """Screen-space bounds reported by the accessibility provider."""

    model_config = ConfigDict(extra="forbid")

    left: float
    top: float
    right: float
    bottom: float

    @model_validator(mode="after")
    def validate_bounds(self) -> "StructuralBounds":
        """Reject a non-finite or inverted provider rectangle."""
        values = (self.left, self.top, self.right, self.bottom)
        if not all(math.isfinite(value) for value in values):
            raise ValueError("structural bounds must be finite")
        if self.right < self.left or self.bottom < self.top:
            raise ValueError("structural bounds must not be inverted")
        return self


class StructuralElement(BaseModel):
    """Stable and semantic fields exposed for one accessibility element."""

    model_config = ConfigDict(extra="forbid")

    automation_id: _StructuralText | None = None
    role: _StructuralText | None = None
    role_source: _ProviderIdentifier | None = None
    control_type: _StructuralText | None = None
    name: _StructuralText | None = None
    class_name: _StructuralText | None = None
    framework_id: _StructuralText | None = None
    native_window_handle: int | None = None
    bounds: StructuralBounds | None = None
    supported_patterns: list[_StructuralText] | None = Field(
        default=None,
        max_length=64,
    )
    protected_value: bool = False

    @model_validator(mode="after")
    def exclude_protected_text(self) -> "StructuralElement":
        """Never retain a protected control's accessible name as evidence."""
        if self.protected_value and self.name is not None:
            raise ValueError("a protected structural element must not retain its name")
        return self


class StructuralAncestor(BaseModel):
    """One parent in the target's accessibility ancestry."""

    model_config = ConfigDict(extra="forbid")

    automation_id: _StructuralText | None = None
    role: _StructuralText | None = None
    role_source: _ProviderIdentifier | None = None
    control_type: _StructuralText | None = None
    name: _StructuralText | None = None
    class_name: _StructuralText | None = None
    bounds: StructuralBounds | None = None


class StructuralProcessIdentity(BaseModel):
    """Identity of the process that owned the observed element."""

    model_config = ConfigDict(extra="forbid")

    process_id: int | None = Field(default=None, ge=0)
    process_name: _StructuralText | None = None


class StructuralWindowIdentity(BaseModel):
    """Identity of the target's top-level window."""

    model_config = ConfigDict(extra="forbid")

    title: _StructuralText | None = None
    automation_id: _StructuralText | None = None
    class_name: _StructuralText | None = None
    native_window_handle: int | None = None
    bounds: StructuralBounds | None = None


class StructuralCandidateContext(BaseModel):
    """How candidate cardinality was measured."""

    model_config = ConfigDict(extra="forbid")

    scope: Literal["top_level_window"]
    matched_fields: list[Literal["automation_id", "control_type", "name"]] = Field(min_length=1)


class StructuralCaptureWindowBinding(BaseModel):
    """Exact window and geometry epoch reserved with one native action."""

    model_config = ConfigDict(extra="forbid")

    window_id: str = Field(min_length=1)
    process_id: int = Field(gt=0)
    process_start_time: float = Field(gt=0)
    bounds: StructuralBounds
    scale_x: float = Field(gt=0)
    scale_y: float = Field(gt=0)
    geometry_generation: int = Field(ge=1)
    display_topology_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class StructuralObservation(BaseModel):
    """UI structure retained beside one native action event."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["openadapt.capture.structural-observation/v1"] = (
        STRUCTURAL_OBSERVATION_SCHEMA_VERSION
    )
    provider: _ProviderIdentifier = Field(
        description=(
            "Accessibility-provider identifier. Native Capture providers are "
            "windows_uia, macos_ax, and linux_atspi."
        ),
    )
    event_timestamp: float
    receipt_monotonic_ns: int = Field(ge=0)
    completed_monotonic_ns: int = Field(ge=0)
    completion_latency_ms: float = Field(ge=0)
    action_kind: Literal["key", "mouse_button", "mouse_scroll"]
    action_name: _StructuralText
    action_pressed: bool | None = None
    action_x: float | None = None
    action_y: float | None = None
    observer_phase: Literal["pre_action", "post_action_unverified"]
    action_target_eligible: bool
    capture_window: StructuralCaptureWindowBinding | None = None
    display_topology_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    observed_at: float
    query_kind: Literal["point", "focused"]
    element: StructuralElement
    process: StructuralProcessIdentity | None = None
    window: StructuralWindowIdentity | None = None
    ancestry: list[StructuralAncestor] | None = Field(
        default=None,
        max_length=MAX_STRUCTURAL_ANCESTRY_DEPTH,
    )
    candidate_count: int | None = Field(default=None, ge=0)
    candidate_context: StructuralCandidateContext | None = None

    @model_validator(mode="after")
    def validate_receipt_binding(self) -> "StructuralObservation":
        """Require exact timing, coordinates, and causal-use declarations."""
        numeric = (self.event_timestamp, self.observed_at, self.completion_latency_ms)
        if not all(math.isfinite(value) for value in numeric):
            raise ValueError("structural timing values must be finite")
        if self.completed_monotonic_ns < self.receipt_monotonic_ns:
            raise ValueError("structural completion precedes native receipt")
        expected_latency = (
            self.completed_monotonic_ns - self.receipt_monotonic_ns
        ) / 1_000_000
        if not math.isclose(
            self.completion_latency_ms,
            expected_latency,
            rel_tol=0,
            abs_tol=1e-6,
        ):
            raise ValueError("structural completion latency differs from its clocks")
        if (self.action_x is None) != (self.action_y is None):
            raise ValueError("structural action coordinates must be complete or absent")
        if self.action_x is not None and not all(
            math.isfinite(value) for value in (self.action_x, self.action_y)
        ):
            raise ValueError("structural action coordinates must be finite")
        if self.query_kind == "point" and self.action_x is None:
            raise ValueError("point structural evidence requires action coordinates")
        if self.query_kind == "focused" and self.action_x is not None:
            raise ValueError("focused structural evidence must not claim point coordinates")
        if self.action_kind in {"key", "mouse_button"}:
            if self.action_pressed is None:
                raise ValueError("key/button structural evidence requires pressed state")
        elif self.action_pressed is not None:
            raise ValueError("scroll structural evidence must not claim pressed state")
        expected_eligible = self.observer_phase == "pre_action"
        if self.action_target_eligible is not expected_eligible:
            raise ValueError("structural target eligibility differs from observer phase")
        if self.capture_window is not None:
            topology = self.capture_window.display_topology_sha256
            if self.display_topology_sha256 not in (None, topology):
                raise ValueError("capture-window and action topology digests differ")
        return self


@dataclass(frozen=True)
class StructuralObservationRequest:
    """An action-time request passed to a platform structural observer."""

    event_timestamp: float
    action_name: str
    x: float | None = None
    y: float | None = None
    action_pressed: bool | None = None
    receipt_monotonic_ns: int = 0
    action_kind: Literal["key", "mouse_button", "mouse_scroll"] | None = None
    observer_phase: Literal["pre_action", "post_action_unverified"] = "pre_action"
    capture_window: StructuralCaptureWindowBinding | None = None
    display_topology_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.action_kind is None:
            inferred_kind = (
                "mouse_scroll"
                if self.action_name == "scroll"
                else "mouse_button"
                if self.x is not None
                else "key"
            )
            object.__setattr__(self, "action_kind", inferred_kind)
        if self.action_pressed is None and self.action_kind in {"key", "mouse_button"}:
            object.__setattr__(
                self,
                "action_pressed",
                self.action_name in {"press", "click"},
            )
        if not math.isfinite(float(self.event_timestamp)):
            raise ValueError("structural event timestamp must be finite")
        if self.receipt_monotonic_ns < 0:
            raise ValueError("structural receipt monotonic time must be non-negative")
        if (self.x is None) != (self.y is None):
            raise ValueError("structural request coordinates must be complete or absent")
        if self.x is not None and not all(
            math.isfinite(float(value)) for value in (self.x, self.y)
        ):
            raise ValueError("structural request coordinates must be finite")
        if self.action_kind in {"key", "mouse_button"}:
            if self.action_pressed is None:
                raise ValueError("key/button structural request requires pressed state")
        elif self.action_pressed is not None:
            raise ValueError("scroll structural request must not claim pressed state")


@dataclass(frozen=True, slots=True)
class _ObservationTask:
    request: StructuralObservationRequest
    done: threading.Event
    cancelled: threading.Event
    result: list[StructuralObservation | None]


@runtime_checkable
class StructuralObserver(Protocol):
    """Injectable interface for platform accessibility observation."""

    def observe(
        self,
        request: StructuralObservationRequest,
    ) -> StructuralObservation | None:
        """Return provider evidence for the action, or ``None`` if unavailable."""
        ...


def structural_observation_receipt_fields(
    request: StructuralObservationRequest,
    *,
    completed_monotonic_ns: int | None = None,
) -> dict[str, object]:
    """Return the closed action/timing fields copied into provider evidence."""
    completed = time.monotonic_ns() if completed_monotonic_ns is None else int(
        completed_monotonic_ns
    )
    if completed < request.receipt_monotonic_ns:
        raise ValueError("structural completion precedes native receipt")
    return {
        "event_timestamp": request.event_timestamp,
        "receipt_monotonic_ns": request.receipt_monotonic_ns,
        "completed_monotonic_ns": completed,
        "completion_latency_ms": (
            completed - request.receipt_monotonic_ns
        ) / 1_000_000,
        "action_kind": request.action_kind,
        "action_name": request.action_name,
        "action_pressed": request.action_pressed,
        "action_x": request.x,
        "action_y": request.y,
        "observer_phase": request.observer_phase,
        "action_target_eligible": request.observer_phase == "pre_action",
        "capture_window": request.capture_window,
        "display_topology_sha256": request.display_topology_sha256,
    }


class BoundedStructuralObserver:
    """Run one optional native provider behind a strict receipt-time deadline."""

    def __init__(
        self,
        observer: StructuralObserver,
        *,
        deadline_seconds: float = DEFAULT_STRUCTURAL_OBSERVATION_DEADLINE_SECONDS,
        startup_timeout_seconds: float = (
            DEFAULT_STRUCTURAL_OBSERVER_STARTUP_TIMEOUT_SECONDS
        ),
    ) -> None:
        if not math.isfinite(deadline_seconds) or deadline_seconds <= 0:
            raise ValueError("structural observation deadline must be positive")
        if not math.isfinite(startup_timeout_seconds) or startup_timeout_seconds <= 0:
            raise ValueError("structural observer startup timeout must be positive")
        self._observer = observer
        self.deadline_seconds = deadline_seconds
        self.startup_timeout_seconds = startup_timeout_seconds
        self._queue: queue.Queue[_ObservationTask | object] = queue.Queue(maxsize=1)
        self._sentinel = object()
        self._ready = threading.Event()
        self._stopped = threading.Event()
        self._quarantined = threading.Event()
        self._thread: threading.Thread | None = None
        self._start_lock = threading.Lock()

    @property
    def quarantined(self) -> bool:
        """Return whether one timed-out provider call disabled this session."""
        return self._quarantined.is_set()

    def start(self) -> bool:
        """Start and prewarm the provider without an unbounded recorder wait."""
        with self._start_lock:
            if self._thread is None:
                thread = threading.Thread(
                    target=self._worker,
                    name="openadapt-structural-observer",
                    daemon=True,
                )
                self._thread = thread
                thread.start()
        if not self._ready.wait(self.startup_timeout_seconds):
            self._quarantined.set()
            _logger.warning(
                "Structural observation disabled after a %.3fs startup timeout",
                self.startup_timeout_seconds,
            )
            return False
        return not self._quarantined.is_set()

    def capture(
        self,
        request: StructuralObservationRequest,
    ) -> StructuralObservation | None:
        """Return one receipt snapshot or omit it before the deadline."""
        if self._stopped.is_set() or self._quarantined.is_set() or not self.start():
            return None
        task = _ObservationTask(request, threading.Event(), threading.Event(), [])
        try:
            self._queue.put_nowait(task)
        except queue.Full:
            _logger.warning("Structural observation omitted because its worker is busy")
            return None
        if not task.done.wait(self.deadline_seconds):
            task.cancelled.set()
            self._quarantined.set()
            _logger.warning(
                "Structural observation omitted after its %.3fs receipt deadline",
                self.deadline_seconds,
            )
            return None
        observation = task.result[0] if task.result else None
        if observation is None:
            return None
        if observation.completion_latency_ms > self.deadline_seconds * 1000:
            self._quarantined.set()
            _logger.warning("Structural observation completed after its receipt deadline")
            return None
        return observation

    def stop(self) -> None:
        """Request worker shutdown without waiting on a hung native provider."""
        self._stopped.set()
        thread = self._thread
        if thread is None:
            return
        try:
            self._queue.put_nowait(self._sentinel)
        except queue.Full:
            pass
        thread.join(self.deadline_seconds)
        if thread.is_alive():
            _logger.warning("Structural observer worker did not stop before its deadline")

    def _worker(self) -> None:
        open_hook = getattr(self._observer, "open_current_thread", None)
        close_hook = getattr(self._observer, "close_current_thread", None)
        try:
            if callable(open_hook):
                open_hook()
        except Exception as exc:
            self._quarantined.set()
            _logger.warning("Structural observer startup failed: %s", exc)
        finally:
            self._ready.set()
        try:
            while not self._stopped.is_set():
                try:
                    item = self._queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                try:
                    if item is self._sentinel:
                        return
                    assert isinstance(item, _ObservationTask)
                    try:
                        observation = self._observer.observe(item.request)
                        validated = (
                            None
                            if observation is None
                            else StructuralObservation.model_validate(observation)
                        )
                    except Exception as exc:
                        _logger.warning(
                            "Structural observation omitted after provider failure: %s",
                            exc,
                        )
                        validated = None
                    if not item.cancelled.is_set():
                        item.result.append(validated)
                finally:
                    if isinstance(item, _ObservationTask):
                        item.done.set()
                    self._queue.task_done()
                if self._quarantined.is_set():
                    return
        finally:
            if callable(close_hook):
                try:
                    close_hook()
                except Exception as exc:
                    _logger.warning("Structural observer cleanup failed: %s", exc)


def create_structural_observer(
    *,
    enabled: bool = True,
    platform_name: str | None = None,
) -> StructuralObserver | None:
    """Create the native observer without importing UIA on other platforms."""

    if not enabled:
        return None
    resolved_platform = platform_name or sys.platform
    try:
        if resolved_platform == "win32":
            from openadapt_capture.structural_observer.windows import (
                WindowsUIAStructuralObserver,
            )

            return WindowsUIAStructuralObserver()
        if resolved_platform == "darwin":
            from openadapt_capture.structural_observer.macos import (
                MacOSAXStructuralObserver,
            )

            return MacOSAXStructuralObserver()
        if resolved_platform.startswith("linux"):
            from openadapt_capture.structural_observer.linux import (
                LinuxATSpiStructuralObserver,
            )

            return LinuxATSpiStructuralObserver()
        return None
    except Exception as exc:
        _logger.warning(
            "%s structural observation is unavailable: %s",
            resolved_platform,
            exc,
        )
        return None


def observe_structural_action(
    observer: StructuralObserver | None,
    request: StructuralObservationRequest,
) -> StructuralObservation | None:
    """Call an observer conservatively and validate its public contract."""

    if observer is None:
        return None
    try:
        observation = observer.observe(request)
        if observation is None:
            return None
        return StructuralObservation.model_validate(observation)
    except Exception as exc:
        # Native accessibility trees can disappear between input receipt and
        # observation.  Missing optional authoring evidence must not corrupt the
        # otherwise valid screen/input recording.
        _logger.warning("Structural observation omitted after provider failure: %s", exc)
        return None


__all__ = [
    "BoundedStructuralObserver",
    "DEFAULT_STRUCTURAL_OBSERVATION_DEADLINE_SECONDS",
    "DEFAULT_STRUCTURAL_OBSERVER_STARTUP_TIMEOUT_SECONDS",
    "MAX_STRUCTURAL_ANCESTRY_DEPTH",
    "MAX_STRUCTURAL_TEXT_LENGTH",
    "STRUCTURAL_OBSERVATION_SCHEMA_VERSION",
    "StructuralAncestor",
    "StructuralBounds",
    "StructuralCandidateContext",
    "StructuralCaptureWindowBinding",
    "StructuralElement",
    "StructuralObservation",
    "StructuralObservationRequest",
    "StructuralObserver",
    "StructuralProcessIdentity",
    "StructuralWindowIdentity",
    "create_structural_observer",
    "observe_structural_action",
    "structural_observation_receipt_fields",
]
