"""Window-scoped capture: record ONE window in that window's own pixel space.

Why this exists (the Citrix / remote-display wedge): openadapt-flow's
``RemoteDisplayBackend`` (``record --backend rdp``, ``rdp_window`` mode)
*replays* against the pixels of a single client window (Parallels, Citrix
Workspace, Microsoft Remote Desktop) captured per-window — on macOS via
``CGWindowListCreateImage`` by window id. A demonstration recorded FULL-SCREEN
is in a different coordinate space than that replay surface, so converters had
to work around the mismatch (record inside the session, or full-screen the
client). Window-scoped recording removes the mismatch at the source: frames
are captured in the target window's pixel space and input coordinates are
translated into that same space at capture time.

Coordinate semantics (kept in exact parity with openadapt-flow
``backends/remote_display.py`` — read that module before changing these):

- ``bounds`` is ``(x, y, w, h)`` in **screen points**, top-left origin — the
  space native platform observers use for global mouse coordinates.
- A captured frame contains the window's own **pixels** (macOS:
  ``CGWindowListCreateImage`` with ``kCGWindowImageBoundsIgnoreFraming`` — the
  identical call flow's replay capture path uses).
- ``scale`` = captured pixel width / bounds width (e.g. 2.0 on Retina).
- Replay maps a captured pixel to a screen point as
  ``screen = bounds_origin + pixel / scale`` (flow's ``_to_screen``).
  Recording therefore maps a global screen point to a window pixel as the
  exact inverse: ``pixel = (screen - bounds_origin) * scale``
  (:func:`translate_point`).

Importing this module must never touch the display (platform bindings are
imported lazily inside the resolver/capturer functions), preserving the
package's headless-import invariant (tests/test_headless_import.py).
"""

from __future__ import annotations

import math
import os
import sys
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Mapping, Optional

from loguru import logger

if TYPE_CHECKING:
    from PIL import Image

WINDOW_CAPTURE_SCHEMA_VERSION = "openadapt.capture.window-scoped/v2"


class WindowCaptureError(RuntimeError):
    """The target window could not be resolved or captured.

    Raised LOUDLY (never swallowed into an empty frame): a recording that
    silently fell back to full-screen would produce coordinates in the wrong
    space — a corrupt demonstration that *looks* valid.
    """


@dataclass(frozen=True)
class WindowTarget:
    """How to find the window to record: case-insensitive substrings.

    Matches openadapt-flow ``RemoteDisplayBackend``'s window identification
    (owner substring, optional title substring to disambiguate).
    """

    owner: str | None = None
    title: str | None = None

    def __post_init__(self) -> None:
        """Validate that at least one selector is provided."""
        if not (self.owner or self.title):
            raise ValueError(
                "WindowTarget requires an 'owner' and/or 'title' substring "
                "(e.g. WindowTarget(owner='Parallels'))"
            )

    @classmethod
    def from_spec(cls, spec: "WindowTarget | dict | None") -> "WindowTarget | None":
        """Build a target from the ``Recorder(window=...)`` spec.

        Accepts ``None`` (window mode off), an existing :class:`WindowTarget`,
        or a dict of the shape ``{"owner": "Parallels", "title": None}``.
        Unknown keys are rejected loudly rather than ignored.
        """
        if spec is None:
            return None
        if isinstance(spec, WindowTarget):
            return spec
        if isinstance(spec, dict):
            unknown = set(spec) - {"owner", "title"}
            if unknown:
                raise ValueError(
                    f"unknown window spec keys {sorted(unknown)}; expected {{'owner', 'title'}}"
                )
            return cls(owner=spec.get("owner"), title=spec.get("title"))
        raise TypeError(f"window spec must be a dict or WindowTarget, got {type(spec).__name__}")


@dataclass(frozen=True)
class TargetWindow:
    """One resolved on-screen window.

    ``bounds`` is ``(x, y, w, h)`` in screen points, top-left origin — the
    same space as native global mouse coordinates. Same field semantics as
    openadapt-flow's ``WindowInfo``.
    """

    window_id: int
    owner: str
    title: str
    pid: int
    bounds: tuple[float, float, float, float]
    on_screen: bool = True
    process_start_time: float | None = None
    coordinate_source: str = "platform-screen"

    @property
    def identity(self) -> tuple[int, int, float | None, str]:
        """Return the process-bound identity used for the whole session."""
        return (
            self.window_id,
            self.pid,
            self.process_start_time,
            self.owner.casefold(),
        )


def translate_point(
    x: float,
    y: float,
    bounds: tuple[float, float, float, float],
    scale: float,
) -> tuple[float, float]:
    """Map a global screen point to window-relative captured-pixel coordinates.

    Exact inverse of flow's replay mapping ``screen = origin + pixel / scale``:

        ``pixel = (screen - origin) * scale``

    Points outside the window bounds translate to coordinates outside
    ``[0, viewport)`` (possibly negative); they are recorded as-is so
    downstream consumers can detect out-of-window input instead of receiving
    silently clamped (wrong) coordinates.
    """
    ox, oy = bounds[0], bounds[1]
    return ((x - ox) * scale, (y - oy) * scale)


ResolverFn = Callable[[WindowTarget], Optional[TargetWindow]]
CapturerFn = Callable[[TargetWindow], "Image.Image"]


class WindowCaptureScope:
    """Thread-safe tracker of the target window's bounds/scale during recording.

    The screen-reader thread calls :meth:`capture_frame` (which re-resolves the
    window each frame — windows move and resize); native observer threads call
    :meth:`translate` concurrently to convert global input coordinates into
    the captured frame's pixel space using the freshest bounds.

    ``resolver`` / ``capturer`` default to the platform implementations and
    are injectable for display-free unit tests.
    """

    def __init__(
        self,
        target: WindowTarget,
        resolver: ResolverFn | None = None,
        capturer: CapturerFn | None = None,
    ) -> None:
        """Initialize the scope for ``target``."""
        self.target = target
        self._resolver = resolver or resolve_window
        self._capturer = capturer or capture_window
        self._lock = threading.Lock()
        self._window: TargetWindow | None = None
        self._scale: float | None = None
        self._scale_x: float | None = None
        self._scale_y: float | None = None
        self._viewport: tuple[int, int] | None = None
        self._source_viewport: tuple[int, int] | None = None
        self._content_rect: tuple[int, int, int, int] | None = None
        self._fit_scale: float | None = None
        self._generation = 0
        self._geometry_signature: tuple | None = None
        self._published_generation = 0
        self._published_window: TargetWindow | None = None
        self._published_scale_x: float | None = None
        self._published_scale_y: float | None = None
        self._published_content_rect: tuple[int, int, int, int] | None = None
        self._bound_identity: tuple[int, int, float | None, str] | None = None
        # Window of the last CAPTURED frame (not merely resolved): the
        # bounds-timeline 'changed' flag compares frame to frame, so a bare
        # resolve() (e.g. a pre-flight existence check) never suppresses the
        # first frame's timeline entry.
        self._frame_window: TargetWindow | None = None

    def resolve(self) -> TargetWindow:
        """Resolve the target window without changing captured-frame geometry.

        Raises:
            WindowCaptureError: If no matching window is on screen.
        """
        win = self._resolver(self.target)
        if win is None:
            raise WindowCaptureError(
                f"no window matching owner {self.target.owner!r} "
                f"title {self.target.title!r}; is the target application "
                "running with a visible window?"
            )
        if self.target.owner and self.target.owner.casefold() not in win.owner.casefold():
            raise WindowCaptureError(
                "the window resolver returned an owner outside the configured selector: "
                f"expected {self.target.owner!r}, got {win.owner!r}"
            )
        if self.target.title and self.target.title.casefold() not in win.title.casefold():
            raise WindowCaptureError(
                "the window resolver returned a title outside the configured selector: "
                f"expected {self.target.title!r}, got {win.title!r}"
            )
        if win.pid <= 0:
            raise WindowCaptureError("the resolved target has no owning process identity")
        if (
            win.process_start_time is None
            or not math.isfinite(win.process_start_time)
            or win.process_start_time <= 0
        ):
            raise WindowCaptureError(
                "the resolved target has no stable process start identity"
            )
        if not win.coordinate_source.strip():
            raise WindowCaptureError("the resolved target has no coordinate source")
        return win

    def _assert_bound_identity(self, win: TargetWindow) -> None:
        """Reject a recycled window handle or a different owning process."""
        with self._lock:
            bound_identity = self._bound_identity
        if bound_identity is not None and win.identity != bound_identity:
            raise WindowCaptureError(
                "the resolved target changed window identity or owning process during recording: "
                f"expected {bound_identity!r}, got {win.identity!r}"
            )

    def capture_frame(self, *, publish: bool = True) -> tuple["Image.Image", bool]:
        """Capture the target window's current pixels.

        Re-resolves the window first so bounds/scale can never disagree with
        the frame just captured (mirrors flow's ``screenshot()`` contract).
        The first successful frame fixes the recording viewport. If the window
        later resizes, the complete new frame is scaled to fit that viewport
        and letterboxed. This preserves one encodable video stream without
        discarding resize frames or mixing coordinate spaces.

        Returns:
            (PIL.Image in the window's pixel space,
             changed: True when window identity/bounds/title differ from the
             previous frame — the caller should persist a bounds-timeline
             event).

        Raises:
            WindowCaptureError: If the window is gone or capture fails.
        """
        with self._lock:
            prev = self._frame_window
            output_viewport = self._viewport

        # A capture is valid only when the process identity and geometry are
        # unchanged on both sides of the platform grab. A move or resize can
        # happen between those calls. Such a frame has no single coordinate
        # space and must never enter a complete recording.
        pre = self.resolve()
        self._assert_bound_identity(pre)
        source_image = self._capturer(pre)
        post = self.resolve()
        self._assert_bound_identity(post)
        if pre.identity != post.identity:
            raise WindowCaptureError(
                "the target process identity changed while a frame was captured"
            )
        if pre.bounds != post.bounds:
            raise WindowCaptureError(
                "the target moved or resized while a frame was captured; "
                "no action can bind to mixed frame geometry"
            )
        win = post
        if source_image.width <= 0 or source_image.height <= 0:
            raise WindowCaptureError("window capture returned an empty frame")
        source_viewport = (source_image.width, source_image.height)
        output_viewport = output_viewport or source_viewport
        output_width, output_height = output_viewport
        fit_scale = min(
            output_width / source_image.width,
            output_height / source_image.height,
        )
        fitted_width = max(1, min(output_width, round(source_image.width * fit_scale)))
        fitted_height = max(1, min(output_height, round(source_image.height * fit_scale)))
        offset_x = (output_width - fitted_width) // 2
        offset_y = (output_height - fitted_height) // 2
        if source_viewport == output_viewport:
            image = source_image
        else:
            from PIL import Image

            resized = source_image.resize((fitted_width, fitted_height), Image.Resampling.LANCZOS)
            image = Image.new("RGB", output_viewport, color=(0, 0, 0))
            image.paste(resized, (offset_x, offset_y))
        bounds_w = win.bounds[2] or float(source_image.width)
        bounds_h = win.bounds[3] or float(source_image.height)
        scale_x = fitted_width / bounds_w
        scale_y = fitted_height / bounds_h
        geometry_signature = (
            win.identity,
            win.bounds,
            win.coordinate_source,
            output_viewport,
            source_viewport,
            (offset_x, offset_y, fitted_width, fitted_height),
            scale_x,
            scale_y,
        )
        with self._lock:
            self._window = win
            # ``scale`` is the historical scalar field. Keep it as the x-axis
            # value for old readers. Current readers can use both exact axes.
            # Integer resize rounding can make the axes differ slightly.
            self._scale = scale_x
            self._scale_x = scale_x
            self._scale_y = scale_y
            self._viewport = output_viewport
            self._source_viewport = source_viewport
            self._content_rect = (offset_x, offset_y, fitted_width, fitted_height)
            self._fit_scale = fit_scale
            if self._bound_identity is None:
                self._bound_identity = win.identity
            if geometry_signature != self._geometry_signature:
                self._generation += 1
                self._geometry_signature = geometry_signature
            self._frame_window = win
            generation = self._generation
            if publish:
                self._publish_locked(generation)
        changed = (
            prev is None
            or prev.window_id != win.window_id
            or prev.bounds != win.bounds
            or prev.title != win.title
        )
        return image, changed

    def _publish_locked(self, generation: int) -> None:
        """Expose one committed frame geometry to action observers."""
        if generation != self._generation or self._window is None:
            raise WindowCaptureError(
                f"cannot publish geometry generation {generation}; "
                f"the current generation is {self._generation}"
            )
        self._published_generation = generation
        self._published_window = self._window
        self._published_scale_x = self._scale_x
        self._published_scale_y = self._scale_y
        self._published_content_rect = self._content_rect

    def publish_frame(self, generation: int) -> None:
        """Publish geometry after its window metadata and pixels enter the queue."""
        with self._lock:
            self._publish_locked(generation)

    def translate(self, x: float, y: float) -> tuple[float, float]:
        """Translate a global screen point into window-relative pixels.

        Uses the bounds/scale of the most recently captured frame (the frame
        this input event will be associated with).

        Raises:
            WindowCaptureError: If called before the first
                :meth:`capture_frame` (no bounds are known yet, and guessing
                a coordinate space would be a silent wrong action).
        """
        px, py, _generation = self.translate_with_generation(x, y)
        return px, py

    def _geometry_for_action(
        self,
    ) -> tuple[
        TargetWindow,
        float,
        float,
        tuple[int, int, int, int],
        int,
    ]:
        """Return the published geometry after exact live revalidation."""
        with self._lock:
            window = self._published_window
            scale_x = self._published_scale_x
            scale_y = self._published_scale_y
            content_rect = self._published_content_rect
            generation = self._published_generation
        if window is None or scale_x is None or scale_y is None or content_rect is None:
            raise WindowCaptureError(
                "an action arrived before the first captured frame; "
                "capture_frame() must succeed before input can be scoped"
            )
        live = self.resolve()
        self._assert_bound_identity(live)
        if not live.on_screen:
            raise WindowCaptureError("the target window is not on screen at action time")
        if live.bounds != window.bounds:
            raise WindowCaptureError(
                "the target moved or resized after the last published frame; "
                "wait for a matching frame before recording input"
            )
        return window, scale_x, scale_y, content_rect, generation

    def generation_for_action(self) -> int:
        """Bind a non-pointer action to the exact current published frame."""
        return self._geometry_for_action()[4]

    def translate_with_generation(self, x: float, y: float) -> tuple[float, float, int]:
        """Translate against the exact published frame after live revalidation."""
        window, scale_x, scale_y, content_rect, generation = self._geometry_for_action()
        return (
            (x - window.bounds[0]) * scale_x + content_rect[0],
            (y - window.bounds[1]) * scale_y + content_rect[1],
            generation,
        )

    def window_event_data(self) -> dict:
        """Bounds-timeline entry for the WindowEvent table.

        Keys match the WindowEvent columns written by the recorder pipeline
        (``title``/``left``/``top``/``width``/``height``/``window_id`` +
        ``state`` JSON). Integer columns truncate, so exact float bounds and
        the pixel scale live in ``state``.
        """
        with self._lock:
            window = self._window
            scale = self._scale
            scale_x = self._scale_x
            scale_y = self._scale_y
            viewport = self._viewport
            source_viewport = self._source_viewport
            content_rect = self._content_rect
            fit_scale = self._fit_scale
            generation = self._generation
        if window is None:
            raise WindowCaptureError("no resolved window; call capture_frame() first")
        x, y, w, h = window.bounds
        return {
            "title": window.title,
            "left": int(x),
            "top": int(y),
            "width": int(w),
            "height": int(h),
            "window_id": str(window.window_id),
            "state": {
                "schema_version": WINDOW_CAPTURE_SCHEMA_VERSION,
                "window_capture": True,
                "owner": window.owner,
                "pid": window.pid,
                "process_start_time": window.process_start_time,
                "coordinate_source": window.coordinate_source,
                "geometry_generation": generation,
                "bounds": [x, y, w, h],
                "scale": scale,
                "scale_x": scale_x,
                "scale_y": scale_y,
                "viewport": list(viewport) if viewport else None,
                "source_viewport": (list(source_viewport) if source_viewport else None),
                "content_rect": list(content_rect) if content_rect else None,
                "fit_scale": fit_scale,
                "on_screen": window.on_screen,
            },
        }

    def snapshot(self) -> dict:
        """Window-scoping metadata persisted on the Recording (config JSON).

        Converters (e.g. openadapt-flow's capture adapter) read this to know
        the recording is already in window-pixel space (``coordinate_space``)
        and which window it was scoped to.
        """
        with self._lock:
            window = self._window
            scale = self._scale
            scale_x = self._scale_x
            scale_y = self._scale_y
            viewport = self._viewport
            source_viewport = self._source_viewport
            content_rect = self._content_rect
            fit_scale = self._fit_scale
            generation = self._generation
        data: dict = {
            "schema_version": WINDOW_CAPTURE_SCHEMA_VERSION,
            "target": {"owner": self.target.owner, "title": self.target.title},
            "coordinate_space": "window_pixels",
        }
        if window is not None:
            data.update(
                {
                    "window_id": window.window_id,
                    "owner": window.owner,
                    "title": window.title,
                    "pid": window.pid,
                    "process_start_time": window.process_start_time,
                    "coordinate_source": window.coordinate_source,
                    "geometry_generation": generation,
                    "initial_bounds": list(window.bounds),
                    "scale": scale,
                    "scale_x": scale_x,
                    "scale_y": scale_y,
                    "viewport": list(viewport) if viewport else None,
                    "source_viewport": (list(source_viewport) if source_viewport else None),
                    "content_rect": list(content_rect) if content_rect else None,
                    "fit_scale": fit_scale,
                }
            )
        return data


# ---------------------------------------------------------------------------
# Platform implementations (lazy imports: module import stays display-free)
# ---------------------------------------------------------------------------


def resolve_window(target: WindowTarget) -> TargetWindow | None:
    """Find the front-most/largest window matching ``target`` on this platform."""
    if sys.platform == "darwin":
        return _resolve_window_macos(target)
    if sys.platform == "win32":
        return _resolve_window_windows(target)
    if sys.platform.startswith("linux"):
        return _resolve_window_linux(target)
    raise WindowCaptureError(f"window-scoped capture is not supported on {sys.platform}")


def capture_window(window: TargetWindow) -> "Image.Image":
    """Capture ``window``'s pixels as a PIL image on this platform."""
    if sys.platform == "darwin":
        return _capture_window_macos(window)
    if sys.platform == "win32":
        return _capture_window_windows(window)
    if sys.platform.startswith("linux"):
        return _capture_window_linux(window)
    raise WindowCaptureError(f"window-scoped capture is not supported on {sys.platform}")


def _process_start_time(pid: int) -> float:
    """Return a stable process creation identity or fail closed."""
    import psutil

    try:
        return float(psutil.Process(pid).create_time())
    except psutil.Error as exc:
        raise WindowCaptureError(
            f"could not bind window owner PID {pid} to its process start time: {exc}"
        ) from exc


def _resolve_window_macos(target: WindowTarget) -> TargetWindow | None:
    """macOS: CGWindowList by owner/title substring.

    Same selection semantics as flow's ``MacWindowClient.find_window``:
    ``kCGWindowListOptionAll`` (a momentarily hidden client is still
    resolvable/capturable), layer 0 only, case-insensitive substring match,
    largest window wins.
    """
    import Quartz

    owner_l = target.owner.lower() if target.owner else None
    title_l = target.title.lower() if target.title else None
    wins = Quartz.CGWindowListCopyWindowInfo(Quartz.kCGWindowListOptionAll, Quartz.kCGNullWindowID)
    matches: list[TargetWindow] = []
    for w in wins or []:
        owner = str(w.get("kCGWindowOwnerName", "") or "")
        name = str(w.get("kCGWindowName", "") or "")
        if owner_l is not None and owner_l not in owner.lower():
            continue
        if title_l is not None and title_l not in name.lower():
            continue
        if int(w.get("kCGWindowLayer", 0) or 0) != 0:
            continue  # skip menubar/overlay layers; the app window is layer 0
        b = w.get("kCGWindowBounds", {}) or {}
        bounds = (
            float(b.get("X", 0.0)),
            float(b.get("Y", 0.0)),
            float(b.get("Width", 0.0)),
            float(b.get("Height", 0.0)),
        )
        if bounds[2] > 0 and bounds[3] > 0:
            pid = int(w.get("kCGWindowOwnerPID", 0) or 0)
            matches.append(
                TargetWindow(
                    window_id=int(w.get("kCGWindowNumber", 0) or 0),
                    owner=owner,
                    title=name,
                    pid=pid,
                    bounds=bounds,
                    on_screen=bool(w.get("kCGWindowIsOnscreen", False)),
                    process_start_time=_process_start_time(pid),
                    coordinate_source="quartz-screen-points",
                )
            )
    if not matches:
        return None
    # Prefer a visible target. Hidden windows remain resolvable for capture,
    # but cannot receive a safe global pointer action.
    return max(
        matches,
        key=lambda candidate: (
            candidate.on_screen,
            candidate.bounds[2] * candidate.bounds[3],
        ),
    )


def _capture_window_macos(window: TargetWindow) -> "Image.Image":
    """macOS: per-window capture via ``CGWindowListCreateImage``.

    The identical call (``CGRectNull`` + ``kCGWindowListOptionIncludingWindow``
    + ``kCGWindowImageBoundsIgnoreFraming``) and BGRA->RGB conversion as flow's
    ``MacWindowClient.capture`` — the replay surface — so recorded frames and
    replay frames share coordinate semantics byte for byte.
    """
    import Quartz
    from PIL import Image

    img_ref = Quartz.CGWindowListCreateImage(
        Quartz.CGRectNull,
        Quartz.kCGWindowListOptionIncludingWindow,
        window.window_id,
        Quartz.kCGWindowImageBoundsIgnoreFraming,
    )
    if img_ref is None:
        raise WindowCaptureError(
            f"CGWindowListCreateImage returned None for window "
            f"{window.window_id} ({window.owner!r}); if this recurs, check "
            "Screen Recording permission for the recording process"
        )
    w = int(Quartz.CGImageGetWidth(img_ref))
    h = int(Quartz.CGImageGetHeight(img_ref))
    if w <= 0 or h <= 0:
        raise WindowCaptureError("captured window image has zero size")
    bpr = int(Quartz.CGImageGetBytesPerRow(img_ref))
    provider = Quartz.CGImageGetDataProvider(img_ref)
    data = Quartz.CGDataProviderCopyData(provider)
    buf = bytes(data)
    # CGImage from the window server is BGRA, premultiplied; read with the row
    # stride and drop alpha for a stable RGB frame.
    img = Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", bpr, 1)
    return img.convert("RGB")


def _resolve_window_windows(target: WindowTarget) -> TargetWindow | None:
    """Windows: enumerate top-level windows via Win32 (ctypes, no extra deps).

    ``owner`` matches the owning process's executable name (e.g. ``prl_client``
    for Parallels Client, ``wfica32`` for Citrix Workspace); ``title`` matches
    the window title. Both case-insensitive substrings; the largest visible
    match wins (parity with the macOS resolver). Bounds prefer the DWM
    extended frame (excludes the invisible resize border GetWindowRect
    includes) so captured pixels align with the visible window.
    """
    import ctypes
    import ctypes.wintypes as wintypes

    import psutil

    user32 = ctypes.windll.user32
    owner_l = target.owner.lower() if target.owner else None
    title_l = target.title.lower() if target.title else None

    matches: list[TargetWindow] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    def _enum_cb(hwnd: int, _lparam: int) -> bool:
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value
        if not title:
            return True  # unnamed tool/host windows
        if title_l is not None and title_l not in title.lower():
            return True
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        try:
            process = psutil.Process(pid.value)
            proc_name = process.name()
            process_start_time = float(process.create_time())
        except psutil.Error:
            return True
        if owner_l is not None and owner_l not in proc_name.lower():
            return True
        rect = _window_rect(hwnd)
        if rect is None:
            return True
        left, top, right, bottom = rect
        matches.append(
            TargetWindow(
                window_id=int(hwnd),
                owner=proc_name,
                title=title,
                pid=int(pid.value),
                bounds=(
                    float(left),
                    float(top),
                    float(right - left),
                    float(bottom - top),
                ),
                on_screen=True,
                process_start_time=process_start_time,
                coordinate_source="dwm-physical-pixels",
            )
        )
        return True

    user32.EnumWindows(_enum_cb, 0)
    if not matches:
        return None
    return max(matches, key=lambda m: m.bounds[2] * m.bounds[3])


def _window_rect(hwnd: int) -> tuple[int, int, int, int] | None:
    """Return DWM physical bounds; never mix DPI-virtualized coordinates."""
    import ctypes
    import ctypes.wintypes as wintypes

    rect = wintypes.RECT()
    try:
        dwmapi = ctypes.windll.dwmapi
    except (AttributeError, OSError):  # pragma: no cover - supported Windows has DWM
        return None
    DWMWA_EXTENDED_FRAME_BOUNDS = 9
    res = dwmapi.DwmGetWindowAttribute(
        wintypes.HWND(hwnd),
        ctypes.wintypes.DWORD(DWMWA_EXTENDED_FRAME_BOUNDS),
        ctypes.byref(rect),
        ctypes.sizeof(rect),
    )
    if res != 0:
        # GetWindowRect is intentionally not a fallback. It is DPI virtualized
        # for an unaware caller while MSS and low-level mouse hooks use physical
        # screen coordinates. Mixing them can record a plausible wrong action.
        return None
    return (rect.left, rect.top, rect.right, rect.bottom)


def _capture_window_windows(window: TargetWindow) -> "Image.Image":
    """Windows: grab the window's screen region via mss (already a dependency).

    A region grab of the resolved bounds: unlike the macOS per-window buffer
    this captures whatever overlaps the rectangle, so the target window should
    stay unoccluded during recording (same operational guidance as flow's
    RECORDING.md). Bounds are re-resolved every frame, so a moved window stays
    correctly scoped.
    """
    from PIL import Image

    from openadapt_capture.utils import get_process_local_sct

    x, y, w, h = window.bounds
    if w <= 0 or h <= 0:
        raise WindowCaptureError(f"window {window.window_id} has empty bounds")
    monitor = {"left": int(x), "top": int(y), "width": int(w), "height": int(h)}
    try:
        sct_img = get_process_local_sct().grab(monitor)
    except Exception as exc:  # mss.ScreenShotError subclasses vary
        raise WindowCaptureError(f"window region grab failed: {exc}") from exc
    return Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")


def _require_x11_session(environ: Mapping[str, str] | None = None) -> str:
    """Return DISPLAY for a native X11 session or fail closed on Wayland."""
    env = os.environ if environ is None else environ
    if env.get("XDG_SESSION_TYPE", "").casefold() == "wayland" or env.get("WAYLAND_DISPLAY"):
        raise WindowCaptureError(
            "native Wayland window capture requires a compositor portal with "
            "stable window identity and geometry; the X11 scope refuses XWayland-only capture"
        )
    display_name = env.get("DISPLAY")
    if not display_name:
        raise WindowCaptureError("Linux window capture requires a native X11 DISPLAY")
    return display_name


def _x11_library(display_name: str):
    """Open one configured libX11 connection."""
    import ctypes
    import ctypes.util

    from openadapt_capture.x11_threads import ensure_xlib_thread_support

    ensure_xlib_thread_support()
    library_name = ctypes.util.find_library("X11")
    if not library_name:
        raise WindowCaptureError("Linux window capture requires the system libX11 runtime")
    try:
        x11 = ctypes.CDLL(library_name)
    except OSError as exc:
        raise WindowCaptureError(f"could not load libX11: {exc}") from exc
    x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x11.XOpenDisplay.restype = ctypes.c_void_p
    x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
    x11.XCloseDisplay.restype = ctypes.c_int
    x11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
    x11.XDefaultRootWindow.restype = ctypes.c_ulong
    x11.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    x11.XInternAtom.restype = ctypes.c_ulong
    x11.XGetWindowProperty.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_long,
        ctypes.c_long,
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
    ]
    x11.XGetWindowProperty.restype = ctypes.c_int
    x11.XGetGeometry.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
    ]
    x11.XGetGeometry.restype = ctypes.c_int
    x11.XTranslateCoordinates.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    x11.XTranslateCoordinates.restype = ctypes.c_int
    x11.XFree.argtypes = [ctypes.c_void_p]
    x11.XFree.restype = ctypes.c_int
    display = x11.XOpenDisplay(display_name.encode())
    if not display:
        raise WindowCaptureError(
            f"could not open X11 display {display_name!r}; authorize the recording user"
        )
    return x11, display


def _x11_property(
    x11,
    display,
    window_id: int,
    name: str,
    *,
    property_type: int = 0,
) -> tuple[int, int, bytes | list[int]] | None:
    """Read one complete X11 property and release the Xlib allocation."""
    import ctypes

    atom = int(x11.XInternAtom(display, name.encode(), 1))
    if not atom:
        return None
    actual_type = ctypes.c_ulong()
    actual_format = ctypes.c_int()
    item_count = ctypes.c_ulong()
    bytes_after = ctypes.c_ulong()
    value = ctypes.POINTER(ctypes.c_ubyte)()
    status = int(
        x11.XGetWindowProperty(
            display,
            ctypes.c_ulong(window_id),
            ctypes.c_ulong(atom),
            0,
            1 << 20,
            0,
            ctypes.c_ulong(property_type),
            ctypes.byref(actual_type),
            ctypes.byref(actual_format),
            ctypes.byref(item_count),
            ctypes.byref(bytes_after),
            ctypes.byref(value),
        )
    )
    if status != 0 or not value:
        return None
    try:
        if actual_format.value == 8:
            data: bytes | list[int] = ctypes.string_at(value, item_count.value)
        elif actual_format.value == 32:
            longs = ctypes.cast(value, ctypes.POINTER(ctypes.c_ulong))
            data = [int(longs[index]) for index in range(item_count.value)]
        else:
            return None
        return int(actual_type.value), int(actual_format.value), data
    finally:
        x11.XFree(value)


def _x11_text_property(x11, display, window_id: int, *names: str) -> str:
    for name in names:
        prop = _x11_property(x11, display, window_id, name)
        if prop is None or not isinstance(prop[2], bytes):
            continue
        text = prop[2].decode("utf-8", errors="replace").rstrip("\x00")
        if text:
            return text
    return ""


def _x11_geometry(x11, display, root: int, window_id: int):
    """Return root-relative client bounds for one X11 window."""
    import ctypes

    returned_root = ctypes.c_ulong()
    x = ctypes.c_int()
    y = ctypes.c_int()
    width = ctypes.c_uint()
    height = ctypes.c_uint()
    border = ctypes.c_uint()
    depth = ctypes.c_uint()
    if not x11.XGetGeometry(
        display,
        ctypes.c_ulong(window_id),
        ctypes.byref(returned_root),
        ctypes.byref(x),
        ctypes.byref(y),
        ctypes.byref(width),
        ctypes.byref(height),
        ctypes.byref(border),
        ctypes.byref(depth),
    ):
        return None
    root_x = ctypes.c_int()
    root_y = ctypes.c_int()
    child = ctypes.c_ulong()
    if not x11.XTranslateCoordinates(
        display,
        ctypes.c_ulong(window_id),
        ctypes.c_ulong(root),
        0,
        0,
        ctypes.byref(root_x),
        ctypes.byref(root_y),
        ctypes.byref(child),
    ):
        return None
    return (
        float(root_x.value),
        float(root_y.value),
        float(width.value),
        float(height.value),
    )


def _resolve_window_linux(target: WindowTarget) -> TargetWindow | None:
    """Resolve an EWMH client window in native X11 root-pixel coordinates."""
    display_name = _require_x11_session()
    x11, display = _x11_library(display_name)
    try:
        root = int(x11.XDefaultRootWindow(display))
        client_list = _x11_property(x11, display, root, "_NET_CLIENT_LIST_STACKING")
        if client_list is None or not isinstance(client_list[2], list):
            raise WindowCaptureError(
                "the X11 window manager does not expose _NET_CLIENT_LIST_STACKING"
            )
        owner_l = target.owner.casefold() if target.owner else None
        title_l = target.title.casefold() if target.title else None
        matches: list[TargetWindow] = []
        for window_id in client_list[2]:
            pid_property = _x11_property(x11, display, window_id, "_NET_WM_PID")
            if pid_property is None or not isinstance(pid_property[2], list):
                continue
            pid = int(pid_property[2][0]) if pid_property[2] else 0
            if pid <= 0:
                continue
            import psutil

            try:
                process = psutil.Process(pid)
                owner = process.name()
                process_start_time = float(process.create_time())
            except psutil.Error:
                continue
            title = _x11_text_property(x11, display, window_id, "_NET_WM_NAME", "WM_NAME")
            if owner_l is not None and owner_l not in owner.casefold():
                continue
            if title_l is not None and title_l not in title.casefold():
                continue
            bounds = _x11_geometry(x11, display, root, window_id)
            if bounds is None or bounds[2] <= 0 or bounds[3] <= 0:
                continue
            matches.append(
                TargetWindow(
                    window_id=window_id,
                    owner=owner,
                    title=title,
                    pid=pid,
                    bounds=bounds,
                    on_screen=True,
                    process_start_time=process_start_time,
                    coordinate_source="x11-root-physical-pixels",
                )
            )
        if not matches:
            return None
        # Stacking order is bottom-to-top. Prefer the largest match, then the
        # top-most one for deterministic selection among equal surfaces.
        return max(
            enumerate(matches),
            key=lambda item: (item[1].bounds[2] * item[1].bounds[3], item[0]),
        )[1]
    finally:
        x11.XCloseDisplay(display)


def _capture_window_linux(window: TargetWindow) -> "Image.Image":
    """Capture the exact X11 root rectangle through the shared MSS runtime."""
    return _capture_window_windows(window)


def build_window_scope(owner: str | None, title: str | None) -> WindowCaptureScope | None:
    """Build a :class:`WindowCaptureScope` when a target is configured.

    Central place the recorder uses to turn (possibly-empty) config values
    into window mode: returns ``None`` when neither selector is set.
    """
    if not (owner or title):
        return None
    logger.info(f"window-scoped capture: owner={owner!r} title={title!r}")
    return WindowCaptureScope(WindowTarget(owner=owner, title=title))
