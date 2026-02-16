"""High-level recording API.

Provides a simple interface for capturing GUI interactions.

Architecture (matching legacy OpenAdapt record.py):
- Screenshots captured continuously via mss in a background thread
- Video encoding runs in a separate process to avoid GIL contention
- Action-gated capture: video frames written only when actions occur
  (not every screenshot), so encoding load is ~1-5 fps instead of 24fps
"""

from __future__ import annotations

import multiprocessing
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from openadapt_capture.events import ScreenFrameEvent
from openadapt_capture.stats import CaptureStats
from openadapt_capture.storage import Capture, CaptureStorage

if TYPE_CHECKING:
    from PIL import Image


def _get_screen_dimensions() -> tuple[int, int]:
    """Get screen dimensions in physical pixels (for video).

    Uses mss (matching legacy OpenAdapt) which returns physical pixel
    dimensions directly. Falls back to PIL.ImageGrab if mss unavailable.
    """
    try:
        import mss
        with mss.mss() as sct:
            monitor = sct.monitors[0]  # All monitors combined
            sct_img = sct.grab(monitor)
            return sct_img.size
    except Exception:
        try:
            from PIL import ImageGrab
            screenshot = ImageGrab.grab()
            return screenshot.size
        except Exception:
            return (1920, 1080)


def _get_display_pixel_ratio() -> float:
    """Get the display pixel ratio (e.g., 2.0 for Retina).

    This is the ratio of physical pixels to logical pixels.
    Mouse coordinates from pynput are in logical space.

    Uses mss to get logical monitor dimensions (like OpenAdapt).
    """
    try:
        import mss
        from PIL import ImageGrab

        # Get physical dimensions from screenshot
        screenshot = ImageGrab.grab()
        physical_width = screenshot.size[0]

        # Get logical dimensions from mss (works on macOS, Windows, Linux)
        with mss.mss() as sct:
            # monitors[0] is the "all monitors" bounding box on multi-monitor setups
            # monitors[1] is typically the primary monitor
            monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
            logical_width = monitor["width"]

        if logical_width > 0:
            return physical_width / logical_width

        return 1.0
    except ImportError:
        # mss not installed, try alternative methods
        try:
            from PIL import ImageGrab

            screenshot = ImageGrab.grab()
            physical_width = screenshot.size[0]

            if sys.platform == "win32":
                import ctypes
                user32 = ctypes.windll.user32
                user32.SetProcessDPIAware()
                logical_width = user32.GetSystemMetrics(0)
                return physical_width / logical_width
        except Exception:
            pass

        return 1.0
    except Exception:
        return 1.0


def _video_writer_worker(
    queue: multiprocessing.Queue,
    video_path: str,
    width: int,
    height: int,
    fps: int,
) -> None:
    """Video encoding worker running in a separate process.

    Matches the legacy OpenAdapt architecture where video encoding is
    decoupled from screenshot capture to avoid GIL contention.
    Ignores SIGINT so only the main process handles Ctrl+C.

    Args:
        queue: Queue receiving (image_bytes, size, timestamp) tuples.
               None sentinel signals shutdown.
        video_path: Path to output video file.
        width: Video width.
        height: Video height.
        fps: Frames per second.
    """
    import signal

    from PIL import Image

    from openadapt_capture.video import VideoWriter

    # Ignore SIGINT in worker — main process handles Ctrl+C and sends sentinel
    # (matches legacy OpenAdapt pattern)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    writer = VideoWriter(video_path, width=width, height=height, fps=fps)
    is_first_frame = True

    while True:
        item = queue.get()
        if item is None:
            break

        image_bytes, size, timestamp = item
        image = Image.frombytes("RGB", size, image_bytes)

        if is_first_frame:
            # Write first frame as key frame (matches legacy pattern for seekability)
            writer.write_frame(image, timestamp, force_key_frame=True)
            is_first_frame = False
        else:
            writer.write_frame(image, timestamp)

    writer.close()


class Recorder:
    """High-level recorder for GUI interactions.

    Captures mouse, keyboard, and screen events with minimal configuration.

    Architecture (matching legacy OpenAdapt record.py):
    - Screenshots captured continuously in a background thread (using mss)
    - Most recent screenshot is buffered (not encoded)
    - When an action event occurs (click, keystroke), the buffered screenshot
      is sent to the video encoding process — this is "action-gated capture"
    - Video encoding runs in a separate process to avoid GIL contention
    - Result: encoding load is ~1-5 fps (action frequency) not 24fps

    Set record_full_video=True to encode every frame (legacy RECORD_FULL_VIDEO).

    Usage:
        with Recorder("./my_capture") as recorder:
            # Recording happens automatically
            input("Press Enter to stop...")

        print(f"Captured {recorder.event_count} events")
    """

    def __init__(
        self,
        capture_dir: str | Path,
        task_description: str | None = None,
        capture_video: bool = True,
        capture_audio: bool = False,
        video_fps: int = 24,
        capture_mouse_moves: bool = True,
        record_full_video: bool = False,
    ) -> None:
        """Initialize recorder.

        Args:
            capture_dir: Directory to store capture files.
            task_description: Optional description of the task being recorded.
            capture_video: Whether to capture screen video.
            capture_audio: Whether to capture audio.
            video_fps: Video frames per second.
            capture_mouse_moves: Whether to capture mouse move events.
            record_full_video: If True, encode every frame (24fps).
                If False (default), only encode frames when actions occur
                (matching legacy OpenAdapt RECORD_FULL_VIDEO=False).
        """
        self.capture_dir = Path(capture_dir)
        self.task_description = task_description
        self.capture_video = capture_video
        self.capture_audio = capture_audio
        self.video_fps = video_fps
        self.capture_mouse_moves = capture_mouse_moves
        self.record_full_video = record_full_video

        self._capture: Capture | None = None
        self._storage: CaptureStorage | None = None
        self._input_listener = None
        self._screen_capturer = None
        self._video_process: multiprocessing.Process | None = None
        self._video_queue: multiprocessing.Queue | None = None
        self._video_start_time: float | None = None
        self._audio_recorder = None
        self._running = False
        self._event_count = 0
        self._lock = threading.Lock()
        self._stats = CaptureStats()

        # Action-gated capture state (matching legacy prev_screen_event pattern).
        # Stores the PIL Image directly (not bytes) to avoid 6MB/frame allocation
        # for frames that are mostly discarded. Only convert to bytes when sending.
        self._prev_screen_image: "Image" | None = None
        self._prev_screen_timestamp: float = 0
        self._prev_saved_screen_timestamp: float = 0

    @property
    def event_count(self) -> int:
        """Get the number of events captured."""
        return self._event_count

    @property
    def is_recording(self) -> bool:
        """Check if recording is active."""
        return self._running

    @property
    def stats(self) -> CaptureStats:
        """Get performance statistics."""
        return self._stats

    def _on_input_event(self, event: Any) -> None:
        """Handle input events from listener.

        In action-gated mode (record_full_video=False), this is where
        video frames actually get sent to the encoding process — only
        when the user performs an action (click, keystroke, scroll).
        Matches legacy OpenAdapt's process_events() action handling.
        """
        if self._storage is not None and self._running:
            self._storage.write_event(event)
            with self._lock:
                self._event_count += 1
            # Record performance stat
            event_type = event.type if isinstance(event.type, str) else event.type.value
            self._stats.record_event(event_type, event.timestamp)

            # Action-gated video: send buffered screenshot to video process
            # (matching legacy: when action arrives, write prev_screen_event)
            if (
                not self.record_full_video
                and self._video_queue is not None
                and self._prev_screen_image is not None
            ):
                screen_ts = self._prev_screen_timestamp
                # Only send if this screenshot hasn't been sent already
                if screen_ts > self._prev_saved_screen_timestamp:
                    image = self._prev_screen_image
                    # Convert to bytes only when actually sending (not every frame)
                    self._video_queue.put(
                        (image.tobytes(), image.size, screen_ts)
                    )
                    self._prev_saved_screen_timestamp = screen_ts

                    # Record screen frame event
                    if self._video_start_time is None:
                        self._video_start_time = screen_ts
                    frame_event = ScreenFrameEvent(
                        timestamp=screen_ts,
                        video_timestamp=screen_ts - self._video_start_time,
                        width=image.width,
                        height=image.height,
                    )
                    self._storage.write_event(frame_event)
                    self._stats.record_event("screen.frame", screen_ts)

    def _on_screen_frame(self, image: "Image", timestamp: float) -> None:
        """Handle screen frames from the capture thread.

        In action-gated mode (default): buffers the frame, doesn't encode.
        In full video mode: sends every frame to the encoding process.

        Matches legacy OpenAdapt's process_events() screen handling:
        - screen event arrives → store in prev_screen_event
        - if RECORD_FULL_VIDEO: also send to video_write_q immediately
        """
        if not self._running:
            return

        if self.record_full_video and self._video_queue is not None:
            # Full video mode: send every frame (legacy RECORD_FULL_VIDEO=True)
            if self._video_start_time is None:
                self._video_start_time = timestamp
            self._video_queue.put((image.tobytes(), image.size, timestamp))

            # Record screen frame event in storage
            if self._storage is not None:
                event = ScreenFrameEvent(
                    timestamp=timestamp,
                    video_timestamp=timestamp - self._video_start_time,
                    width=image.width,
                    height=image.height,
                )
                self._storage.write_event(event)
                self._stats.record_event("screen.frame", timestamp)
        else:
            # Action-gated mode: buffer the PIL Image directly (not bytes).
            # Only convert to bytes when an action triggers sending to video
            # process. This avoids ~144MB/s of wasted allocation at 24fps.
            # (Matches legacy: prev_screen_event stores the PIL Image)
            self._prev_screen_image = image
            self._prev_screen_timestamp = timestamp

    def start(self) -> None:
        """Start recording."""
        if self._running:
            return

        # Create capture directory
        self.capture_dir.mkdir(parents=True, exist_ok=True)

        # Start performance stats tracking
        self._stats.start()

        # Get screen dimensions and pixel ratio
        screen_width, screen_height = _get_screen_dimensions()
        pixel_ratio = _get_display_pixel_ratio()

        # Initialize storage
        import uuid
        capture_id = str(uuid.uuid4())[:8]
        self._capture = Capture(
            id=capture_id,
            started_at=time.time(),
            platform=sys.platform,
            screen_width=screen_width,
            screen_height=screen_height,
            pixel_ratio=pixel_ratio,
            task_description=self.task_description,
        )

        db_path = self.capture_dir / "capture.db"
        self._storage = CaptureStorage(db_path)
        self._storage.init_capture(self._capture)

        self._running = True

        # Start input capture
        try:
            from openadapt_capture.input import InputListener
            self._input_listener = InputListener(
                callback=self._on_input_event,
                capture_mouse_moves=self.capture_mouse_moves,
            )
            self._input_listener.start()
        except ImportError:
            pass  # Input capture not available

        # Start video capture (encoding in separate process like legacy OpenAdapt)
        if self.capture_video:
            try:
                from openadapt_capture.input import ScreenCapturer

                video_path = self.capture_dir / "video.mp4"
                self._video_queue = multiprocessing.Queue()
                self._video_process = multiprocessing.Process(
                    target=_video_writer_worker,
                    args=(
                        self._video_queue,
                        str(video_path),
                        screen_width,
                        screen_height,
                        self.video_fps,
                    ),
                    daemon=False,
                )
                self._video_process.start()

                self._screen_capturer = ScreenCapturer(
                    callback=self._on_screen_frame,
                    fps=self.video_fps,
                )
                self._screen_capturer.start()
            except ImportError:
                pass  # Video capture not available

        # Start audio capture
        if self.capture_audio:
            try:
                from openadapt_capture.audio import AudioRecorder
                self._audio_recorder = AudioRecorder()
                self._audio_recorder.start()
            except ImportError:
                pass  # Audio capture not available

    def stop(self) -> None:
        """Stop recording."""
        if not self._running:
            return

        self._running = False

        # Stop input capture
        if self._input_listener is not None:
            self._input_listener.stop()
            self._input_listener = None

        # Stop screen capture
        if self._screen_capturer is not None:
            self._screen_capturer.stop()
            self._screen_capturer = None

        # Stop video writer process
        if self._video_queue is not None:
            self._video_queue.put(None)  # Sentinel to stop
        if self._video_process is not None:
            self._video_process.join(timeout=30)
            if self._video_process.is_alive():
                self._video_process.terminate()
            self._video_process = None
        if self._video_queue is not None:
            self._video_queue = None
        if self._capture is not None:
            self._capture.video_start_time = self._video_start_time

        # Stop audio capture
        if self._audio_recorder is not None:
            if self._capture is not None:
                self._capture.audio_start_time = self._audio_recorder.start_time
            self._audio_recorder.stop()
            # Save audio file
            audio_path = self.capture_dir / "audio.flac"
            self._audio_recorder.save_flac(audio_path)
            self._audio_recorder = None

        # Update capture metadata
        if self._capture is not None and self._storage is not None:
            self._capture.ended_at = time.time()
            self._storage.update_capture(self._capture)

        # Close storage
        if self._storage is not None:
            self._storage.close()
            self._storage = None

    def __enter__(self) -> "Recorder":
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.stop()
