"""Platform-neutral contracts for native global input observation."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, TypeAlias


class InputObserverError(RuntimeError):
    """Base error for fail-loud input observation."""


class InputObserverUnavailableError(InputObserverError):
    """The current platform/session cannot provide complete input observation."""


class InputObserverPermissionError(InputObserverError):
    """The operating system denied global input-observation permission."""


@dataclass(frozen=True, slots=True)
class ObservedMouseMove:
    """A global mouse-pointer movement in logical screen coordinates."""

    x: float
    y: float
    injected: bool = False


@dataclass(frozen=True, slots=True)
class ObservedMouseButton:
    """A global mouse-button transition."""

    x: float
    y: float
    button: str
    pressed: bool
    injected: bool = False


@dataclass(frozen=True, slots=True)
class ObservedMouseScroll:
    """A global scroll event using platform-normalized wheel units."""

    x: float
    y: float
    dx: float
    dy: float
    injected: bool = False


@dataclass(frozen=True, slots=True)
class ObservedKey:
    """A global key transition with both physical and canonical identity."""

    pressed: bool
    key_name: str | None = None
    key_char: str | None = None
    key_vk: str | None = None
    canonical_key_name: str | None = None
    canonical_key_char: str | None = None
    canonical_key_vk: str | None = None
    injected: bool = False


ObservedInput: TypeAlias = (
    ObservedMouseMove | ObservedMouseButton | ObservedMouseScroll | ObservedKey
)
InputCallback: TypeAlias = Callable[[ObservedInput], None]


class InputObserver(ABC):
    """Lifecycle contract for a complete native input observer."""

    @abstractmethod
    def start(self) -> None:
        """Start observing, or raise before returning if setup is incomplete."""

    @abstractmethod
    def check_health(self) -> None:
        """Raise if the observer failed after startup."""

    @abstractmethod
    def stop(self) -> None:
        """Stop and join the observer, surfacing any observer failure."""

    def __enter__(self) -> "InputObserver":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


class ThreadedInputObserver(InputObserver):
    """Shared fail-loud lifecycle for native event-loop implementations."""

    def __init__(
        self,
        callback: InputCallback,
        *,
        observe_keyboard: bool,
        observe_mouse: bool,
        capture_mouse_moves: bool,
        startup_timeout: float = 5.0,
        shutdown_timeout: float = 5.0,
    ) -> None:
        if not observe_keyboard and not observe_mouse:
            raise ValueError("at least one of observe_keyboard or observe_mouse is required")
        self.callback = callback
        self.observe_keyboard = observe_keyboard
        self.observe_mouse = observe_mouse
        self.capture_mouse_moves = capture_mouse_moves
        self.startup_timeout = startup_timeout
        self.shutdown_timeout = shutdown_timeout
        self._ready = threading.Event()
        self._stop_requested = threading.Event()
        self._thread: threading.Thread | None = None
        self._failure: BaseException | None = None

    @abstractmethod
    def _setup(self) -> None:
        """Create platform resources on the observer thread."""

    @abstractmethod
    def _run_loop(self) -> None:
        """Run until ``_stop_requested`` is set."""

    @abstractmethod
    def _teardown(self) -> None:
        """Release any resources created by ``_setup``."""

    def _wake(self) -> None:
        """Wake a blocked event loop during shutdown, when needed."""

    def _emit(self, event: ObservedInput) -> None:
        self.callback(event)

    def _thread_main(self) -> None:
        try:
            self._setup()
            self._ready.set()
            self._run_loop()
        except BaseException as exc:
            self._failure = exc
            self._ready.set()
        finally:
            try:
                self._teardown()
            except BaseException as exc:
                if self._failure is None:
                    self._failure = exc

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._ready.clear()
        self._stop_requested.clear()
        self._failure = None
        self._thread = threading.Thread(
            target=self._thread_main,
            name=f"{type(self).__name__}-event-loop",
            daemon=True,
        )
        self._thread.start()
        if not self._ready.wait(self.startup_timeout):
            self._stop_requested.set()
            self._wake()
            raise InputObserverError(
                f"{type(self).__name__} did not become ready within "
                f"{self.startup_timeout:.1f}s"
            )
        self.check_health()

    def check_health(self) -> None:
        if self._failure is not None:
            if isinstance(self._failure, InputObserverError):
                raise self._failure
            raise InputObserverError(
                f"{type(self).__name__} failed: {self._failure}"
            ) from self._failure
        if self._thread is not None and not self._thread.is_alive():
            raise InputObserverError(f"{type(self).__name__} stopped unexpectedly")

    def stop(self) -> None:
        thread = self._thread
        if thread is None:
            return
        self._stop_requested.set()
        self._wake()
        thread.join(self.shutdown_timeout)
        if thread.is_alive():
            raise InputObserverError(
                f"{type(self).__name__} did not stop within "
                f"{self.shutdown_timeout:.1f}s"
            )
        self._thread = None
        self.check_health()

