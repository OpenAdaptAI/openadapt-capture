"""Configuration for shadow-mode pattern mining.

Shadow mining is off unless a caller passes ``ShadowConfig(enabled=True)``.
The configuration is a plain dataclass on purpose: it reads no environment
variable, settings file, or remote policy, so nothing outside the calling
process can turn it on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

#: Roles whose label names a piece of UI chrome rather than a piece of data.
#: Only these labels may be kept in plain text for the review draft, and only
#: when :attr:`ShadowConfig.keep_chrome_labels` is on.
DEFAULT_CHROME_ROLES: frozenset[str] = frozenset(
    {"button", "menuitem", "menubaritem", "tab", "checkbox", "radiobutton"}
)

#: Roles whose label identifies the control (a field name or a button title),
#: so the label digest is part of the structural symbol. A label on any other
#: role (a table cell, a list row, a link) is treated as data: it becomes a
#: value digest and stays out of the symbol.
DEFAULT_STRUCTURAL_LABEL_ROLES: frozenset[str] = DEFAULT_CHROME_ROLES | frozenset(
    {"textfield", "textarea", "combobox", "searchfield"}
)


@dataclass(frozen=True)
class ShadowConfig:
    """Settings for :class:`~openadapt_capture.shadow.observer.ShadowObserver`.

    Attributes:
        enabled: Off by default. While off, the observer drops every event,
            opens no file, and never mines or prompts.
        max_symbols: Size cap of the ring buffer. The oldest symbol is
            overwritten first.
        max_age_s: Time cap of the ring buffer. Older symbols expire on every
            write and every read.
        store_path: Optional SQLite file for the ring buffer. ``None`` keeps
            the buffer in memory only.
        idle_gap_s: A gap longer than this starts a new session. A motif never
            spans two sessions.
        window_s: Occurrences are counted inside a sliding window of this
            length. The default is one day, which is what the prompt text
            ("today") assumes.
        min_occurrences: How many times a sequence must repeat inside
            ``window_s`` before it is offered.
        min_length: Shortest motif, in symbols.
        max_length: Longest motif, in symbols.
        min_apps: Distinct applications a motif must touch. The default of 2
            restricts mining to cross-application sequences.
        similarity_threshold: Structural similarity (0 to 1) an approximate
            occurrence needs before it joins a motif's episodes.
        significance: Family-wise false-alarm budget for the chance test that
            separates a real repeat from a coincidence in a busy stream.
        keep_chrome_labels: Keep short plain-text labels of chrome controls
            (for example "Save") so a person can read the review draft.
        chrome_roles: Roles eligible for a plain-text label.
        structural_label_roles: Roles whose label digest is part of a symbol.
    """

    enabled: bool = False
    max_symbols: int = 20_000
    max_age_s: float = 24 * 3600.0
    store_path: Path | None = None
    idle_gap_s: float = 300.0
    window_s: float = 24 * 3600.0
    min_occurrences: int = 3
    min_length: int = 4
    max_length: int = 40
    min_apps: int = 2
    similarity_threshold: float = 0.8
    significance: float = 1e-3
    keep_chrome_labels: bool = True
    chrome_roles: frozenset[str] = field(default=DEFAULT_CHROME_ROLES)
    structural_label_roles: frozenset[str] = field(default=DEFAULT_STRUCTURAL_LABEL_ROLES)

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("enabled must be a bool; shadow mining needs an explicit opt-in")
        if self.max_symbols < 1:
            raise ValueError("max_symbols must be at least 1")
        if self.max_age_s <= 0:
            raise ValueError("max_age_s must be positive")
        if self.min_occurrences < 2:
            raise ValueError("min_occurrences must be at least 2")
        if not 2 <= self.min_length <= self.max_length:
            raise ValueError("need 2 <= min_length <= max_length")
        if self.min_apps < 1:
            raise ValueError("min_apps must be at least 1")
        if not 0.0 < self.similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be in (0, 1]")
        if not 0.0 < self.significance < 1.0:
            raise ValueError("significance must be in (0, 1)")
