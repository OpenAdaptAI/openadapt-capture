"""Shadow mode: watch for a repeated cross-application task, offer a draft.

:class:`ShadowObserver` ties the pieces together::

    ShadowEvent -> Tokenizer -> SymbolRing -> mine_motifs -> MotifPrompt
                                                     |
                     [Review draft] -> episodes export (for Flow's induce)
                     [Ignore]       -> SuppressionList

The observer is inert unless its configuration says ``enabled=True``. While
inert it drops events without tokenizing them, opens no file, and never
prompts. It opens no network connection in any state, and it never runs
anything: the most it produces is a JSON export of value-free episodes that a
person may hand to Flow.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any

from openadapt_capture.shadow.config import ShadowConfig
from openadapt_capture.shadow.events import ShadowEvent
from openadapt_capture.shadow.motifs import Motif, mine_motifs
from openadapt_capture.shadow.notify import (
    MotifNotifier,
    MotifPrompt,
    PromptAction,
    SuppressionList,
)
from openadapt_capture.shadow.ring import Clock, SymbolRing
from openadapt_capture.shadow.symbols import ShadowSymbol, Tokenizer

EPISODES_SCHEMA = "openadapt.shadow.episodes/v1"

PRIVACY_POSTURE = {
    "typed_values": "keyed digest only; secure fields dropped",
    "control_labels": "keyed digest; short chrome labels in plain text when enabled",
    "window_titles": "never read",
    "urls": "scheme, host, and at most one path word",
    "clipboard_contents": "never read; copy and paste come from the key chord",
    "screenshots": "never taken",
    "network": "none",
}


class ShadowModeDisabled(RuntimeError):
    """Raised when a caller asks a disabled observer to mine or export."""


class ShadowObserver:
    """Passive pattern miner. Off unless ``config.enabled`` is True."""

    def __init__(
        self,
        config: ShadowConfig | None = None,
        *,
        notifier: MotifNotifier | None = None,
        suppression: SuppressionList | None = None,
        digest_key: bytes | None = None,
        clock: Clock = time.time,
    ) -> None:
        self.config = config if config is not None else ShadowConfig()
        self._clock = clock
        self._notifier = notifier
        self._suppression = suppression if suppression is not None else SuppressionList()
        self._offered: dict[str, int] = {}
        self._motifs: dict[str, Motif] = {}
        self._symbols_cache: list[ShadowSymbol] = []
        self._tokenizer: Tokenizer | None = None
        self._ring: SymbolRing | None = None
        if self.config.enabled:
            self._tokenizer = Tokenizer(self.config, digest_key=digest_key)
            self._ring = SymbolRing(
                max_symbols=self.config.max_symbols,
                max_age_s=self.config.max_age_s,
                path=self.config.store_path,
                clock=clock,
            )

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def observe(self, event: ShadowEvent | None) -> None:
        """Record one event. A disabled observer drops it untouched."""

        if not self.enabled or event is None:
            return
        assert self._tokenizer is not None and self._ring is not None
        self._ring.extend(self._tokenizer.feed(event))

    def observe_all(self, events: Iterable[ShadowEvent | None]) -> None:
        for event in events:
            self.observe(event)

    def symbols(self) -> list[ShadowSymbol]:
        """The live ring buffer contents, oldest first."""

        if not self.enabled:
            return []
        assert self._tokenizer is not None and self._ring is not None
        self._ring.extend(self._tokenizer.flush())
        return self._ring.snapshot()

    def scan(self) -> list[MotifPrompt]:
        """Mine the buffer and offer each new, unsuppressed motif once.

        A motif is offered again only when its count has grown since the last
        offer. Returns the prompts offered by this call.
        """

        if not self.enabled:
            return []
        symbols = self.symbols()
        prompts: list[MotifPrompt] = []
        self._symbols_cache = symbols
        for motif in mine_motifs(symbols, self.config, now=self._clock()):
            if self._suppression.is_suppressed(motif.motif_id, motif.tokens):
                continue
            self._motifs[motif.motif_id] = motif
            if self._offered.get(motif.motif_id, 0) >= motif.count_in_window:
                continue
            self._offered[motif.motif_id] = motif.count_in_window
            prompt = MotifPrompt(motif_id=motif.motif_id, count=motif.count_in_window)
            prompts.append(prompt)
            if self._notifier is not None:
                self._notifier.offer(prompt)
        return prompts

    def decide(self, motif_id: str, action: PromptAction | str) -> dict[str, Any] | None:
        """Apply a person's answer to a prompt.

        ``ignore`` suppresses the motif (and close variants) and returns None.
        ``review_draft`` returns the episodes export for Flow. Neither answer
        runs anything.
        """

        if not self.enabled:
            raise ShadowModeDisabled("shadow mining is off")
        action = PromptAction(action)
        motif = self._motifs.get(motif_id)
        if motif is None:
            raise KeyError(f"unknown or expired motif {motif_id}")
        if action is PromptAction.IGNORE:
            self._suppression.add(motif.motif_id, motif.tokens)
            self._motifs.pop(motif_id, None)
            return None
        return self.export(motif_id)

    def export(self, motif_id: str) -> dict[str, Any]:
        """Episodes of one motif, in the ``openadapt.shadow.episodes/v1`` form."""

        if not self.enabled:
            raise ShadowModeDisabled("shadow mining is off")
        motif = self._motifs[motif_id]
        return export_episodes(motif, self._symbols_cache, self.config)

    def purge(self) -> None:
        """Delete every stored symbol and forget every motif."""

        self._motifs.clear()
        self._offered.clear()
        self._symbols_cache = []
        if self._ring is not None:
            self._ring.purge()

    def close(self) -> None:
        if self._ring is not None:
            self._ring.close()


def export_episodes(
    motif: Motif, symbols: list[ShadowSymbol], config: ShadowConfig
) -> dict[str, Any]:
    """Build the JSON-ready export Flow's ``induce`` bridge reads."""

    episodes = []
    for occ in motif.occurrences:
        steps = [symbols[i].to_dict() for i in range(occ.start, occ.end)]
        episodes.append(
            {
                "t_start": occ.t_start,
                "t_end": occ.t_end,
                "exact": occ.exact,
                "similarity": occ.similarity,
                "steps": steps,
            }
        )
    return {
        "schema": EPISODES_SCHEMA,
        "motif_id": motif.motif_id,
        "tokens": list(motif.tokens),
        "apps": list(motif.apps),
        "count_in_window": motif.count_in_window,
        "window_s": config.window_s,
        "exact_count": motif.exact_count,
        "expected_by_chance": motif.expected_by_chance,
        "p_value": motif.p_value,
        "status": "candidate",
        "privacy": dict(PRIVACY_POSTURE),
        "episodes": episodes,
    }
