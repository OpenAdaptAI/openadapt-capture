"""Shadow-mode pattern mining. Off by default.

Watches value-free symbols of what a person does across applications, notices
when the same sequence repeats, and offers a draft. See
``docs/SHADOW_MINING.md`` for the privacy posture and the admission path.
"""

from openadapt_capture.shadow.config import ShadowConfig
from openadapt_capture.shadow.events import (
    ShadowEvent,
    from_browser_event,
    from_capture_event,
    from_window_event,
)
from openadapt_capture.shadow.motifs import Motif, Occurrence, mine_motifs
from openadapt_capture.shadow.notify import (
    CollectingNotifier,
    MotifNotifier,
    MotifPrompt,
    PromptAction,
    SuppressionList,
)
from openadapt_capture.shadow.observer import (
    EPISODES_SCHEMA,
    ShadowModeDisabled,
    ShadowObserver,
    export_episodes,
)
from openadapt_capture.shadow.ring import SymbolRing
from openadapt_capture.shadow.symbols import ShadowSymbol, Tokenizer

__all__ = [
    "EPISODES_SCHEMA",
    "CollectingNotifier",
    "Motif",
    "MotifNotifier",
    "MotifPrompt",
    "Occurrence",
    "PromptAction",
    "ShadowConfig",
    "ShadowEvent",
    "ShadowModeDisabled",
    "ShadowObserver",
    "ShadowSymbol",
    "SuppressionList",
    "SymbolRing",
    "Tokenizer",
    "export_episodes",
    "from_browser_event",
    "from_capture_event",
    "from_window_event",
    "mine_motifs",
]
