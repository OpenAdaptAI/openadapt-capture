"""The notice a person must acknowledge before shadow mode turns on.

:class:`~openadapt_capture.shadow.observer.ShadowObserver` refuses to start
enabled without an :class:`Acknowledgement` of the current notice. The notice
says what is captured, that the buffer is encrypted, local, and kept for 24
hours, that nothing leaves the computer, that no administrator can see it or
turn it on, and that one action deletes everything and turns it off.

The acknowledgement is recorded on this computer only, in an owner-only JSON
file: the notice version, a SHA-256 of the notice text, and the time. Turning
shadow mode off with **Delete everything and turn off** records the time it
was revoked; the next opt-in needs a fresh acknowledgement.

Changing the notice text changes its hash, so an acknowledgement of an older
notice no longer counts.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

NOTICE_VERSION = "2026-10-17"
NOTICE_TITLE = "Turn on shadow mode?"
NOTICE_INTRO = (
    "Shadow mode watches for tasks you repeat across apps and offers to turn one "
    "into a draft automation. It is off until you turn it on, and only you can "
    "turn it on."
)
NOTICE_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "What it records",
        (
            "Which app you switch to, and the kind of control you use (a button, a text "
            "field, a list row).",
            "Short button and menu labels made of common words, such as Save or Send. "
            "Any other label is replaced with a placeholder.",
            "The shape of what you type (digits, a date, an email address) and a keyed "
            "fingerprint of it, never the text itself. Password and PIN fields are "
            "skipped.",
            "On the work sites you list: the site name and the first word of the page "
            "address, with record numbers and names replaced. On any other site: only "
            "that you were in a browser.",
        ),
    ),
    (
        "What it never records",
        ("Screenshots, window titles, clipboard contents, or what you type in readable form.",),
    ),
    (
        "Where it is kept",
        (
            "In an encrypted file on this computer. Each entry is deleted after 24 hours.",
            "The encryption key is in this computer's keychain. The key, and every "
            "fingerprint made with it, is destroyed every 24 hours.",
            "Nothing leaves this computer. Shadow mode makes no network connections.",
            "No administrator or OpenAdapt service can see it or turn it on. There is "
            "no remote or admin setting for it.",
        ),
    ),
    (
        "What it does with it",
        (
            "It may show: You did this N times today. You choose Review draft or Ignore.",
            "A draft never runs. To automate the task, you record it and a person "
            "reviews and admits the automation.",
        ),
    ),
    (
        "Turning it off",
        ("Delete everything and turn off removes the buffer and the key at once.",),
    ),
)
ACKNOWLEDGE_LABEL = "Turn on shadow mode"
DECLINE_LABEL = "Not now"
PURGE_AND_DISABLE_LABEL = "Delete everything and turn off"


def notice_text() -> str:
    """The full notice as plain text, exactly as it is hashed."""

    lines = [NOTICE_TITLE, "", NOTICE_INTRO]
    for heading, items in NOTICE_SECTIONS:
        lines += ["", heading]
        lines += [f"- {item}" for item in items]
    return "\n".join(lines) + "\n"


def notice_sha256() -> str:
    return hashlib.sha256(notice_text().encode("utf-8")).hexdigest()


def notice() -> dict[str, Any]:
    """The notice as data, for a UI to render."""

    return {
        "version": NOTICE_VERSION,
        "sha256": notice_sha256(),
        "title": NOTICE_TITLE,
        "intro": NOTICE_INTRO,
        "sections": [{"heading": h, "items": list(items)} for h, items in NOTICE_SECTIONS],
        "acknowledge_label": ACKNOWLEDGE_LABEL,
        "decline_label": DECLINE_LABEL,
        "purge_and_disable_label": PURGE_AND_DISABLE_LABEL,
        "text": notice_text(),
    }


class ShadowConsentRequired(PermissionError):
    """Shadow mode can't turn on without an acknowledgement of the current notice."""


@dataclass(frozen=True)
class Acknowledgement:
    """A person's acknowledgement of one notice, at one time."""

    notice_version: str
    notice_sha256: str
    acknowledged_at: float

    @property
    def current(self) -> bool:
        return self.notice_version == NOTICE_VERSION and self.notice_sha256 == notice_sha256()


def require_current(ack: Acknowledgement | None) -> Acknowledgement:
    if not isinstance(ack, Acknowledgement) or not ack.current:
        raise ShadowConsentRequired(
            "shadow mode needs the person to acknowledge the current notice first"
        )
    return ack


class ConsentLedger:
    """Local record of acknowledgements and revocations."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"events": []}
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {"events": []}
        if not isinstance(data, dict) or not isinstance(data.get("events"), list):
            return {"events": []}
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def acknowledge(self, sha256: str, *, now: float | None = None) -> Acknowledgement:
        """Record that the person acknowledged the notice with hash ``sha256``.

        The caller passes back the hash of the notice it showed, so an outdated
        screen can't acknowledge a newer notice.
        """

        if sha256 != notice_sha256():
            raise ShadowConsentRequired("the acknowledged notice is not the current notice")
        ack = Acknowledgement(NOTICE_VERSION, sha256, time.time() if now is None else now)
        data = self._read()
        data["events"].append(
            {
                "event": "acknowledged",
                "at": ack.acknowledged_at,
                "notice_version": ack.notice_version,
                "notice_sha256": ack.notice_sha256,
            }
        )
        self._write(data)
        return ack

    def revoke(self, *, now: float | None = None) -> None:
        data = self._read()
        data["events"].append({"event": "revoked", "at": time.time() if now is None else now})
        self._write(data)

    def current(self) -> Acknowledgement | None:
        """The standing acknowledgement of the current notice, if any."""

        for event in reversed(self._read()["events"]):
            if not isinstance(event, dict):
                continue
            if event.get("event") == "revoked":
                return None
            if event.get("event") == "acknowledged":
                try:
                    ack = Acknowledgement(
                        str(event["notice_version"]),
                        str(event["notice_sha256"]),
                        float(event["at"]),
                    )
                except (KeyError, TypeError, ValueError):
                    return None
                return ack if ack.current else None
        return None

    def history(self) -> list[dict[str, Any]]:
        return [e for e in self._read()["events"] if isinstance(e, dict)]
