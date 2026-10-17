"""A bounded, self-expiring ring buffer of shadow symbols.

Two caps apply at once: a size cap (the oldest symbol is overwritten first)
and a time cap (a symbol older than ``max_age_s`` is deleted on every write
and every read). The buffer lives in memory unless a ``store_path`` is given.

The on-disk form is a single SQLite file with owner-only permissions,
``secure_delete`` on (deleted rows are zeroed, not just unlinked), and a
rollback journal instead of a write-ahead log, so expired rows don't linger in
a side file. Capture has no encryption at rest today, so this file is not
encrypted. It holds only :class:`~openadapt_capture.shadow.symbols.ShadowSymbol`
records, which carry no raw typed text, titles, or URLs.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path

from openadapt_capture.shadow.symbols import ShadowSymbol

Clock = Callable[[], float]


class SymbolRing:
    """Ring buffer with a size cap, a time cap, and automatic overwrite."""

    def __init__(
        self,
        *,
        max_symbols: int,
        max_age_s: float,
        path: Path | None = None,
        clock: Clock = time.time,
    ) -> None:
        if max_symbols < 1:
            raise ValueError("max_symbols must be at least 1")
        if max_age_s <= 0:
            raise ValueError("max_age_s must be positive")
        self.max_symbols = int(max_symbols)
        self.max_age_s = float(max_age_s)
        self._clock = clock
        self._lock = threading.Lock()
        self._path = Path(path) if path is not None else None
        self._mem: deque[ShadowSymbol] = deque(maxlen=self.max_symbols)
        self._db: sqlite3.Connection | None = None
        if self._path is not None:
            self._db = self._open(self._path)
            self._expire_locked()

    @staticmethod
    def _open(path: Path) -> sqlite3.Connection:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        os.chmod(path, 0o600)
        db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        db.execute("PRAGMA secure_delete=ON")
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute(
            "CREATE TABLE IF NOT EXISTS shadow_symbol ("
            "seq INTEGER PRIMARY KEY AUTOINCREMENT, t REAL NOT NULL, payload TEXT NOT NULL)"
        )
        db.execute("CREATE INDEX IF NOT EXISTS shadow_symbol_t ON shadow_symbol(t)")
        return db

    @property
    def path(self) -> Path | None:
        return self._path

    def append(self, symbol: ShadowSymbol) -> None:
        """Add one symbol, then enforce both caps."""

        with self._lock:
            if self._db is not None:
                self._db.execute(
                    "INSERT INTO shadow_symbol (t, payload) VALUES (?, ?)",
                    (symbol.t, json.dumps(symbol.to_dict(), sort_keys=True)),
                )
            else:
                self._mem.append(symbol)
            self._expire_locked()

    def extend(self, symbols: list[ShadowSymbol]) -> None:
        for symbol in symbols:
            self.append(symbol)

    def snapshot(self) -> list[ShadowSymbol]:
        """Return the live symbols, oldest first, after expiring stale ones."""

        with self._lock:
            self._expire_locked()
            if self._db is not None:
                rows = self._db.execute("SELECT payload FROM shadow_symbol ORDER BY seq").fetchall()
                return [ShadowSymbol.from_dict(json.loads(r[0])) for r in rows]
            # A clock step backwards can leave a stale symbol behind a fresh
            # one; filter so nothing past the time cap is ever returned.
            cutoff = self._clock() - self.max_age_s
            live = [symbol for symbol in self._mem if symbol.t >= cutoff]
            if len(live) != len(self._mem):
                self._mem = deque(live, maxlen=self.max_symbols)
            return live

    def __len__(self) -> int:
        return len(self.snapshot())

    def purge(self) -> None:
        """Delete every symbol now."""

        with self._lock:
            self._mem.clear()
            if self._db is not None:
                self._db.execute("DELETE FROM shadow_symbol")
                self._db.execute("VACUUM")

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def _expire_locked(self) -> None:
        cutoff = self._clock() - self.max_age_s
        if self._db is not None:
            self._db.execute("DELETE FROM shadow_symbol WHERE t < ?", (cutoff,))
            self._db.execute(
                "DELETE FROM shadow_symbol WHERE seq <= (SELECT MAX(seq) FROM shadow_symbol) - ?",
                (self.max_symbols,),
            )
            return
        while self._mem and self._mem[0].t < cutoff:
            self._mem.popleft()
