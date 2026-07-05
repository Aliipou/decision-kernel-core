"""Durable, atomic spent-token store — makes a one-time capability token one-time
ACROSS Executor/TokenStore instances (workers, replicas, restarts), not merely
within one process.

HB-1: :class:`TokenStore` tracked spent token_ids in an in-memory ``set``. A
second store (a fresh process, a second replica behind a load balancer, or the
same process after a restart) starts empty, so a captured signed token can be
spent again inside its 30s TTL — one decision, two effects.

The fix is a shared spend-record whose "have I seen this token_id?" test is
ATOMIC and DURABLE. This module provides the same seam as decision-os-min's
spentstore: :class:`SpentStore` (protocol), :class:`FileSpentStore` (default,
``O_CREAT | O_EXCL`` one file per token_id), :class:`SqliteSpentStore` (UNIQUE
constraint), and :class:`InMemorySpentStore` (the OLD behaviour, kept as an
EXPLICIT single-process opt-in).

FAIL CLOSED: if the store cannot be reached, :meth:`try_spend` raises
:class:`SpentStoreUnavailable`; the caller must treat that as a refusal, never as
"unspent".

HONEST LIMIT: the file/sqlite backends are durable and atomic on a SINGLE shared
filesystem/volume — they close cross-process replay on one host / shared volume.
They are NOT distributed consensus: two replicas on independent local disks would
each accept the token once. For multi-machine deployments back the store with a
shared volume or implement :class:`SpentStore` over Redis SETNX / a shared-DB
UNIQUE. The protocol is that seam.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path
from typing import Protocol, runtime_checkable


class SpentStoreUnavailable(RuntimeError):
    """The spent-store could not be reached. Callers MUST fail closed."""


@runtime_checkable
class SpentStore(Protocol):
    def try_spend(self, token_id: str) -> bool:
        """Atomically record ``token_id`` as spent. Returns True iff THIS call was
        the first to record it (previously unspent); False on replay. Raises
        :class:`SpentStoreUnavailable` if the store cannot be reached."""
        ...


class FileSpentStore:
    """Default durable store: one marker file per token_id, created with
    ``O_CREAT | O_EXCL`` so "first to spend" is an atomic filesystem op shared by
    every process pointed at the same directory."""

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:  # pragma: no cover - environment dependent
            raise SpentStoreUnavailable(f"cannot create spent-store dir {self._dir}: {e}") from e

    @staticmethod
    def _safe_name(token_id: str) -> str:
        return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in token_id) or "_empty"

    def try_spend(self, token_id: str) -> bool:
        path = self._dir / self._safe_name(token_id)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False
        except OSError as e:
            raise SpentStoreUnavailable(f"spent-store unreachable for {token_id!r}: {e}") from e
        try:
            os.write(fd, token_id.encode("utf-8"))
            os.fsync(fd)
        except OSError as e:  # pragma: no cover - environment dependent
            raise SpentStoreUnavailable(f"spent-store write failed for {token_id!r}: {e}") from e
        finally:
            os.close(fd)
        return True


class SqliteSpentStore:
    """Alternative durable store: a single sqlite DB with a UNIQUE constraint on
    token_id (the failed INSERT is the atomic compare-and-set)."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = str(db_path)
        self._lock = threading.Lock()
        try:
            p = Path(self._path)
            if p.parent and not p.parent.exists():
                p.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS spent (token_id TEXT PRIMARY KEY)")
        except sqlite3.Error as e:  # pragma: no cover - environment dependent
            raise SpentStoreUnavailable(f"cannot init sqlite spent-store {self._path}: {e}") from e

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def try_spend(self, token_id: str) -> bool:
        try:
            with self._lock, self._connect() as conn:
                try:
                    conn.execute("INSERT INTO spent (token_id) VALUES (?)", (token_id,))
                except sqlite3.IntegrityError:
                    return False
                return True
        except sqlite3.Error as e:
            raise SpentStoreUnavailable(f"sqlite spent-store unreachable: {e}") from e


class InMemorySpentStore:
    """The ORIGINAL in-process set. NOT durable, NOT shared across processes. Kept
    as an EXPLICIT single-process opt-in — selecting it is a deliberate choice, so
    cross-instance replay (HB-1) can only happen if a deployer knowingly picks it."""

    def __init__(self) -> None:
        self._spent: set[str] = set()
        self._lock = threading.Lock()

    def try_spend(self, token_id: str) -> bool:
        with self._lock:
            if token_id in self._spent:
                return False
            self._spent.add(token_id)
            return True


def default_spent_store() -> SpentStore:
    """The durable default: a file-backed store on a stable, shared path so a
    second TokenStore process/replica on the same volume sees an already-spent
    token. Overridable via ``$DECISION_KERNEL_SPENT_DIR``."""
    import tempfile

    directory = os.environ.get("DECISION_KERNEL_SPENT_DIR") or str(
        Path(tempfile.gettempdir()) / "decision_kernel_core_spent"
    )
    return FileSpentStore(directory)
