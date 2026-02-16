"""Immutable chained audit log.

Each entry contains a SHA-256 hash of the previous entry so that
tampering is detectable.  Entries are kept in memory as JSON-lines.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AuditEntry:
    timestamp: float
    event: str
    data: Dict[str, Any]
    prev_hash: str
    entry_hash: str


class AuditLog:
    """Append-only hash-chained audit log."""

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []
        self._prev_hash: str = "0" * 64  # genesis

    def append(self, event: str, data: Dict[str, Any]) -> AuditEntry:
        ts = time.time()
        payload = json.dumps(
            {"timestamp": ts, "event": event, "data": data, "prev_hash": self._prev_hash},
            sort_keys=True,
            separators=(",", ":"),
        )
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()
        entry = AuditEntry(
            timestamp=ts,
            event=event,
            data=data,
            prev_hash=self._prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        self._prev_hash = entry_hash
        return entry

    def entries(self) -> List[Dict[str, Any]]:
        return [
            {
                "timestamp": e.timestamp,
                "event": e.event,
                "data": e.data,
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
            }
            for e in self._entries
        ]

    def verify_chain(self) -> bool:
        """Verify the integrity of the full chain."""
        prev = "0" * 64
        for e in self._entries:
            if e.prev_hash != prev:
                return False
            payload = json.dumps(
                {
                    "timestamp": e.timestamp,
                    "event": e.event,
                    "data": e.data,
                    "prev_hash": e.prev_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            expected = hashlib.sha256(payload.encode()).hexdigest()
            if e.entry_hash != expected:
                return False
            prev = e.entry_hash
        return True
