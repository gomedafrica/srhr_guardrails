"""Consent records, pseudonymous IDs and data rights (withdraw, delete, export).

Designed around data minimisation (Nigeria Data Protection Act 2023, GDPR-style
principles): the platform user ID (e.g. a Telegram ID or phone number) is never
stored; only a keyed hash of it is.
"""

import hashlib
import hmac
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def pseudonymise(user_id: str, secret: bytes) -> str:
    """Keyed hash so stored records cannot be linked back without the secret."""
    return hmac.new(secret, str(user_id).encode(), hashlib.sha256).hexdigest()[:32]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class UserRecord:
    pid: str
    consent: str = "none"            # none | granted | withdrawn
    consent_version: str | None = None
    consent_at: str | None = None
    minor_flag: str | None = None    # reason, if an under-18 signal was seen
    handover: dict | None = None     # active, unresolved escalation
    messages: list[dict] = field(default_factory=list)  # redacted only


class MemoryStore:
    """In-memory store. Swap for a database-backed store with the same methods."""

    def __init__(self):
        self._data: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get(self, pid: str) -> UserRecord | None:
        with self._lock:
            d = self._data.get(pid)
            return UserRecord(**json.loads(json.dumps(d))) if d else None

    def put(self, rec: UserRecord) -> None:
        with self._lock:
            self._data[rec.pid] = asdict(rec)

    def delete(self, pid: str) -> bool:
        with self._lock:
            return self._data.pop(pid, None) is not None


class JSONFileStore(MemoryStore):
    """Single-file JSON store for pilots and demos. Not for production scale."""

    def __init__(self, path: str | Path):
        super().__init__()
        self.path = Path(path)
        if self.path.exists():
            self._data = json.loads(self.path.read_text(encoding="utf-8"))

    def _flush(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def put(self, rec):
        super().put(rec)
        with self._lock:
            self._flush()

    def delete(self, pid):
        ok = super().delete(pid)
        with self._lock:
            self._flush()
        return ok


class ConsentManager:
    def __init__(self, store: MemoryStore, policy_version: str):
        self.store = store
        self.policy_version = policy_version

    def record(self, pid: str) -> UserRecord:
        return self.store.get(pid) or UserRecord(pid=pid)

    def has_consent(self, pid: str) -> bool:
        rec = self.store.get(pid)
        return bool(rec and rec.consent == "granted"
                    and rec.consent_version == self.policy_version)

    def grant(self, pid: str, *, minor_flag: str | None = None) -> UserRecord:
        rec = self.record(pid)
        rec.consent, rec.consent_version, rec.consent_at = "granted", self.policy_version, _now()
        rec.minor_flag = rec.minor_flag or minor_flag
        self.store.put(rec)
        return rec

    def withdraw(self, pid: str) -> None:
        """Withdrawal stops processing and erases stored conversation content."""
        rec = self.record(pid)
        rec.consent, rec.consent_at, rec.messages = "withdrawn", _now(), []
        self.store.put(rec)

    def erase(self, pid: str) -> bool:
        return self.store.delete(pid)

    def export(self, pid: str) -> dict:
        rec = self.store.get(pid)
        return asdict(rec) if rec else {}
