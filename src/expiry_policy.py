"""
Shared TTL policy for EDL entries and Whitelist rules.
Sliding window: TTL resets on each activity touch.
ttl_days = -1 means permanent (never expires).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ExpiryPolicy:
    ttl_days: int                        # -1 = permanent
    last_activity: datetime | None = field(default=None)

    def is_expired(self) -> bool:
        if self.ttl_days == -1:
            return False
        if self.last_activity is None:
            return False                 # never hit → keep
        delta = datetime.now(timezone.utc) - self.last_activity
        return delta.days > self.ttl_days

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "ttl_days": self.ttl_days,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ExpiryPolicy:
        la = d.get("last_activity")
        return cls(
            ttl_days=int(d.get("ttl_days", 30)),
            last_activity=datetime.fromisoformat(la) if la else None,
        )
