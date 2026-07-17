from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock:
    """Test double: returns a fixed, settable instant. Always tz-aware."""

    def __init__(self, t: datetime):
        if t.tzinfo is None:
            raise ValueError("FixedClock requires a tz-aware datetime")
        self._t = t

    def now(self) -> datetime:
        return self._t

    def advance(self, delta: timedelta) -> None:
        self._t += delta

    def set(self, t: datetime) -> None:
        if t.tzinfo is None:
            raise ValueError("FixedClock requires a tz-aware datetime")
        self._t = t
