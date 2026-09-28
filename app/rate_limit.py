from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, max_entries: int = 10_000) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._max_entries = max_entries

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                return False
            events.append(now)
            if len(self._events) > self._max_entries:
                self._prune(cutoff)
            return True

    def _prune(self, cutoff: float) -> None:
        for key in list(self._events)[: max(1, len(self._events) // 10)]:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if not events:
                self._events.pop(key, None)

