"""Synchronous and asynchronous token buckets for endpoint rate limits."""

from __future__ import annotations

import asyncio
import time


class TokenBucket:
    """Token bucket updated from a server-advertised requests-per-minute limit."""

    def __init__(self) -> None:
        self._rate: float | None = None
        self._allowance = 0.0
        self._last_check = time.monotonic()

    def update(self, requests_per_minute: float) -> None:
        """Set the rate limit for future calls."""
        if requests_per_minute <= 0:
            return
        self._rate = requests_per_minute / 60.0
        self._allowance = min(self._allowance, 1.0)

    def _delay(self) -> float:
        now = time.monotonic()
        elapsed = now - self._last_check
        self._last_check = now
        if self._rate is None:
            return 0.0
        self._allowance = min(1.0, self._allowance + elapsed * self._rate)
        if self._allowance >= 1.0:
            self._allowance -= 1.0
            return 0.0
        return (1.0 - self._allowance) / self._rate

    def consume(self) -> None:
        """Wait synchronously until a request token becomes available."""
        while (delay := self._delay()) > 0:
            time.sleep(delay)

    async def aconsume(self) -> None:
        """Wait asynchronously until a request token becomes available."""
        while (delay := self._delay()) > 0:
            await asyncio.sleep(delay)
