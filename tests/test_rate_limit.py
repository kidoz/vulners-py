from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from vulners._rate_limit import TokenBucket

if TYPE_CHECKING:
    import pytest


def test_token_bucket_updates_and_calculates_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    bucket = TokenBucket()
    bucket.update(0)
    assert bucket._rate is None

    bucket.update(60)
    bucket._allowance = 0.0
    bucket._last_check = 10.0
    monkeypatch.setattr("vulners._rate_limit.time.monotonic", lambda: 10.25)
    assert bucket._delay() == 0.75

    bucket._allowance = 1.0
    assert bucket._delay() == 0.0


def test_sync_token_bucket_sleeps(monkeypatch: pytest.MonkeyPatch) -> None:
    bucket = TokenBucket()
    delays = iter((0.25, 0.0))
    slept: list[float] = []
    monkeypatch.setattr(bucket, "_delay", lambda: next(delays))
    monkeypatch.setattr("vulners._rate_limit.time.sleep", slept.append)
    bucket.consume()
    assert slept == [0.25]


async def test_async_token_bucket_uses_asyncio_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    bucket = TokenBucket()
    delays = iter((0.25, 0.0))
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(bucket, "_delay", lambda: next(delays))
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    await bucket.aconsume()
    assert slept == [0.25]
