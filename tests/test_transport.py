from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from typing import TYPE_CHECKING

import httpx
import pytest
import respx

from vulners import (
    AsyncVulners,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    Vulners,
    VulnersAPIError,
    VulnersError,
    __version__,
)
from vulners._rate_limit import TokenBucket
from vulners._transport import _parse_retry_after, _rate_limit_from, _retry_delay, parse_response

if TYPE_CHECKING:
    from pathlib import Path

BASE_URL = "https://vulners.test"
LUCENE_URL = f"{BASE_URL}/api/v3/search/lucene/"
SUCCESS = {"result": "OK", "data": {"search": [], "total": 0}}


@respx.mock
def test_version_and_user_agent_are_consistent() -> None:
    route = respx.post(LUCENE_URL).mock(return_value=httpx.Response(200, json=SUCCESS))
    with Vulners("key", base_url=BASE_URL) as client:
        client.search.bulletins("test")

    assert __version__.count(".") == 2
    assert route.calls[0].request.headers["User-Agent"] == f"vulners-py/{__version__}"
    assert route.calls[0].request.headers["X-Api-Key"] == "key"


@respx.mock
def test_v3_body_error_is_mapped() -> None:
    respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(
            200, json={"result": "error", "data": {"error": "Invalid query", "errorCode": 42}}
        )
    )
    with (
        Vulners("not-a-real-key", base_url=BASE_URL) as client,
        pytest.raises(VulnersAPIError, match="Invalid query") as error,
    ):
        client.search.bulletins("bad")

    assert error.value.status_code == 200
    assert error.value.error_code == 42


@respx.mock
@pytest.mark.parametrize("status", [401, 403])
def test_authentication_errors(status: int) -> None:
    respx.post(LUCENE_URL).mock(return_value=httpx.Response(status, json={"message": "No access"}))
    with Vulners("not-a-real-key", base_url=BASE_URL) as client, pytest.raises(AuthenticationError):
        client.search.bulletins("test")


@respx.mock
def test_rate_limit_error_exposes_retry_after() -> None:
    respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(
            429, headers={"Retry-After": "3"}, json={"message": "Slow down"}
        )
    )
    with (
        Vulners("not-a-real-key", base_url=BASE_URL, retries=1) as client,
        pytest.raises(RateLimitError) as error,
    ):
        client.search.bulletins("test")

    assert error.value.retry_after == 3.0


@respx.mock
def test_retryable_server_error_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    route = respx.post(LUCENE_URL).mock(
        side_effect=[
            httpx.Response(503, headers={"Retry-After": "2"}, json={"message": "Unavailable"}),
            httpx.Response(200, json=SUCCESS),
        ]
    )
    delays: list[float] = []
    monkeypatch.setattr("vulners._transport.time.sleep", delays.append)
    with Vulners("not-a-real-key", base_url=BASE_URL, retries=2) as client:
        page = client.search.bulletins("test")

    assert route.call_count == 2
    assert delays == [2.0]
    assert page.total == 0


@respx.mock
def test_retry_exhaustion_raises_server_error(monkeypatch: pytest.MonkeyPatch) -> None:
    respx.post(LUCENE_URL).mock(return_value=httpx.Response(503, json={"message": "Unavailable"}))
    monkeypatch.setattr("vulners._transport.time.sleep", lambda _: None)
    with (
        Vulners("not-a-real-key", base_url=BASE_URL, retries=2) as client,
        pytest.raises(ServerError),
    ):
        client.search.bulletins("test")


def test_client_repr_redacts_api_key() -> None:
    client = Vulners("very-secret-api-key", base_url=BASE_URL)
    try:
        assert "very-secret-api-key" not in repr(client)
        assert "very-secret-api-key" not in repr(client._transport)
    finally:
        client.close()


@pytest.mark.parametrize(
    ("status", "error_type"),
    [(404, NotFoundError), (400, VulnersAPIError)],
)
@respx.mock
def test_other_http_errors_are_mapped(status: int, error_type: type[Exception]) -> None:
    respx.post(LUCENE_URL).mock(return_value=httpx.Response(status, json={"message": "failure"}))
    with Vulners("key", base_url=BASE_URL, retries=1) as client, pytest.raises(error_type):
        client.search.bulletins("test")


def test_response_helpers_handle_empty_and_invalid_content() -> None:
    empty = httpx.Response(200, request=httpx.Request("GET", BASE_URL))
    invalid = httpx.Response(
        200,
        content=b"not-json",
        request=httpx.Request("GET", BASE_URL),
        headers={"Set-Cookie": "x=y"},
    )
    assert parse_response(empty) is None
    assert parse_response(invalid) is None
    assert "set-cookie" not in invalid.headers


def test_invalid_retry_count_and_environment_key(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="retries"):
        Vulners("key", retries=0)
    monkeypatch.delenv("VULNERS_API_KEY", raising=False)
    with pytest.raises(ValueError, match="api_key"):
        Vulners()


@respx.mock
async def test_async_transport_retries_and_redacts(monkeypatch: pytest.MonkeyPatch) -> None:
    route = respx.post(LUCENE_URL).mock(
        side_effect=[
            httpx.Response(503, headers={"Retry-After": "1.5"}, json={"message": "retry"}),
            httpx.Response(200, json=SUCCESS),
        ]
    )

    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr("vulners._transport.asyncio.sleep", record_sleep)
    async with AsyncVulners("secret", base_url=BASE_URL, retries=2) as client:
        assert "secret" not in repr(client)
        page = await client.search.bulletins("test")
    assert page.total == 0
    assert route.call_count == 2
    assert delays == [1.5]


@pytest.mark.parametrize("status", [401, 403])
@respx.mock
async def test_async_authentication_errors(status: int) -> None:
    respx.post(LUCENE_URL).mock(return_value=httpx.Response(status, json={"message": "No access"}))
    async with AsyncVulners("key", base_url=BASE_URL, retries=1) as client:
        with pytest.raises(AuthenticationError):
            await client.search.bulletins("test")


@respx.mock
async def test_async_rate_limit_and_v3_body_errors() -> None:
    route = respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(
            429, headers={"Retry-After": "4"}, json={"message": "Slow down"}
        )
    )
    async with AsyncVulners("key", base_url=BASE_URL, retries=1) as client:
        with pytest.raises(RateLimitError) as rate_error:
            await client.search.bulletins("test")
    assert rate_error.value.retry_after == 4.0

    route.mock(
        return_value=httpx.Response(
            200, json={"result": "error", "data": {"error": "Invalid query"}}
        )
    )
    async with AsyncVulners("key", base_url=BASE_URL, retries=1) as client:
        with pytest.raises(VulnersAPIError, match="Invalid query"):
            await client.search.bulletins("bad")


@respx.mock
async def test_async_json_retry_exhaustion(monkeypatch: pytest.MonkeyPatch) -> None:
    route = respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(503, json={"message": "Unavailable"})
    )
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr("vulners._transport.asyncio.sleep", record_sleep)
    async with AsyncVulners("key", base_url=BASE_URL, retries=2) as client:
        with pytest.raises(ServerError):
            await client.search.bulletins("test")
    assert route.call_count == 2
    assert len(delays) == 1


async def test_async_transport_error_is_wrapped() -> None:
    async def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    raw = httpx.AsyncClient(base_url=BASE_URL, transport=httpx.MockTransport(fail))
    try:
        client = AsyncVulners("key", base_url=BASE_URL, retries=1, http_client=raw)
        with pytest.raises(VulnersError, match="Unable to reach"):
            await client.search.bulletins("test")
        await client.aclose()
    finally:
        await raw.aclose()


def test_retry_and_rate_headers_handle_invalid_values() -> None:
    request = httpx.Request("GET", BASE_URL)
    invalid_retry = httpx.Response(429, headers={"Retry-After": "later"}, request=request)
    now = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    dated_retry = httpx.Response(
        429,
        headers={"Retry-After": format_datetime(now + timedelta(seconds=45), usegmt=True)},
        request=request,
    )
    # Upstream advertises only X-Vulners-Ratelimit-Reqlimit (requests-per-minute);
    # the legacy X-Vulners-Ratelimit-Rate header is intentionally not honored.
    ignored_rate = httpx.Response(200, headers={"X-Vulners-Ratelimit-Rate": "120"}, request=request)
    valid_rate = httpx.Response(
        200, headers={"X-Vulners-Ratelimit-Reqlimit": "120"}, request=request
    )
    invalid_rate = httpx.Response(
        200, headers={"X-Vulners-Ratelimit-Reqlimit": "many"}, request=request
    )
    assert _parse_retry_after(invalid_retry) is None
    assert _parse_retry_after(dated_retry, now=now) == 45.0
    assert _rate_limit_from(ignored_rate) is None
    assert _rate_limit_from(valid_rate) == 120.0
    assert _rate_limit_from(invalid_rate) is None
    assert 0.25 <= _retry_delay(1) <= 0.35
    assert 1.0 <= _retry_delay(3) <= 1.1


@respx.mock
def test_rate_limit_false_bypasses_bucket(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_consume(bucket: TokenBucket) -> None:
        pytest.fail(f"rate limiter consumed a token from {bucket!r}")

    monkeypatch.setattr(TokenBucket, "consume", unexpected_consume)
    respx.post(LUCENE_URL).mock(return_value=httpx.Response(200, json=SUCCESS))
    with Vulners("key", base_url=BASE_URL, rate_limit=False) as client:
        assert client.search.bulletins("test").total == 0


@respx.mock
async def test_async_rate_limit_false_bypasses_bucket(monkeypatch: pytest.MonkeyPatch) -> None:
    async def unexpected_consume(bucket: TokenBucket) -> None:
        pytest.fail(f"rate limiter consumed a token from {bucket!r}")

    monkeypatch.setattr(TokenBucket, "aconsume", unexpected_consume)
    respx.post(LUCENE_URL).mock(return_value=httpx.Response(200, json=SUCCESS))
    async with AsyncVulners("key", base_url=BASE_URL, rate_limit=False) as client:
        assert (await client.search.bulletins("test")).total == 0


def test_sync_transport_rejects_and_never_replays_cookies() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        headers = {"Set-Cookie": "session=topsecret"} if len(requests) == 1 else {}
        return httpx.Response(200, json=SUCCESS, headers=headers, request=request)

    raw = httpx.Client(base_url=BASE_URL, transport=httpx.MockTransport(handler))
    raw.cookies.set("preexisting", "secret")
    try:
        client = Vulners("key", base_url=BASE_URL, http_client=raw)
        client.search.bulletins("first")
        client.search.bulletins("second")
        client.close()
    finally:
        raw.close()

    assert [request.headers.get("Cookie") for request in requests] == [None, None]
    assert not raw.cookies


async def test_async_transport_rejects_and_never_replays_cookies() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        headers = {"Set-Cookie": "session=topsecret"} if len(requests) == 1 else {}
        return httpx.Response(200, json=SUCCESS, headers=headers, request=request)

    raw = httpx.AsyncClient(base_url=BASE_URL, transport=httpx.MockTransport(handler))
    raw.cookies.set("preexisting", "secret")
    try:
        client = AsyncVulners("key", base_url=BASE_URL, http_client=raw)
        await client.search.bulletins("first")
        await client.search.bulletins("second")
        await client.aclose()
    finally:
        await raw.aclose()

    assert [request.headers.get("Cookie") for request in requests] == [None, None]
    assert not raw.cookies


@respx.mock
def test_stream_download_retries_and_maps_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"{BASE_URL}/api/v3/archive/getsploit/"
    route = respx.get(url).mock(
        side_effect=[httpx.Response(503), httpx.Response(200, content=b"archive")]
    )
    monkeypatch.setattr("vulners._transport.time.sleep", lambda _: None)
    with Vulners("key", base_url=BASE_URL, retries=2) as client:
        destination = client.archive.getsploit("CVE-1", tmp_path / "archive.zip")
    assert destination.read_bytes() == b"archive"
    assert route.call_count == 2

    respx.get(url).mock(return_value=httpx.Response(404, json={"message": "missing"}))
    with (
        Vulners("key", base_url=BASE_URL, retries=1) as client,
        pytest.raises(NotFoundError),
    ):
        client.archive.getsploit("missing", tmp_path / "missing.zip")


@respx.mock
async def test_async_stream_download_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = respx.get(f"{BASE_URL}/api/v3/archive/getsploit/").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, content=b"archive")]
    )

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr("vulners._transport.asyncio.sleep", no_sleep)
    async with AsyncVulners("key", base_url=BASE_URL, retries=2) as client:
        destination = await client.archive.getsploit("CVE-1", tmp_path / "archive.zip")
    assert destination.read_bytes() == b"archive"
    assert route.call_count == 2


# request_bytes / download failure paths: retry exhaustion, transport errors,
# body-level errors inside a 200, and Set-Cookie hygiene on non-JSON paths.
COLLECTION_V4_URL = f"{BASE_URL}/api/v4/archive/collection"
GETSPLOIT_URL = f"{BASE_URL}/api/v3/archive/getsploit/"


@respx.mock
def test_request_bytes_retry_exhaustion_raises_server_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = respx.get(COLLECTION_V4_URL).mock(
        return_value=httpx.Response(503, json={"message": "Unavailable"})
    )
    monkeypatch.setattr("vulners._transport.time.sleep", lambda _: None)
    with (
        Vulners("key", base_url=BASE_URL, retries=2) as client,
        pytest.raises(ServerError),
    ):
        client.archive.collection_v4("exploitdb")
    assert route.call_count == 2


@respx.mock
async def test_async_request_bytes_retry_exhaustion_raises_server_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = respx.get(COLLECTION_V4_URL).mock(
        return_value=httpx.Response(503, json={"message": "Unavailable"})
    )

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr("vulners._transport.asyncio.sleep", no_sleep)
    async with AsyncVulners("key", base_url=BASE_URL, retries=2) as client:
        with pytest.raises(ServerError):
            await client.archive.collection_v4("exploitdb")
    assert route.call_count == 2


@respx.mock
def test_request_bytes_transport_error_is_wrapped() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    transport = httpx.MockTransport(fail)
    raw = httpx.Client(base_url=BASE_URL, transport=transport)
    try:
        client = Vulners("key", base_url=BASE_URL, retries=1, http_client=raw)
        with pytest.raises(VulnersError, match="Unable to reach"):
            client.archive.collection_v4("exploitdb")
        client.close()
    finally:
        raw.close()


@respx.mock
async def test_async_request_bytes_transport_error_is_wrapped() -> None:
    async def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    raw = httpx.AsyncClient(base_url=BASE_URL, transport=httpx.MockTransport(fail))
    try:
        client = AsyncVulners("key", base_url=BASE_URL, retries=1, http_client=raw)
        with pytest.raises(VulnersError, match="Unable to reach"):
            await client.archive.collection_v4("exploitdb")
        await client.aclose()
    finally:
        await raw.aclose()


@respx.mock
def test_request_bytes_strips_set_cookie() -> None:
    # The bytes path now runs through the shared _run loop, which pops Set-Cookie.
    # Assert directly: a custom transport returns the live response, and after the
    # call the cookie header is gone from it.
    seen: list[httpx.Response] = []

    def handler(request: httpx.Request) -> httpx.Response:
        response = httpx.Response(
            200, content=b"[]", headers={"Set-Cookie": "session=secret"}, request=request
        )
        seen.append(response)
        return response

    transport = httpx.MockTransport(handler)
    raw = httpx.Client(base_url=BASE_URL, transport=transport)
    try:
        client = Vulners("key", base_url=BASE_URL, retries=1, http_client=raw)
        assert client.archive.collection_v4("exploitdb") == ()
        client.close()
    finally:
        raw.close()
    assert seen, "mock transport was never called"
    assert "set-cookie" not in seen[0].headers


@respx.mock
def test_download_transport_error_is_wrapped(tmp_path: Path) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    transport = httpx.MockTransport(fail)
    raw = httpx.Client(base_url=BASE_URL, transport=transport)
    try:
        client = Vulners("key", base_url=BASE_URL, retries=1, http_client=raw)
        with pytest.raises(VulnersError, match="Unable to reach"):
            client.archive.getsploit("CVE-1", tmp_path / "out.zip")
        client.close()
    finally:
        raw.close()


@respx.mock
async def test_async_download_transport_error_is_wrapped(tmp_path: Path) -> None:
    async def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    raw = httpx.AsyncClient(base_url=BASE_URL, transport=httpx.MockTransport(fail))
    try:
        client = AsyncVulners("key", base_url=BASE_URL, retries=1, http_client=raw)
        with pytest.raises(VulnersError, match="Unable to reach"):
            await client.archive.getsploit("CVE-1", tmp_path / "out.zip")
        await client.aclose()
    finally:
        await raw.aclose()


@respx.mock
def test_rate_limit_header_updates_bucket() -> None:
    # The X-Vulners-Ratelimit-Reqlimit header carries requests-per-minute.
    # TokenBucket.update converts it to a per-second rate, so 120 rpm -> 2.0 rps.
    respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(
            200, json=SUCCESS, headers={"X-Vulners-Ratelimit-Reqlimit": "120"}
        )
    )
    with Vulners("key", base_url=BASE_URL, rate_limit=True) as client:
        client.search.bulletins("test")
        bucket = client._transport._buckets["/api/v3/search/lucene/"]
    assert bucket._rate == 2.0
