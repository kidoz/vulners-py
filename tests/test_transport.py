from __future__ import annotations

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
)
from vulners._transport import _parse_retry_after, _rate_limit_from, _retry_delay, parse_response

if TYPE_CHECKING:
    from pathlib import Path

BASE_URL = "https://vulners.test"
LUCENE_URL = f"{BASE_URL}/api/v3/search/lucene/"
SUCCESS = {"result": "OK", "data": {"search": [], "total": 0}}


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
def test_http_error_types_and_retry_after() -> None:
    respx.post(LUCENE_URL).mock(return_value=httpx.Response(401, json={"message": "No access"}))
    with Vulners("not-a-real-key", base_url=BASE_URL) as client, pytest.raises(AuthenticationError):
        client.search.bulletins("test")

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
            httpx.Response(503, json={"message": "Unavailable"}),
            httpx.Response(200, json=SUCCESS),
        ]
    )
    monkeypatch.setattr("vulners._transport.time.sleep", lambda _: None)
    with Vulners("not-a-real-key", base_url=BASE_URL, retries=2) as client:
        page = client.search.bulletins("test")

    assert route.call_count == 2
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
            httpx.Response(503, json={"message": "retry"}),
            httpx.Response(200, json=SUCCESS),
        ]
    )

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr("vulners._transport.asyncio.sleep", no_sleep)
    async with AsyncVulners("secret", base_url=BASE_URL, retries=2) as client:
        assert "secret" not in repr(client)
        page = await client.search.bulletins("test")
    assert page.total == 0
    assert route.call_count == 2


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
    fallback_rate = httpx.Response(
        200, headers={"X-Vulners-Ratelimit-Rate": "120"}, request=request
    )
    invalid_rate = httpx.Response(
        200, headers={"X-Vulners-Ratelimit-Reqlimit": "many"}, request=request
    )
    assert _parse_retry_after(invalid_retry) is None
    assert _rate_limit_from(fallback_rate) == 120.0
    assert _rate_limit_from(invalid_rate) is None
    assert _retry_delay(1) >= 0.25


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
