from __future__ import annotations

import httpx
import pytest
import respx

from vulners import AuthenticationError, RateLimitError, ServerError, Vulners, VulnersAPIError

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
