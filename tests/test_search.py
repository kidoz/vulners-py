from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

import httpx
import pytest
import respx
from pydantic import ValidationError

from vulners import AsyncVulners, Vulners
from vulners.resources.search import _parse_history, _parse_search_page, _parse_web_vulns
from vulners.types import SearchDocument, SearchPage

if TYPE_CHECKING:
    from collections.abc import Callable

BASE_URL = "https://vulners.test"
LUCENE_URL = f"{BASE_URL}/api/v3/search/lucene/"
HISTORY_URL = f"{BASE_URL}/api/v3/search/history/"
WEB_VULNS_URL = f"{BASE_URL}/api/v4/search/web-vulns/"


def load_fixture(name: str) -> dict[str, object]:
    return cast(
        "dict[str, object]", json.loads((Path(__file__).parent / "fixtures" / name).read_text())
    )


@respx.mock
def test_sync_bulletins_sends_verified_wire_payload() -> None:
    route = respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("search_page.json"))
    )
    with Vulners("not-a-real-key", base_url=BASE_URL) as client:
        page = client.search.bulletins("wordpress 4.7", limit=5, offset=2, fields=("id", "title"))

    assert route.called
    assert route.calls[0].request.headers["X-Api-Key"] == "not-a-real-key"
    assert json.loads(route.calls[0].request.content) == {
        "query": "wordpress 4.7",
        "size": 5,
        "skip": 2,
        "fields": ["id", "title"],
    }
    assert isinstance(page, SearchPage)
    assert page.total == 1
    assert page.max_search_size == 100
    assert page.documents[0].bulletin_family == "NVD"


@respx.mock
async def test_async_bulletins_matches_sync_contract() -> None:
    respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("search_page.json"))
    )
    async with AsyncVulners("not-a-real-key", base_url=BASE_URL) as client:
        page = await client.search.bulletins("wordpress 4.7", limit=5)

    assert isinstance(page, SearchPage)
    assert page.documents[0].id == "CVE-2024-0001"


@respx.mock
def test_bulletins_iter_paginates_and_stops_at_total() -> None:
    first_page = {
        "result": "OK",
        "data": {
            "search": [{"_source": {"id": "CVE-2024-0001"}}],
            "total": 2,
            "maxSearchSize": 1,
        },
    }
    second_page = {
        "result": "OK",
        "data": {
            "search": [{"_source": {"id": "CVE-2024-0002"}}],
            "total": 2,
            "maxSearchSize": 1,
        },
    }
    route = respx.post(LUCENE_URL).mock(
        side_effect=[httpx.Response(200, json=first_page), httpx.Response(200, json=second_page)]
    )
    with Vulners("not-a-real-key", base_url=BASE_URL) as client:
        documents = list(client.search.bulletins_iter("test", limit=1))

    assert [document.id for document in documents] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert route.call_count == 2


@respx.mock
def test_bulletins_iter_stops_at_empty_page() -> None:
    empty_route = respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"search": [], "total": 2}})
    )
    with Vulners("key", base_url=BASE_URL) as client:
        assert list(client.search.bulletins_iter("empty", limit=1)) == []
    assert empty_route.call_count == 1


@respx.mock
def test_bulletins_iter_stops_at_search_window() -> None:
    window_route = respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "result": "OK",
                "data": {"search": [{"_source": {"id": "LAST"}}], "total": 10_002},
            },
        )
    )
    with Vulners("key", base_url=BASE_URL) as client:
        documents = list(client.search.bulletins_iter("large", limit=20, offset=9_999))

    assert [document.id for document in documents] == ["LAST"]
    assert window_route.call_count == 1
    assert json.loads(window_route.calls[0].request.content)["size"] == 1


@respx.mock
async def test_async_bulletins_iter_paginates() -> None:
    first_page = {"result": "OK", "data": {"search": [{"_source": {"id": "A"}}], "total": 2}}
    second_page = {"result": "OK", "data": {"search": [{"_source": {"id": "B"}}], "total": 2}}
    respx.post(LUCENE_URL).mock(
        side_effect=[httpx.Response(200, json=first_page), httpx.Response(200, json=second_page)]
    )
    async with AsyncVulners("not-a-real-key", base_url=BASE_URL) as client:
        documents = [document async for document in client.search.bulletins_iter("test", limit=1)]

    assert [document.id for document in documents] == ["A", "B"]


@respx.mock
def test_exploit_search_builds_legacy_compatible_query() -> None:
    route = respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("search_page.json"))
    )
    with Vulners("not-a-real-key", base_url=BASE_URL) as client:
        client.search.exploits("cve-2024-1234", lookup_fields=("title",))

    payload = json.loads(route.calls[0].request.content)
    assert payload["query"] == 'bulletinFamily:exploit AND (title:""cve-2024-1234"")'


def test_search_models_are_frozen() -> None:
    document = SearchDocument(id="CVE-2024-0001")
    with pytest.raises(ValidationError):
        document.id = "CVE-2024-0002"


@respx.mock
def test_history_returns_typed_entries() -> None:
    route = respx.get(HISTORY_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "result": "OK",
                "data": {
                    "result": [{"field": "cvss3", "published": "2024-01-01T00:00:00", "value": {}}]
                },
            },
        )
    )
    with Vulners("not-a-real-key", base_url=BASE_URL) as client:
        entries = client.search.history("CVE-2024-0001")

    assert entries[0].field == "cvss3"
    assert route.calls[0].request.url.params["id"] == "CVE-2024-0001"
    assert not route.calls[0].request.content


@respx.mock
async def test_async_history_matches_get_contract() -> None:
    route = respx.get(HISTORY_URL).mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"result": []}})
    )
    async with AsyncVulners("key", base_url=BASE_URL) as client:
        assert await client.search.history("CVE-2024-0001") == ()
    assert route.calls[0].request.url.params["id"] == "CVE-2024-0001"


@respx.mock
async def test_async_web_vulns_returns_matches_by_path() -> None:
    route = respx.post(WEB_VULNS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"result": {"wp-content": [{"id": "CVE-2024-0001", "type": "cve"}]}},
        )
    )
    async with AsyncVulners("not-a-real-key", base_url=BASE_URL) as client:
        result = await client.search.web_vulns(
            ("wp-content",), application="wordpress", config=("php",)
        )

    assert result.matches["wp-content"][0].id == "CVE-2024-0001"
    assert json.loads(route.calls[0].request.content) == {
        "paths": ["wp-content"],
        "application": "wordpress",
        "match": "partial",
        "catalog": "official",
        "config": ["php"],
    }


def test_search_input_validation() -> None:
    with Vulners("key", base_url=BASE_URL) as client:
        with pytest.raises(ValueError, match="limit"):
            client.search.bulletins("test", limit=0)
        with pytest.raises(ValueError, match="offset"):
            client.search.bulletins("test", offset=-1)
        with pytest.raises(ValueError, match="offset"):
            client.search.bulletins("test", offset=10_000)
        with pytest.raises(ValueError, match="paths"):
            client.search.web_vulns(())


@respx.mock
def test_sync_web_vulns_and_async_history_parsers() -> None:
    respx.post(WEB_VULNS_URL).mock(return_value=httpx.Response(200, json={"result": {"/": []}}))
    with Vulners("key", base_url=BASE_URL) as client:
        assert client.search.web_vulns(("/",)).matches["/"] == ()


@pytest.mark.parametrize(
    ("parser", "payload"),
    [
        (_parse_search_page, None),
        (_parse_search_page, {"search": "bad", "total": 1}),
        (_parse_history, {}),
        (_parse_web_vulns, {"result": []}),
    ],
)
def test_search_parsers_reject_malformed_envelopes(
    parser: Callable[[object], object], payload: object
) -> None:
    with pytest.raises(ValueError, match="Unexpected"):
        parser(payload)
