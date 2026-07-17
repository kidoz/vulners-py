from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import httpx
import pytest
import respx
from pydantic import ValidationError

from vulners import AsyncVulners, Vulners
from vulners.types import SearchDocument, SearchPage

BASE_URL = "https://vulners.test"
LUCENE_URL = f"{BASE_URL}/api/v3/search/lucene/"


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
