from __future__ import annotations

import json

import httpx
import pytest
import respx

from vulners import AsyncVulners, Vulners
from vulners.resources.bulletins import _parse_id_documents, _references_for
from vulners.types import BulletinWithReferences

BASE_URL = "https://vulners.test"
BULLETINS_URL = f"{BASE_URL}/api/v3/search/id/"
LUCENE_URL = f"{BASE_URL}/api/v3/search/lucene/"

BULLETIN_RESPONSE = {
    "result": "OK",
    "data": {
        "documents": {
            "CVE-2024-0001": {
                "id": "CVE-2024-0001",
                "title": "Example vulnerability",
                "type": "cve",
            }
        },
        "references": {
            "CVE-2024-0001": {"nvd": [{"id": "NVD:CVE-2024-0001", "title": "NVD reference"}]}
        },
    },
}


@respx.mock
def test_get_many_with_references_uses_verified_payload() -> None:
    route = respx.post(BULLETINS_URL).mock(return_value=httpx.Response(200, json=BULLETIN_RESPONSE))
    with Vulners("not-a-real-key", base_url=BASE_URL) as client:
        result = client.bulletins.get_many_with_references(("CVE-2024-0001",))

    assert isinstance(result[0], BulletinWithReferences)
    assert result[0].document is not None
    assert result[0].document.id == "CVE-2024-0001"
    assert result[0].references.sources["nvd"][0].id == "NVD:CVE-2024-0001"
    assert json.loads(route.calls[0].request.content) == {
        "id": ["CVE-2024-0001"],
        "fields": [
            "id",
            "title",
            "description",
            "type",
            "bulletinFamily",
            "cvss",
            "published",
            "modified",
            "lastseen",
            "href",
            "sourceHref",
            "sourceData",
            "cvelist",
            "vulnStatus",
            "assigned",
        ],
        "references": True,
    }


@respx.mock
async def test_async_bulletins_by_id_returns_typed_document() -> None:
    respx.post(BULLETINS_URL).mock(return_value=httpx.Response(200, json=BULLETIN_RESPONSE))
    async with AsyncVulners("not-a-real-key", base_url=BASE_URL) as client:
        document = await client.bulletins.by_id("CVE-2024-0001")

    assert document is not None
    assert document.title == "Example vulnerability"


@respx.mock
def test_bulletin_helpers_and_kb_queries() -> None:
    respx.post(BULLETINS_URL).mock(return_value=httpx.Response(200, json=BULLETIN_RESPONSE))
    lucene = respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"search": [], "total": 0}})
    )
    with Vulners("key", base_url=BASE_URL) as client:
        assert client.bulletins.by_ids(("CVE-2024-0001",))[0].id == "CVE-2024-0001"
        assert client.bulletins.by_id("CVE-2024-0001") is not None
        assert client.bulletins.references("CVE-2024-0001").sources["nvd"]
        assert client.bulletins.get_with_references("CVE-2024-0001").document is not None
        assert client.bulletins.kb_seeds("MISSING").superseeds == ()
        assert client.bulletins.kb_updates("KB123").total == 0

    assert json.loads(lucene.calls[0].request.content)["query"] == "type:msupdate AND kb:(KB123)"


@respx.mock
async def test_async_bulletin_helpers() -> None:
    respx.post(BULLETINS_URL).mock(return_value=httpx.Response(200, json=BULLETIN_RESPONSE))
    respx.post(LUCENE_URL).mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"search": [], "total": 0}})
    )
    async with AsyncVulners("key", base_url=BASE_URL) as client:
        assert (await client.bulletins.by_ids(("CVE-2024-0001",)))[0].id == "CVE-2024-0001"
        assert (await client.bulletins.references("CVE-2024-0001")).sources
        combined = await client.bulletins.get_with_references("CVE-2024-0001")
        assert combined.document is not None
        assert (await client.bulletins.kb_seeds("MISSING")).parentseeds == ()
        assert (await client.bulletins.kb_updates("KB123")).total == 0


@respx.mock
def test_kb_seeds_accepts_json_null_relationships() -> None:
    respx.post(BULLETINS_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "result": "OK",
                "data": {
                    "documents": {
                        "KB123": {
                            "id": "KB123",
                            "superseeds": None,
                            "parentseeds": None,
                        }
                    },
                    "references": {},
                },
            },
        )
    )
    with Vulners("key", base_url=BASE_URL) as client:
        seeds = client.bulletins.kb_seeds("KB123")
    assert seeds.superseeds == ()
    assert seeds.parentseeds == ()


def test_bulletin_input_and_response_validation() -> None:
    with Vulners("key", base_url=BASE_URL) as client, pytest.raises(ValueError, match="ids"):
        client.bulletins.by_ids(())

    with pytest.raises(ValueError, match="Unexpected response"):
        _parse_id_documents(None)
    with pytest.raises(ValueError, match="Unexpected document"):
        _parse_id_documents({"documents": []})
    with pytest.raises(ValueError, match="Unexpected references"):
        _references_for("CVE-1", {"CVE-1": []})
