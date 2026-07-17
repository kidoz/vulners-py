from __future__ import annotations

import httpx
import pytest
import respx

from vulners import AsyncVulners, Vulners
from vulners.resources.misc import _mapping, _strings

BASE_URL = "https://vulners.test"


def _routes() -> None:
    respx.post(f"{BASE_URL}/api/v3/search/suggest/").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"suggest": ["cve"]}})
    )
    respx.post(f"{BASE_URL}/api/v3/search/autocomplete/").mock(
        return_value=httpx.Response(
            200, json={"result": "OK", "data": {"suggestions": [["type:cve", 1], "cvss"]}}
        )
    )
    respx.get(f"{BASE_URL}/api/v4/search/cpe").mock(
        return_value=httpx.Response(
            200, json={"result": {"best_match": "cpe:example", "cpe": ["cpe:other"]}}
        )
    )
    respx.get(f"{BASE_URL}/api/v3/burp/rules/").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"rules": ["rule"]}})
    )
    respx.get(f"{BASE_URL}/api/v4/stix/bundle").mock(
        return_value=httpx.Response(
            200, json={"result": {"type": "bundle", "id": "bundle--1", "objects": []}}
        )
    )


@respx.mock
def test_misc_and_stix_sync() -> None:
    _routes()
    with Vulners("key", base_url=BASE_URL) as client:
        assert client.misc.suggest("type", "cv") == ("cve",)
        assert client.misc.autocomplete("cv") == ("type:cve", "cvss")
        assert client.misc.cpe("curl", vendor="haxx", size=5).best_match == "cpe:example"
        assert client.misc.waf_rules() == ("rule",)
        assert client.stix.bundle("CVE-2024-0001", opencti_id="x").id == "bundle--1"


@respx.mock
async def test_misc_and_stix_async() -> None:
    _routes()
    async with AsyncVulners("key", base_url=BASE_URL) as client:
        assert await client.misc.suggest("type") == ("cve",)
        assert await client.misc.autocomplete("cv") == ("type:cve", "cvss")
        assert (await client.misc.cpe("curl")).cpe == ("cpe:other",)
        assert await client.misc.waf_rules() == ("rule",)
        assert (await client.stix.bundle("CVE-2024-0001")).type == "bundle"


@respx.mock
def test_misc_response_variants_and_validation() -> None:
    with pytest.raises(ValueError, match="missing"):
        _mapping(None, "result")
    with pytest.raises(ValueError, match="string-list"):
        _strings({})

    autocomplete = respx.post(f"{BASE_URL}/api/v3/search/autocomplete/").mock(
        return_value=httpx.Response(
            200, json={"result": "OK", "data": {"suggestions": {"invalid": True}}}
        )
    )
    waf = respx.get(f"{BASE_URL}/api/v3/burp/rules/").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": "raw-rule"})
    )
    with Vulners("key", base_url=BASE_URL) as client:
        with pytest.raises(ValueError, match="autocomplete"):
            client.misc.autocomplete("bad")
        assert client.misc.waf_rules() == ("raw-rule",)

    autocomplete.mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"suggestions": []}})
    )
    waf.mock(return_value=httpx.Response(200, json={"result": "OK", "data": ["one", 2]}))
    with Vulners("key", base_url=BASE_URL) as client:
        assert client.misc.autocomplete("empty") == ()
        assert client.misc.waf_rules() == ("one",)
