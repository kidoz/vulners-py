from __future__ import annotations

import json

import httpx
import respx

from vulners import AsyncVulners, Vulners
from vulners.types import SubscriptionDelivery, SubscriptionQuery

BASE_URL = "https://vulners.test"


def _routes() -> None:
    subscription = {
        "id": "sub-1",
        "name": "Critical",
        "query": {"type": "query", "query": "cvss:[9 TO *]"},
        "delivery": {"type": "pooling"},
    }
    respx.get(f"{BASE_URL}/api/v4/subscriptions/list/").mock(
        return_value=httpx.Response(200, json={"result": [subscription]})
    )
    respx.get(f"{BASE_URL}/api/v4/subscriptions/get/").mock(
        return_value=httpx.Response(200, json={"result": subscription})
    )
    for method, path in (
        ("POST", "/api/v4/subscriptions/create/"),
        ("PUT", "/api/v4/subscriptions/update/"),
        ("DELETE", "/api/v4/subscriptions/delete/"),
    ):
        respx.request(method, f"{BASE_URL}{path}").mock(
            return_value=httpx.Response(200, json={"result": {"id": "sub-1"}})
        )

    email = {"id": "email-1", "query": "type:cve", "email": "a@example.com"}
    respx.get(f"{BASE_URL}/api/v3/subscriptions/listEmailSubscriptions/").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"subscriptions": [email]}})
    )
    for path in (
        "/api/v3/subscriptions/addEmailSubscription/",
        "/api/v3/subscriptions/editEmailSubscription/",
    ):
        respx.post(f"{BASE_URL}{path}").mock(
            return_value=httpx.Response(200, json={"result": "OK", "data": email})
        )
    respx.post(f"{BASE_URL}/api/v3/subscriptions/removeEmailSubscription/").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {}})
    )

    polling = {"id": "poll-1", "query": "type:cve", "webhook": "https://example.test"}
    respx.get(f"{BASE_URL}/api/v3/subscriptions/listWebhookSubscriptions/").mock(
        return_value=httpx.Response(
            200, json={"result": "OK", "data": {"subscriptions": [polling]}}
        )
    )
    respx.post(f"{BASE_URL}/api/v3/subscriptions/addWebhookSubscription/").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": polling})
    )
    for path in (
        "/api/v3/subscriptions/editWebhookSubscription/",
        "/api/v3/subscriptions/removeWebhookSubscription/",
    ):
        respx.post(f"{BASE_URL}{path}").mock(
            return_value=httpx.Response(200, json={"result": "OK", "data": {}})
        )
    respx.get(f"{BASE_URL}/api/v3/subscriptions/webhook").mock(
        return_value=httpx.Response(
            200, json={"result": "OK", "data": {"result": [{"id": "CVE-1"}]}}
        )
    )


def _query() -> SubscriptionQuery:
    return SubscriptionQuery(type="query", query="cvss:[9 TO *]")


def _delivery() -> SubscriptionDelivery:
    return SubscriptionDelivery(type="pooling")


@respx.mock
def test_sync_subscription_namespaces() -> None:
    _routes()
    with Vulners("key", base_url=BASE_URL) as client:
        assert client.subscriptions.list()[0].id == "sub-1"
        assert client.subscriptions.get("sub-1").name == "Critical"
        assert client.subscriptions.create("Critical", _query(), _delivery()).id == "sub-1"
        assert client.subscriptions.update("sub-1", "Critical", _query(), _delivery()).id == "sub-1"
        assert client.subscriptions.delete("sub-1").id == "sub-1"
        assert client.subscriptions.email.list()[0].id == "email-1"
        assert client.subscriptions.email.add("type:cve", "a@example.com").id == "email-1"
        assert client.subscriptions.email.edit("email-1", active=False).id == "email-1"
        client.subscriptions.email.delete("email-1")
        assert client.webhooks.list()[0].id == "poll-1"
        assert client.webhooks.add("type:cve").id == "poll-1"
        client.webhooks.edit("poll-1", active=True)
        client.webhooks.enable("poll-1", False)
        assert client.webhooks.read("poll-1", newest_only=False).result[0]["id"] == "CVE-1"
        client.webhooks.delete("poll-1")

    add_call = respx.calls.last.request
    assert add_call is not None


@respx.mock
async def test_async_subscription_namespaces() -> None:
    _routes()
    async with AsyncVulners("key", base_url=BASE_URL) as client:
        assert (await client.subscriptions.list())[0].id == "sub-1"
        assert (await client.subscriptions.get("sub-1")).id == "sub-1"
        assert (await client.subscriptions.create("Critical", _query(), _delivery())).id == "sub-1"
        assert (
            await client.subscriptions.update("sub-1", "Critical", _query(), _delivery())
        ).id == "sub-1"
        assert (await client.subscriptions.delete("sub-1")).id == "sub-1"
        assert (await client.subscriptions.email.list())[0].id == "email-1"
        assert (
            await client.subscriptions.email.add("type:cve", "a@example.com", crontab="0 0 * * *")
        ).id == "email-1"
        assert (
            await client.subscriptions.email.edit("email-1", format="json", crontab="0 * * * *")
        ).id == "email-1"
        await client.subscriptions.email.delete("email-1")
        assert (await client.webhooks.list())[0].id == "poll-1"
        assert (await client.webhooks.add("type:cve")).id == "poll-1"
        await client.webhooks.edit("poll-1", active=True)
        await client.webhooks.enable("poll-1", False)
        assert (await client.webhooks.read("poll-1")).result[0]["id"] == "CVE-1"
        await client.webhooks.delete("poll-1")

    bodies = [json.loads(call.request.content) for call in respx.calls if call.request.content]
    assert any(body.get("apiKey") == "key" for body in bodies)
