"""Static contract checks for the stable public client surface.

This module is checked by mypy and deliberately is not collected by pytest.
"""

from vulners import AsyncVulners, Vulners, __version__
from vulners.types import LuceneSubscriptionQuery, PollingSubscriptionDelivery


def check_sync_client(client: Vulners) -> None:
    """Exercise representative calls on every synchronous namespace."""
    query = LuceneSubscriptionQuery(query="type:cve")
    delivery = PollingSubscriptionDelivery()
    client.search.bulletins("type:cve")
    client.documents.get("CVE-2024-0001")
    client.audit.cve("CVE-2024-0001")
    client.archive.collection_update("cve", "2026-01-01T00:00:00")
    client.reports.vulns_summary()
    client.subscriptions.create("CVEs", query, delivery)
    client.webhooks.enable("subscription-id", True)
    client.stix.bundle("CVE-2024-0001")
    client.misc.cpe("curl")
    assert __version__ == "1.0.0"


async def check_async_client(client: AsyncVulners) -> None:
    """Exercise representative calls on every asynchronous namespace."""
    query = LuceneSubscriptionQuery(query="type:cve")
    delivery = PollingSubscriptionDelivery()
    await client.search.bulletins("type:cve")
    await client.documents.get("CVE-2024-0001")
    await client.audit.cve("CVE-2024-0001")
    await client.archive.collection_update("cve", "2026-01-01T00:00:00")
    await client.reports.vulns_summary()
    await client.subscriptions.create("CVEs", query, delivery)
    await client.webhooks.enable("subscription-id", False)
    await client.stix.bundle("CVE-2024-0001")
    await client.misc.cpe("curl")
