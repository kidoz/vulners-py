"""Optional read-only integration checks for a real Vulners API key."""

from __future__ import annotations

import os

import pytest

from vulners import AsyncVulners, Vulners
from vulners.types import AuditSoftware

pytestmark = pytest.mark.skipif(
    os.getenv("VULNERS_LIVE") != "1" or not os.getenv("VULNERS_API_KEY"),
    reason="set VULNERS_LIVE=1 and VULNERS_API_KEY to run read-only integration checks",
)


def test_live_read_only_sync_contracts() -> None:
    with Vulners(timeout=30, retries=2, rate_limit=False) as client:
        assert client.search.bulletins("id:CVE-2024-23622", limit=1).documents
        assert client.search.history("CVE-2024-23622")
        assert client.bulletins.by_id("CVE-2024-23622") is not None
        assert client.audit.cve("CVE-2024-23622").cve == "CVE-2024-23622"
        assert isinstance(
            client.audit.software((AuditSoftware(product="curl", vendor="haxx", version="8.0"),)),
            tuple,
        )
        assert (
            client.audit.linux("ubuntu", "22.04", ("curl 7.81.0-1ubuntu1.20 amd64",)).total_packages
            == 1
        )
        assert client.audit.library(("pkg:pypi/requests@2.20.0",)).total_packages == 1
        assert client.misc.autocomplete("type:cv")
        assert client.misc.cpe("curl").cpe
        assert client.misc.waf_rules().rules
        assert client.stix.bundle("CVE-2024-23622").type == "bundle"
        assert isinstance(client.subscriptions.list(), tuple)
        assert isinstance(client.subscriptions.email.list(), tuple)
        assert isinstance(client.webhooks.list(), tuple)


async def test_live_read_only_async_contracts() -> None:
    async with AsyncVulners(timeout=30, retries=2, rate_limit=False) as client:
        assert (await client.search.bulletins("id:CVE-2024-23622", limit=1)).documents
        assert await client.search.history("CVE-2024-23622")
        assert (await client.bulletins.by_id("CVE-2024-23622")) is not None
        assert (await client.audit.cve("CVE-2024-23622")).cve == "CVE-2024-23622"
        assert await client.misc.autocomplete("type:cv")
        assert (await client.misc.waf_rules()).rules
