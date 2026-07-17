from __future__ import annotations

import json

import httpx
import pytest
import respx

from vulners import AsyncVulners, Vulners

BASE_URL = "https://vulners.test"


def _report_response(request: httpx.Request) -> httpx.Response:
    report_type = json.loads(request.content)["reporttype"]
    rows = {
        "vulnssummary": [{"vulnID": "CVE-1", "count": 2}],
        "vulnslist": [{"vulnID": "CVE-1", "agentip": "127.0.0.1"}],
        "ipsummary": [{"agentid": "agent", "total": 1}],
        "scanlist": [{"id": "scan", "OS": "Ubuntu"}],
        "hostvulns": [{"agentip": "127.0.0.1", "vulnerabilities": ["CVE-1"]}],
    }[report_type]
    return httpx.Response(
        200,
        json={"result": "OK", "data": {"report": rows, "indexName": "x", "totalCount": 1}},
    )


@respx.mock
def test_all_sync_reports_and_validation() -> None:
    respx.post(f"{BASE_URL}/api/v3/reports/vulnsreport").mock(side_effect=_report_response)
    with Vulners("key", base_url=BASE_URL) as client:
        assert client.reports.vulns_summary()[0].count == 2
        assert client.reports.vulns_list()[0].agent_ip == "127.0.0.1"
        assert client.reports.ip_summary()[0].agent_id == "agent"
        assert client.reports.scan_list()[0].os == "Ubuntu"
        assert client.reports.host_vulns()[0].vulnerabilities == ("CVE-1",)
        with pytest.raises(ValueError, match="limit"):
            client.reports.vulns_summary(limit=0)
        with pytest.raises(ValueError, match="offset"):
            client.reports.vulns_summary(offset=10000)


@respx.mock
async def test_all_async_reports() -> None:
    respx.post(f"{BASE_URL}/api/v3/reports/vulnsreport").mock(side_effect=_report_response)
    async with AsyncVulners("key", base_url=BASE_URL) as client:
        assert (await client.reports.vulns_summary())[0].vuln_id == "CVE-1"
        assert (await client.reports.vulns_list())[0].vuln_id == "CVE-1"
        assert (await client.reports.ip_summary())[0].total == 1
        assert (await client.reports.scan_list())[0].id == "scan"
        assert (await client.reports.host_vulns())[0].agent_ip == "127.0.0.1"
