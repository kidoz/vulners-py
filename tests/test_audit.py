from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx
import pytest
import respx

from vulners import AsyncVulners, Vulners
from vulners.types import AuditSoftware, WindowsSoftware

if TYPE_CHECKING:
    from pathlib import Path

BASE_URL = "https://vulners.test"


@respx.mock
def test_software_audit_serializes_typed_input() -> None:
    route = respx.post(f"{BASE_URL}/api/v4/audit/software/").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": [
                    {
                        "input": {"product": "curl", "version": "8.0"},
                        "matched_criteria": "cpe:2.3:a:haxx:curl:8.0:*:*:*:*:*:*:*",
                        "vulnerabilities": [{"id": "CVE-2024-0001", "title": "Example"}],
                    }
                ]
            },
        )
    )
    with Vulners("not-a-real-key", base_url=BASE_URL) as client:
        result = client.audit.software((AuditSoftware(product="curl", version="8.0"),))

    assert result[0].vulnerabilities[0].id == "CVE-2024-0001"
    assert json.loads(route.calls[0].request.content) == {
        "software": [{"product": "curl", "version": "8.0"}],
        "match": "partial",
        "catalog": "official",
    }


@respx.mock
async def test_async_cve_audit_returns_typed_result() -> None:
    respx.post(f"{BASE_URL}/api/v4/audit/cve").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": {
                    "cve": "CVE-2024-0001",
                    "affectedCpe": [
                        {
                            "id": "ADV-1",
                            "type": "cve",
                            "cpeConfigurations": {"vulnersCpeConfiguration": []},
                        }
                    ],
                    "affectedPackages": [],
                }
            },
        )
    )
    async with AsyncVulners("not-a-real-key", base_url=BASE_URL) as client:
        result = await client.audit.cve("CVE-2024-0001")

    assert result.cve == "CVE-2024-0001"
    assert len(result.affected_cpe) == 1


@respx.mock
def test_host_and_cve_batch_audits() -> None:
    host_route = respx.post(f"{BASE_URL}/api/v4/audit/host/").mock(
        return_value=httpx.Response(200, json={"result": []})
    )
    respx.post(f"{BASE_URL}/api/v4/audit/cves").mock(
        return_value=httpx.Response(
            200,
            json={"result": [{"cve": "CVE-2024-0001", "affectedCpe": [], "affectedPackages": []}]},
        )
    )
    with Vulners("key", base_url=BASE_URL) as client:
        assert client.audit.host(("curl 8.0",), application="wordpress 6.0") == ()
        assert client.audit.cves(("CVE-2024-0001",))[0].cve == "CVE-2024-0001"
        with pytest.raises(ValueError, match="host requires"):
            client.audit.host(("curl 8.0",))
        with pytest.raises(ValueError, match="ids"):
            client.audit.cves(())
        with pytest.raises(ValueError, match="software"):
            client.audit.software(())

    payload = json.loads(host_route.calls[0].request.content)
    assert payload["application"] == "wordpress 6.0"


@respx.mock
async def test_async_audit_methods() -> None:
    respx.post(f"{BASE_URL}/api/v4/audit/software/").mock(
        return_value=httpx.Response(200, json={"result": []})
    )
    respx.post(f"{BASE_URL}/api/v4/audit/host/").mock(
        return_value=httpx.Response(200, json={"result": []})
    )
    respx.post(f"{BASE_URL}/api/v4/audit/cves").mock(
        return_value=httpx.Response(200, json={"result": [{"cve": "CVE-2024-0001"}]})
    )
    async with AsyncVulners("key", base_url=BASE_URL) as client:
        assert await client.audit.software(("curl 8.0",)) == ()
        assert await client.audit.host(("curl 8.0",), hardware="server") == ()
        assert (await client.audit.cves(("CVE-2024-0001",)))[0].cve == "CVE-2024-0001"
        with pytest.raises(ValueError, match="host requires"):
            await client.audit.host(("curl 8.0",))
        with pytest.raises(ValueError, match="ids"):
            await client.audit.cves(())


@respx.mock
def test_smart_audit_contract_and_validation() -> None:
    route = respx.post(f"{BASE_URL}/api/v4/audit/smart").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": [
                    {
                        "input": "OpenSSL 1.0.1",
                        "cpe": "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*",
                        "purls": [],
                        "confidence": 0.9,
                        "vulnerabilities": [{"id": "CVE-2024-0001"}],
                    }
                ]
            },
        )
    )
    with Vulners("key", base_url=BASE_URL) as client:
        result = client.audit.smart(("OpenSSL 1.0.1",))
        with pytest.raises(ValueError, match="between 1 and 500"):
            client.audit.smart(())
        with pytest.raises(ValueError, match="between 1 and 512"):
            client.audit.smart(("",))

    assert result[0].confidence == 0.9
    assert result[0].vulnerabilities[0].id == "CVE-2024-0001"
    assert json.loads(route.calls[0].request.content) == {
        "software": ["OpenSSL 1.0.1"],
        "catalog": "official",
    }


@respx.mock
async def test_async_smart_audit() -> None:
    respx.post(f"{BASE_URL}/api/v4/audit/smart").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": [
                    {
                        "input": "nginx 1.14",
                        "cpe": "",
                        "purls": [],
                        "confidence": 0.0,
                        "vulnerabilities": [],
                    }
                ]
            },
        )
    )
    async with AsyncVulners("key", base_url=BASE_URL) as client:
        result = await client.audit.smart(("nginx 1.14",), catalog="extended")
    assert result[0].input == "nginx 1.14"


@respx.mock
def test_package_and_legacy_audit_contracts() -> None:
    classic = respx.post(f"{BASE_URL}/api/v3/audit/audit/").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": "OK",
                "data": {"id": "audit-id", "cvelist": ["CVE-2024-0001"]},
            },
        )
    )
    linux = respx.post(f"{BASE_URL}/api/v4/audit/linux").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": {
                    "issues": [
                        {
                            "package": "openssl",
                            "version": "1.0.1",
                            "fixedVersion": "1.0.2",
                            "applicableAdvisories": [{"id": "CVE-2024-0001"}],
                        }
                    ],
                    "errors": {},
                    "totalPackages": 1,
                }
            },
        )
    )
    library = respx.post(f"{BASE_URL}/api/v4/audit/library").mock(
        return_value=httpx.Response(
            200, json={"result": {"issues": [], "errors": {}, "totalPackages": 1}}
        )
    )
    kb = respx.post(f"{BASE_URL}/api/v3/audit/kb/").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": "OK",
                "data": {"cvelist": [], "kbLatest": "KB1", "kbMissed": ["KB2"]},
            },
        )
    )
    winaudit = respx.post(f"{BASE_URL}/api/v3/audit/winaudit/").mock(
        return_value=httpx.Response(200, json={"result": "OK", "data": {"id": "windows-audit"}})
    )

    with Vulners("key", base_url=BASE_URL) as client:
        classic_result = client.audit.os_packages("ubuntu", "22.04", ("openssl 1.0.1",))
        linux_result = client.audit.linux(
            "ubuntu",
            "22.04",
            ("openssl 1.0.1 amd64",),
            os_arch="amd64",
            include_candidates=True,
        )
        library_result = client.audit.library(("pkg:pypi/requests@2.0.0",))
        kb_result = client.audit.kb("Windows 11", ("KB1",))
        windows_result = client.audit.winaudit(
            "Windows",
            "11",
            ("KB1",),
            (WindowsSoftware(software="Example", version="1.0"),),
            platform="x64",
        )
        with pytest.raises(ValueError, match="packages must not be empty"):
            client.audit.os_packages("ubuntu", "22.04", ())
        with pytest.raises(ValueError, match="between 1 and 2500"):
            client.audit.library(())

    assert classic_result.id == "audit-id"
    assert linux_result.issues[0].applicable_advisories[0].id == "CVE-2024-0001"
    assert library_result.total_packages == 1
    assert kb_result.kb_missed == ("KB2",)
    assert windows_result.id == "windows-audit"
    assert json.loads(classic.calls[0].request.content)["package"] == ["openssl 1.0.1"]
    assert json.loads(linux.calls[0].request.content)["osArch"] == "amd64"
    assert json.loads(library.calls[0].request.content)["packages"] == ["pkg:pypi/requests@2.0.0"]
    assert json.loads(kb.calls[0].request.content)["kbList"] == ["KB1"]
    assert json.loads(winaudit.calls[0].request.content) == {
        "os": "Windows",
        "os_version": "11",
        "kb_list": ["KB1"],
        "software": [{"software": "Example", "version": "1.0"}],
        "platform": "x64",
        "apiKey": "key",
    }


@respx.mock
async def test_async_package_and_legacy_audit_contracts() -> None:
    for path, response in (
        ("/api/v3/audit/audit/", {"result": "OK", "data": {"id": "classic"}}),
        (
            "/api/v4/audit/linux",
            {"result": {"issues": [], "errors": {}, "totalPackages": 1}},
        ),
        (
            "/api/v4/audit/library",
            {"result": {"issues": [], "errors": {}, "totalPackages": 1}},
        ),
        ("/api/v3/audit/kb/", {"result": "OK", "data": {"kbLatest": None}}),
        ("/api/v3/audit/winaudit/", {"result": "OK", "data": {"id": "windows"}}),
    ):
        respx.post(f"{BASE_URL}{path}").mock(return_value=httpx.Response(200, json=response))

    async with AsyncVulners("key", base_url=BASE_URL) as client:
        assert (await client.audit.os_packages("debian", "12", ("curl 8.0",))).id == "classic"
        assert (await client.audit.linux("debian", "12", ("curl 8.0",))).total_packages == 1
        assert (await client.audit.library(("pkg:pypi/requests@2.0.0",))).total_packages == 1
        assert (await client.audit.kb("Windows 11", ())).kb_latest is None
        assert (
            await client.audit.winaudit(
                "Windows", "11", (), (WindowsSoftware(software="App", version="1"),)
            )
        ).id == "windows"
        with pytest.raises(ValueError, match="packages must not be empty"):
            await client.audit.os_packages("debian", "12", ())


@respx.mock
def test_sbom_multipart_upload(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
    route = respx.post(f"{BASE_URL}/api/v4/audit/sbom").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": {
                    "data": [
                        {
                            "package": "requests",
                            "version": "2.0",
                            "applicableAdvisories": [{"id": "CVE-1"}],
                        }
                    ],
                    "summaryId": "summary-1",
                    "totalPackages": 1,
                }
            },
        )
    )
    with Vulners("key", base_url=BASE_URL) as client:
        result = client.audit.sbom(sbom)
    assert result.data[0].applicable_advisories[0].id == "CVE-1"
    assert b'filename="sbom.json"' in route.calls[0].request.content


@respx.mock
async def test_async_sbom_multipart_upload(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"spdxVersion":"SPDX-2.3","packages":[]}', encoding="utf-8")
    respx.post(f"{BASE_URL}/api/v4/audit/sbom").mock(
        return_value=httpx.Response(
            200, json={"result": {"data": [], "summaryId": None, "totalPackages": 0}}
        )
    )
    async with AsyncVulners("key", base_url=BASE_URL) as client:
        result = await client.audit.sbom(sbom)
    assert result.total_packages == 0
