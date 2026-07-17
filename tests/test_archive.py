from __future__ import annotations

import gzip
from io import BytesIO
from typing import TYPE_CHECKING
from zipfile import ZipFile

import httpx
import pytest
import respx

from vulners import AsyncVulners, Vulners
from vulners._serde import archive_loads

if TYPE_CHECKING:
    from pathlib import Path

BASE_URL = "https://vulners.test"


def test_archive_decoder_edge_cases() -> None:
    assert archive_loads(b"") == []
    assert archive_loads(b'{"id":"CVE-1"}') == [{"id": "CVE-1"}]
    assert archive_loads(b'{"id":"CVE-1"}\n{"id":"CVE-2"}') == [
        {"id": "CVE-1"},
        {"id": "CVE-2"},
    ]
    with pytest.raises(ValueError, match="Invalid ZIP"):
        archive_loads(b"PK-invalid")


def _zip_payload() -> bytes:
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("records.json", '[{"_source":{"id":"CVE-1","type":"cve"}}]')
    return output.getvalue()


def _routes() -> None:
    respx.get(f"{BASE_URL}/api/v3/archive/collection/").mock(
        return_value=httpx.Response(200, content=_zip_payload())
    )
    ndjson = b'{"id":"EDB-1","type":"exploitdb"}\n'
    respx.get(f"{BASE_URL}/api/v4/archive/collection").mock(
        return_value=httpx.Response(200, content=gzip.compress(ndjson))
    )
    respx.get(f"{BASE_URL}/api/v4/archive/collection-update").mock(
        return_value=httpx.Response(200, content=ndjson)
    )
    respx.get(f"{BASE_URL}/api/v3/archive/distributive/").mock(
        return_value=httpx.Response(200, content=b'[{"_source":{"id":"USN-1"}}]')
    )
    respx.get(f"{BASE_URL}/api/v3/archive/getsploit/").mock(
        return_value=httpx.Response(200, content=b"archive")
    )


@respx.mock
def test_sync_archive_decode_and_stream(tmp_path: Path) -> None:
    _routes()
    destination = tmp_path / "collection.gz"
    update_destination = tmp_path / "update.ndjson"
    exploit_destination = tmp_path / "getsploit.zip"
    with Vulners("key", base_url=BASE_URL) as client:
        assert client.archive.collection("cve")[0].id == "CVE-1"
        assert client.archive.collection_v4("exploitdb")[0].id == "EDB-1"
        assert client.archive.collection_update("exploitdb", "2026-01-01T00:00:00")[0].id == "EDB-1"
        assert client.archive.distributive("ubuntu", "22.04")[0].id == "USN-1"
        assert (
            client.archive.collection_v4("exploitdb", raw=True, destination=destination)
            == destination
        )
        assert (
            client.archive.collection_update(
                "exploitdb",
                "2026-01-01T00:00:00",
                raw=True,
                destination=update_destination,
            )
            == update_destination
        )
        assert client.archive.getsploit("CVE-1", exploit_destination) == exploit_destination
        with pytest.raises(ValueError, match="destination"):
            client.archive.collection_v4("cve", raw=True)
    assert destination.read_bytes().startswith(b"\x1f\x8b")
    assert exploit_destination.read_bytes() == b"archive"


@respx.mock
async def test_async_archive_decode_and_stream(tmp_path: Path) -> None:
    _routes()
    destination = tmp_path / "collection.zip"
    distributive_destination = tmp_path / "ubuntu.zip"
    exploit_destination = tmp_path / "getsploit.zip"
    async with AsyncVulners("key", base_url=BASE_URL) as client:
        assert (await client.archive.collection("cve"))[0].id == "CVE-1"
        assert (await client.archive.collection_v4("exploitdb"))[0].id == "EDB-1"
        assert (await client.archive.collection_update("exploitdb", "2026-01-01T00:00:00"))[
            0
        ].id == "EDB-1"
        assert (await client.archive.distributive("ubuntu", "22.04"))[0].id == "USN-1"
        assert (
            await client.archive.collection("cve", raw=True, destination=destination) == destination
        )
        assert (
            await client.archive.distributive(
                "ubuntu", "22.04", raw=True, destination=distributive_destination
            )
            == distributive_destination
        )
        assert await client.archive.getsploit("CVE-1", exploit_destination) == exploit_destination
    assert destination.read_bytes().startswith(b"PK")
