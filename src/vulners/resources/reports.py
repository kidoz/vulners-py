"""Sync and async Vulners report resources."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Final, Literal

from ..types.reports import (
    _HOST_VULNS_ADAPTER,
    _IP_SUMMARY_ADAPTER,
    _SCAN_LIST_ADAPTER,
    _VULNS_LIST_ADAPTER,
    _VULNS_SUMMARY_ADAPTER,
    HostVulnsRow,
    IPSummaryRow,
    ScanListRow,
    VulnsListRow,
    VulnsSummaryRow,
)

if TYPE_CHECKING:
    from .._transport import AsyncTransport, ResponseData, SyncTransport

_PATH: Final = "/api/v3/reports/vulnsreport"
ReportType = Literal["vulnssummary", "vulnslist", "ipsummary", "scanlist", "hostvulns"]


def _payload(
    report_type: ReportType,
    limit: int,
    offset: int,
    filter: Mapping[str, object] | None,
    sort: str,
) -> dict[str, object]:
    if not 1 <= limit <= 10000:
        msg = "limit must be between 1 and 10000"
        raise ValueError(msg)
    if not 0 <= offset < 10000:
        msg = "offset must be between 0 and 9999"
        raise ValueError(msg)
    return {
        "reporttype": report_type,
        "size": limit,
        "skip": offset,
        "filter": dict(filter or {}),
        "sort": sort,
    }


def _report(data: ResponseData) -> object:
    if not isinstance(data, Mapping) or "report" not in data:
        msg = "Unexpected report response shape"
        raise ValueError(msg)
    return data["report"]


class ReportsResource:
    """Synchronous server-side scan reports."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def vulns_summary(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: Mapping[str, object] | None = None,
        sort: str = "",
    ) -> tuple[VulnsSummaryRow, ...]:
        """Return vulnerability summaries through ``POST /api/v3/reports/vulnsreport``."""
        data = self._transport.request(
            "POST", _PATH, json=_payload("vulnssummary", limit, offset, filter, sort)
        )
        return _VULNS_SUMMARY_ADAPTER.validate_python(_report(data))

    def vulns_list(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: Mapping[str, object] | None = None,
        sort: str = "",
    ) -> tuple[VulnsListRow, ...]:
        """Return vulnerability occurrences through the reports endpoint."""
        data = self._transport.request(
            "POST", _PATH, json=_payload("vulnslist", limit, offset, filter, sort)
        )
        return _VULNS_LIST_ADAPTER.validate_python(_report(data))

    def ip_summary(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: Mapping[str, object] | None = None,
        sort: str = "",
    ) -> tuple[IPSummaryRow, ...]:
        """Return per-host summaries through the reports endpoint."""
        data = self._transport.request(
            "POST", _PATH, json=_payload("ipsummary", limit, offset, filter, sort)
        )
        return _IP_SUMMARY_ADAPTER.validate_python(_report(data))

    def scan_list(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: Mapping[str, object] | None = None,
        sort: str = "",
    ) -> tuple[ScanListRow, ...]:
        """Return scan rows through the reports endpoint."""
        data = self._transport.request(
            "POST", _PATH, json=_payload("scanlist", limit, offset, filter, sort)
        )
        return _SCAN_LIST_ADAPTER.validate_python(_report(data))

    def host_vulns(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: Mapping[str, object] | None = None,
        sort: str = "",
    ) -> tuple[HostVulnsRow, ...]:
        """Return host vulnerabilities through the reports endpoint."""
        data = self._transport.request(
            "POST", _PATH, json=_payload("hostvulns", limit, offset, filter, sort)
        )
        return _HOST_VULNS_ADAPTER.validate_python(_report(data))


class AsyncReportsResource:
    """Asynchronous server-side scan reports."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def _request(
        self,
        report_type: ReportType,
        *,
        limit: int,
        offset: int,
        filter: Mapping[str, object] | None,
        sort: str,
    ) -> object:
        data = await self._transport.request(
            "POST", _PATH, json=_payload(report_type, limit, offset, filter, sort)
        )
        return _report(data)

    async def vulns_summary(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: Mapping[str, object] | None = None,
        sort: str = "",
    ) -> tuple[VulnsSummaryRow, ...]:
        """Return vulnerability summaries through the reports endpoint."""
        return _VULNS_SUMMARY_ADAPTER.validate_python(
            await self._request(
                "vulnssummary", limit=limit, offset=offset, filter=filter, sort=sort
            )
        )

    async def vulns_list(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: Mapping[str, object] | None = None,
        sort: str = "",
    ) -> tuple[VulnsListRow, ...]:
        """Return vulnerability occurrences through the reports endpoint."""
        return _VULNS_LIST_ADAPTER.validate_python(
            await self._request("vulnslist", limit=limit, offset=offset, filter=filter, sort=sort)
        )

    async def ip_summary(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: Mapping[str, object] | None = None,
        sort: str = "",
    ) -> tuple[IPSummaryRow, ...]:
        """Return per-host summaries through the reports endpoint."""
        return _IP_SUMMARY_ADAPTER.validate_python(
            await self._request("ipsummary", limit=limit, offset=offset, filter=filter, sort=sort)
        )

    async def scan_list(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: Mapping[str, object] | None = None,
        sort: str = "",
    ) -> tuple[ScanListRow, ...]:
        """Return scan rows through the reports endpoint."""
        return _SCAN_LIST_ADAPTER.validate_python(
            await self._request("scanlist", limit=limit, offset=offset, filter=filter, sort=sort)
        )

    async def host_vulns(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: Mapping[str, object] | None = None,
        sort: str = "",
    ) -> tuple[HostVulnsRow, ...]:
        """Return host vulnerabilities through the reports endpoint."""
        return _HOST_VULNS_ADAPTER.validate_python(
            await self._request("hostvulns", limit=limit, offset=offset, filter=filter, sort=sort)
        )
