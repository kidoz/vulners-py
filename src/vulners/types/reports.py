"""Typed Vulners report rows."""

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


class _ReportRow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow", populate_by_name=True)


class VulnsSummaryRow(_ReportRow):
    """Summary for one vulnerability across audited hosts."""

    vuln_id: str | None = Field(default=None, alias="vulnID")
    title: str | None = None
    severity: int | None = None
    count: int | None = None
    score: float | None = None


class VulnsListRow(_ReportRow):
    """Vulnerability occurrence on an audited host."""

    vuln_id: str | None = Field(default=None, alias="vulnID")
    title: str | None = None
    agent_ip: str | None = Field(default=None, alias="agentip")
    scan_id: str | None = Field(default=None, alias="scanid")


class IPSummaryRow(_ReportRow):
    """Vulnerability summary for one host."""

    agent_id: str | None = Field(default=None, alias="agentid")
    agent_ip: str | None = Field(default=None, alias="agentip")
    total: int | None = None
    score: float | None = None


class ScanListRow(_ReportRow):
    """One audit scan report row."""

    id: str | None = None
    ip_address: str | None = Field(default=None, alias="ipaddress")
    os: str | None = Field(default=None, alias="OS")
    os_version: str | None = Field(default=None, alias="OSVersion")


class HostVulnsRow(_ReportRow):
    """Vulnerability identifiers affecting one host."""

    agent_ip: str | None = Field(default=None, alias="agentip")
    os_name: str | None = Field(default=None, alias="osname")
    os_version: str | None = Field(default=None, alias="osversion")
    vulnerabilities: tuple[str, ...] = ()


_VULNS_SUMMARY_ADAPTER = TypeAdapter(tuple[VulnsSummaryRow, ...])
_VULNS_LIST_ADAPTER = TypeAdapter(tuple[VulnsListRow, ...])
_IP_SUMMARY_ADAPTER = TypeAdapter(tuple[IPSummaryRow, ...])
_SCAN_LIST_ADAPTER = TypeAdapter(tuple[ScanListRow, ...])
_HOST_VULNS_ADAPTER = TypeAdapter(tuple[HostVulnsRow, ...])
