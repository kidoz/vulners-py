"""Typed sync and async resources for Vulners v4 audit endpoints."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Final

from ..types.audit import (
    _AUDIT_MATCHES_ADAPTER,
    _CVE_RESULT_ADAPTER,
    _CVE_RESULTS_ADAPTER,
    _KB_AUDIT_RESULT_ADAPTER,
    _LEGACY_AUDIT_RESULT_ADAPTER,
    _PACKAGE_AUDIT_RESULT_ADAPTER,
    _SBOM_AUDIT_RESULT_ADAPTER,
    _SMART_AUDIT_RESULTS_ADAPTER,
    AuditCatalog,
    AuditMatch,
    AuditMatchMode,
    AuditSoftware,
    CVEAuditResult,
    KBAuditResult,
    LegacyAuditResult,
    PackageAuditResult,
    SBOMAuditResult,
    SmartAuditResult,
    WindowsSoftware,
)

if TYPE_CHECKING:
    from pathlib import Path

    from .._transport import AsyncTransport, ResponseData, SyncTransport

_SOFTWARE_PATH: Final = "/api/v4/audit/software/"
_HOST_PATH: Final = "/api/v4/audit/host/"
_CVE_PATH: Final = "/api/v4/audit/cve"
_CVES_PATH: Final = "/api/v4/audit/cves"
_SMART_PATH: Final = "/api/v4/audit/smart"
_CLASSIC_PATH: Final = "/api/v3/audit/audit/"
_LINUX_PATH: Final = "/api/v4/audit/linux"
_LIBRARY_PATH: Final = "/api/v4/audit/library"
_KB_PATH: Final = "/api/v3/audit/kb/"
_WINAUDIT_PATH: Final = "/api/v3/audit/winaudit/"
_SBOM_PATH: Final = "/api/v4/audit/sbom"


def _software_value(value: AuditSoftware | str) -> object:
    if isinstance(value, str):
        return value
    return value.model_dump(mode="json", exclude_none=True)


def _result(data: ResponseData) -> object:
    if not isinstance(data, Mapping) or "result" not in data:
        msg = "Unexpected v4 audit response shape"
        raise ValueError(msg)
    return data["result"]


def _audit_payload(
    software: Sequence[AuditSoftware | str],
    *,
    match: AuditMatchMode,
    fields: Sequence[str] | None,
    config: Sequence[str] | None,
    catalog: AuditCatalog,
    application: AuditSoftware | str | None = None,
    operating_system: AuditSoftware | str | None = None,
    hardware: AuditSoftware | str | None = None,
) -> dict[str, object]:
    if not software:
        msg = "software must not be empty"
        raise ValueError(msg)
    payload: dict[str, object] = {
        "software": [_software_value(item) for item in software],
        "match": match,
        "catalog": catalog,
    }
    for key, value in (
        ("application", application),
        ("operating_system", operating_system),
        ("hardware", hardware),
    ):
        if value is not None:
            payload[key] = _software_value(value)
    if fields is not None:
        payload["fields"] = list(fields)
    if config is not None:
        payload["config"] = list(config)
    return payload


def _smart_payload(software: Sequence[str], catalog: AuditCatalog) -> dict[str, object]:
    if not 1 <= len(software) <= 500:
        msg = "software must contain between 1 and 500 items"
        raise ValueError(msg)
    if any(not item or len(item) > 512 for item in software):
        msg = "each software string must contain between 1 and 512 characters"
        raise ValueError(msg)
    return {"software": list(software), "catalog": catalog}


def _package_options(
    packages: Sequence[str],
    include_unofficial: bool,
    include_candidates: bool,
    include_any_version: bool,
    cvelist_metrics: bool,
) -> dict[str, object]:
    if not 1 <= len(packages) <= 2500:
        msg = "packages must contain between 1 and 2500 items"
        raise ValueError(msg)
    return {
        "packages": list(packages),
        "includeUnofficial": include_unofficial,
        "includeCandidates": include_candidates,
        "includeAnyVersion": include_any_version,
        "cvelistMetrics": cvelist_metrics,
    }


class AuditResource:
    """Synchronous Vulners audit operations."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def software(
        self,
        software: Sequence[AuditSoftware | str],
        *,
        match: AuditMatchMode = "partial",
        fields: Sequence[str] | None = None,
        config: Sequence[str] | None = None,
        catalog: AuditCatalog = "official",
    ) -> tuple[AuditMatch, ...]:
        """Audit software through ``POST /api/v4/audit/software/``.

        Args:
            software: Software inventory to audit.
            match: Matching strictness.
            fields: Response fields to request.
            config: Optional matching configuration.
            catalog: Vulnerability catalog to search.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        payload = _audit_payload(
            software, match=match, fields=fields, config=config, catalog=catalog
        )
        return _AUDIT_MATCHES_ADAPTER.validate_python(
            _result(self._transport.request("POST", _SOFTWARE_PATH, json=payload))
        )

    def host(
        self,
        software: Sequence[AuditSoftware | str],
        *,
        application: AuditSoftware | str | None = None,
        operating_system: AuditSoftware | str | None = None,
        hardware: AuditSoftware | str | None = None,
        match: AuditMatchMode = "partial",
        fields: Sequence[str] | None = None,
        config: Sequence[str] | None = None,
        catalog: AuditCatalog = "official",
    ) -> tuple[AuditMatch, ...]:
        """Audit a host through ``POST /api/v4/audit/host/``.

        Args:
            software: Software inventory to audit.
            application: Optional application identity or metadata.
            operating_system: Optional operating-system identity.
            hardware: Optional hardware identity.
            match: Matching strictness.
            fields: Response fields to request.
            config: Optional matching configuration.
            catalog: Vulnerability catalog to search.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        if application is None and operating_system is None and hardware is None:
            msg = "host requires application, operating_system, or hardware"
            raise ValueError(msg)
        payload = _audit_payload(
            software,
            match=match,
            fields=fields,
            config=config,
            catalog=catalog,
            application=application,
            operating_system=operating_system,
            hardware=hardware,
        )
        return _AUDIT_MATCHES_ADAPTER.validate_python(
            _result(self._transport.request("POST", _HOST_PATH, json=payload))
        )

    def cve(self, id: str) -> CVEAuditResult:
        """Audit one CVE through ``POST /api/v4/audit/cve``.

        Args:
            id: Vulners bulletin or subscription identifier.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = self._transport.request("POST", _CVE_PATH, json={"cve": id})
        return _CVE_RESULT_ADAPTER.validate_python(_result(data))

    def cves(self, ids: Sequence[str]) -> tuple[CVEAuditResult, ...]:
        """Audit CVEs through ``POST /api/v4/audit/cves``.

        Args:
            ids: Identifiers to process.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        if not ids:
            msg = "ids must not be empty"
            raise ValueError(msg)
        data = self._transport.request("POST", _CVES_PATH, json={"cve": list(ids)})
        return _CVE_RESULTS_ADAPTER.validate_python(_result(data))

    def smart(
        self, software: Sequence[str], *, catalog: AuditCatalog = "official"
    ) -> tuple[SmartAuditResult, ...]:
        """Audit raw software strings through ``POST /api/v4/audit/smart``.

        This preview endpoint is billed per submitted string.

        Args:
            software: Software inventory to audit.
            catalog: Vulnerability catalog to search.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = self._transport.request("POST", _SMART_PATH, json=_smart_payload(software, catalog))
        return _SMART_AUDIT_RESULTS_ADAPTER.validate_python(_result(data))

    def os_packages(self, os: str, version: str, packages: Sequence[str]) -> LegacyAuditResult:
        """Audit OS packages through POST /api/v3/audit/audit/.

        Args:
            os: Operating-system name.
            version: Operating-system version.
            packages: Package inventory to audit.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        if not packages:
            msg = "packages must not be empty"
            raise ValueError(msg)
        data = self._transport.request(
            "POST",
            _CLASSIC_PATH,
            json={"os": os, "version": version, "package": list(packages)},
        )
        return _LEGACY_AUDIT_RESULT_ADAPTER.validate_python(data)

    def linux(
        self,
        os_name: str,
        os_version: str,
        packages: Sequence[str],
        *,
        os_arch: str | None = None,
        include_unofficial: bool = False,
        include_candidates: bool = False,
        include_any_version: bool = False,
        cvelist_metrics: bool = False,
    ) -> PackageAuditResult:
        """Audit Linux packages through ``POST /api/v4/audit/linux``.

        Args:
            os_name: Linux distribution name.
            os_version: Operating-system version.
            packages: Package inventory to audit.
            os_arch: Optional operating-system architecture.
            include_unofficial: Whether unofficial advisories are included.
            include_candidates: Whether candidate matches are included.
            include_any_version: Whether versionless matches are included.
            cvelist_metrics: Whether CVE-list metrics are included.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        payload = _package_options(
            packages,
            include_unofficial,
            include_candidates,
            include_any_version,
            cvelist_metrics,
        )
        payload.update({"osName": os_name, "osVersion": os_version})
        if os_arch is not None:
            payload["osArch"] = os_arch
        data = self._transport.request("POST", _LINUX_PATH, json=payload)
        return _PACKAGE_AUDIT_RESULT_ADAPTER.validate_python(_result(data))

    def library(
        self,
        packages: Sequence[str],
        *,
        include_unofficial: bool = False,
        include_candidates: bool = False,
        include_any_version: bool = False,
        cvelist_metrics: bool = False,
    ) -> PackageAuditResult:
        """Audit package URLs through ``POST /api/v4/audit/library``.

        Args:
            packages: Package inventory to audit.
            include_unofficial: Whether unofficial advisories are included.
            include_candidates: Whether candidate matches are included.
            include_any_version: Whether versionless matches are included.
            cvelist_metrics: Whether CVE-list metrics are included.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        payload = _package_options(
            packages,
            include_unofficial,
            include_candidates,
            include_any_version,
            cvelist_metrics,
        )
        data = self._transport.request("POST", _LIBRARY_PATH, json=payload)
        return _PACKAGE_AUDIT_RESULT_ADAPTER.validate_python(_result(data))

    def sbom(self, file: Path) -> SBOMAuditResult:
        """Audit an SPDX or CycloneDX JSON file through ``POST /api/v4/audit/sbom``.

        Args:
            file: SPDX or CycloneDX JSON file.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = self._transport.request(
            "POST",
            _SBOM_PATH,
            files={"file": (file.name, file.read_bytes(), "application/json")},
        )
        return _SBOM_AUDIT_RESULT_ADAPTER.validate_python(_result(data))

    def kb(self, os: str, kb_list: Sequence[str]) -> KBAuditResult:
        """Audit installed Windows KBs through POST /api/v3/audit/kb/.

        Args:
            os: Operating-system name.
            kb_list: Installed Windows KB identifiers.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = self._transport.request("POST", _KB_PATH, json={"os": os, "kbList": list(kb_list)})
        return _KB_AUDIT_RESULT_ADAPTER.validate_python(data)

    def winaudit(
        self,
        os: str,
        os_version: str,
        kb_list: Sequence[str],
        software: Sequence[WindowsSoftware],
        *,
        platform: str | None = None,
    ) -> LegacyAuditResult:
        """Audit a Windows host through POST /api/v3/audit/winaudit/.

        Args:
            os: Operating-system name.
            os_version: Operating-system version.
            kb_list: Installed Windows KB identifiers.
            software: Software inventory to audit.
            platform: Optional Windows platform architecture.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        payload: dict[str, object] = {
            "os": os,
            "os_version": os_version,
            "kb_list": list(kb_list),
            "software": [item.model_dump(mode="json") for item in software],
        }
        if platform is not None:
            payload["platform"] = platform
        data = self._transport.request("POST", _WINAUDIT_PATH, json=payload, add_api_key=True)
        return _LEGACY_AUDIT_RESULT_ADAPTER.validate_python(data)


class AsyncAuditResource:
    """Asynchronous Vulners audit operations."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def software(
        self,
        software: Sequence[AuditSoftware | str],
        *,
        match: AuditMatchMode = "partial",
        fields: Sequence[str] | None = None,
        config: Sequence[str] | None = None,
        catalog: AuditCatalog = "official",
    ) -> tuple[AuditMatch, ...]:
        """Audit software through ``POST /api/v4/audit/software/``.

        Args:
            software: Software inventory to audit.
            match: Matching strictness.
            fields: Response fields to request.
            config: Optional matching configuration.
            catalog: Vulnerability catalog to search.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        payload = _audit_payload(
            software, match=match, fields=fields, config=config, catalog=catalog
        )
        data = await self._transport.request("POST", _SOFTWARE_PATH, json=payload)
        return _AUDIT_MATCHES_ADAPTER.validate_python(_result(data))

    async def host(
        self,
        software: Sequence[AuditSoftware | str],
        *,
        application: AuditSoftware | str | None = None,
        operating_system: AuditSoftware | str | None = None,
        hardware: AuditSoftware | str | None = None,
        match: AuditMatchMode = "partial",
        fields: Sequence[str] | None = None,
        config: Sequence[str] | None = None,
        catalog: AuditCatalog = "official",
    ) -> tuple[AuditMatch, ...]:
        """Audit a host through ``POST /api/v4/audit/host/``.

        Args:
            software: Software inventory to audit.
            application: Optional application identity or metadata.
            operating_system: Optional operating-system identity.
            hardware: Optional hardware identity.
            match: Matching strictness.
            fields: Response fields to request.
            config: Optional matching configuration.
            catalog: Vulnerability catalog to search.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        if application is None and operating_system is None and hardware is None:
            msg = "host requires application, operating_system, or hardware"
            raise ValueError(msg)
        payload = _audit_payload(
            software,
            match=match,
            fields=fields,
            config=config,
            catalog=catalog,
            application=application,
            operating_system=operating_system,
            hardware=hardware,
        )
        data = await self._transport.request("POST", _HOST_PATH, json=payload)
        return _AUDIT_MATCHES_ADAPTER.validate_python(_result(data))

    async def cve(self, id: str) -> CVEAuditResult:
        """Audit one CVE through ``POST /api/v4/audit/cve``.

        Args:
            id: Vulners bulletin or subscription identifier.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = await self._transport.request("POST", _CVE_PATH, json={"cve": id})
        return _CVE_RESULT_ADAPTER.validate_python(_result(data))

    async def cves(self, ids: Sequence[str]) -> tuple[CVEAuditResult, ...]:
        """Audit CVEs through ``POST /api/v4/audit/cves``.

        Args:
            ids: Identifiers to process.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        if not ids:
            msg = "ids must not be empty"
            raise ValueError(msg)
        data = await self._transport.request("POST", _CVES_PATH, json={"cve": list(ids)})
        return _CVE_RESULTS_ADAPTER.validate_python(_result(data))

    async def smart(
        self, software: Sequence[str], *, catalog: AuditCatalog = "official"
    ) -> tuple[SmartAuditResult, ...]:
        """Audit raw software strings through ``POST /api/v4/audit/smart``.

        This preview endpoint is billed per submitted string.

        Args:
            software: Software inventory to audit.
            catalog: Vulnerability catalog to search.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = await self._transport.request(
            "POST", _SMART_PATH, json=_smart_payload(software, catalog)
        )
        return _SMART_AUDIT_RESULTS_ADAPTER.validate_python(_result(data))

    async def os_packages(
        self, os: str, version: str, packages: Sequence[str]
    ) -> LegacyAuditResult:
        """Audit OS packages through POST /api/v3/audit/audit/.

        Args:
            os: Operating-system name.
            version: Operating-system version.
            packages: Package inventory to audit.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        if not packages:
            msg = "packages must not be empty"
            raise ValueError(msg)
        data = await self._transport.request(
            "POST",
            _CLASSIC_PATH,
            json={"os": os, "version": version, "package": list(packages)},
        )
        return _LEGACY_AUDIT_RESULT_ADAPTER.validate_python(data)

    async def linux(
        self,
        os_name: str,
        os_version: str,
        packages: Sequence[str],
        *,
        os_arch: str | None = None,
        include_unofficial: bool = False,
        include_candidates: bool = False,
        include_any_version: bool = False,
        cvelist_metrics: bool = False,
    ) -> PackageAuditResult:
        """Audit Linux packages through ``POST /api/v4/audit/linux``.

        Args:
            os_name: Linux distribution name.
            os_version: Operating-system version.
            packages: Package inventory to audit.
            os_arch: Optional operating-system architecture.
            include_unofficial: Whether unofficial advisories are included.
            include_candidates: Whether candidate matches are included.
            include_any_version: Whether versionless matches are included.
            cvelist_metrics: Whether CVE-list metrics are included.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        payload = _package_options(
            packages,
            include_unofficial,
            include_candidates,
            include_any_version,
            cvelist_metrics,
        )
        payload.update({"osName": os_name, "osVersion": os_version})
        if os_arch is not None:
            payload["osArch"] = os_arch
        data = await self._transport.request("POST", _LINUX_PATH, json=payload)
        return _PACKAGE_AUDIT_RESULT_ADAPTER.validate_python(_result(data))

    async def library(
        self,
        packages: Sequence[str],
        *,
        include_unofficial: bool = False,
        include_candidates: bool = False,
        include_any_version: bool = False,
        cvelist_metrics: bool = False,
    ) -> PackageAuditResult:
        """Audit package URLs through ``POST /api/v4/audit/library``.

        Args:
            packages: Package inventory to audit.
            include_unofficial: Whether unofficial advisories are included.
            include_candidates: Whether candidate matches are included.
            include_any_version: Whether versionless matches are included.
            cvelist_metrics: Whether CVE-list metrics are included.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        payload = _package_options(
            packages,
            include_unofficial,
            include_candidates,
            include_any_version,
            cvelist_metrics,
        )
        data = await self._transport.request("POST", _LIBRARY_PATH, json=payload)
        return _PACKAGE_AUDIT_RESULT_ADAPTER.validate_python(_result(data))

    async def sbom(self, file: Path) -> SBOMAuditResult:
        """Audit an SPDX or CycloneDX JSON file through ``POST /api/v4/audit/sbom``.

        Args:
            file: SPDX or CycloneDX JSON file.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        contents = await asyncio.to_thread(file.read_bytes)
        data = await self._transport.request(
            "POST",
            _SBOM_PATH,
            files={"file": (file.name, contents, "application/json")},
        )
        return _SBOM_AUDIT_RESULT_ADAPTER.validate_python(_result(data))

    async def kb(self, os: str, kb_list: Sequence[str]) -> KBAuditResult:
        """Audit installed Windows KBs through POST /api/v3/audit/kb/.

        Args:
            os: Operating-system name.
            kb_list: Installed Windows KB identifiers.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = await self._transport.request(
            "POST", _KB_PATH, json={"os": os, "kbList": list(kb_list)}
        )
        return _KB_AUDIT_RESULT_ADAPTER.validate_python(data)

    async def winaudit(
        self,
        os: str,
        os_version: str,
        kb_list: Sequence[str],
        software: Sequence[WindowsSoftware],
        *,
        platform: str | None = None,
    ) -> LegacyAuditResult:
        """Audit a Windows host through POST /api/v3/audit/winaudit/.

        Args:
            os: Operating-system name.
            os_version: Operating-system version.
            kb_list: Installed Windows KB identifiers.
            software: Software inventory to audit.
            platform: Optional Windows platform architecture.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        payload: dict[str, object] = {
            "os": os,
            "os_version": os_version,
            "kb_list": list(kb_list),
            "software": [item.model_dump(mode="json") for item in software],
        }
        if platform is not None:
            payload["platform"] = platform
        data = await self._transport.request("POST", _WINAUDIT_PATH, json=payload, add_api_key=True)
        return _LEGACY_AUDIT_RESULT_ADAPTER.validate_python(data)
