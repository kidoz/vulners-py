"""Typed request and response models for Vulners audit APIs."""

from __future__ import annotations

from collections.abc import Mapping  # noqa: TC003 - Required by Pydantic at runtime.
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from .search import SearchDocument  # noqa: TC001 - Required by Pydantic at runtime.


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow", populate_by_name=True)


class AuditSoftware(_FrozenModel):
    """A CPE-like software, operating-system, application, or hardware input."""

    product: str
    part: Literal["a", "o", "h"] | None = None
    vendor: str | None = None
    version: str | None = None
    update: str | None = None
    edition: str | None = None
    language: str | None = None
    sw_edition: str | None = None
    target_sw: str | None = None
    target_hw: str | None = None
    other: str | None = None


class AuditMatch(_FrozenModel):
    """Vulnerabilities matched to one audit input."""

    input: Mapping[str, object]
    matched_criteria: str | None = None
    vulnerabilities: tuple[SearchDocument, ...]


class CVEAuditResult(_FrozenModel):
    """Affected products and packages for one CVE."""

    cve: str
    affected_cpe: tuple[object, ...] = Field(default=(), alias="affectedCpe")
    affected_packages: tuple[object, ...] = Field(default=(), alias="affectedPackages")


class SmartAuditResult(_FrozenModel):
    """One Smart Audit match for a raw software description."""

    input: str
    cpe: str | None = None
    purls: tuple[str, ...]
    confidence: float
    vulnerabilities: tuple[SearchDocument, ...]


class PackageAuditIssue(_FrozenModel):
    """One vulnerable package returned by Linux or library audit."""

    package: str
    version: str
    fixed_version: str | None = Field(default=None, alias="fixedVersion")
    applicable_advisories: tuple[SearchDocument, ...] = Field(
        default=(), alias="applicableAdvisories"
    )


class PackageAuditResult(_FrozenModel):
    """Linux or package-library audit result."""

    issues: tuple[PackageAuditIssue, ...]
    errors: Mapping[str, object]
    total_packages: int = Field(alias="totalPackages")


class LegacyAuditResult(_FrozenModel):
    """Classic Linux or Windows v3 audit result."""

    id: str | None = None
    cvelist: tuple[str, ...] = ()
    vulnerabilities: tuple[str, ...] = ()


class KBAuditResult(_FrozenModel):
    """Windows KB audit result."""

    cvelist: tuple[str, ...] = ()
    kb_latest: str | None = Field(default=None, alias="kbLatest")
    kb_missed: tuple[str, ...] = Field(default=(), alias="kbMissed")


class WindowsSoftware(_FrozenModel):
    """Installed Windows software input."""

    software: str
    version: str


class SBOMComponent(_FrozenModel):
    """One component and its advisories from an SBOM audit."""

    package: str
    version: str
    fixed_version: str | None = Field(default=None, alias="fixedVersion")
    applicable_advisories: tuple[SearchDocument, ...] = Field(
        default=(), alias="applicableAdvisories"
    )


class SBOMAuditResult(_FrozenModel):
    """Typed result of an SPDX or CycloneDX audit."""

    data: tuple[SBOMComponent, ...]
    summary_id: str | None = Field(default=None, alias="summaryId")
    total_packages: int = Field(alias="totalPackages")


_AUDIT_MATCHES_ADAPTER = TypeAdapter(tuple[AuditMatch, ...])
_CVE_RESULT_ADAPTER = TypeAdapter(CVEAuditResult)
_CVE_RESULTS_ADAPTER = TypeAdapter(tuple[CVEAuditResult, ...])
_SMART_AUDIT_RESULTS_ADAPTER = TypeAdapter(tuple[SmartAuditResult, ...])
_PACKAGE_AUDIT_RESULT_ADAPTER = TypeAdapter(PackageAuditResult)
_LEGACY_AUDIT_RESULT_ADAPTER = TypeAdapter(LegacyAuditResult)
_KB_AUDIT_RESULT_ADAPTER = TypeAdapter(KBAuditResult)
_SBOM_AUDIT_RESULT_ADAPTER = TypeAdapter(SBOMAuditResult)

AuditMatchMode = Literal["partial", "full"]
AuditCatalog = Literal["official", "extended"]
