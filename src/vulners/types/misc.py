"""Typed models for miscellaneous Vulners endpoints."""

from __future__ import annotations

from collections.abc import Mapping  # noqa: TC003 - Required by Pydantic at runtime.

from pydantic import BaseModel, ConfigDict, TypeAdapter


class CPEMatch(BaseModel):
    """Best and alternate CPE matches for a product."""

    model_config = ConfigDict(frozen=True, extra="allow")

    best_match: str | None = None
    cpe: tuple[str, ...] = ()


class WAFRule(BaseModel):
    """One software detection rule returned by the legacy Burp endpoint."""

    model_config = ConfigDict(frozen=True, extra="allow")

    alias: str
    regex: str
    type: str


class WAFRules(BaseModel):
    """Web-application detection rules keyed by software name."""

    model_config = ConfigDict(frozen=True, extra="allow")

    rules: Mapping[str, WAFRule]


class STIXBundle(BaseModel):
    """A STIX 2.x bundle returned for a bulletin."""

    model_config = ConfigDict(frozen=True, extra="allow")

    type: str = "bundle"
    id: str | None = None
    objects: tuple[STIXObject, ...] = ()


class STIXObject(BaseModel):
    """A forward-compatible STIX domain or relationship object."""

    model_config = ConfigDict(frozen=True, extra="allow")

    type: str
    id: str | None = None


_CPE_MATCH_ADAPTER = TypeAdapter(CPEMatch)
_WAF_RULES_ADAPTER = TypeAdapter(WAFRules)
_STIX_BUNDLE_ADAPTER = TypeAdapter(STIXBundle)
