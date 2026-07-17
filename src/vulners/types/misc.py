"""Typed models for miscellaneous Vulners endpoints."""

from pydantic import BaseModel, ConfigDict, TypeAdapter


class CPEMatch(BaseModel):
    """Best and alternate CPE matches for a product."""

    model_config = ConfigDict(frozen=True, extra="allow")

    best_match: str | None = None
    cpe: tuple[str, ...] = ()


class STIXBundle(BaseModel):
    """A STIX 2.x bundle returned for a bulletin."""

    model_config = ConfigDict(frozen=True, extra="allow")

    type: str = "bundle"
    id: str | None = None
    objects: tuple[object, ...] = ()


_CPE_MATCH_ADAPTER = TypeAdapter(CPEMatch)
_STIX_BUNDLE_ADAPTER = TypeAdapter(STIXBundle)
