"""Pydantic models for Vulners bulletin retrieval."""

from __future__ import annotations

from collections.abc import Mapping  # noqa: TC003 - Required by Pydantic at runtime.

from pydantic import BaseModel, ConfigDict

from .search import SearchDocument  # noqa: TC001 - Required by Pydantic at runtime.


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow")


class BulletinReferences(_FrozenModel):
    """References grouped by source for one bulletin."""

    id: str
    sources: Mapping[str, tuple[SearchDocument, ...]]


class BulletinWithReferences(_FrozenModel):
    """A bulletin paired with its grouped references."""

    document: SearchDocument | None
    references: BulletinReferences


class KBSeeds(_FrozenModel):
    """Microsoft KB supersedence relationships."""

    kbid: str
    superseeds: tuple[str, ...]
    parentseeds: tuple[str, ...]
