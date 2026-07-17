"""Pydantic models for the Vulners full-text search API."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow", populate_by_name=True)


class SearchDocument(_FrozenModel):
    """A document returned by the Vulners Lucene search endpoint."""

    id: str | None = None
    title: str | None = None
    description: str | None = None
    type: str | None = None
    bulletin_family: str | None = Field(default=None, alias="bulletinFamily")
    published: str | None = None
    modified: str | None = None
    href: str | None = None
    vhref: str | None = None


class SearchPage(_FrozenModel):
    """A page of documents returned by the Vulners Lucene search endpoint."""

    documents: tuple[SearchDocument, ...]
    total: int
    max_search_size: int | None = None


_DOCUMENTS_ADAPTER = TypeAdapter(list[SearchDocument])
_PAGE_ADAPTER = TypeAdapter(SearchPage)
