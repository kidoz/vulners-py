"""Typed sync and async resources for Vulners full-text search."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, Final, cast

from ..types.search import _DOCUMENTS_ADAPTER, _PAGE_ADAPTER, SearchDocument, SearchPage

if TYPE_CHECKING:
    from .._transport import AsyncTransport, ResponseData, SyncTransport

_LUCENE_PATH: Final = "/api/v3/search/lucene/"
DEFAULT_SEARCH_FIELDS: Final = (
    "id",
    "title",
    "description",
    "type",
    "bulletinFamily",
    "cvss",
    "published",
    "modified",
    "lastseen",
    "href",
    "sourceHref",
    "sourceData",
    "cvelist",
    "vulnStatus",
    "assigned",
)
_CVE_PATTERN: Final = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def _search_payload(
    query: str, limit: int, offset: int, fields: Sequence[str]
) -> dict[str, object]:
    if limit <= 0 or limit > 10_000:
        msg = "limit must be between 1 and 10000"
        raise ValueError(msg)
    if offset < 0 or offset > 10_000:
        msg = "offset must be between 0 and 10000"
        raise ValueError(msg)
    return {"query": query, "size": limit, "skip": offset, "fields": list(fields)}


def _parse_search_page(data: ResponseData) -> SearchPage:
    if not isinstance(data, Mapping):
        msg = "Unexpected response shape for /api/v3/search/lucene/"
        raise ValueError(msg)
    raw_search = data.get("search")
    raw_total = data.get("total")
    raw_max_size = data.get("maxSearchSize")
    if (
        not isinstance(raw_search, list)
        or isinstance(raw_total, bool)
        or not isinstance(raw_total, int)
    ):
        msg = "Unexpected search payload from /api/v3/search/lucene/"
        raise ValueError(msg)
    raw_documents: list[object] = []
    for hit in raw_search:
        if not isinstance(hit, Mapping) or not isinstance(hit.get("_source"), Mapping):
            msg = "Search hit is missing its _source document"
            raise ValueError(msg)
        raw_documents.append(dict(cast("Mapping[str, object]", hit["_source"])))
    documents = _DOCUMENTS_ADAPTER.validate_python(raw_documents)
    max_search_size = (
        raw_max_size
        if isinstance(raw_max_size, int) and not isinstance(raw_max_size, bool)
        else None
    )
    return _PAGE_ADAPTER.validate_python(
        {"documents": tuple(documents), "total": raw_total, "max_search_size": max_search_size}
    )


def _exploit_query(query: str, lookup_fields: Sequence[str] | None) -> str:
    normalized_query = query.strip()
    if _CVE_PATTERN.fullmatch(normalized_query):
        normalized_query = f'"{normalized_query}"'
    if lookup_fields:
        criteria = " OR ".join(f'{field}:"{normalized_query}"' for field in lookup_fields)
        return f"bulletinFamily:exploit AND ({criteria})"
    return f"bulletinFamily:exploit AND ({normalized_query})"


class SearchResource:
    """Synchronous full-text and exploit search operations."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def bulletins(
        self,
        query: str,
        *,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] = DEFAULT_SEARCH_FIELDS,
    ) -> SearchPage:
        """Search Vulners bulletins through ``POST /api/v3/search/lucene/``.

        Args:
            query: Lucene query string.
            limit: Number of records to request, from 1 through 10,000.
            offset: Number of matching records to skip.
            fields: Wire fields to include in each document.

        Returns:
            A typed page of matching Vulners documents.

        Raises:
            VulnersAPIError: If the API rejects the search.
        """
        data = self._transport.request(
            "POST", _LUCENE_PATH, json=_search_payload(query, limit, offset, fields)
        )
        return _parse_search_page(data)

    def bulletins_iter(
        self,
        query: str,
        *,
        limit: int = 100,
        offset: int = 0,
        fields: Sequence[str] = DEFAULT_SEARCH_FIELDS,
    ) -> Iterator[SearchDocument]:
        """Iterate every matching bulletin via ``POST /api/v3/search/lucene/``.

        Args:
            query: Lucene query string.
            limit: Requested page size, from 1 through 10,000.
            offset: First matching record to include.
            fields: Wire fields to include in each document.

        Yields:
            Typed Vulners documents until the endpoint is exhausted.
        """
        current_offset = offset
        while True:
            page = self.bulletins(query, limit=limit, offset=current_offset, fields=fields)
            yield from page.documents
            fetched = len(page.documents)
            if fetched == 0 or current_offset + fetched >= page.total:
                return
            current_offset += fetched

    def exploits(
        self,
        query: str,
        *,
        lookup_fields: Sequence[str] | None = None,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] = DEFAULT_SEARCH_FIELDS,
    ) -> SearchPage:
        """Search public exploits through ``POST /api/v3/search/lucene/``.

        Args:
            query: Vulnerability or software search term.
            lookup_fields: Optional fields used for exact matching.
            limit: Number of records to request, from 1 through 10,000.
            offset: Number of matching records to skip.
            fields: Wire fields to include in each document.

        Returns:
            A typed page of matching exploit documents.
        """
        return self.bulletins(
            _exploit_query(query, lookup_fields), limit=limit, offset=offset, fields=fields
        )

    def exploits_iter(
        self,
        query: str,
        *,
        lookup_fields: Sequence[str] | None = None,
        limit: int = 100,
        offset: int = 0,
        fields: Sequence[str] = DEFAULT_SEARCH_FIELDS,
    ) -> Iterator[SearchDocument]:
        """Iterate public exploits through ``POST /api/v3/search/lucene/``.

        Args:
            query: Vulnerability or software search term.
            lookup_fields: Optional fields used for exact matching.
            limit: Requested page size, from 1 through 10,000.
            offset: First matching record to include.
            fields: Wire fields to include in each document.

        Yields:
            Typed exploit documents until the endpoint is exhausted.
        """
        yield from self.bulletins_iter(
            _exploit_query(query, lookup_fields), limit=limit, offset=offset, fields=fields
        )


class AsyncSearchResource:
    """Asynchronous full-text and exploit search operations."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def bulletins(
        self,
        query: str,
        *,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] = DEFAULT_SEARCH_FIELDS,
    ) -> SearchPage:
        """Search Vulners bulletins through ``POST /api/v3/search/lucene/``.

        Args:
            query: Lucene query string.
            limit: Number of records to request, from 1 through 10,000.
            offset: Number of matching records to skip.
            fields: Wire fields to include in each document.

        Returns:
            A typed page of matching Vulners documents.
        """
        data = await self._transport.request(
            "POST", _LUCENE_PATH, json=_search_payload(query, limit, offset, fields)
        )
        return _parse_search_page(data)

    async def bulletins_iter(
        self,
        query: str,
        *,
        limit: int = 100,
        offset: int = 0,
        fields: Sequence[str] = DEFAULT_SEARCH_FIELDS,
    ) -> AsyncIterator[SearchDocument]:
        """Iterate every matching bulletin via ``POST /api/v3/search/lucene/``.

        Args:
            query: Lucene query string.
            limit: Requested page size, from 1 through 10,000.
            offset: First matching record to include.
            fields: Wire fields to include in each document.

        Yields:
            Typed Vulners documents until the endpoint is exhausted.
        """
        current_offset = offset
        while True:
            page = await self.bulletins(query, limit=limit, offset=current_offset, fields=fields)
            for document in page.documents:
                yield document
            fetched = len(page.documents)
            if fetched == 0 or current_offset + fetched >= page.total:
                return
            current_offset += fetched

    async def exploits(
        self,
        query: str,
        *,
        lookup_fields: Sequence[str] | None = None,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] = DEFAULT_SEARCH_FIELDS,
    ) -> SearchPage:
        """Search public exploits through ``POST /api/v3/search/lucene/``.

        Args:
            query: Vulnerability or software search term.
            lookup_fields: Optional fields used for exact matching.
            limit: Number of records to request, from 1 through 10,000.
            offset: Number of matching records to skip.
            fields: Wire fields to include in each document.

        Returns:
            A typed page of matching exploit documents.
        """
        return await self.bulletins(
            _exploit_query(query, lookup_fields), limit=limit, offset=offset, fields=fields
        )

    async def exploits_iter(
        self,
        query: str,
        *,
        lookup_fields: Sequence[str] | None = None,
        limit: int = 100,
        offset: int = 0,
        fields: Sequence[str] = DEFAULT_SEARCH_FIELDS,
    ) -> AsyncIterator[SearchDocument]:
        """Iterate public exploits through ``POST /api/v3/search/lucene/``.

        Args:
            query: Vulnerability or software search term.
            lookup_fields: Optional fields used for exact matching.
            limit: Requested page size, from 1 through 10,000.
            offset: First matching record to include.
            fields: Wire fields to include in each document.

        Yields:
            Typed exploit documents until the endpoint is exhausted.
        """
        async for document in self.bulletins_iter(
            _exploit_query(query, lookup_fields), limit=limit, offset=offset, fields=fields
        ):
            yield document
