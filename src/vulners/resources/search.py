"""Typed sync and async resources for Vulners full-text search."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, Final, cast

from ..types.search import (
    _DOCUMENTS_ADAPTER,
    _HISTORY_ADAPTER,
    _PAGE_ADAPTER,
    _WEB_VULNERABILITIES_ADAPTER,
    HistoryEntry,
    SearchDocument,
    SearchPage,
    WebCatalog,
    WebMatchMode,
    WebVulnerabilityResult,
)

if TYPE_CHECKING:
    from .._transport import AsyncTransport, ResponseData, SyncTransport

_LUCENE_PATH: Final = "/api/v3/search/lucene/"
_HISTORY_PATH: Final = "/api/v3/search/history/"
_WEB_VULNS_PATH: Final = "/api/v4/search/web-vulns/"
_MAX_SEARCH_WINDOW: Final = 10_000
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
    if limit <= 0 or limit > _MAX_SEARCH_WINDOW:
        msg = "limit must be between 1 and 10000"
        raise ValueError(msg)
    if offset < 0 or offset >= _MAX_SEARCH_WINDOW:
        msg = "offset must be between 0 and 9999"
        raise ValueError(msg)
    size = min(limit, _MAX_SEARCH_WINDOW - offset)
    return {"query": query, "size": size, "skip": offset, "fields": list(fields)}


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


def _parse_history(data: ResponseData) -> tuple[HistoryEntry, ...]:
    if not isinstance(data, Mapping) or not isinstance(data.get("result"), list):
        msg = "Unexpected response shape for /api/v3/search/history/"
        raise ValueError(msg)
    return _HISTORY_ADAPTER.validate_python(data["result"])


def _parse_web_vulns(data: ResponseData) -> WebVulnerabilityResult:
    if not isinstance(data, Mapping) or not isinstance(data.get("result"), Mapping):
        msg = "Unexpected response shape for /api/v4/search/web-vulns/"
        raise ValueError(msg)
    matches = _WEB_VULNERABILITIES_ADAPTER.validate_python(data["result"])
    return WebVulnerabilityResult(matches=matches)


def _web_vulns_payload(
    paths: Sequence[str],
    application: str | Mapping[str, object] | None,
    match: WebMatchMode,
    config: Sequence[str] | None,
    catalog: WebCatalog,
) -> dict[str, object]:
    if not paths:
        msg = "paths must not be empty"
        raise ValueError(msg)
    payload: dict[str, object] = {
        "paths": list(paths),
        "application": application,
        "match": match,
        "catalog": catalog,
    }
    if config is not None:
        payload["config"] = list(config)
    return payload


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

    def all_bulletins(
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


        Returns:
            An iterator over typed API results.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        current_offset = offset
        while True:
            page = self.bulletins(query, limit=limit, offset=current_offset, fields=fields)
            yield from page.documents
            fetched = len(page.documents)
            window_end = min(page.total, _MAX_SEARCH_WINDOW)
            if fetched == 0 or current_offset + fetched >= window_end:
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


        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        return self.bulletins(
            _exploit_query(query, lookup_fields), limit=limit, offset=offset, fields=fields
        )

    def all_exploits(
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


        Returns:
            An iterator over typed API results.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        yield from self.all_bulletins(
            _exploit_query(query, lookup_fields), limit=limit, offset=offset, fields=fields
        )

    def history(self, id: str) -> tuple[HistoryEntry, ...]:
        """Get bulletin history through ``GET /api/v3/search/history/``.

        Args:
            id: Vulners bulletin or subscription identifier.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = self._transport.request("GET", _HISTORY_PATH, params={"id": id})
        return _parse_history(data)

    def web_vulns(
        self,
        paths: Sequence[str],
        *,
        application: str | Mapping[str, object] | None = None,
        match: WebMatchMode = "partial",
        config: Sequence[str] | None = None,
        catalog: WebCatalog = "official",
    ) -> WebVulnerabilityResult:
        """Search web vulnerabilities through ``POST /api/v4/search/web-vulns/``.

        Args:
            paths: Web paths or URLs to match.
            application: Optional application identity or metadata.
            match: Matching strictness.
            config: Optional matching configuration.
            catalog: Vulnerability catalog to search.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        payload = _web_vulns_payload(paths, application, match, config, catalog)
        data = self._transport.request("POST", _WEB_VULNS_PATH, json=payload)
        return _parse_web_vulns(data)


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


        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = await self._transport.request(
            "POST", _LUCENE_PATH, json=_search_payload(query, limit, offset, fields)
        )
        return _parse_search_page(data)

    async def all_bulletins(
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


        Returns:
            An iterator over typed API results.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        current_offset = offset
        while True:
            page = await self.bulletins(query, limit=limit, offset=current_offset, fields=fields)
            for document in page.documents:
                yield document
            fetched = len(page.documents)
            window_end = min(page.total, _MAX_SEARCH_WINDOW)
            if fetched == 0 or current_offset + fetched >= window_end:
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


        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        return await self.bulletins(
            _exploit_query(query, lookup_fields), limit=limit, offset=offset, fields=fields
        )

    async def all_exploits(
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


        Returns:
            An iterator over typed API results.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        async for document in self.all_bulletins(
            _exploit_query(query, lookup_fields), limit=limit, offset=offset, fields=fields
        ):
            yield document

    async def history(self, id: str) -> tuple[HistoryEntry, ...]:
        """Get bulletin history through ``GET /api/v3/search/history/``.

        Args:
            id: Vulners bulletin or subscription identifier.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = await self._transport.request("GET", _HISTORY_PATH, params={"id": id})
        return _parse_history(data)

    async def web_vulns(
        self,
        paths: Sequence[str],
        *,
        application: str | Mapping[str, object] | None = None,
        match: WebMatchMode = "partial",
        config: Sequence[str] | None = None,
        catalog: WebCatalog = "official",
    ) -> WebVulnerabilityResult:
        """Search web vulnerabilities through ``POST /api/v4/search/web-vulns/``.

        Args:
            paths: Web paths or URLs to match.
            application: Optional application identity or metadata.
            match: Matching strictness.
            config: Optional matching configuration.
            catalog: Vulnerability catalog to search.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        payload = _web_vulns_payload(paths, application, match, config, catalog)
        data = await self._transport.request("POST", _WEB_VULNS_PATH, json=payload)
        return _parse_web_vulns(data)
