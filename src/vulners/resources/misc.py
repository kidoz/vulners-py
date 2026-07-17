"""Sync and async resources for miscellaneous Vulners endpoints."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Final

from .._serde import json_loads
from ..types.misc import _CPE_MATCH_ADAPTER, _STIX_BUNDLE_ADAPTER, CPEMatch, STIXBundle

if TYPE_CHECKING:
    from .._transport import AsyncTransport, ResponseData, SyncTransport

_SUGGEST_PATH: Final = "/api/v3/search/suggest/"
_AUTOCOMPLETE_PATH: Final = "/api/v3/search/autocomplete/"
_CPE_PATH: Final = "/api/v4/search/cpe"
_WAF_PATH: Final = "/api/v3/burp/rules/"
_STIX_PATH: Final = "/api/v4/stix/bundle"


def _mapping(data: ResponseData, key: str) -> object:
    if not isinstance(data, Mapping) or key not in data:
        msg = f"Unexpected response shape: missing {key}"
        raise ValueError(msg)
    return data[key]


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        msg = "Unexpected string-list response shape"
        raise ValueError(msg)
    return tuple(item for item in value if isinstance(item, str))


def _stix(data: ResponseData) -> STIXBundle:
    value = _mapping(data, "result")
    if isinstance(value, str):
        value = json_loads(value.encode())
    return _STIX_BUNDLE_ADAPTER.validate_python(value)


class MiscResource:
    """Synchronous search helpers and web-application rules."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def suggest(self, field_name: str, query: str = "") -> tuple[str, ...]:
        """Return distinct field suggestions from ``POST /api/v3/search/suggest/``.

        Args:
            field_name: Vulners field to suggest values for.
            query: Lucene query or search text.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = self._transport.request(
            "POST",
            _SUGGEST_PATH,
            json={"fieldName": field_name, "type": "distinct", "query": query},
        )
        return _strings(_mapping(data, "suggest"))

    def autocomplete(self, query: str) -> tuple[str, ...]:
        """Complete a Lucene query through ``POST /api/v3/search/autocomplete/``.

        Args:
            query: Lucene query or search text.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = self._transport.request("POST", _AUTOCOMPLETE_PATH, json={"query": query})
        suggestions = _mapping(data, "suggestions")
        if isinstance(suggestions, list):
            return tuple(
                item if isinstance(item, str) else item[0]
                for item in suggestions
                if isinstance(item, str)
                or (isinstance(item, list) and item and isinstance(item[0], str))
            )
        msg = "Unexpected autocomplete response shape"
        raise ValueError(msg)

    def cpe(self, product: str, *, vendor: str | None = None, size: int | None = None) -> CPEMatch:
        """Find CPEs through ``GET /api/v4/search/cpe``.

        Args:
            product: Product name used for CPE matching.
            vendor: Optional product vendor.
            size: Optional maximum number of matches.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        params: dict[str, str | int] = {"product": product}
        if vendor is not None:
            params["vendor"] = vendor
        if size is not None:
            params["size"] = size
        data = self._transport.request("GET", _CPE_PATH, params=params)
        return _CPE_MATCH_ADAPTER.validate_python(_mapping(data, "result"))

    def waf_rules(self) -> tuple[str, ...]:
        """Return legacy WAF rules from ``GET /api/v3/burp/rules/``.

        Args:
            None.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = self._transport.request("GET", _WAF_PATH)
        if isinstance(data, str):
            return (data,)
        if isinstance(data, list):
            return tuple(item for item in data if isinstance(item, str))
        if isinstance(data, Mapping):
            rules = data.get("rules", ())
            return _strings(rules) if isinstance(rules, list) else ()
        return ()


class AsyncMiscResource:
    """Asynchronous search helpers and web-application rules."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def suggest(self, field_name: str, query: str = "") -> tuple[str, ...]:
        """Return distinct field suggestions from ``POST /api/v3/search/suggest/``.

        Args:
            field_name: Vulners field to suggest values for.
            query: Lucene query or search text.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = await self._transport.request(
            "POST",
            _SUGGEST_PATH,
            json={"fieldName": field_name, "type": "distinct", "query": query},
        )
        return _strings(_mapping(data, "suggest"))

    async def autocomplete(self, query: str) -> tuple[str, ...]:
        """Complete a Lucene query through ``POST /api/v3/search/autocomplete/``.

        Args:
            query: Lucene query or search text.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = await self._transport.request("POST", _AUTOCOMPLETE_PATH, json={"query": query})
        suggestions = _mapping(data, "suggestions")
        if isinstance(suggestions, list):
            return tuple(
                item if isinstance(item, str) else item[0]
                for item in suggestions
                if isinstance(item, str)
                or (isinstance(item, list) and item and isinstance(item[0], str))
            )
        msg = "Unexpected autocomplete response shape"
        raise ValueError(msg)

    async def cpe(
        self, product: str, *, vendor: str | None = None, size: int | None = None
    ) -> CPEMatch:
        """Find CPEs through ``GET /api/v4/search/cpe``.

        Args:
            product: Product name used for CPE matching.
            vendor: Optional product vendor.
            size: Optional maximum number of matches.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        params: dict[str, str | int] = {"product": product}
        if vendor is not None:
            params["vendor"] = vendor
        if size is not None:
            params["size"] = size
        data = await self._transport.request("GET", _CPE_PATH, params=params)
        return _CPE_MATCH_ADAPTER.validate_python(_mapping(data, "result"))

    async def waf_rules(self) -> tuple[str, ...]:
        """Return legacy WAF rules from ``GET /api/v3/burp/rules/``.

        Args:
            None.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = await self._transport.request("GET", _WAF_PATH)
        if isinstance(data, str):
            return (data,)
        if isinstance(data, list):
            return tuple(item for item in data if isinstance(item, str))
        if isinstance(data, Mapping):
            rules = data.get("rules", ())
            return _strings(rules) if isinstance(rules, list) else ()
        return ()


class STIXResource:
    """Synchronous STIX operations."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def bundle(self, id: str, *, opencti_id: str | None = None) -> STIXBundle:
        """Build a bundle through ``GET /api/v4/stix/bundle``.

        Args:
            id: Vulners bulletin or subscription identifier.
            opencti_id: Optional OpenCTI object identifier.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        params = {"id": id}
        if opencti_id is not None:
            params["opencti_id"] = opencti_id
        data = self._transport.request("GET", _STIX_PATH, params=params)
        return _stix(data)


class AsyncSTIXResource:
    """Asynchronous STIX operations."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def bundle(self, id: str, *, opencti_id: str | None = None) -> STIXBundle:
        """Build a bundle through ``GET /api/v4/stix/bundle``.

        Args:
            id: Vulners bulletin or subscription identifier.
            opencti_id: Optional OpenCTI object identifier.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        params = {"id": id}
        if opencti_id is not None:
            params["opencti_id"] = opencti_id
        data = await self._transport.request("GET", _STIX_PATH, params=params)
        return _stix(data)
