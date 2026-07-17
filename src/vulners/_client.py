"""Public client entry points and resource wiring."""

from __future__ import annotations

import os
from typing import Self

import httpx  # noqa: TC002 - HTTPX client classes are instantiated at runtime.

from ._transport import AsyncTransport, SyncTransport
from .resources.search import AsyncSearchResource, SearchResource

_DEFAULT_BASE_URL = "https://vulners.com"


def _resolve_api_key(api_key: str | None) -> str:
    """Get an API key from the explicit argument or process environment."""
    resolved_api_key = api_key or os.getenv("VULNERS_API_KEY")
    if not resolved_api_key:
        msg = "api_key must be provided or set in the VULNERS_API_KEY environment variable"
        raise ValueError(msg)
    return resolved_api_key


class Vulners:
    """Synchronous client for the Vulners API.

    Args:
        api_key: Vulners API key. Falls back to ``VULNERS_API_KEY`` when omitted.
        base_url: API base URL.
        timeout: HTTP request timeout.
        proxy: Optional HTTP proxy URL.
        retries: Maximum total attempts for retryable requests.
        rate_limit: Whether to honor server-advertised rate limits.
        http_client: Optional preconfigured HTTPX client. It remains caller-owned.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float | httpx.Timeout = 60.0,
        proxy: str | None = None,
        retries: int = 3,
        rate_limit: bool = True,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._transport = SyncTransport(
            api_key=_resolve_api_key(api_key),
            base_url=base_url,
            timeout=timeout,
            proxy=proxy,
            retries=retries,
            rate_limit=rate_limit,
            http_client=http_client,
        )
        self.search = SearchResource(self._transport)

    def __enter__(self) -> Self:
        """Enter the client context."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close an internally created HTTP client on context exit."""
        self.close()

    def __repr__(self) -> str:
        """Return a representation that does not disclose the API key."""
        return f"Vulners(base_url={self._transport.base_url!r})"

    def close(self) -> None:
        """Close the internally created HTTP client, if any."""
        self._transport.close()


class AsyncVulners:
    """Asynchronous client for the Vulners API.

    Args:
        api_key: Vulners API key. Falls back to ``VULNERS_API_KEY`` when omitted.
        base_url: API base URL.
        timeout: HTTP request timeout.
        proxy: Optional HTTP proxy URL.
        retries: Maximum total attempts for retryable requests.
        rate_limit: Whether to honor server-advertised rate limits.
        http_client: Optional preconfigured asynchronous HTTPX client. It remains caller-owned.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float | httpx.Timeout = 60.0,
        proxy: str | None = None,
        retries: int = 3,
        rate_limit: bool = True,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._transport = AsyncTransport(
            api_key=_resolve_api_key(api_key),
            base_url=base_url,
            timeout=timeout,
            proxy=proxy,
            retries=retries,
            rate_limit=rate_limit,
            http_client=http_client,
        )
        self.search = AsyncSearchResource(self._transport)

    async def __aenter__(self) -> Self:
        """Enter the asynchronous client context."""
        return self

    async def __aexit__(self, *_: object) -> None:
        """Close an internally created asynchronous HTTP client on context exit."""
        await self.aclose()

    def __repr__(self) -> str:
        """Return a representation that does not disclose the API key."""
        return f"AsyncVulners(base_url={self._transport.base_url!r})"

    async def aclose(self) -> None:
        """Close the internally created asynchronous HTTP client, if any."""
        await self._transport.aclose()
