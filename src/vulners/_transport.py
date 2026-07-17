"""Shared HTTP request construction, response parsing, retries, and rate limiting."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookiejar import Cookie, DefaultCookiePolicy
from importlib.util import find_spec
from random import SystemRandom
from typing import TYPE_CHECKING, Final, TypeAlias, TypeVar

import httpx

if TYPE_CHECKING:
    from pathlib import Path
    from urllib.request import Request as URLRequest

from ._exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    VulnersAPIError,
    VulnersError,
)
from ._rate_limit import TokenBucket
from ._serde import JSONValue, json_loads
from ._version import __version__

HTTPMethod: TypeAlias = str
QueryValue: TypeAlias = str | int | float | bool
FileValue: TypeAlias = tuple[str, bytes, str]
ResponseData: TypeAlias = Mapping[str, object] | list[object] | str | int | float | bool | None
_T = TypeVar("_T")
_RETRYABLE_STATUS_CODES: Final = frozenset({429, 500, 502, 503, 504})
_HTTP2_AVAILABLE: Final = find_spec("h2") is not None
_JITTER_RANDOM: Final = SystemRandom()


_USER_AGENT: Final = f"vulners-py/{__version__}"


def _request_headers(api_key: str) -> dict[str, str]:
    return {"User-Agent": _USER_AGENT, "X-Api-Key": api_key}


class _RejectCookiesPolicy(DefaultCookiePolicy):
    """Reject response cookies and prevent a client jar from replaying them."""

    def set_ok(self, cookie: Cookie, request: URLRequest) -> bool:
        return False

    def return_ok(self, cookie: Cookie, request: URLRequest) -> bool:
        return False


def _parse_retry_after(response: httpx.Response, *, now: datetime | None = None) -> float | None:
    value = response.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return max(float(value), 0.0)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        return max((retry_at - current).total_seconds(), 0.0)


def _response_object(payload: JSONValue) -> Mapping[str, object] | None:
    return payload if isinstance(payload, Mapping) else None


def _read_json(response: httpx.Response) -> JSONValue | None:
    if not response.content:
        return None
    try:
        return json_loads(response.content)
    except (TypeError, UnicodeDecodeError, ValueError):
        return None


def _message_from_payload(
    payload: Mapping[str, object] | None, default: str
) -> tuple[int | str | None, str]:
    if payload is None:
        return None, default
    data = payload.get("data")
    error_payload = data if isinstance(data, Mapping) else payload
    message = error_payload.get("error", error_payload.get("message", default))
    error_code = error_payload.get("errorCode", error_payload.get("error_code"))
    return (
        error_code if isinstance(error_code, (int, str)) else None,
        message if isinstance(message, str) else default,
    )


def _raise_api_error(response: httpx.Response, payload: JSONValue | None) -> None:
    payload_object = _response_object(payload) if payload is not None else None
    error_code, message = _message_from_payload(payload_object, response.reason_phrase)
    status_code = response.status_code
    if status_code in {401, 403}:
        raise AuthenticationError(status_code, error_code, message, payload_object)
    if status_code == 404:
        raise NotFoundError(status_code, error_code, message, payload_object)
    if status_code == 429:
        raise RateLimitError(
            status_code,
            error_code,
            message,
            payload_object,
            retry_after=_parse_retry_after(response),
        )
    if status_code >= 500:
        raise ServerError(status_code, error_code, message, payload_object)
    raise VulnersAPIError(status_code, error_code, message, payload_object)


def parse_response(response: httpx.Response) -> ResponseData:
    """Validate HTTP and v3 envelope errors, then unwrap the v3 data envelope."""
    response.headers.pop("set-cookie", None)
    payload = _read_json(response)
    if response.is_error:
        _raise_api_error(response, payload)
    payload_object = _response_object(payload) if payload is not None else None
    if payload_object is not None and payload_object.get("result") == "error":
        _raise_api_error(response, payload)
    if payload_object is not None and "data" in payload_object:
        data = payload_object["data"]
        if isinstance(data, (Mapping, list, str, int, float, bool)) or data is None:
            return data
    if payload is None:
        return None
    return payload


def _retry_delay(attempt: int, response: httpx.Response | None = None) -> float:
    if response is not None and (retry_after := _parse_retry_after(response)) is not None:
        return retry_after
    jitter = _JITTER_RANDOM.uniform(0.0, 0.1)
    return float((2 ** (attempt - 1)) * 0.25 + jitter)


def _rate_limit_from(response: httpx.Response) -> float | None:
    # Upstream advertises the per-endpoint request allowance as requests-per-minute
    # in the X-Vulners-Ratelimit-Reqlimit response header. TokenBucket.update
    # converts that to a per-second rate, so the raw value is forwarded unchanged.
    value = response.headers.get("X-Vulners-Ratelimit-Reqlimit")
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


class _TransportBase:
    def __init__(self, api_key: str, base_url: str, retries: int, rate_limit: bool) -> None:
        if retries < 1:
            msg = "retries must be at least 1"
            raise ValueError(msg)
        self._api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._retries = retries
        self._rate_limit = rate_limit
        self._buckets: dict[str, TokenBucket] = {}

    def __repr__(self) -> str:
        """Return transport diagnostics without exposing the API key."""
        return (
            f"{type(self).__name__}(base_url={self.base_url!r}, "
            f"retries={self._retries!r}, rate_limit={self._rate_limit!r})"
        )

    def _bucket_for(self, path: str) -> TokenBucket:
        return self._buckets.setdefault(path, TokenBucket())

    def _update_rate_limit(self, path: str, response: httpx.Response) -> None:
        if self._rate_limit and (limit := _rate_limit_from(response)) is not None:
            self._bucket_for(path).update(limit)


class SyncTransport(_TransportBase):
    """Synchronous HTTPX transport using shared response semantics."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        timeout: float | httpx.Timeout,
        proxy: str | None,
        retries: int,
        rate_limit: bool,
        http_client: httpx.Client | None,
    ) -> None:
        super().__init__(api_key, base_url, retries, rate_limit)
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            proxy=proxy,
            http2=_HTTP2_AVAILABLE,
            follow_redirects=True,
        )
        self._client.cookies.clear()
        self._client.cookies.jar.set_policy(_RejectCookiesPolicy())

    def close(self) -> None:
        """Close an internally managed HTTPX client."""
        if self._owns_client:
            self._client.close()

    def _run(
        self,
        path: str,
        send: Callable[[Mapping[str, str]], httpx.Response],
        finalize: Callable[[httpx.Response], _T],
    ) -> _T:
        """Run one transport call through the shared synchronous retry loop.

        ``send`` issues the request, ``finalize`` reads a value from a response
        that is neither retryable nor an API error. Both the JSON and binary
        paths funnel through here so their retry, rate-limit, ``Set-Cookie``
        stripping, and error-mapping behavior stay identical.
        """
        bucket = self._bucket_for(path)
        headers = _request_headers(self._api_key)
        for attempt in range(1, self._retries + 1):
            if self._rate_limit:
                bucket.consume()
            try:
                response = send(headers)
            except httpx.TransportError as error:
                if attempt == self._retries:
                    raise VulnersError("Unable to reach the Vulners API") from error
                time.sleep(_retry_delay(attempt))
                continue
            self._client.cookies.clear()
            response.headers.pop("set-cookie", None)
            self._update_rate_limit(path, response)
            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < self._retries:
                time.sleep(_retry_delay(attempt, response))
                continue
            return finalize(response)
        msg = "Retry loop exited unexpectedly"
        raise RuntimeError(msg)

    def request(
        self,
        method: HTTPMethod,
        path: str,
        *,
        json: Mapping[str, object] | None = None,
        params: Mapping[str, QueryValue] | None = None,
        files: Mapping[str, FileValue] | None = None,
        add_api_key: bool = False,
    ) -> ResponseData:
        """Make an API request and return its parsed payload."""
        payload = dict(json) if json is not None else None
        query = dict(params) if params is not None else None
        if add_api_key and payload is not None:
            payload["apiKey"] = self._api_key

        def send(headers: Mapping[str, str]) -> httpx.Response:
            return self._client.request(
                method, path, json=payload, params=query, files=files, headers=headers
            )

        return self._run(path, send, parse_response)

    def request_bytes(
        self, method: HTTPMethod, path: str, *, params: Mapping[str, QueryValue]
    ) -> bytes:
        """Request a binary response, retaining retry and error semantics."""

        def send(headers: Mapping[str, str]) -> httpx.Response:
            return self._client.request(method, path, params=params, headers=headers)

        def finalize(response: httpx.Response) -> bytes:
            if response.is_error:
                _raise_api_error(response, _read_json(response))
            return response.content

        return self._run(path, send, finalize)

    def download(
        self,
        method: HTTPMethod,
        path: str,
        destination: Path,
        *,
        params: Mapping[str, QueryValue],
    ) -> Path:
        """Stream a binary response directly to a local file.

        Streaming decides retryability after the headers arrive but must consume
        the body inside the same context manager, so it keeps its own loop while
        reusing the shared helpers for rate limiting, ``Set-Cookie`` stripping,
        backoff, and error mapping.
        """
        bucket = self._bucket_for(path)
        headers = _request_headers(self._api_key)
        for attempt in range(1, self._retries + 1):
            if self._rate_limit:
                bucket.consume()
            try:
                with self._client.stream(method, path, params=params, headers=headers) as response:
                    self._client.cookies.clear()
                    response.headers.pop("set-cookie", None)
                    self._update_rate_limit(path, response)
                    if response.status_code in _RETRYABLE_STATUS_CODES and attempt < self._retries:
                        response.read()
                        time.sleep(_retry_delay(attempt, response))
                        continue
                    if response.is_error:
                        response.read()
                        _raise_api_error(response, _read_json(response))
                    with destination.open("wb") as output:
                        for chunk in response.iter_raw():
                            output.write(chunk)
                return destination
            except httpx.TransportError as error:
                if attempt == self._retries:
                    raise VulnersError("Unable to reach the Vulners API") from error
                time.sleep(_retry_delay(attempt))
        msg = "Retry loop exited unexpectedly"
        raise RuntimeError(msg)


class AsyncTransport(_TransportBase):
    """Asynchronous HTTPX transport using shared response semantics."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        timeout: float | httpx.Timeout,
        proxy: str | None,
        retries: int,
        rate_limit: bool,
        http_client: httpx.AsyncClient | None,
    ) -> None:
        super().__init__(api_key, base_url, retries, rate_limit)
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            proxy=proxy,
            http2=_HTTP2_AVAILABLE,
            follow_redirects=True,
        )
        self._client.cookies.clear()
        self._client.cookies.jar.set_policy(_RejectCookiesPolicy())

    async def aclose(self) -> None:
        """Close an internally managed asynchronous HTTPX client."""
        if self._owns_client:
            await self._client.aclose()

    async def _arun(
        self,
        path: str,
        send: Callable[[Mapping[str, str]], Awaitable[httpx.Response]],
        finalize: Callable[[httpx.Response], _T],
    ) -> _T:
        """Run one transport call through the shared asynchronous retry loop.

        Async mirror of ``SyncTransport._run``; every wait uses ``asyncio.sleep``
        so the event loop is never blocked.
        """
        bucket = self._bucket_for(path)
        headers = _request_headers(self._api_key)
        for attempt in range(1, self._retries + 1):
            if self._rate_limit:
                await bucket.aconsume()
            try:
                response = await send(headers)
            except httpx.TransportError as error:
                if attempt == self._retries:
                    raise VulnersError("Unable to reach the Vulners API") from error
                await asyncio.sleep(_retry_delay(attempt))
                continue
            self._client.cookies.clear()
            response.headers.pop("set-cookie", None)
            self._update_rate_limit(path, response)
            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < self._retries:
                await asyncio.sleep(_retry_delay(attempt, response))
                continue
            return finalize(response)
        msg = "Retry loop exited unexpectedly"
        raise RuntimeError(msg)

    async def request(
        self,
        method: HTTPMethod,
        path: str,
        *,
        json: Mapping[str, object] | None = None,
        params: Mapping[str, QueryValue] | None = None,
        files: Mapping[str, FileValue] | None = None,
        add_api_key: bool = False,
    ) -> ResponseData:
        """Make an API request and return its parsed payload without blocking the event loop."""
        payload = dict(json) if json is not None else None
        query = dict(params) if params is not None else None
        if add_api_key and payload is not None:
            payload["apiKey"] = self._api_key

        async def send(headers: Mapping[str, str]) -> httpx.Response:
            return await self._client.request(
                method, path, json=payload, params=query, files=files, headers=headers
            )

        return await self._arun(path, send, parse_response)

    async def request_bytes(
        self, method: HTTPMethod, path: str, *, params: Mapping[str, QueryValue]
    ) -> bytes:
        """Request a binary response, retaining retry and error semantics."""

        async def send(headers: Mapping[str, str]) -> httpx.Response:
            return await self._client.request(method, path, params=params, headers=headers)

        def finalize(response: httpx.Response) -> bytes:
            if response.is_error:
                _raise_api_error(response, _read_json(response))
            return response.content

        return await self._arun(path, send, finalize)

    async def download(
        self,
        method: HTTPMethod,
        path: str,
        destination: Path,
        *,
        params: Mapping[str, QueryValue],
    ) -> Path:
        """Stream a binary response directly to a local file without blocking the event loop."""
        bucket = self._bucket_for(path)
        headers = _request_headers(self._api_key)
        for attempt in range(1, self._retries + 1):
            if self._rate_limit:
                await bucket.aconsume()
            try:
                async with self._client.stream(
                    method, path, params=params, headers=headers
                ) as response:
                    self._client.cookies.clear()
                    response.headers.pop("set-cookie", None)
                    self._update_rate_limit(path, response)
                    if response.status_code in _RETRYABLE_STATUS_CODES and attempt < self._retries:
                        await response.aread()
                        await asyncio.sleep(_retry_delay(attempt, response))
                        continue
                    if response.is_error:
                        await response.aread()
                        _raise_api_error(response, _read_json(response))
                    output = await asyncio.to_thread(destination.open, "wb")
                    try:
                        async for chunk in response.aiter_raw():
                            await asyncio.to_thread(output.write, chunk)
                    finally:
                        await asyncio.to_thread(output.close)
                return destination
            except httpx.TransportError as error:
                if attempt == self._retries:
                    raise VulnersError("Unable to reach the Vulners API") from error
                await asyncio.sleep(_retry_delay(attempt))
        msg = "Retry loop exited unexpectedly"
        raise RuntimeError(msg)
