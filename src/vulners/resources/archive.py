"""Streaming sync and async Vulners archive resources."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal, overload

from .._serde import archive_loads
from ..types.archive import _ARCHIVE_RECORDS_ADAPTER, ArchiveRecord

if TYPE_CHECKING:
    from pathlib import Path

    from .._transport import AsyncTransport, SyncTransport

_COLLECTION_V3: Final = "/api/v3/archive/collection/"
_COLLECTION_V4: Final = "/api/v4/archive/collection"
_COLLECTION_UPDATE: Final = "/api/v4/archive/collection-update"
_DISTRIBUTIVE: Final = "/api/v3/archive/distributive/"
_GETSPLOIT: Final = "/api/v3/archive/getsploit/"


def _records(payload: bytes) -> tuple[ArchiveRecord, ...]:
    values = archive_loads(payload)
    normalized = [
        value["_source"]
        if isinstance(value, dict) and isinstance(value.get("_source"), dict)
        else value
        for value in values
    ]
    return _ARCHIVE_RECORDS_ADAPTER.validate_python(normalized)


def _destination(raw: bool, destination: Path | None) -> Path:
    if not raw or destination is None:
        msg = "destination is required when raw=True"
        raise ValueError(msg)
    return destination


class ArchiveResource:
    """Synchronous archive downloads and decoding."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    @overload
    def collection(
        self,
        type: str,
        *,
        date_from: str = "1976-01-01",
        date_to: str = "2199-01-01",
        raw: Literal[False] = False,
        destination: None = None,
    ) -> tuple[ArchiveRecord, ...]: ...

    @overload
    def collection(
        self,
        type: str,
        *,
        date_from: str = "1976-01-01",
        date_to: str = "2199-01-01",
        raw: Literal[True],
        destination: Path,
    ) -> Path: ...

    def collection(
        self,
        type: str,
        *,
        date_from: str = "1976-01-01",
        date_to: str = "2199-01-01",
        raw: bool = False,
        destination: Path | None = None,
    ) -> tuple[ArchiveRecord, ...] | Path:
        """Download the classic collection ZIP from ``GET /api/v3/archive/collection/``.

        Args:
            type: Vulners collection type.
            date_from: Inclusive ISO date lower bound.
            date_to: Inclusive ISO date upper bound.
            raw: Stream the encoded response instead of decoding it.
            destination: Output path required for a raw download.

        Returns:
            Decoded archive records, or the written path for a raw download.

        Raises:
            ValueError: If ``raw`` is true without a destination.
            VulnersError: If the API request fails.
        """
        params = {"type": type, "datefrom": date_from, "dateto": date_to}
        if raw:
            return self._transport.download(
                "GET", _COLLECTION_V3, _destination(raw, destination), params=params
            )
        return _records(self._transport.request_bytes("GET", _COLLECTION_V3, params=params))

    @overload
    def collection_v4(
        self,
        type: str,
        *,
        raw: Literal[False] = False,
        destination: None = None,
    ) -> tuple[ArchiveRecord, ...]: ...

    @overload
    def collection_v4(
        self,
        type: str,
        *,
        raw: Literal[True],
        destination: Path,
    ) -> Path: ...

    def collection_v4(
        self,
        type: str,
        *,
        raw: bool = False,
        destination: Path | None = None,
    ) -> tuple[ArchiveRecord, ...] | Path:
        """Download the current collection stream from ``GET /api/v4/archive/collection``.

        Args:
            type: Vulners collection type.
            raw: Stream the encoded response instead of decoding it.
            destination: Output path required for a raw download.

        Returns:
            Decoded archive records, or the written path for a raw download.

        Raises:
            ValueError: If ``raw`` is true without a destination.
            VulnersError: If the API request fails.
        """
        params = {"type": type}
        if raw:
            return self._transport.download(
                "GET", _COLLECTION_V4, _destination(raw, destination), params=params
            )
        return _records(self._transport.request_bytes("GET", _COLLECTION_V4, params=params))

    def collection_update(
        self,
        type: str,
        after: str,
        *,
        raw: bool = False,
        destination: Path | None = None,
    ) -> tuple[ArchiveRecord, ...] | Path:
        """Get incremental records through ``GET /api/v4/archive/collection-update``.

        Args:
            type: Vulners collection type.
            after: ISO timestamp after which records are selected.
            raw: Stream the encoded response instead of decoding it.
            destination: Output path required for a raw download.

        Returns:
            Decoded archive records, or the written path for a raw download.

        Raises:
            ValueError: If ``raw`` is true without a destination.
            VulnersError: If the API request fails.
        """
        params = {"type": type, "after": after}
        if raw:
            return self._transport.download(
                "GET", _COLLECTION_UPDATE, _destination(raw, destination), params=params
            )
        payload = self._transport.request_bytes("GET", _COLLECTION_UPDATE, params=params)
        return _records(payload)

    def distributive(
        self,
        os: str,
        version: str,
        *,
        raw: bool = False,
        destination: Path | None = None,
    ) -> tuple[ArchiveRecord, ...] | Path:
        """Get an OS archive through ``GET /api/v3/archive/distributive/``.

        Args:
            os: Distribution name.
            version: Distribution version.
            raw: Stream the encoded response instead of decoding it.
            destination: Output path required for a raw download.

        Returns:
            Decoded archive records, or the written path for a raw download.

        Raises:
            ValueError: If ``raw`` is true without a destination.
            VulnersError: If the API request fails.
        """
        params = {"os": os, "version": version}
        if raw:
            return self._transport.download(
                "GET", _DISTRIBUTIVE, _destination(raw, destination), params=params
            )
        payload = self._transport.request_bytes("GET", _DISTRIBUTIVE, params=params)
        return _records(payload)

    def getsploit(self, id: str, destination: Path) -> Path:
        """Stream a Getsploit archive through ``GET /api/v3/archive/getsploit/``.

        Args:
            id: Bulletin identifier.
            destination: Output archive path.

        Returns:
            The written output path.

        Raises:
            VulnersError: If the API request fails.
        """
        return self._transport.download("GET", _GETSPLOIT, destination, params={"id": id})


class AsyncArchiveResource:
    """Asynchronous archive downloads and decoding."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def collection(
        self,
        type: str,
        *,
        date_from: str = "1976-01-01",
        date_to: str = "2199-01-01",
        raw: bool = False,
        destination: Path | None = None,
    ) -> tuple[ArchiveRecord, ...] | Path:
        """Download the classic collection ZIP from ``GET /api/v3/archive/collection/``.

        Args:
            type: Vulners collection type.
            date_from: Inclusive ISO date lower bound.
            date_to: Inclusive ISO date upper bound.
            raw: Stream the encoded response instead of decoding it.
            destination: Output path required for a raw download.

        Returns:
            Decoded archive records, or the written path for a raw download.

        Raises:
            ValueError: If ``raw`` is true without a destination.
            VulnersError: If the API request fails.
        """
        params = {"type": type, "datefrom": date_from, "dateto": date_to}
        if raw:
            return await self._transport.download(
                "GET", _COLLECTION_V3, _destination(raw, destination), params=params
            )
        return _records(await self._transport.request_bytes("GET", _COLLECTION_V3, params=params))

    async def collection_v4(
        self,
        type: str,
        *,
        raw: bool = False,
        destination: Path | None = None,
    ) -> tuple[ArchiveRecord, ...] | Path:
        """Download the current collection stream from ``GET /api/v4/archive/collection``.

        Args:
            type: Vulners collection type.
            raw: Stream the encoded response instead of decoding it.
            destination: Output path required for a raw download.

        Returns:
            Decoded archive records, or the written path for a raw download.

        Raises:
            ValueError: If ``raw`` is true without a destination.
            VulnersError: If the API request fails.
        """
        params = {"type": type}
        if raw:
            return await self._transport.download(
                "GET", _COLLECTION_V4, _destination(raw, destination), params=params
            )
        return _records(await self._transport.request_bytes("GET", _COLLECTION_V4, params=params))

    async def collection_update(
        self,
        type: str,
        after: str,
        *,
        raw: bool = False,
        destination: Path | None = None,
    ) -> tuple[ArchiveRecord, ...] | Path:
        """Get incremental records through ``GET /api/v4/archive/collection-update``.

        Args:
            type: Vulners collection type.
            after: ISO timestamp after which records are selected.
            raw: Stream the encoded response instead of decoding it.
            destination: Output path required for a raw download.

        Returns:
            Decoded archive records, or the written path for a raw download.

        Raises:
            ValueError: If ``raw`` is true without a destination.
            VulnersError: If the API request fails.
        """
        params = {"type": type, "after": after}
        if raw:
            return await self._transport.download(
                "GET", _COLLECTION_UPDATE, _destination(raw, destination), params=params
            )
        payload = await self._transport.request_bytes("GET", _COLLECTION_UPDATE, params=params)
        return _records(payload)

    async def distributive(
        self,
        os: str,
        version: str,
        *,
        raw: bool = False,
        destination: Path | None = None,
    ) -> tuple[ArchiveRecord, ...] | Path:
        """Get an OS archive through ``GET /api/v3/archive/distributive/``.

        Args:
            os: Distribution name.
            version: Distribution version.
            raw: Stream the encoded response instead of decoding it.
            destination: Output path required for a raw download.

        Returns:
            Decoded archive records, or the written path for a raw download.

        Raises:
            ValueError: If ``raw`` is true without a destination.
            VulnersError: If the API request fails.
        """
        params = {"os": os, "version": version}
        if raw:
            return await self._transport.download(
                "GET", _DISTRIBUTIVE, _destination(raw, destination), params=params
            )
        payload = await self._transport.request_bytes("GET", _DISTRIBUTIVE, params=params)
        return _records(payload)

    async def getsploit(self, id: str, destination: Path) -> Path:
        """Stream a Getsploit archive through ``GET /api/v3/archive/getsploit/``.

        Args:
            id: Bulletin identifier.
            destination: Output archive path.

        Returns:
            The written output path.

        Raises:
            VulnersError: If the API request fails.
        """
        return await self._transport.download("GET", _GETSPLOIT, destination, params={"id": id})
