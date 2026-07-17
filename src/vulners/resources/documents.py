"""Typed sync and async retrieval of Vulners bulletins and their references."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Final

from pydantic import TypeAdapter

from ..types.documents import BulletinReferences, BulletinWithReferences, KBSeeds
from ..types.search import SearchDocument, SearchPage

if TYPE_CHECKING:
    from .._transport import AsyncTransport, ResponseData, SyncTransport
    from .search import AsyncSearchResource, SearchResource

_DOCUMENTS_PATH: Final = "/api/v3/search/id/"
DEFAULT_DOCUMENT_FIELDS: Final = (
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
_DOCUMENTS_ADAPTER = TypeAdapter(dict[str, SearchDocument])
_REFERENCE_SOURCES_ADAPTER = TypeAdapter(dict[str, tuple[SearchDocument, ...]])
_SEEDS_ADAPTER = TypeAdapter(tuple[str, ...])


def _document_payload(
    ids: Sequence[str], fields: Sequence[str], references: bool
) -> dict[str, object]:
    if not ids:
        msg = "ids must not be empty"
        raise ValueError(msg)
    return {"id": list(ids), "fields": list(fields), "references": references}


def _parse_documents(data: ResponseData) -> tuple[dict[str, SearchDocument], Mapping[str, object]]:
    if not isinstance(data, Mapping):
        msg = "Unexpected response shape for /api/v3/search/id/"
        raise ValueError(msg)
    raw_documents = data.get("documents")
    raw_references = data.get("references", {})
    if not isinstance(raw_documents, Mapping) or not isinstance(raw_references, Mapping):
        msg = "Unexpected document payload from /api/v3/search/id/"
        raise ValueError(msg)
    return _DOCUMENTS_ADAPTER.validate_python(raw_documents), raw_references


def _references_for(id: str, raw_references: Mapping[str, object]) -> BulletinReferences:
    raw_sources = raw_references.get(id, {})
    if not isinstance(raw_sources, Mapping):
        msg = "Unexpected references payload from /api/v3/search/id/"
        raise ValueError(msg)
    return BulletinReferences(
        id=id, sources=_REFERENCE_SOURCES_ADAPTER.validate_python(raw_sources)
    )


def _documents_in_order(
    ids: Sequence[str], documents: Mapping[str, SearchDocument]
) -> tuple[SearchDocument, ...]:
    return tuple(documents[id] for id in ids if id in documents)


class DocumentsResource:
    """Synchronous bulletin retrieval operations."""

    def __init__(self, transport: SyncTransport, search: SearchResource) -> None:
        self._transport = transport
        self._search = search

    def get(
        self, id: str, *, fields: Sequence[str] = DEFAULT_DOCUMENT_FIELDS
    ) -> SearchDocument | None:
        """Get one bulletin through ``POST /api/v3/search/id/``.

        Args:
            id: Vulners bulletin or subscription identifier.
            fields: Response fields to request.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        documents = self.get_many((id,), fields=fields)
        return documents[0] if documents else None

    def get_many(
        self, ids: Sequence[str], *, fields: Sequence[str] = DEFAULT_DOCUMENT_FIELDS
    ) -> tuple[SearchDocument, ...]:
        """Get the found bulletins through ``POST /api/v3/search/id/``.

        Args:
            ids: Identifiers to process.
            fields: Response fields to request.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = self._transport.request(
            "POST", _DOCUMENTS_PATH, json=_document_payload(ids, fields, False)
        )
        documents, _ = _parse_documents(data)
        return _documents_in_order(ids, documents)

    def references(self, id: str) -> BulletinReferences:
        """Get references for one bulletin through ``POST /api/v3/search/id/``.

        Args:
            id: Vulners bulletin or subscription identifier.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        return self.references_many((id,))[0]

    def references_many(self, ids: Sequence[str]) -> tuple[BulletinReferences, ...]:
        """Get references for multiple bulletins through ``POST /api/v3/search/id/``.

        Args:
            ids: Identifiers to process.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = self._transport.request(
            "POST", _DOCUMENTS_PATH, json=_document_payload(ids, (), True)
        )
        _, raw_references = _parse_documents(data)
        return tuple(_references_for(id, raw_references) for id in ids)

    def get_with_references(
        self, id: str, *, fields: Sequence[str] = DEFAULT_DOCUMENT_FIELDS
    ) -> BulletinWithReferences:
        """Get one bulletin and references through ``POST /api/v3/search/id/``.

        Args:
            id: Vulners bulletin or subscription identifier.
            fields: Response fields to request.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        return self.get_many_with_references((id,), fields=fields)[0]

    def get_many_with_references(
        self, ids: Sequence[str], *, fields: Sequence[str] = DEFAULT_DOCUMENT_FIELDS
    ) -> tuple[BulletinWithReferences, ...]:
        """Get bulletins and references through ``POST /api/v3/search/id/``.

        Args:
            ids: Identifiers to process.
            fields: Response fields to request.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = self._transport.request(
            "POST", _DOCUMENTS_PATH, json=_document_payload(ids, fields, True)
        )
        documents, raw_references = _parse_documents(data)
        return tuple(
            BulletinWithReferences(
                document=documents.get(id), references=_references_for(id, raw_references)
            )
            for id in ids
        )

    def kb_seeds(self, kbid: str) -> KBSeeds:
        """Get KB supersedence data through ``POST /api/v3/search/id/``.

        Args:
            kbid: Microsoft KB identifier.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        document = self.get(kbid, fields=("superseeds", "parentseeds"))
        extra = document.model_extra or {} if document is not None else {}
        return KBSeeds(
            kbid=kbid,
            superseeds=_SEEDS_ADAPTER.validate_python(extra.get("superseeds") or ()),
            parentseeds=_SEEDS_ADAPTER.validate_python(extra.get("parentseeds") or ()),
        )

    def kb_updates(
        self, kbid: str, *, fields: Sequence[str] = DEFAULT_DOCUMENT_FIELDS
    ) -> SearchPage:
        """Search KB updates through ``POST /api/v3/search/lucene/``.

        Args:
            kbid: Microsoft KB identifier.
            fields: Response fields to request.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        return self._search.bulletins(f"type:msupdate AND kb:({kbid})", limit=1000, fields=fields)


class AsyncDocumentsResource:
    """Asynchronous bulletin retrieval operations."""

    def __init__(self, transport: AsyncTransport, search: AsyncSearchResource) -> None:
        self._transport = transport
        self._search = search

    async def get(
        self, id: str, *, fields: Sequence[str] = DEFAULT_DOCUMENT_FIELDS
    ) -> SearchDocument | None:
        """Get one bulletin through ``POST /api/v3/search/id/``.

        Args:
            id: Vulners bulletin or subscription identifier.
            fields: Response fields to request.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        documents = await self.get_many((id,), fields=fields)
        return documents[0] if documents else None

    async def get_many(
        self, ids: Sequence[str], *, fields: Sequence[str] = DEFAULT_DOCUMENT_FIELDS
    ) -> tuple[SearchDocument, ...]:
        """Get the found bulletins through ``POST /api/v3/search/id/``.

        Args:
            ids: Identifiers to process.
            fields: Response fields to request.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = await self._transport.request(
            "POST", _DOCUMENTS_PATH, json=_document_payload(ids, fields, False)
        )
        documents, _ = _parse_documents(data)
        return _documents_in_order(ids, documents)

    async def references(self, id: str) -> BulletinReferences:
        """Get references for one bulletin through ``POST /api/v3/search/id/``.

        Args:
            id: Vulners bulletin or subscription identifier.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        return (await self.references_many((id,)))[0]

    async def references_many(self, ids: Sequence[str]) -> tuple[BulletinReferences, ...]:
        """Get references for multiple bulletins through ``POST /api/v3/search/id/``.

        Args:
            ids: Identifiers to process.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = await self._transport.request(
            "POST", _DOCUMENTS_PATH, json=_document_payload(ids, (), True)
        )
        _, raw_references = _parse_documents(data)
        return tuple(_references_for(id, raw_references) for id in ids)

    async def get_with_references(
        self, id: str, *, fields: Sequence[str] = DEFAULT_DOCUMENT_FIELDS
    ) -> BulletinWithReferences:
        """Get one bulletin and references through ``POST /api/v3/search/id/``.

        Args:
            id: Vulners bulletin or subscription identifier.
            fields: Response fields to request.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        return (await self.get_many_with_references((id,), fields=fields))[0]

    async def get_many_with_references(
        self, ids: Sequence[str], *, fields: Sequence[str] = DEFAULT_DOCUMENT_FIELDS
    ) -> tuple[BulletinWithReferences, ...]:
        """Get bulletins and references through ``POST /api/v3/search/id/``.

        Args:
            ids: Identifiers to process.
            fields: Response fields to request.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        data = await self._transport.request(
            "POST", _DOCUMENTS_PATH, json=_document_payload(ids, fields, True)
        )
        documents, raw_references = _parse_documents(data)
        return tuple(
            BulletinWithReferences(
                document=documents.get(id), references=_references_for(id, raw_references)
            )
            for id in ids
        )

    async def kb_seeds(self, kbid: str) -> KBSeeds:
        """Get KB supersedence data through ``POST /api/v3/search/id/``.

        Args:
            kbid: Microsoft KB identifier.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        document = await self.get(kbid, fields=("superseeds", "parentseeds"))
        extra = document.model_extra or {} if document is not None else {}
        return KBSeeds(
            kbid=kbid,
            superseeds=_SEEDS_ADAPTER.validate_python(extra.get("superseeds") or ()),
            parentseeds=_SEEDS_ADAPTER.validate_python(extra.get("parentseeds") or ()),
        )

    async def kb_updates(
        self, kbid: str, *, fields: Sequence[str] = DEFAULT_DOCUMENT_FIELDS
    ) -> SearchPage:
        """Search KB updates through ``POST /api/v3/search/lucene/``.

        Args:
            kbid: Microsoft KB identifier.
            fields: Response fields to request.

        Returns:
            The typed API result.

        Raises:
            ValueError: If an argument or response fails validation.
            VulnersError: If the API request fails.
        """
        return await self._search.bulletins(
            f"type:msupdate AND kb:({kbid})", limit=1000, fields=fields
        )
