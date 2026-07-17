"""Typed archive records."""

from pydantic import BaseModel, ConfigDict, TypeAdapter


class ArchiveRecord(BaseModel):
    """A forward-compatible document decoded from a Vulners archive."""

    model_config = ConfigDict(frozen=True, extra="allow")

    id: str | None = None
    type: str | None = None


_ARCHIVE_RECORDS_ADAPTER = TypeAdapter(tuple[ArchiveRecord, ...])
