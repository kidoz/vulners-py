"""JSON serialization helpers with an optional orjson fast path."""

from __future__ import annotations

import json
from gzip import decompress
from importlib import import_module
from io import BytesIO
from typing import Protocol, TypeAlias, cast
from zipfile import BadZipFile, ZipFile

JSONValue: TypeAlias = dict[str, object] | list[object] | str | int | float | bool | None


class _OrjsonModule(Protocol):
    def loads(self, __obj: bytes) -> JSONValue:
        """Deserialize JSON bytes."""


_orjson: _OrjsonModule | None
try:
    _orjson = cast("_OrjsonModule", import_module("orjson"))
except ModuleNotFoundError:  # pragma: no cover - depends on optional installation
    _orjson = None


def json_loads(payload: bytes) -> JSONValue:
    """Deserialize a JSON HTTP payload."""
    if _orjson is not None:
        return _orjson.loads(payload)
    return cast("JSONValue", json.loads(payload.decode("utf-8")))


def archive_loads(payload: bytes) -> list[object]:
    """Decode ZIP, gzip, JSON, or NDJSON archive bytes into records."""
    if payload.startswith(b"PK"):
        try:
            with ZipFile(BytesIO(payload)) as archive:
                records: list[object] = []
                for name in archive.namelist():
                    if not name.endswith("/"):
                        records.extend(archive_loads(archive.read(name)))
                return records
        except BadZipFile as error:
            msg = "Invalid ZIP archive returned by Vulners"
            raise ValueError(msg) from error
    if payload.startswith(b"\x1f\x8b"):
        return archive_loads(decompress(payload))
    stripped = payload.strip()
    if not stripped:
        return []
    try:
        value = json_loads(stripped)
    except (TypeError, UnicodeDecodeError, ValueError):
        records = []
        for line in stripped.splitlines():
            value = json_loads(line)
            records.extend(value if isinstance(value, list) else [value])
        return records
    return value if isinstance(value, list) else [value]
