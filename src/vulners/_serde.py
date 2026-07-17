"""JSON serialization helpers with an optional orjson fast path."""

from __future__ import annotations

import json
from importlib import import_module
from typing import Protocol, TypeAlias, cast

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
