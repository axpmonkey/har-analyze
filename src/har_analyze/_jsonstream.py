"""Typed wrapper around ijson's event parser (ijson ships no type information)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import IO, Any, cast

import ijson  # pyright: ignore[reportMissingTypeStubs] - no stubs published
from ijson.common import (  # pyright: ignore[reportMissingTypeStubs]
    ObjectBuilder as _IjsonObjectBuilder,
)

__all__ = ["JSONStreamError", "ObjectBuilder", "iter_json_events"]

JSONStreamError: type[Exception] = cast("type[Exception]", ijson.JSONError)


class ObjectBuilder:
    """Build one JSON value from parser events (see ``ijson.common.ObjectBuilder``)."""

    def __init__(self) -> None:
        """Start an empty value."""
        self._builder: Any = _IjsonObjectBuilder()

    def event(self, event: str, value: object) -> None:
        """Feed one parser event."""
        self._builder.event(event, value)

    @property
    def value(self) -> object:
        """The value built so far."""
        return cast("object", self._builder.value)


# HAR files embed multi-megabyte bodies as single JSON strings. With ijson's default
# 64 KiB buffer the C backend re-assembles such strings chunk by chunk, which made a
# 950 MB capture take 23 s to read; with 8 MiB it takes about 1 s.
READ_BUFFER_BYTES = 8 * 1024 * 1024


def iter_json_events(handle: IO[bytes]) -> Iterator[tuple[str, str, object]]:
    """Yield ``(prefix, event, value)`` for a binary JSON stream; numbers become floats/ints."""
    events = cast(
        "Iterator[tuple[str, str, object]]",
        ijson.parse(handle, use_float=True, buf_size=READ_BUFFER_BYTES),
    )
    yield from events
