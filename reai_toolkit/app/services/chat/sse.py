"""Pure Server-Sent-Events frame parsing for the Agent Chat stream.

Ports the SSE read loop of ``Dashboard/utils/v2/agent/agentApi.ts::streamEvents``:
line-based framing, only ``data:`` frames, buffering across chunk boundaries,
``[DONE]`` handling and stopping on terminal events. No Qt / IDA / SDK imports,
so it is unit-testable against a fake byte-chunk iterator.
"""

from __future__ import annotations

import json
from typing import Callable, Iterable, Iterator, Optional

from reai_toolkit.app.services.chat.schema import (
    TERMINAL_EVENTS,
    ChatEvent,
    normalize_event,
)


def parse_sse_data_line(line: str) -> Optional[dict]:
    """Decode a single SSE line into its JSON object, or ``None``.

    Only ``data:`` lines carry payloads; ``event:`` / ``id:`` / comment (``:``)
    lines and the ``[DONE]`` sentinel are ignored.
    """
    line = line.strip()
    if not line.startswith("data:"):
        return None
    payload = line[len("data:"):].strip()
    if not payload or payload == "[DONE]":
        return None
    try:
        obj = json.loads(payload)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def event_from_frame(obj: dict) -> Optional[ChatEvent]:
    """Turn a decoded ``{type, event_id, data}`` envelope into a ChatEvent."""
    ev = normalize_event(obj.get("type"), obj.get("data"))
    if ev is None:
        return None
    eid = obj.get("event_id")
    if isinstance(eid, int) and not isinstance(eid, bool):
        ev.event_id = eid
    return ev


def iter_sse_events(
    chunks: Iterable[bytes],
    stop: Optional[Callable[[], bool]] = None,
) -> Iterator[ChatEvent]:
    """Yield :class:`ChatEvent`\\ s parsed from an iterable of raw byte chunks.

    ``stop`` is polled between chunks for cooperative cancellation. Iteration
    stops after a terminal event (RUN_FINISHED / RUN_ERROR / RUN_CANCELLED).
    """
    buf = b""
    for chunk in chunks:
        if stop is not None and stop():
            return
        if not chunk:
            continue
        buf += chunk
        parts = buf.split(b"\n")
        buf = parts.pop()
        for raw in parts:
            line = raw.rstrip(b"\r").decode("utf-8", "replace")
            obj = parse_sse_data_line(line)
            if obj is None:
                continue
            ev = event_from_frame(obj)
            if ev is None:
                continue
            yield ev
            if ev.type in TERMINAL_EVENTS:
                return
