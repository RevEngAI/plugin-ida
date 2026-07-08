"""SSE frame parser tests — feed fake byte chunks, no network."""

from reai_toolkit.app.services.chat.schema import EntityRef, normalize_event
from reai_toolkit.app.services.chat.sse import (
    event_from_frame,
    iter_sse_events,
    parse_sse_data_line,
)


def _frame(obj_json: str) -> bytes:
    return f"data: {obj_json}\n".encode()


def test_parse_data_line_ignores_non_data():
    assert parse_sse_data_line("event: message") is None
    assert parse_sse_data_line(": comment") is None
    assert parse_sse_data_line("id: 5") is None
    assert parse_sse_data_line("") is None


def test_parse_data_line_done_and_empty():
    assert parse_sse_data_line("data: [DONE]") is None
    assert parse_sse_data_line("data:") is None


def test_parse_data_line_decodes_json():
    assert parse_sse_data_line('data: {"type": 1}') == {"type": 1}


def test_event_from_frame_tracks_event_id():
    ev = event_from_frame({"type": 7, "event_id": 9, "data": {"message_id": "m", "delta": "x"}})
    assert ev is not None
    assert ev.type == "TEXT_MESSAGE_CONTENT"
    assert ev.event_id == 9
    assert ev.delta == "x"


def test_integer_type_is_decoded():
    events = list(iter_sse_events([_frame('{"type": 6, "data": {"message_id": "m1"}}')]))
    assert [e.type for e in events] == ["TEXT_MESSAGE_START"]
    assert events[0].role == "assistant"


def test_string_type_passthrough():
    events = list(iter_sse_events([_frame('{"type": "TITLE_UPDATED", "data": {"title": "T"}}')]))
    assert events[0].type == "TITLE_UPDATED"
    assert events[0].title == "T"


def test_snake_case_leaf_normalization():
    frame = _frame('{"type": 9, "data": {"tool_call_id": "t1", "tool_name": "read_fn"}}')
    ev = list(iter_sse_events([frame]))[0]
    assert ev.tool_call_id == "t1"
    assert ev.tool_name == "read_fn"


def test_frames_split_across_chunk_boundaries():
    whole = _frame('{"type": 7, "data": {"message_id": "m", "delta": "hello"}}')
    mid = len(whole) // 2
    chunks = [whole[:mid], whole[mid:]]
    events = list(iter_sse_events(chunks))
    assert len(events) == 1
    assert events[0].delta == "hello"


def test_crlf_line_endings():
    frame = b'data: {"type": "TITLE_UPDATED", "data": {"title": "T"}}\r\n'
    events = list(iter_sse_events([frame]))
    assert events[0].title == "T"


def test_multiple_frames_in_one_chunk():
    chunk = (
        _frame('{"type": 1}')
        + _frame('{"type": 7, "data": {"message_id": "m", "delta": "a"}}')
    )
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["RUN_STARTED", "TEXT_MESSAGE_CONTENT"]


def test_event_and_id_lines_ignored():
    chunk = b"event: message\nid: 3\n" + _frame('{"type": 1}')
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["RUN_STARTED"]


def test_done_sentinel_and_blank_lines_skipped():
    chunk = b"\n" + _frame('{"type": 1}') + b"data: [DONE]\n"
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["RUN_STARTED"]


def test_terminal_event_stops_iteration():
    chunk = (
        _frame('{"type": 2}')
        + _frame('{"type": 1}')
    )
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["RUN_FINISHED"]


def test_stop_callback_short_circuits():
    calls = {"n": 0}

    def stop():
        calls["n"] += 1
        return True

    events = list(iter_sse_events([_frame('{"type": 1}')], stop=stop))
    assert events == []


def test_bad_json_frame_is_skipped():
    chunk = b"data: {not json}\n" + _frame('{"type": 1}')
    events = list(iter_sse_events([chunk]))
    assert [e.type for e in events] == ["RUN_STARTED"]


def test_unknown_int_type_is_dropped():
    assert normalize_event(999, {}) is None
    events = list(iter_sse_events([_frame('{"type": 999, "data": {}}')]))
    assert events == []


def test_run_error_defaults_message():
    ev = list(iter_sse_events([_frame('{"type": 3, "data": {}}')]))[0]
    assert ev.type == "RUN_ERROR"
    assert ev.message == "Unknown error"


def test_run_error_uses_error_key_as_message():
    ev = list(iter_sse_events([_frame('{"type": 3, "data": {"error": "kaboom"}}')]))[0]
    assert ev.message == "kaboom"


def test_tool_result_entity_updates_parsed():
    frame = _frame(
        '{"type": 12, "data": {"tool_call_id": "t", "tool_name": "d", '
        '"updated": [{"type": "function", "ids": [1, 2]}]}}'
    )
    ev = list(iter_sse_events([frame]))[0]
    assert ev.updated is not None
    assert ev.updated[0].type == "function"
    assert ev.updated[0].ids == [1, 2]
    assert ev.updated[0].refs == []


def test_tool_result_entity_refs_parsed():
    frame = _frame(
        '{"type": 12, "data": {"tool_call_id": "t", "tool_name": "rename_functions", '
        '"updated": [{"type": "function", "ids": [2015699787], '
        '"refs": [{"id": 2015699787, "name": "region_position", "vaddr": 4198416}]}]}}'
    )
    ev = list(iter_sse_events([frame]))[0]
    assert ev.updated is not None
    assert ev.updated[0].refs == [
        EntityRef(id=2015699787, name="region_position", vaddr=4198416)
    ]
