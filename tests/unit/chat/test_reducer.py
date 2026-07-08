"""Reducer state-machine tests — mirror every case of the Dashboard reducer.ts."""

from reai_toolkit.app.services.chat.reducer import (
    ApiError,
    Cancel,
    ConfirmTool,
    EventAction,
    SendMessage,
    build_initial_state,
    chat_reducer,
    initial_state,
)
from reai_toolkit.app.services.chat.schema import (
    AssistantMessage,
    ChatEvent,
    ContextCompacted,
    EntityRef,
    EntityUpdate,
    FunctionRef,
    Step,
    ToolCall,
    ToolConfirmation,
    UserMessage,
    UserMessageReplay,
)


def _ev(type_, **kw):
    return ChatEvent(type=type_, **kw)


def _fold(events, state=None):
    state = state or initial_state()
    for ev in events:
        state = chat_reducer(state, EventAction(ev))
    return state


def test_send_message_appends_user_and_runs():
    state = chat_reducer(initial_state(), SendMessage(id="u1", content="hi"))
    assert state.run_status == "running"
    assert len(state.items) == 1
    assert isinstance(state.items[0], UserMessage)
    assert state.items[0].content == "hi"


def test_text_message_flow_accumulates_by_id():
    state = _fold(
        [
            _ev("TEXT_MESSAGE_START", message_id="a"),
            _ev("TEXT_MESSAGE_CONTENT", message_id="a", delta="Hel"),
            _ev("TEXT_MESSAGE_CONTENT", message_id="a", delta="lo"),
            _ev("TEXT_MESSAGE_END", message_id="a"),
        ]
    )
    msg = state.items[-1]
    assert isinstance(msg, AssistantMessage)
    assert msg.content == "Hello"
    assert msg.is_streaming is False


def test_text_message_start_is_deduped():
    state = _fold(
        [
            _ev("TEXT_MESSAGE_START", message_id="a"),
            _ev("TEXT_MESSAGE_START", message_id="a"),
        ]
    )
    assistants = [i for i in state.items if isinstance(i, AssistantMessage)]
    assert len(assistants) == 1


def test_tool_call_lifecycle():
    state = _fold(
        [
            _ev("TOOL_CALL_START", tool_call_id="t1", tool_name="read_function"),
            _ev("TOOL_CALL_END", tool_call_id="t1"),
        ]
    )
    tool = state.items[-1]
    assert isinstance(tool, ToolCall)
    assert tool.name == "read_function"
    assert tool.status == "finished"
    assert tool.is_error is False


def test_tool_call_result_sets_error_and_finished():
    state = _fold(
        [
            _ev("TOOL_CALL_START", tool_call_id="t1", tool_name="do"),
            _ev("TOOL_CALL_RESULT", tool_call_id="t1", tool_name="do", is_error=True),
        ]
    )
    tool = state.items[-1]
    assert tool.status == "finished"
    assert tool.is_error is True


def test_confirmation_then_confirm_tool_approved():
    state = _fold(
        [_ev("TOOL_CONFIRMATION_REQUIRED", tool_call_id="c1", tool_name="rm", message="ok?")]
    )
    state = chat_reducer(state, ConfirmTool(id="c1", approved=True))
    conf = state.items[-1]
    assert isinstance(conf, ToolConfirmation)
    assert conf.status == "approved"
    assert state.run_status == "running"


def test_confirm_tool_rejected_keeps_status():
    state = _fold(
        [_ev("TOOL_CONFIRMATION_REQUIRED", tool_call_id="c1", tool_name="rm", message="ok?")]
    )
    state = chat_reducer(state, ConfirmTool(id="c1", approved=False))
    assert state.items[-1].status == "rejected"
    assert state.run_status == "idle"


def test_tool_call_result_resolves_pending_confirmation():
    state = _fold(
        [
            _ev("TOOL_CONFIRMATION_REQUIRED", tool_call_id="c1", tool_name="rm", message="?"),
            _ev("TOOL_CALL_RESULT", tool_call_id="c1", tool_name="rm", is_error=False),
        ]
    )
    conf = [i for i in state.items if isinstance(i, ToolConfirmation)][0]
    assert conf.status == "approved"


def test_tool_call_result_error_rejects_pending_confirmation():
    state = _fold(
        [
            _ev("TOOL_CONFIRMATION_REQUIRED", tool_call_id="c1", tool_name="rm", message="?"),
            _ev("TOOL_CALL_RESULT", tool_call_id="c1", tool_name="rm", is_error=True),
        ]
    )
    conf = [i for i in state.items if isinstance(i, ToolConfirmation)][0]
    assert conf.status == "rejected"


def test_cancel_finalizes_running_items():
    state = _fold(
        [
            _ev("TEXT_MESSAGE_START", message_id="a"),
            _ev("TOOL_CALL_START", tool_call_id="t1", tool_name="x"),
            _ev("STEP_STARTED"),
            _ev("TOOL_CONFIRMATION_REQUIRED", tool_call_id="c1", tool_name="y", message="?"),
        ]
    )
    state = chat_reducer(state, Cancel())
    assert state.run_status == "idle"
    kinds = {}
    for i in state.items:
        kinds[i.kind] = i
    assert kinds["assistant-message"].is_streaming is False
    assert kinds["tool-call"].status == "finished"
    assert kinds["step"].status == "finished"
    assert kinds["tool-confirmation"].status == "rejected"


def test_run_error_sets_error_and_finalizes():
    state = _fold([_ev("TOOL_CALL_START", tool_call_id="t1", tool_name="x")])
    state = _fold([_ev("RUN_ERROR", message="boom")], state)
    assert state.run_status == "error"
    assert state.run_error.message == "boom"
    assert state.items[-1].status == "finished"


def test_run_lifecycle_status():
    state = _fold([_ev("RUN_STARTED")])
    assert state.run_status == "running"
    state = _fold([_ev("RUN_FINISHED")], state)
    assert state.run_status == "idle"


def test_run_cancelled_goes_idle():
    state = _fold([_ev("TOOL_CALL_START", tool_call_id="t", tool_name="x"), _ev("RUN_CANCELLED")])
    assert state.run_status == "idle"
    assert state.items[-1].status == "finished"


def test_title_updated():
    state = _fold([_ev("TITLE_UPDATED", title="My chat")])
    assert state.title == "My chat"


def test_step_started_and_finished():
    state = _fold([_ev("STEP_STARTED")])
    assert isinstance(state.items[-1], Step)
    assert state.items[-1].status == "running"
    state = _fold([_ev("STEP_FINISHED")], state)
    assert state.items[-1].status == "finished"


def test_context_compacted_appends():
    state = _fold([_ev("CONTEXT_COMPACTED")])
    assert isinstance(state.items[-1], ContextCompacted)


def test_tool_call_args_delta_is_noop():
    before = _fold([_ev("TOOL_CALL_START", tool_call_id="t", tool_name="x")])
    after = chat_reducer(before, EventAction(_ev("TOOL_CALL_ARGS_DELTA", tool_call_id="t", delta="{")))
    assert len(after.items) == len(before.items)


def test_api_error_action_finalizes():
    state = _fold([_ev("TEXT_MESSAGE_START", message_id="a")])
    state = chat_reducer(state, ApiError(message="nope", code="X", doc_url="u"))
    assert state.run_status == "error"
    assert state.run_error.code == "X"
    assert state.items[-1].is_streaming is False


def _rename_result_events():
    return [
        _ev("TOOL_CALL_START", tool_call_id="t1", tool_name="rename_functions"),
        _ev(
            "TOOL_CALL_RESULT",
            tool_call_id="t1",
            tool_name="rename_functions",
            updated=[
                EntityUpdate(
                    type="function",
                    ids=[2015699787],
                    refs=[
                        EntityRef(id=2015699787, name="region_position", vaddr=4198416)
                    ],
                )
            ],
        ),
    ]


def test_tool_call_result_attaches_function_links_from_refs():
    state = _fold(_rename_result_events())
    tool = [i for i in state.items if isinstance(i, ToolCall)][0]
    assert tool.functions == [FunctionRef(ea=4198416, name="region_position")]


def test_tool_call_result_links_persist_on_replay():
    state = build_initial_state(_rename_result_events())
    tool = [i for i in state.items if isinstance(i, ToolCall)][0]
    assert tool.functions == [FunctionRef(ea=4198416, name="region_position")]


def test_tool_call_result_without_refs_leaves_no_links():
    state = _fold(
        [
            _ev("TOOL_CALL_START", tool_call_id="t1", tool_name="do"),
            _ev("TOOL_CALL_RESULT", tool_call_id="t1", tool_name="do"),
        ]
    )
    tool = [i for i in state.items if isinstance(i, ToolCall)][0]
    assert tool.functions is None


def test_build_initial_state_replays_user_and_events():
    events = [
        UserMessageReplay(id="u1", content="what is this?"),
        _ev("TEXT_MESSAGE_START", message_id="a"),
        _ev("TEXT_MESSAGE_CONTENT", message_id="a", delta="an answer"),
        _ev("TEXT_MESSAGE_END", message_id="a"),
        _ev("TITLE_UPDATED", title="T"),
    ]
    state = build_initial_state(events)
    assert isinstance(state.items[0], UserMessage)
    assert state.items[0].content == "what is this?"
    assert isinstance(state.items[1], AssistantMessage)
    assert state.items[1].content == "an answer"
    assert state.title == "T"
