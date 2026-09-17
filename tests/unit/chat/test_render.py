"""Panel markdown renderer tests.

The renderer is deliberately kept in a pure module (`chat_render`) so it is
testable headlessly. The Qt panel itself (`chat_tab`) cannot be imported under
idalib — Qt only loads in the GUI version of IDA — so, like every other Qt view
in this repo, it is covered by byte-compile + manual verification in IDA, not by
unit tests.
"""

from reai_toolkit.app.components.tabs.chat_render import (
    find_pending_confirmation,
    jump_href,
    parse_jump_href,
    render_transcript_markdown,
    rewrite_entity_links,
    title_case,
)
from reai_toolkit.app.services.chat.reducer import build_initial_state
from reai_toolkit.app.services.chat.schema import (
    AssistantMessage,
    ChatEvent,
    ChatState,
    ContextCompacted,
    EntityRef,
    EntityUpdate,
    FunctionRef,
    RunError,
    Step,
    ToolCall,
    ToolConfirmation,
    UserMessage,
)


def test_title_case():
    assert title_case("read_function") == "Read Function"
    assert title_case("") == "tool"


def test_render_transcript_markdown():
    state = ChatState(
        items=[
            UserMessage(id="u", content="what is this?"),
            AssistantMessage(id="a", content="a func", is_streaming=True),
            ToolCall(id="t", name="read_function", status="running", is_error=False),
            ToolConfirmation(id="c", tool_name="rename_fn", message="Rename?", status="pending"),
            Step(id="s", step_name="Processing", status="running"),
            ContextCompacted(id="x"),
        ],
        title="Demo",
        run_status="running",
    )
    md = render_transcript_markdown(state)
    assert "**You:** what is this?" in md
    assert "▍" in md
    assert "Read Function" in md
    assert "Approval needed" in md
    assert "context compacted" in md


def test_render_error_state():
    state = ChatState(run_status="error", run_error=RunError(message="access denied"))
    assert "access denied" in render_transcript_markdown(state)


def test_render_thinking_indicator():
    state = ChatState(items=[UserMessage(id="u", content="hi")], run_status="running")
    assert "Thinking" in render_transcript_markdown(state)


def test_jump_href_roundtrip():
    assert parse_jump_href(jump_href(0x407F30)) == 0x407F30
    assert parse_jump_href("https://example.com") is None
    assert parse_jump_href("ida://jump/notanumber") is None


def test_render_function_jump_links():
    state = ChatState(
        items=[
            ToolCall(
                id="t",
                name="rename_functions",
                status="finished",
                is_error=False,
                functions=[FunctionRef(ea=0x408140, name="chat_agent_renamed")],
            )
        ]
    )
    md = render_transcript_markdown(state)
    assert "[chat_agent_renamed](ida://jump/4227392)" in md


def test_render_jump_links_persist_from_replayed_refs():
    events = [
        ChatEvent(
            type="TOOL_CALL_START", tool_call_id="t1", tool_name="rename_functions"
        ),
        ChatEvent(
            type="TOOL_CALL_RESULT",
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
    md = render_transcript_markdown(build_initial_state(events))
    assert "[region_position](ida://jump/4198416)" in md


def test_find_pending_confirmation():
    state = ChatState(
        items=[
            ToolConfirmation(id="c1", tool_name="a", message="", status="approved"),
            ToolConfirmation(id="c2", tool_name="b", message="", status="pending"),
        ]
    )
    pending = find_pending_confirmation(state)
    assert pending is not None and pending.id == "c2"
    assert find_pending_confirmation(ChatState()) is None


def _resolver(kind, entity_id):
    if kind == "FUNCTION" and entity_id == 1:
        return jump_href(0x140001000)
    if kind == "FUNCTION":
        return f"https://portal.reveng.ai/analyses/9?view=functions&fn={entity_id}"
    if kind == "ANALYSIS":
        return f"https://portal.reveng.ai/analyses/{entity_id}"
    return None


def test_function_href_in_this_database_becomes_a_local_jump():
    assert rewrite_entity_links("[foo](FUNCTION_1)", _resolver) == (
        f"[foo]({jump_href(0x140001000)})"
    )


def test_function_href_elsewhere_falls_back_to_the_portal():
    assert rewrite_entity_links("[foo](FUNCTION_42)", _resolver) == (
        "[foo](https://portal.reveng.ai/analyses/9?view=functions&fn=42)"
    )


def test_bare_token_in_prose_becomes_a_link():
    assert rewrite_entity_links("renamed FUNCTION_42 today", _resolver) == (
        "renamed [FUNCTION_42]"
        "(https://portal.reveng.ai/analyses/9?view=functions&fn=42) today"
    )


def test_analysis_token_points_at_the_portal():
    assert rewrite_entity_links("[run](ANALYSIS_7)", _resolver) == (
        "[run](https://portal.reveng.ai/analyses/7)"
    )


def test_unresolvable_token_is_left_alone_rather_than_linked_nowhere():
    text = "see [c](COLLECTION_5) and COLLECTION_5"
    assert rewrite_entity_links(text, _resolver) == text


def test_tokens_inside_code_are_left_verbatim():
    fenced = "```\nundefined8 FUNCTION_42(void)\n```"
    assert rewrite_entity_links(fenced, _resolver) == fenced
    assert rewrite_entity_links("`FUNCTION_42`", _resolver) == "`FUNCTION_42`"


def test_a_token_used_as_link_text_is_not_double_wrapped():
    text = f"[FUNCTION_42]({jump_href(16)})"
    assert rewrite_entity_links(text, _resolver) == text


def test_render_without_a_resolver_leaves_the_transcript_untouched():
    state = ChatState(items=[AssistantMessage(id="m1", content="[foo](FUNCTION_1)", is_streaming=False)])
    assert "FUNCTION_1" in render_transcript_markdown(state)


def test_render_applies_the_resolver_to_assistant_text():
    state = ChatState(items=[AssistantMessage(id="m1", content="[foo](FUNCTION_1)", is_streaming=False)])
    out = render_transcript_markdown(state, _resolver)
    assert jump_href(0x140001000) in out
