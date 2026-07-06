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
    title_case,
)
from reai_toolkit.app.services.chat.schema import (
    AssistantMessage,
    ChatState,
    ContextCompacted,
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
