"""Pure presentation helpers for the Agent Chat panel.

Turns a :class:`ChatState` into a markdown transcript. No Qt / IDA imports, so it
is unit-testable without a GUI (Qt only imports in the GUI version of IDA).
"""

from __future__ import annotations

from typing import Optional

from reai_toolkit.app.services.chat.schema import ChatState, ToolConfirmation


def title_case(name: str) -> str:
    pretty = (name or "").replace("_", " ").strip()
    return pretty.title() if pretty else (name or "tool")


def tool_marker(is_error: bool, status: str) -> str:
    if is_error:
        return "✗"
    return "✓" if status == "finished" else "…"


JUMP_SCHEME = "ida://jump/"


def jump_href(ea: int) -> str:
    return f"{JUMP_SCHEME}{ea}"


def parse_jump_href(url: str) -> Optional[int]:
    if not url.startswith(JUMP_SCHEME):
        return None
    try:
        return int(url[len(JUMP_SCHEME):])
    except (ValueError, TypeError):
        return None


def _function_links(functions) -> str:
    parts = [f"[{f.name}]({jump_href(f.ea)})" for f in functions if f.name]
    return "↪ " + " · ".join(parts) if parts else ""


def render_transcript_markdown(state: ChatState) -> str:
    """Build a single markdown document from the chat items."""
    parts: list[str] = []
    for item in state.items:
        kind = item.kind
        if kind == "user-message":
            parts.append(f"**You:** {item.content}")
        elif kind == "assistant-message":
            text = item.content or ""
            if item.is_streaming:
                text = f"{text} ▍"
            parts.append(text if text.strip() else "_…_")
        elif kind == "tool-call":
            parts.append(f"`{tool_marker(item.is_error, item.status)} {title_case(item.name)}`")
            if item.functions:
                links = _function_links(item.functions)
                if links:
                    parts.append(links)
        elif kind == "step":
            if item.status == "running":
                parts.append(f"_{item.step_name}…_")
        elif kind == "tool-confirmation":
            tool = title_case(item.tool_name)
            if item.status == "pending":
                parts.append(f"> ⚠ **Approval needed** — `{tool}`")
            elif item.status == "approved":
                parts.append(f"> ✓ Approved — `{tool}`")
            else:
                parts.append(f"> ✗ Rejected — `{tool}`")
        elif kind == "context-compacted":
            parts.append("_— context compacted —_")

    if state.run_status == "running":
        last = state.items[-1] if state.items else None
        if last is None or last.kind == "user-message":
            parts.append("_Thinking…_")

    if state.run_status == "error" and state.run_error is not None:
        parts.append(f"> ⚠ **Error:** {state.run_error.message}")

    return "\n\n".join(parts)


def find_pending_confirmation(state: ChatState) -> Optional[ToolConfirmation]:
    for item in reversed(state.items):
        if isinstance(item, ToolConfirmation) and item.status == "pending":
            return item
    return None
