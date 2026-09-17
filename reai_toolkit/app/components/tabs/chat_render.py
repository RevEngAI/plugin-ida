"""Pure presentation helpers for the Agent Chat panel.

Turns a :class:`ChatState` into a markdown transcript. No Qt / IDA imports, so it
is unit-testable without a GUI (Qt only imports in the GUI version of IDA).
"""

from __future__ import annotations

import re
from typing import Callable, Optional

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


ENTITY_KINDS = ("FUNCTION", "ANALYSIS", "COLLECTION")

# The agent writes platform entities the way the Dashboard's mention serializer
# does: a markdown link whose href is the pseudo-URL `FUNCTION_<id>`. Qt keeps
# such an href verbatim, so the link renders but leads nowhere until it is
# rewritten. Tokens also arrive bare in prose, which no renderer linkifies.
_KINDS = "|".join(ENTITY_KINDS)
ENTITY_HREF_RE = re.compile(rf"\]\((?P<kind>{_KINDS})_(?P<id>\d+)\)")
# Not preceded by a word char, `[`, `(` or `/`: those mean the token is already
# a link label, an href we left alone, or part of a URL.
BARE_ENTITY_RE = re.compile(rf"(?<![\w\[(/])(?P<kind>{_KINDS})_(?P<id>\d+)\b")
CODE_FENCE_RE = re.compile(r"(```.*?```|`[^`\n]*`)", re.DOTALL)

EntityResolver = Callable[[str, int], Optional[str]]


def rewrite_entity_links(markdown: str, resolve: Optional[EntityResolver]) -> str:
    """Point `FUNCTION_<id>` pseudo-URLs at somewhere the panel can actually go.

    `resolve(kind, entity_id)` returns the destination, or None to leave the
    token alone rather than render a link that cannot be followed. Code spans
    and fenced blocks are left verbatim.
    """
    if not markdown or resolve is None:
        return markdown

    def _target(match: re.Match) -> Optional[str]:
        return resolve(match.group("kind"), int(match.group("id")))

    def _href(match: re.Match) -> str:
        target = _target(match)
        return match.group(0) if target is None else f"]({target})"

    def _bare(match: re.Match) -> str:
        target = _target(match)
        return match.group(0) if target is None else f"[{match.group(0)}]({target})"

    out = []
    for chunk in CODE_FENCE_RE.split(markdown):
        if chunk.startswith("`"):
            out.append(chunk)
        else:
            out.append(BARE_ENTITY_RE.sub(_bare, ENTITY_HREF_RE.sub(_href, chunk)))
    return "".join(out)


def _function_links(functions) -> str:
    parts = [f"[{f.name}]({jump_href(f.ea)})" for f in functions if f.name]
    return "↪ " + " · ".join(parts) if parts else ""


def render_transcript_markdown(
    state: ChatState, resolve_entity: Optional[EntityResolver] = None
) -> str:
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

    return rewrite_entity_links("\n\n".join(parts), resolve_entity)


def find_pending_confirmation(state: ChatState) -> Optional[ToolConfirmation]:
    for item in reversed(state.items):
        if isinstance(item, ToolConfirmation) and item.status == "pending":
            return item
    return None
