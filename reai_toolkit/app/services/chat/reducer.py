"""Pure reducer state machine for the Agent Chat feature.

Direct port of ``Dashboard/components/features/AgentChat/reducer.ts``. Operates
only on :mod:`schema` dataclasses — no Qt / IDA / SDK imports — so it runs under
plain ``pytest``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from typing import Callable, Optional, Union

from reai_toolkit.app.services.chat.schema import (
    AssistantMessage,
    ChatEvent,
    ChatItem,
    ChatState,
    ContextCompacted,
    FunctionRef,
    RunError,
    Step,
    StoredEvent,
    ToolCall,
    ToolConfirmation,
    UserMessage,
    UserMessageReplay,
)


@dataclass
class SendMessage:
    id: str
    content: str


@dataclass
class Cancel:
    pass


@dataclass
class ConfirmTool:
    id: str
    approved: bool


@dataclass
class EventAction:
    event: ChatEvent


@dataclass
class ApiError:
    message: str
    code: Optional[str] = None
    doc_url: Optional[str] = None


@dataclass
class Reset:
    stored_events: Optional[list[StoredEvent]] = None


ChatAction = Union[SendMessage, Cancel, ConfirmTool, EventAction, ApiError, Reset]


def _new_id() -> str:
    return uuid.uuid4().hex


def _find_last_and_update(
    items: list[ChatItem],
    guard: Callable[[ChatItem], bool],
    update: Callable[[ChatItem], ChatItem],
) -> list[ChatItem]:
    """Update the last item matching ``guard``. Returns the same list unchanged
    if no item matches (mirrors ``findAndUpdate`` in reducer.ts)."""
    for idx in range(len(items) - 1, -1, -1):
        if guard(items[idx]):
            next_items = list(items)
            next_items[idx] = update(items[idx])
            return next_items
    return items


def _finalize_running_items(items: list[ChatItem]) -> list[ChatItem]:
    """Flip every in-progress item to a terminal state (CANCEL / *_ERROR)."""
    out: list[ChatItem] = []
    for item in items:
        if isinstance(item, AssistantMessage) and item.is_streaming:
            out.append(replace(item, is_streaming=False))
        elif isinstance(item, (ToolCall, Step)) and item.status == "running":
            out.append(replace(item, status="finished"))
        elif isinstance(item, ToolConfirmation) and item.status == "pending":
            out.append(replace(item, status="rejected"))
        else:
            out.append(item)
    return out


def initial_state() -> ChatState:
    return ChatState()


def chat_reducer(state: ChatState, action: ChatAction) -> ChatState:
    if isinstance(action, SendMessage):
        return replace(
            state,
            items=[*state.items, UserMessage(id=action.id, content=action.content)],
            run_status="running",
            run_error=None,
        )

    if isinstance(action, Reset):
        return build_initial_state(action.stored_events)

    if isinstance(action, Cancel):
        return replace(
            state,
            run_status="idle",
            items=_finalize_running_items(state.items),
        )

    if isinstance(action, ConfirmTool):
        return replace(
            state,
            run_status="running" if action.approved else state.run_status,
            items=_find_last_and_update(
                state.items,
                lambda it: isinstance(it, ToolConfirmation) and it.id == action.id,
                lambda it: replace(
                    it, status="approved" if action.approved else "rejected"
                ),
            ),
        )

    if isinstance(action, ApiError):
        return replace(
            state,
            run_status="error",
            run_error=RunError(
                message=action.message, code=action.code, doc_url=action.doc_url
            ),
            items=_finalize_running_items(state.items),
        )

    if isinstance(action, EventAction):
        return _reduce_event(state, action.event)

    return state


def _functions_from_updates(updates) -> Optional[list[FunctionRef]]:
    if not updates:
        return None
    out: list[FunctionRef] = []
    for u in updates:
        if u.type != "function":
            continue
        for r in u.refs:
            if r.name and r.vaddr:
                out.append(FunctionRef(ea=r.vaddr, name=r.name))
    return out or None


def _reduce_event(state: ChatState, event: ChatEvent) -> ChatState:
    t = event.type

    if t == "RUN_STARTED":
        return replace(state, run_status="running", run_error=None)

    if t == "RUN_FINISHED":
        return replace(state, run_status="idle")

    if t == "RUN_ERROR":
        return replace(
            state,
            run_status="error",
            run_error=RunError(message=event.message or "Unknown error"),
            items=_finalize_running_items(state.items),
        )

    if t == "STEP_STARTED":
        return replace(
            state,
            items=[
                *state.items,
                Step(id=_new_id(), step_name="Processing", status="running"),
            ],
        )

    if t == "STEP_FINISHED":
        return replace(
            state,
            items=_find_last_and_update(
                state.items,
                lambda it: isinstance(it, Step) and it.status == "running",
                lambda it: replace(it, status="finished"),
            ),
        )

    if t == "TEXT_MESSAGE_START":
        if any(
            isinstance(it, AssistantMessage) and it.id == event.message_id
            for it in state.items
        ):
            return state
        return replace(
            state,
            items=[
                *state.items,
                AssistantMessage(
                    id=event.message_id or _new_id(), content="", is_streaming=True
                ),
            ],
        )

    if t == "TEXT_MESSAGE_CONTENT":
        return replace(
            state,
            items=_find_last_and_update(
                state.items,
                lambda it: isinstance(it, AssistantMessage)
                and it.id == event.message_id,
                lambda it: replace(it, content=it.content + (event.delta or "")),
            ),
        )

    if t == "TEXT_MESSAGE_END":
        return replace(
            state,
            items=_find_last_and_update(
                state.items,
                lambda it: isinstance(it, AssistantMessage)
                and it.id == event.message_id,
                lambda it: replace(it, is_streaming=False),
            ),
        )

    if t == "TOOL_CALL_START":
        return replace(
            state,
            items=[
                *state.items,
                ToolCall(
                    id=event.tool_call_id or _new_id(),
                    name=event.tool_name or "",
                    status="running",
                    is_error=False,
                ),
            ],
        )

    if t == "TOOL_CALL_END":
        return replace(
            state,
            items=_find_last_and_update(
                state.items,
                lambda it: isinstance(it, ToolCall) and it.id == event.tool_call_id,
                lambda it: replace(it, status="finished"),
            ),
        )

    if t == "TOOL_CALL_RESULT":
        functions = _functions_from_updates(event.updated)
        items = _find_last_and_update(
            state.items,
            lambda it: isinstance(it, ToolCall) and it.id == event.tool_call_id,
            lambda it: replace(
                it,
                status="finished",
                is_error=event.is_error,
                functions=functions or it.functions,
            ),
        )
        items = _find_last_and_update(
            items,
            lambda it: isinstance(it, ToolConfirmation)
            and it.id == event.tool_call_id
            and it.status == "pending",
            lambda it: replace(it, status="rejected" if event.is_error else "approved"),
        )
        return replace(state, items=items)

    if t == "TITLE_UPDATED":
        return replace(state, title=event.title)

    if t == "RUN_CANCELLED":
        return replace(
            state,
            run_status="idle",
            items=_finalize_running_items(state.items),
        )

    if t == "CONTEXT_COMPACTED":
        return replace(state, items=[*state.items, ContextCompacted(id=_new_id())])

    if t == "TOOL_CONFIRMATION_REQUIRED":
        return replace(
            state,
            items=[
                *state.items,
                ToolConfirmation(
                    id=event.tool_call_id or _new_id(),
                    tool_name=event.tool_name or "",
                    message=event.message or "",
                    status="pending",
                ),
            ],
        )

    return state


def build_initial_state(stored_events: Optional[list[StoredEvent]]) -> ChatState:
    """Replay stored/normalized events into a :class:`ChatState` (history reload).

    Mirrors ``buildInitialState`` in reducer.ts: a ``UserMessageReplay`` drives a
    ``SEND_MESSAGE`` action, everything else an ``EVENT`` action.
    """
    state = initial_state()
    if not stored_events:
        return state
    for ev in stored_events:
        if isinstance(ev, UserMessageReplay):
            state = chat_reducer(state, SendMessage(id=ev.id, content=ev.content))
        elif isinstance(ev, ChatEvent):
            state = chat_reducer(state, EventAction(ev))
    return state
