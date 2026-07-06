"""Schema-shape assertions: fail loudly if the revengai conversation API drifts."""

from revengai import (
    ConfirmToolInputBody,
    Conversation,
    ConversationContext,
    ConversationsApi,
    ConversationWithEvents,
    CreateConversationRequest,
    SendMessageRequest,
)
from revengai.models.event import Event


def test_conversations_api_has_expected_methods():
    for name in (
        "create_conversation",
        "send_message",
        "confirm_tool",
        "cancel_run",
        "get_conversation",
        "list_conversations",
        "stream_events_without_preload_content",
    ):
        assert hasattr(ConversationsApi, name), name


def test_create_conversation_request_fields():
    assert {"context", "title"} <= set(CreateConversationRequest.model_fields)


def test_send_message_request_fields():
    assert {"content", "context"} <= set(SendMessageRequest.model_fields)


def test_conversation_context_fields():
    assert {"analysis_id", "function_id"} <= set(ConversationContext.model_fields)


def test_confirm_tool_input_body_field():
    assert "approved" in ConfirmToolInputBody.model_fields


def test_conversation_fields():
    assert "conversation_uuid" in Conversation.model_fields


def test_conversation_with_events_fields():
    assert {"conversation_uuid", "events"} <= set(ConversationWithEvents.model_fields)


def test_event_fields():
    assert {"type", "role", "data", "event_id"} <= set(Event.model_fields)
