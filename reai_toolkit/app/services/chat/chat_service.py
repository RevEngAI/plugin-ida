"""Streaming chat client for the Agent Chat feature.

Wraps the vendored ``revengai.ConversationsApi`` (create / send / stream / confirm
/ cancel / list / get) behind the plugin's :class:`BaseService` conventions
(``yield_api_client`` + :class:`GenericApiReturn`). The SSE frame parsing lives in
the pure :mod:`sse` module; this class only owns the network lifecycle.
"""

from __future__ import annotations

import threading
from typing import Generator, Optional
from uuid import UUID

import urllib3
from loguru import logger
from revengai import (
    ApiException,
    ConfirmToolInputBody,
    Configuration,
    ConversationContext,
    ConversationsApi,
    CreateConversationRequest,
    FunctionsCoreApi,
    SendMessageRequest,
)

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.core.utils import parse_exception
from reai_toolkit.app.interfaces.base_service import BaseService
from reai_toolkit.app.services.chat.schema import (
    ROLE_USER,
    ChatEvent,
    ConversationContextDTO,
    ConversationReplay,
    ConversationSummary,
    StoredEvent,
    UserMessageReplay,
    normalize_event,
    resolve_type,
)
from reai_toolkit.app.services.chat.sse import iter_sse_events

CONNECT_TIMEOUT: float = 10.0
READ_TIMEOUT: float = 300.0


class ChatService(BaseService):
    def __init__(
        self, netstore_service: SimpleNetStore, sdk_config: Configuration
    ) -> None:
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)
        self._active_response: Optional[urllib3.HTTPResponse] = None

    def create_conversation(
        self, context: Optional[ConversationContextDTO], title: Optional[str] = None
    ) -> GenericApiReturn[str]:
        req = CreateConversationRequest(context=self._to_sdk_context(context), title=title)
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                conv = ConversationsApi(api_client).create_conversation(req)
            return GenericApiReturn(success=True, data=conv.conversation_uuid)
        except ApiException as e:
            return self._api_error(e)
        except Exception as e:
            return GenericApiReturn(success=False, error_message=f"Unexpected error: {e}")

    def send_message(
        self,
        conversation_id: str,
        content: str,
        context: Optional[ConversationContextDTO],
    ) -> GenericApiReturn[None]:
        req = SendMessageRequest(content=content, context=self._to_sdk_context(context))
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                ConversationsApi(api_client).send_message(UUID(conversation_id), req)
            return GenericApiReturn(success=True)
        except ApiException as e:
            if e.status == 409:
                return GenericApiReturn(success=True)
            return self._api_error(e)
        except Exception as e:
            return GenericApiReturn(success=False, error_message=f"Unexpected error: {e}")

    def confirm_tool(
        self, conversation_id: str, approved: bool
    ) -> GenericApiReturn[None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                ConversationsApi(api_client).confirm_tool(
                    UUID(conversation_id), ConfirmToolInputBody(approved=approved)
                )
            return GenericApiReturn(success=True)
        except ApiException as e:
            if e.status == 404:
                return GenericApiReturn(success=True)
            return self._api_error(e)
        except Exception as e:
            return GenericApiReturn(success=False, error_message=f"Unexpected error: {e}")

    def cancel_run(self, conversation_id: str) -> GenericApiReturn[None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                ConversationsApi(api_client).cancel_run(UUID(conversation_id))
            return GenericApiReturn(success=True)
        except ApiException as e:
            if e.status == 404:
                return GenericApiReturn(success=True)
            return self._api_error(e)
        except Exception as e:
            return GenericApiReturn(success=False, error_message=f"Unexpected error: {e}")

    def list_conversations(self) -> GenericApiReturn[list[ConversationSummary]]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                convs = ConversationsApi(api_client).list_conversations()
            summaries = [
                ConversationSummary(
                    conversation_uuid=c.conversation_uuid,
                    title=c.title,
                    updated_at=str(c.updated_at) if c.updated_at is not None else None,
                )
                for c in (convs or [])
            ]
            return GenericApiReturn(success=True, data=summaries)
        except ApiException as e:
            return self._api_error(e)
        except Exception as e:
            return GenericApiReturn(success=False, error_message=f"Unexpected error: {e}")

    def get_conversation(
        self, conversation_id: str
    ) -> GenericApiReturn[ConversationReplay]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                conv = ConversationsApi(api_client).get_conversation(UUID(conversation_id))
            replay = ConversationReplay(
                conversation_uuid=conv.conversation_uuid,
                title=conv.title,
                events=self._replay_events(conv.events or []),
            )
            return GenericApiReturn(success=True, data=replay)
        except ApiException as e:
            return self._api_error(e)
        except Exception as e:
            return GenericApiReturn(success=False, error_message=f"Unexpected error: {e}")

    def get_function_name(self, function_id: int) -> GenericApiReturn[str]:
        """Fetch a single function's current name from the backend (the same
        info the agent's 'Get Function Info' tool reads)."""
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                details = FunctionsCoreApi(api_client).get_function_details_0(
                    function_id=function_id
                )
            return GenericApiReturn(success=True, data=details.function_name)
        except ApiException as e:
            return self._api_error(e)
        except Exception as e:
            return GenericApiReturn(success=False, error_message=f"Unexpected error: {e}")

    def stream(
        self,
        conversation_id: str,
        stop_event: threading.Event,
        last_event_id: Optional[int] = None,
    ) -> Generator[ChatEvent, None, None]:
        """Yield normalized :class:`ChatEvent`\\ s from the live SSE stream.

        Uses ``stream_events_without_preload_content`` to get the raw urllib3
        response and iterates it incrementally. Ends gracefully on a terminal
        event, a set ``stop_event``, or a dropped/closed connection.
        """
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            resp = ConversationsApi(api_client).stream_events_without_preload_content(
                id=UUID(conversation_id),
                last_event_id=last_event_id,
                _request_timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            self._active_response = resp
            try:
                yield from iter_sse_events(
                    resp.stream(1024, decode_content=True),
                    stop=stop_event.is_set,
                )
            except (urllib3.exceptions.HTTPError, OSError) as e:
                logger.debug(f"[Chat] SSE stream ended: {e}")
                return
            finally:
                self._active_response = None
                try:
                    resp.release_conn()
                except Exception:
                    pass

    def close_active_stream(self) -> None:
        """Interrupt a blocked stream read from another thread (cancellation)."""
        resp = self._active_response
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass

    @staticmethod
    def _to_sdk_context(
        dto: Optional[ConversationContextDTO],
    ) -> Optional[ConversationContext]:
        if dto is None or dto.is_empty():
            return None
        return ConversationContext(
            analysis_id=dto.analysis_id, function_id=dto.function_id
        )

    @staticmethod
    def _replay_events(sdk_events: list) -> list[StoredEvent]:
        """Reconstruct stored events for history replay.

        Mirrors ``getConversation`` in agentApi.ts: role-USER TEXT_MESSAGE_*
        events collapse into a single :class:`UserMessageReplay`; everything else
        is normalized like a live frame.
        """
        out: list[StoredEvent] = []
        emitted_user_ids: set[str] = set()
        current_user_id: Optional[str] = None
        current_user_content = ""

        for ev in sdk_events:
            etype = resolve_type(getattr(ev, "type", None))
            role = getattr(ev, "role", None)
            data = getattr(ev, "data", None)
            data = data if isinstance(data, dict) else {}

            if role == ROLE_USER:
                if etype == "TEXT_MESSAGE_START":
                    msg_id = str(
                        data.get("message_id") or getattr(ev, "event_id", "") or ""
                    )
                    if msg_id not in emitted_user_ids:
                        current_user_id = msg_id
                        current_user_content = ""
                    else:
                        current_user_id = None
                elif etype == "TEXT_MESSAGE_CONTENT":
                    if current_user_id is not None:
                        current_user_content += str(data.get("delta") or "")
                elif etype == "TEXT_MESSAGE_END":
                    if current_user_id is not None:
                        out.append(
                            UserMessageReplay(
                                id=current_user_id, content=current_user_content
                            )
                        )
                        emitted_user_ids.add(current_user_id)
                        current_user_id = None
                        current_user_content = ""
                continue

            norm = normalize_event(getattr(ev, "type", None), data)
            if norm is not None:
                out.append(norm)
        return out

    @staticmethod
    def _api_error(e: ApiException) -> GenericApiReturn:
        error_response = parse_exception(e)
        if error_response and error_response.errors and len(error_response.errors) > 0:
            return GenericApiReturn(
                success=False,
                error_message=f"{error_response.errors[0].code}: {error_response.errors[0].message}",
            )
        return GenericApiReturn(success=False, error_message=f"API Exception: {e}")
