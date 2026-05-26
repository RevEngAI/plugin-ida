import threading
from typing import Any, Callable

from loguru import logger
from revengai import (
    ApiException,
    Configuration,
    FunctionMapping,
    FunctionsAIDecompilationApi,
)
from revengai.models.task_status import TaskStatus
from revengai.models.tokenised_data import TokenisedData
from revengai.models.workflow_progress import WorkflowProgress

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.core.utils import parse_exception
from reai_toolkit.app.interfaces.thread_service import IThreadService


POLL_INTERVAL_SECONDS: float = 1.5
MAX_REQUEUE_ATTEMPTS = 2


class AiDecompService(IThreadService):
    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration) -> None:
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)
        self._thread_callback: Callable[[GenericApiReturn[TokenisedData]], None] | None = None
        self._decomp_cache: dict[int, TokenisedData] = {}

    def call_callback(self, generic_return: GenericApiReturn[TokenisedData]) -> None:
        if self._thread_callback:
            self._thread_callback(generic_return)

    def thread_in_progress(self) -> bool:
        return self.is_worker_running()

    def start_ai_decomp_task(self, ea: int, thread_callback: Callable[..., Any]) -> None:
        self.stop_worker()
        self._thread_callback = thread_callback
        self.start_worker(target=self._begin_ai_decomp_task, args=(ea,))

    def _get_function_id(self, start_ea: int) -> int | None:
        function_map: FunctionMapping | None = self.netstore_service.get_function_mapping()
        if function_map is None:
            return None
        return function_map.inverse_function_map.get(str(start_ea))

    def _safe_callback(
        self,
        stop_event: threading.Event,
        generic_return: GenericApiReturn[TokenisedData],
    ) -> None:
        # Suppress callbacks from a worker that has been superseded by a newer one;
        # `start_ai_decomp_task` calls stop_worker() (which sets this event) before
        # spawning the next worker, so a stale poll's callback gets dropped here.
        if stop_event.is_set():
            return
        self.call_callback(generic_return)

    def _queue_decompilation(self, function_id: int) -> tuple[bool, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                FunctionsAIDecompilationApi(api_client).create_ai_decompilation(
                    function_id=function_id,
                    context_aware=True,
                )
            return True, None
        except ApiException as e:
            if e.status == 409:
                return True, None
            return False, _format_api_error(e)
        except Exception as e:
            return False, f"Unexpected error queuing AI decompilation: {e}"

    def _fetch_status(
        self, function_id: int
    ) -> tuple[WorkflowProgress | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                progress = FunctionsAIDecompilationApi(api_client).get_ai_decompilation_status(
                    function_id=function_id,
                )
            return progress, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching AI decompilation status: {e}"

    def _fetch_tokenised(
        self, function_id: int
    ) -> tuple[TokenisedData | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                tokenised = FunctionsAIDecompilationApi(
                    api_client
                ).get_ai_decompilation_tokenised(function_id=function_id)
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching tokenised AI decompilation: {e}"

        if tokenised.tokenised_decompilation is None:
            return None, "Tokenised AI decompilation returned no content."
        return tokenised, None

    def _begin_ai_decomp_task(self, stop_event: threading.Event, start_ea: int) -> None:
        function_id = self._get_function_id(start_ea=start_ea)
        if function_id is None:
            self._safe_callback(
                stop_event, GenericApiReturn[TokenisedData](success=True, data=None)
            )
            return

        cached = self._decomp_cache.get(function_id)
        if cached is not None:
            self._safe_callback(
                stop_event, GenericApiReturn[TokenisedData](success=True, data=cached)
            )
            return

        queued_ok, queue_err = self._queue_decompilation(function_id)
        if not queued_ok:
            self._safe_callback(
                stop_event,
                GenericApiReturn[TokenisedData](success=False, error_message=queue_err),
            )
            return

        requeue_attempts = 0
        while not stop_event.is_set():
            progress, status_err = self._fetch_status(function_id)
            if status_err is not None or progress is None:
                self._safe_callback(
                    stop_event,
                    GenericApiReturn[TokenisedData](
                        success=False,
                        error_message=status_err or "AI Decompilation status fetch returned nothing.",
                    ),
                )
                return

            logger.info(
                f"RevEng.AI: AI Decompilation progress for function id {function_id}: {progress.status}"
            )

            if progress.status == TaskStatus.COMPLETED:
                break

            if progress.status == TaskStatus.FAILED:
                self._safe_callback(
                    stop_event,
                    GenericApiReturn[TokenisedData](
                        success=False,
                        error_message=_last_message_text(progress.messages)
                        or "AI Decompilation task failed! Please retry the decompilation.",
                    ),
                )
                return

            if progress.status == TaskStatus.UNINITIALISED:
                if requeue_attempts >= MAX_REQUEUE_ATTEMPTS:
                    self._safe_callback(
                        stop_event,
                        GenericApiReturn[TokenisedData](
                            success=False,
                            error_message="AI Decompilation task stayed uninitialised; backend did not start the workflow.",
                        ),
                    )
                    return
                requeue_attempts += 1
                queued_ok, queue_err = self._queue_decompilation(function_id)
                if not queued_ok:
                    self._safe_callback(
                        stop_event,
                        GenericApiReturn[TokenisedData](
                            success=False, error_message=queue_err
                        ),
                    )
                    return

            if stop_event.wait(POLL_INTERVAL_SECONDS):
                return

        tokenised, fetch_err = self._fetch_tokenised(function_id)
        if tokenised is None:
            self._safe_callback(
                stop_event,
                GenericApiReturn[TokenisedData](success=False, error_message=fetch_err),
            )
            return

        self._decomp_cache[function_id] = tokenised
        self._safe_callback(
            stop_event, GenericApiReturn[TokenisedData](success=True, data=tokenised)
        )


def _format_api_error(e: ApiException) -> str:
    error_response = parse_exception(e)
    if error_response and error_response.errors:
        first = error_response.errors[0]
        return f"{first.code}: {first.message}"
    return f"API Exception: {e}"


def _last_message_text(messages: Any) -> str | None:
    if not messages:
        return None
    for msg in reversed(list(messages)):
        text = getattr(msg, "text", None)
        if text:
            return text
    return None
