import threading
from typing import Any, Callable

from loguru import logger
from revengai import (
    ApiException,
    Configuration,
    FunctionMapping,
    FunctionsAIDecompilationApi,
)
from revengai.models.comments_data import CommentsData
from revengai.models.summary_data import SummaryData
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
        self._on_decomp: Callable[[GenericApiReturn[TokenisedData]], None] | None = None
        self._on_summary: Callable[[GenericApiReturn[SummaryData]], None] | None = None
        self._on_comments: Callable[[GenericApiReturn[CommentsData]], None] | None = None
        self._decomp_cache: dict[int, TokenisedData] = {}
        self._summary_cache: dict[int, SummaryData] = {}

    def thread_in_progress(self) -> bool:
        return self.is_worker_running()

    def start_ai_decomp_task(
        self,
        ea: int,
        on_decomp: Callable[[GenericApiReturn[TokenisedData]], None],
        on_summary: Callable[[GenericApiReturn[SummaryData]], None],
        on_comments: Callable[[GenericApiReturn[CommentsData]], None],
    ) -> None:
        self.stop_worker()
        self._on_decomp = on_decomp
        self._on_summary = on_summary
        self._on_comments = on_comments
        self.start_worker(target=self._begin_ai_decomp_task, args=(ea,))

    def _get_function_id(self, start_ea: int) -> int | None:
        function_map: FunctionMapping | None = self.netstore_service.get_function_mapping()
        if function_map is None:
            return None
        return function_map.inverse_function_map.get(str(start_ea))

    @staticmethod
    def _safe_dispatch(
        stop_event: threading.Event,
        callback: Callable[..., Any] | None,
        payload: Any,
    ) -> None:
        if stop_event.is_set() or callback is None:
            return
        callback(payload)

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

    def _fetch_decomp_status(
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

    def _run_decomp_phase(
        self, function_id: int, stop_event: threading.Event
    ) -> TokenisedData | None:
        cached = self._decomp_cache.get(function_id)
        if cached is not None:
            self._safe_dispatch(
                stop_event,
                self._on_decomp,
                GenericApiReturn[TokenisedData](success=True, data=cached),
            )
            return cached

        queued_ok, queue_err = self._queue_decompilation(function_id)
        if not queued_ok:
            self._safe_dispatch(
                stop_event,
                self._on_decomp,
                GenericApiReturn[TokenisedData](success=False, error_message=queue_err),
            )
            return None

        polled_ok, poll_err = self._poll_workflow(
            function_id=function_id,
            stop_event=stop_event,
            status_fn=self._fetch_decomp_status,
            requeue_fn=self._queue_decompilation,
            label="AI Decompilation",
        )
        if not polled_ok:
            if poll_err is not None:
                self._safe_dispatch(
                    stop_event,
                    self._on_decomp,
                    GenericApiReturn[TokenisedData](
                        success=False, error_message=poll_err
                    ),
                )
            return None

        tokenised, fetch_err = self._fetch_tokenised(function_id)
        if tokenised is None:
            self._safe_dispatch(
                stop_event,
                self._on_decomp,
                GenericApiReturn[TokenisedData](success=False, error_message=fetch_err),
            )
            return None

        self._decomp_cache[function_id] = tokenised
        self._safe_dispatch(
            stop_event,
            self._on_decomp,
            GenericApiReturn[TokenisedData](success=True, data=tokenised),
        )
        return tokenised

    def _fetch_summary(
        self, function_id: int
    ) -> tuple[SummaryData | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                summary = FunctionsAIDecompilationApi(
                    api_client
                ).get_ai_decompilation_summary(function_id=function_id)
            return summary, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching AI decompilation summary: {e}"

    def _run_summary_phase(
        self, function_id: int, stop_event: threading.Event
    ) -> None:
        cached = self._summary_cache.get(function_id)
        if cached is not None:
            self._safe_dispatch(
                stop_event,
                self._on_summary,
                GenericApiReturn[SummaryData](success=True, data=cached),
            )
            return

        summary, err = self._fetch_summary(function_id)
        if summary is None:
            self._safe_dispatch(
                stop_event,
                self._on_summary,
                GenericApiReturn[SummaryData](success=False, error_message=err),
            )
            return

        self._summary_cache[function_id] = summary
        self._safe_dispatch(
            stop_event,
            self._on_summary,
            GenericApiReturn[SummaryData](success=True, data=summary),
        )

    def _queue_comments(self, function_id: int) -> tuple[bool, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                FunctionsAIDecompilationApi(
                    api_client
                ).regenerate_ai_decompilation_inline_comments(function_id=function_id)
            return True, None
        except ApiException as e:
            if e.status == 409:
                return True, None
            return False, _format_api_error(e)
        except Exception as e:
            return False, f"Unexpected error queuing inline comments: {e}"

    def _fetch_comments_status(
        self, function_id: int
    ) -> tuple[WorkflowProgress | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                progress = FunctionsAIDecompilationApi(
                    api_client
                ).get_ai_decompilation_inline_comments_status(function_id=function_id)
            return progress, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching inline comments status: {e}"

    def _fetch_comments(
        self, function_id: int
    ) -> tuple[CommentsData | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                comments = FunctionsAIDecompilationApi(
                    api_client
                ).get_ai_decompilation_inline_comments(function_id=function_id)
            return comments, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching inline comments: {e}"

    def _run_comments_phase(
        self, function_id: int, stop_event: threading.Event
    ) -> None:
        comments, err = self._fetch_comments(function_id)
        if comments is None:
            self._safe_dispatch(
                stop_event,
                self._on_comments,
                GenericApiReturn[CommentsData](success=False, error_message=err),
            )
            return

        status = str(comments.task_status)

        if status == TaskStatus.COMPLETED.value:
            self._safe_dispatch(
                stop_event,
                self._on_comments,
                GenericApiReturn[CommentsData](success=True, data=comments),
            )
            return

        if status == TaskStatus.UNINITIALISED.value:
            queued_ok, queue_err = self._queue_comments(function_id)
            if not queued_ok:
                self._safe_dispatch(
                    stop_event,
                    self._on_comments,
                    GenericApiReturn[CommentsData](
                        success=False, error_message=queue_err
                    ),
                )
                return

        polled_ok, poll_err = self._poll_workflow(
            function_id=function_id,
            stop_event=stop_event,
            status_fn=self._fetch_comments_status,
            requeue_fn=self._queue_comments,
            label="Inline Comments",
        )
        if not polled_ok:
            if poll_err is not None:
                self._safe_dispatch(
                    stop_event,
                    self._on_comments,
                    GenericApiReturn[CommentsData](
                        success=False, error_message=poll_err
                    ),
                )
            return

        final, final_err = self._fetch_comments(function_id)
        if final is None:
            self._safe_dispatch(
                stop_event,
                self._on_comments,
                GenericApiReturn[CommentsData](
                    success=False, error_message=final_err
                ),
            )
            return

        self._safe_dispatch(
            stop_event,
            self._on_comments,
            GenericApiReturn[CommentsData](success=True, data=final),
        )

    def _poll_workflow(
        self,
        function_id: int,
        stop_event: threading.Event,
        status_fn: Callable[[int], tuple[WorkflowProgress | None, str | None]],
        requeue_fn: Callable[[int], tuple[bool, str | None]],
        label: str,
    ) -> tuple[bool, str | None]:
        requeue_attempts = 0
        while not stop_event.is_set():
            progress, status_err = status_fn(function_id)
            if status_err is not None or progress is None:
                return False, status_err or f"{label} status fetch returned nothing."

            logger.info(
                f"RevEng.AI: {label} progress for function id {function_id}: {progress.status}"
            )

            if progress.status == TaskStatus.COMPLETED:
                return True, None

            if progress.status == TaskStatus.FAILED:
                return False, (
                    _last_message_text(progress.messages)
                    or f"{label} task failed! Please retry."
                )

            if progress.status == TaskStatus.UNINITIALISED:
                if requeue_attempts >= MAX_REQUEUE_ATTEMPTS:
                    return False, (
                        f"{label} task stayed uninitialised; "
                        "backend did not start the workflow."
                    )
                requeue_attempts += 1
                queued_ok, queue_err = requeue_fn(function_id)
                if not queued_ok:
                    return False, queue_err

            if stop_event.wait(POLL_INTERVAL_SECONDS):
                return False, None

        return False, None

    def _begin_ai_decomp_task(self, stop_event: threading.Event, start_ea: int) -> None:
        function_id = self._get_function_id(start_ea=start_ea)
        if function_id is None:
            self._safe_dispatch(
                stop_event,
                self._on_decomp,
                GenericApiReturn[TokenisedData](success=True, data=None),
            )
            return

        tokenised = self._run_decomp_phase(function_id, stop_event)
        if tokenised is None:
            return

        self._run_summary_phase(function_id, stop_event)
        self._run_comments_phase(function_id, stop_event)


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
