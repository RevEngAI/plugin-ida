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
from revengai.models.decompilation_data import DecompilationData
from revengai.models.summary_data import SummaryData
from revengai.models.task_status import TaskStatus
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
        self._decomp_cache: dict[int, DecompilationData] = {}
        self._summary_cache: dict[int, SummaryData] = {}
        self._comments_cache: dict[int, CommentsData] = {}
        self._inflight: dict[int, threading.Event] = {}
        self._inflight_lock = threading.Lock()

    def thread_in_progress(self) -> bool:
        return self.is_worker_running()

    def is_worker_running(self) -> bool:
        with self._inflight_lock:
            return bool(self._inflight)

    def stop_worker(self) -> None:
        with self._inflight_lock:
            events = list(self._inflight.values())
            self._inflight.clear()
        for evt in events:
            evt.set()
        self._decomp_cache.clear()
        self._summary_cache.clear()
        self._comments_cache.clear()

    def peek_decomp(self, ea: int) -> DecompilationData | None:
        function_id = self._get_function_id(start_ea=ea)
        if function_id is None:
            return None
        return self._decomp_cache.get(function_id)

    def start_ai_decomp_task(
        self,
        ea: int,
        on_decomp: Callable[[GenericApiReturn[DecompilationData]], None],
        on_summary: Callable[[GenericApiReturn[SummaryData]], None],
        on_comments: Callable[[GenericApiReturn[CommentsData]], None],
    ) -> None:
        function_id = self._get_function_id(start_ea=ea)
        if function_id is None:
            on_decomp(GenericApiReturn[DecompilationData](success=True, data=None))
            return

        with self._inflight_lock:
            if function_id in self._inflight:
                return
            stop_event = threading.Event()
            self._inflight[function_id] = stop_event

        worker = threading.Thread(
            target=self._run_task,
            args=(function_id, stop_event, on_decomp, on_summary, on_comments),
            name=f"reai-aidecomp-{function_id}",
            daemon=True,
        )
        worker.start()

    def _run_task(
        self,
        function_id: int,
        stop_event: threading.Event,
        on_decomp: Callable[[GenericApiReturn[DecompilationData]], None],
        on_summary: Callable[[GenericApiReturn[SummaryData]], None],
        on_comments: Callable[[GenericApiReturn[CommentsData]], None],
    ) -> None:
        try:
            if stop_event.is_set():
                return
            decomp = self._run_decomp_phase(function_id, stop_event, on_decomp)
            if decomp is None:
                return
            self._run_summary_phase(function_id, stop_event, on_summary)
            self._run_comments_phase(function_id, stop_event, on_comments)
        except Exception as e:
            logger.error(f"RevEng.AI: AI decompilation task crashed for {function_id}: {e}")
        finally:
            with self._inflight_lock:
                self._inflight.pop(function_id, None)

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

    def _fetch_decompilation(
        self, function_id: int
    ) -> tuple[DecompilationData | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                decomp = FunctionsAIDecompilationApi(
                    api_client
                ).get_ai_decompilation(function_id=function_id)
            return decomp, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            logger.error(
                f"RevEng.AI: failed to parse AI decompilation response for function {function_id}: {e}"
            )
            return None, f"Unexpected error fetching AI decompilation: {e}"

    def _run_decomp_phase(
        self,
        function_id: int,
        stop_event: threading.Event,
        on_decomp: Callable[[GenericApiReturn[DecompilationData]], None],
    ) -> DecompilationData | None:
        cached = self._decomp_cache.get(function_id)
        if cached is not None:
            self._safe_dispatch(
                stop_event,
                on_decomp,
                GenericApiReturn[DecompilationData](success=True, data=cached),
            )
            return cached

        decomp, fetch_err = self._fetch_decompilation(function_id)
        if decomp is None:
            self._safe_dispatch(
                stop_event,
                on_decomp,
                GenericApiReturn[DecompilationData](success=False, error_message=fetch_err),
            )
            return None

        status = str(decomp.status)

        if status == TaskStatus.COMPLETED.value and decomp.decompilation:
            self._decomp_cache[function_id] = decomp
            self._safe_dispatch(
                stop_event,
                on_decomp,
                GenericApiReturn[DecompilationData](success=True, data=decomp),
            )
            return decomp

        if status == TaskStatus.UNINITIALISED.value:
            queued_ok, queue_err = self._queue_decompilation(function_id)
            if not queued_ok:
                self._safe_dispatch(
                    stop_event,
                    on_decomp,
                    GenericApiReturn[DecompilationData](
                        success=False, error_message=queue_err
                    ),
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
                    on_decomp,
                    GenericApiReturn[DecompilationData](
                        success=False, error_message=poll_err
                    ),
                )
            return None

        final, final_err = self._fetch_decompilation(function_id)
        if final is None or not final.decompilation:
            self._safe_dispatch(
                stop_event,
                on_decomp,
                GenericApiReturn[DecompilationData](
                    success=False,
                    error_message=final_err or "AI decompilation returned no content.",
                ),
            )
            return None

        self._decomp_cache[function_id] = final
        self._safe_dispatch(
            stop_event,
            on_decomp,
            GenericApiReturn[DecompilationData](success=True, data=final),
        )
        return final

    def _queue_summary(self, function_id: int) -> tuple[bool, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                FunctionsAIDecompilationApi(
                    api_client
                ).regenerate_ai_decompilation_summary(function_id=function_id)
            return True, None
        except ApiException as e:
            if e.status == 409:
                return True, None
            return False, _format_api_error(e)
        except Exception as e:
            return False, f"Unexpected error queuing AI decompilation summary: {e}"

    def _fetch_summary_status(
        self, function_id: int
    ) -> tuple[WorkflowProgress | None, str | None]:
        try:
            with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                progress = FunctionsAIDecompilationApi(
                    api_client
                ).get_ai_decompilation_summary_status(function_id=function_id)
            return progress, None
        except ApiException as e:
            return None, _format_api_error(e)
        except Exception as e:
            return None, f"Unexpected error fetching AI decompilation summary status: {e}"

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
        self,
        function_id: int,
        stop_event: threading.Event,
        on_summary: Callable[[GenericApiReturn[SummaryData]], None],
    ) -> None:
        cached = self._summary_cache.get(function_id)
        if cached is not None:
            self._safe_dispatch(
                stop_event,
                on_summary,
                GenericApiReturn[SummaryData](success=True, data=cached),
            )
            return

        summary, err = self._fetch_summary(function_id)
        if summary is None:
            self._safe_dispatch(
                stop_event,
                on_summary,
                GenericApiReturn[SummaryData](success=False, error_message=err),
            )
            return

        status = str(summary.task_status)

        if status == TaskStatus.COMPLETED.value:
            self._summary_cache[function_id] = summary
            self._safe_dispatch(
                stop_event,
                on_summary,
                GenericApiReturn[SummaryData](success=True, data=summary),
            )
            return

        if status == TaskStatus.UNINITIALISED.value:
            queued_ok, queue_err = self._queue_summary(function_id)
            if not queued_ok:
                self._safe_dispatch(
                    stop_event,
                    on_summary,
                    GenericApiReturn[SummaryData](
                        success=False, error_message=queue_err
                    ),
                )
                return

        polled_ok, poll_err = self._poll_workflow(
            function_id=function_id,
            stop_event=stop_event,
            status_fn=self._fetch_summary_status,
            requeue_fn=self._queue_summary,
            label="AI Summary",
        )
        if not polled_ok:
            if poll_err is not None:
                self._safe_dispatch(
                    stop_event,
                    on_summary,
                    GenericApiReturn[SummaryData](
                        success=False, error_message=poll_err
                    ),
                )
            return

        final, final_err = self._fetch_summary(function_id)
        if final is None:
            self._safe_dispatch(
                stop_event,
                on_summary,
                GenericApiReturn[SummaryData](
                    success=False, error_message=final_err
                ),
            )
            return

        self._summary_cache[function_id] = final
        self._safe_dispatch(
            stop_event,
            on_summary,
            GenericApiReturn[SummaryData](success=True, data=final),
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
        self,
        function_id: int,
        stop_event: threading.Event,
        on_comments: Callable[[GenericApiReturn[CommentsData]], None],
    ) -> None:
        cached = self._comments_cache.get(function_id)
        if cached is not None:
            self._safe_dispatch(
                stop_event,
                on_comments,
                GenericApiReturn[CommentsData](success=True, data=cached),
            )
            return

        comments, err = self._fetch_comments(function_id)
        if comments is None:
            self._safe_dispatch(
                stop_event,
                on_comments,
                GenericApiReturn[CommentsData](success=False, error_message=err),
            )
            return

        status = str(comments.task_status)

        if status == TaskStatus.COMPLETED.value:
            self._comments_cache[function_id] = comments
            self._safe_dispatch(
                stop_event,
                on_comments,
                GenericApiReturn[CommentsData](success=True, data=comments),
            )
            return

        if status == TaskStatus.UNINITIALISED.value:
            queued_ok, queue_err = self._queue_comments(function_id)
            if not queued_ok:
                self._safe_dispatch(
                    stop_event,
                    on_comments,
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
                    on_comments,
                    GenericApiReturn[CommentsData](
                        success=False, error_message=poll_err
                    ),
                )
            return

        final, final_err = self._fetch_comments(function_id)
        if final is None:
            self._safe_dispatch(
                stop_event,
                on_comments,
                GenericApiReturn[CommentsData](
                    success=False, error_message=final_err
                ),
            )
            return

        self._comments_cache[function_id] = final
        self._safe_dispatch(
            stop_event,
            on_comments,
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
