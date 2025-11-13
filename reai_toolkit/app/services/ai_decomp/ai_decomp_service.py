import threading
import time
from typing import Any, Callable, Optional

from loguru import logger
from revengai import (
    Configuration,
    FunctionMapping,
    FunctionsAIDecompilationApi,
)
from revengai.models import GetAiDecompilationTask

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.interfaces.thread_service import IThreadService


class AiDecompService(IThreadService):
    _thread_callback: Callable[..., Any] = None
    _decomp_cache: dict[int, GetAiDecompilationTask] = {}

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def call_callback(
        self, generic_return: GenericApiReturn[GetAiDecompilationTask]
    ) -> None:
        self._thread_callback(generic_return)

    def thread_in_progress(self) -> bool:
        """
        Notify that the thread is still in progress.
        """
        return self.is_worker_running()

    def start_ai_decomp_task(
        self, ea: int, thread_callback: Callable[..., Any]
    ) -> None:
        """
        Starts AI decompilation task as a background job.
        """
        # Ensure any existing worker is stopped before starting a new one
        self.stop_worker()

        # Set the callback after stopping any existing worker
        self._thread_callback = thread_callback

        self.start_worker(
            target=self._begin_ai_decomp_task,
            args=(ea,),
        )

    def _get_function_id(self, start_ea: int) -> Optional[int]:
        function_map: FunctionMapping = self.safe_get_function_mapping_local()

        inverse_function_map = function_map.inverse_function_map

        function_id = inverse_function_map.get(str(int(start_ea)), None)

        return function_id

    def _poll_ai_decomp_task(
        self, function_id: int
    ) -> Optional[GetAiDecompilationTask]:
        """
        Polls the AI decompilation task until completion or failure.
        """
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            clinet = FunctionsAIDecompilationApi(api_client)

            ai_decomp_task = clinet.get_ai_decompilation_task_result(
                function_id=function_id
            )
            return ai_decomp_task.data

    def _create_ai_decomp_task(self, function_id: int) -> bool:
        """
        Creates the AI decompilation task for the given function ID.
        """
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            client = FunctionsAIDecompilationApi(api_client)

            response = client.create_ai_decompilation_task(
                function_id=function_id,
            )
            return response.status

    def _begin_ai_decomp_task(self, stop_event: threading.Event, start_ea: int) -> None:
        """
        Begins the AI decompilation task for the given function address.
        """

        function_id = self._get_function_id(start_ea=start_ea)

        if function_id is None and not stop_event.is_set():
            self.call_callback(
                GenericApiReturn[GetAiDecompilationTask](
                    success=True,
                    data=None,
                )
            )
            return

        if function_id in self._decomp_cache and not stop_event.is_set():
            self.call_callback(
                GenericApiReturn[GetAiDecompilationTask](
                    success=True,
                    data=self._decomp_cache[function_id],
                )
            )
            return

        while not stop_event.is_set():
            # Sleep between polls without blocking IDA’s UI
            for _ in range(50):  # 50 * 0.1s = 5s; allows quicker cancellation
                if stop_event.is_set():
                    return
                time.sleep(0.5)

                # Fetch result - if uninistialised or none, begin task
                response = self.api_request_returning(
                    fn=lambda: self._poll_ai_decomp_task(function_id=function_id)
                )

                if not response.success:
                    self.call_callback(generic_return=response)
                    return

                data: GetAiDecompilationTask = response.data

                logger.info(
                    f"RevEng.AI: AI Decompilation progress for function id {function_id}: {data.status}"
                )

                if data.status == "uninitialised" and not stop_event.is_set():
                    # Means task not started, so start it
                    response = self.api_request_returning(
                        fn=lambda: self._create_ai_decomp_task(function_id=function_id)
                    )
                    if not response.success:
                        self.call_callback(generic_return=response)
                        return

                elif data.status == "success" and not stop_event.is_set():
                    self._decomp_cache[function_id] = data
                    self.call_callback(
                        GenericApiReturn[GetAiDecompilationTask](
                            success=True,
                            data=data,
                        )
                    )
                    return
                elif data.status == "error" and not stop_event.is_set():
                    self.call_callback(
                        GenericApiReturn[GetAiDecompilationTask](
                            success=False,
                            error_message="AI Decompilation task failed! Please retry the decompilation.",
                        )
                    )
                    return
