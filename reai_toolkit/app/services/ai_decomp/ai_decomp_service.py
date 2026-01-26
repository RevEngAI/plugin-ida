import threading
import time
from typing import Any, Callable

from loguru import logger
from revengai import (
    Configuration,
    FunctionMapping,
    FunctionsAIDecompilationApi,
)
from revengai.models.get_ai_decompilation_task import GetAiDecompilationTask

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.interfaces.thread_service import IThreadService


class AiDecompService(IThreadService):
    def __init__(
        self, netstore_service: SimpleNetStore, sdk_config: Configuration
    ) -> None:
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)
        self._thread_callback: Callable[[GenericApiReturn], None] | None = None
        self._decomp_cache: dict[int, GetAiDecompilationTask] = {}

    def call_callback(
        self, generic_return: GenericApiReturn[GetAiDecompilationTask]
    ) -> None:
        if self._thread_callback:
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

    def _get_function_id(self, start_ea: int) -> int | None:
        function_map: FunctionMapping | None = self.safe_get_function_mapping_local()
        if function_map is None:
            return

        inverse_function_map: dict[str, int] = function_map.inverse_function_map
        return inverse_function_map.get(str(start_ea))

    def _poll_ai_decomp_task(self, function_id: int) -> GetAiDecompilationTask | None:
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
            return response.status if response.status is not None else False

    def _begin_ai_decomp_task(self, stop_event: threading.Event, start_ea: int) -> None:
        """
        Begins the AI decompilation task for the given function address.
        """
        function_id: int | None = self._get_function_id(start_ea=start_ea)

        if function_id is None:
            self.call_callback(
                GenericApiReturn[GetAiDecompilationTask](
                    success=True,
                    data=None,
                )
            )
            return

        if function_id in self._decomp_cache:
            self.call_callback(
                GenericApiReturn[GetAiDecompilationTask](
                    success=True,
                    data=self._decomp_cache[function_id],
                )
            )
            return

        while stop_event.is_set() is False:
            # Sleep between polls without blocking IDA’s UI
            for _ in range(50):
                if stop_event.is_set():
                    return

                time.sleep(0.5)

                response: GenericApiReturn[GetAiDecompilationTask] = (
                    self.api_request_returning(
                        fn=lambda: self._poll_ai_decomp_task(function_id=function_id)
                    )
                )

                if response.success is False or response.data is None:
                    self.call_callback(generic_return=response)
                    return

                data: GetAiDecompilationTask = response.data

                logger.info(
                    f"RevEng.AI: AI Decompilation progress for function id {function_id}: {data.status}"
                )

                if data.status == "error":
                    self.call_callback(
                        GenericApiReturn[GetAiDecompilationTask](
                            success=False,
                            error_message="AI Decompilation task failed! Please retry the decompilation.",
                        )
                    )
                    return

                elif data.status == "uninitialised":
                    # Means task not started, so start it
                    response = self.api_request_returning(
                        fn=lambda: self._create_ai_decomp_task(function_id=function_id)
                    )
                    if response.success is False:
                        self.call_callback(generic_return=response)
                        return

                elif data.status == "success":
                    self._decomp_cache[function_id] = data
                    self.call_callback(
                        GenericApiReturn[GetAiDecompilationTask](
                            success=True,
                            data=data,
                        )
                    )
                    return
