from typing import Callable
import threading
import time

from loguru import logger
from revengai import (
    ApiException,
    Configuration,
    GetMatchesOutputBody,
    GetMatchesStatusOutputBody,
    StartMatchingForFunctionsInputBody,
    TaskStatus,
)

from reai_toolkit.app.core import SimpleNetStore
from reai_toolkit.app.interfaces.thread_service import IThreadService
from revengai.models.matched_function import MatchedFunction
from revengai.api.functions_core_api import FunctionsCoreApi


class SimilarityService(IThreadService):
    def __init__(
        self, netstore_service: SimpleNetStore, sdk_config: Configuration
    ) -> None:
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def fetch_similar_functions(
        self,
        func_id: int,
        vaddr: int,
        callback: Callable[[int, int, list[MatchedFunction], int], None],
    ) -> None:
        self.start_worker(
            target=self._perform_function_similarity_request,
            args=(func_id, vaddr, callback),
        )

    def _perform_function_similarity_request(
        self,
        stop_event: threading.Event,
        func_id: int,
        vaddr: int,
        callback: Callable[[int, int, list[MatchedFunction], int], None],
    ) -> None:
        analysis_id: int | None = self.netstore_service.get_analysis_id()
        if analysis_id is None:
            logger.warning(
                "failed to perform similarity request due to invalid analysis id"
            )
            return

        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            api: FunctionsCoreApi = FunctionsCoreApi(api_client)

            try:
                api.start_functions_matching(
                    StartMatchingForFunctionsInputBody(
                        function_ids=[func_id],
                        results_per_function=16,
                        min_similarity=70,
                    )
                )
            except ApiException as e:
                logger.error(
                    f"failed to start similarity request due to {e}"
                )
                return

            timeout: float = 60.0
            elapsed: float = 0.0
            sleep_interval: float = 0.5

            while stop_event.is_set() is False and elapsed < timeout:
                try:
                    status: GetMatchesStatusOutputBody = (
                        api.get_functions_matching_status(function_ids=[func_id])
                    )
                except ApiException as e:
                    logger.error(
                        f"failed to perform similarity request due to {e}"
                    )
                    return

                logger.info(
                    f"Fetching function similarity result for {func_id}, status: {status.status}"
                )

                if status.status == TaskStatus.FAILED:
                    logger.error(
                        "failed to perform similarity request due to matching failure"
                    )
                    return

                if status.status == TaskStatus.COMPLETED:
                    result: GetMatchesOutputBody = api.get_functions_matches(
                        function_ids=[func_id]
                    )
                    matches: list[MatchedFunction] = []
                    if result.matches:
                        matches = result.matches[0].matched_functions

                    return callback(func_id, vaddr, matches, analysis_id)

                time.sleep(sleep_interval)
                elapsed += sleep_interval

            if elapsed >= timeout:
                logger.error(
                    f"failed to perform similarity request due to timing out after {timeout} seconds"
                )

            if stop_event.is_set():
                logger.warning(
                    "cancelled similarity request due to stop_event being set"
                )
                stop_event.clear()
