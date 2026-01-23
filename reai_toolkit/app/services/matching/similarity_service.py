from typing import Callable
import threading
import time

from loguru import logger
from revengai import (
    BaseResponseBasic,
    Configuration,
)

from reai_toolkit.app.core import SimpleNetStore
from reai_toolkit.app.interfaces.thread_service import IThreadService
from revengai import FunctionMatchingResponse
from revengai.models.function_matching_request import FunctionMatchingRequest
from revengai.models.matched_function import MatchedFunction
from revengai.api.functions_core_api import FunctionsCoreApi
from revengai.api.analyses_core_api import AnalysesCoreApi



class SimilarityService(IThreadService):
    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration) -> None:
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def fetch_similar_functions(self, func_id: int, vaddr: int, callback: Callable[[int, int, list[MatchedFunction]], None]) -> None:
        self.start_worker(
            target=self._perform_function_similarity_request,
            args=(func_id, vaddr, callback),
        )

    def _perform_function_similarity_request(self, stop_event: threading.Event, func_id: int, vaddr: int, callback: Callable[[int, int, list[MatchedFunction]], None]) -> None:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)

            analysis_id: int | None = self.safe_get_analysis_id_local()
            if analysis_id is None:
                logger.warning("failed to perform similarity request due to invalid analysis id")
                return
            
            analysis_details: BaseResponseBasic = analyses_client.get_analysis_basic_info(analysis_id=analysis_id)
            if analysis_details.data is None:
                logger.warning("failed to perform similarity request due to invalid model id")
                return
            
            model_id = analysis_details.data.model_id
            request: FunctionMatchingRequest = FunctionMatchingRequest(model_id=model_id, function_ids=[func_id], results_per_function=16, min_similarity=70)
            api: FunctionsCoreApi = FunctionsCoreApi(api_client)

            timeout: float = 60.0
            elapsed: float = 0.0
            sleep_interval: float = 0.5

            while stop_event.is_set() is False and elapsed < timeout:
                response: FunctionMatchingResponse = api.batch_function_matching(request)

                if response.error_message:
                    logger.error(f"failed to perform similarity request due to {response.error_message}")
                    return

                logger.info(f"Fetching function similarity result for {func_id}, progress: {response.progress}")
                if response.progress == 100:
                    matches: list[MatchedFunction] = []
                    if response.matches:
                        matches = response.matches[0].matched_functions
                    
                    return callback(func_id, vaddr, matches)

                time.sleep(sleep_interval)
                elapsed += sleep_interval

            if elapsed >= timeout:
                logger.error(f"failed to perform similarity request due to timing out after {timeout} seconds")
            
            if stop_event.is_set():
                logger.warning("cancelled similarity request due to stop_event being set")
                stop_event.clear()