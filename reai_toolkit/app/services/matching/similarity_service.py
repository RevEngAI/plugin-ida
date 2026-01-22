from typing import Callable
import threading

from loguru import logger
from revengai import (
    Configuration,
)

from reai_toolkit.app.core import SimpleNetStore
from reai_toolkit.app.interfaces.thread_service import IThreadService
from revengai import FunctionMatchingResponse
from revengai.models.function_matching_request import FunctionMatchingRequest
from revengai.models.matched_function import MatchedFunction
from revengai.api.functions_core_api import FunctionsCoreApi



class SimilarityService(IThreadService):
    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration) -> None:
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def fetch_similar_functions(self, func_addr: int, vaddr: int, callback: Callable[[int, list[MatchedFunction]], None]) -> None:
        logger.debug("called fetch_similar_functions")
        self.start_worker(
            target=self._perform_function_similarity_request,
            args=(func_addr, vaddr, callback),
        )

    def _perform_function_similarity_request(self, stop_event: threading.Event, func_id: int, vaddr: int, callback: Callable[[int, list[MatchedFunction]], None]) -> None:
        # TODO: Remove hardcoded model_id
        # TODO: Get function_id for given func_addr
        # TODO: Add logic to attempt multiple times to perform this on timeout/failure

        func_id = 942454684
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            request: FunctionMatchingRequest = FunctionMatchingRequest(model_id=21, function_ids=[func_id])
            api: FunctionsCoreApi = FunctionsCoreApi(api_client)
            response: FunctionMatchingResponse = api.batch_function_matching(request)

            logger.debug(response.model_dump_json())
            if response.matches:
                return callback(vaddr, response.matches[0].matched_functions)
    