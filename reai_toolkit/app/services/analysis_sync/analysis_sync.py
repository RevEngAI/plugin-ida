import threading
from typing import Any, Callable

import ida_kernwin
import idautils
import idaapi

from loguru import logger
from revengai import AnalysesCoreApi, Configuration, FunctionMapping
from libbs.decompilers.ida.compat import execute_write

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.analysis_sync.schema import MatchedFunctionSummary
from revengai import BaseResponseBasic


class AnalysisSyncService(IThreadService):
    _thread_callback: Callable[..., Any] = None

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def call_callback(self, generic_return: GenericApiReturn) -> None:
        self._thread_callback(generic_return)

    def thread_in_progress(self) -> bool:
        """
        Notify that the thread is still in progress.
        """
        return self.is_worker_running()

    def start_syncing(self, thread_callback: Callable[..., Any]) -> None:
        """
        Starts syncing the analysis data as a background job.
        """
        analysis_id = self.safe_get_analysis_id_local()
        self._thread_callback = thread_callback
        # Ensure any existing worker is stopped before starting a new one
        self.stop_worker()
        self.start_worker(
            target=self._sync_analysis_data,
            args=(analysis_id,),
        )

    def _fetch_model_id(self, analysis_id: int) -> int:
        """
        Fetches the model ID for the given analysis ID.
        """
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)

            analysis_details: BaseResponseBasic = analyses_client.get_analysis_basic_info(
                analysis_id=analysis_id
            )
            model_id = analysis_details.data.model_id
            self.safe_put_model_id(model_id=model_id)
            model_name = analysis_details.data.model_name
            self.safe_put_model_name_local(model_name=model_name)

            if analysis_details.data and analysis_details.data.base_address is not None:
                self._rebase_program(analysis_details.data.base_address)

            return model_id

    @execute_write
    def _rebase_program(self, base_address: int) -> None:
        idaapi.rebase_program(base_address, idaapi.MSF_FIXONCE)

    def _fetch_function_map(self, analysis_id: int) -> FunctionMapping:
        """
        Fetches the function map for the given analysis ID.
        """
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)

            function_map = analyses_client.get_analysis_function_map(
                analysis_id=analysis_id
            )
            func_map = function_map.data.function_maps
            self.safe_put_function_mapping(func_map=func_map)
            return func_map

    def _match_functions(
        self,
        func_map: FunctionMapping,
    ) -> GenericApiReturn[MatchedFunctionSummary]:
        function_map = func_map.function_map
        inverse_function_map = func_map.inverse_function_map

        logger.info(
            f"RevEng.AI: Retrieved {len(function_map)} function mappings from analysis"
        )

        # Compute which IDA functions match the revengai analysis functions
        matched_functions = []
        unmatched_local_functions = []
        unmatched_remote_functions = []

        # Track local functions matched
        local_function_vaddrs_matched = set()
        # print(inverse_function_map)
        # FUN COUNT
        fun_count = 0
        for key, value in func_map.name_map.items():
            if "FUN_" in value:
                fun_count += 1

        # print(f"Function count with 'FUN_': {fun_count}")
        # print(f"Inverse function map: {inverse_function_map}")
        for start_ea in idautils.Functions():
            if str(start_ea) in inverse_function_map:
                new_name: str | None = func_map.name_map.get(str(start_ea), None)
                if new_name is None:
                    return False
                # logger.info(f"RevEng.AI: Renaming function at {start_ea} to {new_name}")
                self.safe_set_name(start_ea, new_name, check_user_flags=True)
                matched_functions.append(
                    (int(inverse_function_map[str(start_ea)]), start_ea)
                )
                local_function_vaddrs_matched.add(start_ea)
            else:
                unmatched_local_functions.append(start_ea)

        unmatched_portal_map = {}
        # Track remote functions not matched
        for func_id_str, func_vaddr in function_map.items():
            if int(func_vaddr) not in local_function_vaddrs_matched:
                unmatched_remote_functions.append((int(func_vaddr), int(func_id_str)))
                unmatched_portal_map[int(func_vaddr)] = int(func_id_str)

        logger.info(f"RevEng.AI: Matched {len(matched_functions)} functions")
        logger.info(
            f"RevEng.AI: {len(unmatched_local_functions)} local functions not matched"
        )
        logger.info(
            f"RevEng.AI: {len(unmatched_remote_functions)} remote functions not matched"
        )

        return GenericApiReturn(
            success=True,
            data=MatchedFunctionSummary(
                matched_local_function_count=len(matched_functions),
                unmatched_local_function_count=len(unmatched_local_functions),
                unmatched_remote_function_count=len(unmatched_remote_functions),
                total_function_count=len(function_map),
            ),
        )

    def _safe_match_functions(
        self, func_map: FunctionMapping
    ) -> GenericApiReturn[MatchedFunctionSummary]:
        data = GenericApiReturn(
            success=False, error_message="Failed to match functions."
        )

        def _do():
            try:
                nonlocal data
                data = self._match_functions(func_map=func_map)
            except Exception as e:
                logger.error(f"RevEng.AI: Exception during function sync: {e}")
                data = GenericApiReturn(
                    success=False, error_message=f"Exception during function sync: {e}"
                )

        ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST)

        return data

    def _sync_analysis_data(
        self, stop_event: threading.Event, analysis_id: int
    ) -> None:
        """
        Syncs the analysis data until completion or failure.
        """

        # Fetch Model ID - Used for function matching

        response = self.api_request_returning(
            fn=lambda: self._fetch_model_id(analysis_id=analysis_id)
        )

        if not response.success:
            self.call_callback(generic_return=response)
            return

        response = self.api_request_returning(
            fn=lambda: self._fetch_function_map(analysis_id=analysis_id)
        )

        if not response.success:
            self.call_callback(generic_return=response)
            return

        function_mapping: FunctionMapping = response.data

        response = self._safe_match_functions(func_map=function_mapping)

        self.call_callback(generic_return=response)
