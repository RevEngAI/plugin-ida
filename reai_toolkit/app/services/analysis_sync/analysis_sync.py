import threading
from typing import Any, Callable

import ida_kernwin
from libbs.decompilers.ida.compat import execute_write, execute_read

import idautils
import idaapi

from loguru import logger
from revengai import (
    AnalysesCoreApi,
    ApiClient,
    Configuration,
    FunctionMapping,
    FunctionDataTypesList,
    FunctionsDataTypesApi,
    BaseResponseFunctionDataTypesList,
    Structure,
    Enumeration,
    TypeDefinition,
    GlobalVariable
)

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.analysis_sync.schema import MatchedFunctionSummary
from reai_toolkit.app.transformations.import_data_types import ImportDataTypes


class TaggedDependency:
    def __init__(self, dependency: Structure | Enumeration | TypeDefinition | GlobalVariable):
        self.dependency: Structure | Enumeration | TypeDefinition | GlobalVariable = dependency
        self.processed: bool = False
        self.name: str = self.dependency.name

    def __repr__(self):
        return self.dependency.__repr__()


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

            analysis_details = analyses_client.get_analysis_basic_info(analysis_id=analysis_id)
            model_id = analysis_details.data.model_id
            self.safe_put_model_id(model_id=model_id)
            model_name = analysis_details.data.model_name
            self.safe_put_model_name_local(model_name=model_name)

            local_base_address: int = self._get_current_base_address()

            if analysis_details.data and analysis_details.data.base_address is not None:
                remote_base_address: int = analysis_details.data.base_address

                if local_base_address != remote_base_address:
                    base_address_delta: int = remote_base_address - local_base_address
                    self._rebase_program(base_address_delta)

            return model_id

    @execute_read
    def _get_current_base_address(self) -> int:
        return idaapi.get_imagebase()

    @execute_write
    def _rebase_program(self, base_address_delta: int) -> None:
        idaapi.rebase_program(base_address_delta, idaapi.MSF_FIXONCE)

    def _fetch_function_map(self, analysis_id: int) -> FunctionMapping:
        """
        Fetches the function map for the given analysis ID.
        """
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)

            function_map = analyses_client.get_analysis_function_map(analysis_id=analysis_id)
            func_map: FunctionMapping = function_map.data.function_maps
            self.safe_put_function_mapping(func_map=func_map)
            return func_map

    def _match_functions(
        self,
        func_map: FunctionMapping,
    ) -> GenericApiReturn[MatchedFunctionSummary]:
        # Mapping of local function addresses to mangled names
        local_vaddr_to_matched_name: dict[str, str] = func_map.name_map

        logger.info(f"RevEng.AI: Retrieved {len(local_vaddr_to_matched_name)} functions from analysis")

        # Compute which IDA functions match the revengai analysis functions
        matched_function_count: int = 0
        unmatched_function_count: int = 0
        total_function_count: int = 0

        local_vaddr: int
        for local_vaddr in idautils.Functions():
            local_vaddr_str: str = str(local_vaddr)
            new_name: str | None = local_vaddr_to_matched_name.get(local_vaddr_str)
            if new_name:
                self.safe_set_name(local_vaddr, new_name, check_user_flags=True)
                matched_function_count += 1
            else:
                unmatched_function_count += 1
            
            total_function_count += 1

        logger.info(f"RevEng.AI: Matched {matched_function_count} functions")
        logger.info(f"RevEng.AI: {unmatched_function_count} functions not matched")

        return GenericApiReturn(
            success=True,
            data=MatchedFunctionSummary(
                matched_function_count=matched_function_count,
                unmatched_function_count=unmatched_function_count,
                total_function_count=total_function_count,
            ),
        )

    def _get_data_types(self, analysis_id: int) -> FunctionDataTypesList | None:
        with ApiClient(configuration=self.sdk_config) as api_client:
            client = FunctionsDataTypesApi(api_client=api_client)
            response: BaseResponseFunctionDataTypesList = (
                client.list_function_data_types_for_analysis(analysis_id)
            )
            if response.status:
                return response.data

    def _safe_match_functions(
        self, func_map: FunctionMapping
    ) -> GenericApiReturn[MatchedFunctionSummary]:
        data = GenericApiReturn(success=False, error_message="Failed to match functions.")

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

    def _sync_analysis_data(self, _: threading.Event, analysis_id: int) -> None:
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

        function_mapping: FunctionMapping | None = response.data

        response = self._safe_match_functions(func_map=function_mapping)
        if not response.success:
            self.call_callback(generic_return=response)
            return

        result: FunctionDataTypesList | None = self._get_data_types(analysis_id)
        if result and result.total_data_types_count:
            import_data_types: ImportDataTypes = ImportDataTypes()
            import_data_types.execute(result)
        else:
            logger.warning(f"found no type information for {analysis_id}")

        self.call_callback(generic_return=response)
