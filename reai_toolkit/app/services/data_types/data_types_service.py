import debugpy

from revengai import Configuration
from revengai.exceptions import NotFoundException

from loguru import logger

from revengai.models.matched_function import MatchedFunction
from reai_toolkit.app.core.netstore_service import SimpleNetStore
from revengai import (
    FunctionsDataTypesApi,
    FunctionDataTypesList,
    BaseResponseFunctionDataTypesList
)

from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.transformations.import_data_types import ImportDataTypes

def wait_for_debugger():
    # Start debug server
    debugpy.listen(60000, in_process_debug_adapter=True)
    debugpy.wait_for_client()  # Pause until debugger connects


class ImportDataTypesService(IThreadService):
    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def import_data_types(self, matches: dict[int, MatchedFunction]):
        # wait_for_debugger()
        idt : ImportDataTypes = ImportDataTypes()

        # Overwrite the matched effective address with the original effective address.
        # We need this in order to ensure that we write the obtained function datatypes to the right location.
        for original_ea, matched_func in matches.items():
            matched_func.function_vaddr = original_ea

        # Batch up function id's by analysis id in order to minimize the number of calls to the data types endpoint.
        funcs_by_analysis_id: dict[int, list[int]] = {}
        for matched_func in matches.values():
            if funcs_by_analysis_id.get(matched_func.analysis_id) is None:
                funcs_by_analysis_id[matched_func.analysis_id] = [matched_func.function_id]
            else:
                funcs_by_analysis_id[matched_func.analysis_id].append(matched_func.function_id)

        # Attempt to retrieve the data types from the API and apply them to our analysis.
        for analysis_id, function_ids in funcs_by_analysis_id.items():
            try:
                response: FunctionDataTypesList | None = self._get_data_types(analysis_id, function_ids)
            except NotFoundException as e:
                logger.warning(f"failed to apply data types for {function_ids} due to: {e}")
            else:
                if response:
                    idt.execute(response)

    def _get_data_types(self, analysis_id: int, function_ids: list[int] | None = None) -> FunctionDataTypesList | None:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            client = FunctionsDataTypesApi(api_client=api_client)
            response: BaseResponseFunctionDataTypesList = (
                client.list_function_data_types_for_analysis(analysis_id, function_ids=function_ids) # type: ignore
            )
            if response.status:
                return response.data

