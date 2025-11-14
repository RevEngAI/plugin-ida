
from revengai import (
    Configuration,
)

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from revengai import (
    FunctionsDataTypesApi,
    FunctionDataTypesList,
    BaseResponseFunctionDataTypesList
)

from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.transformations.import_data_types import ImportDataTypes


class ImportDataTypesService(IThreadService):
    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def import_data_types(self, analysis_id: int, function_ids: list[int] | None = None):
        # TODO: PLU-192 Create lookup of effective_address: matched_function
        # TODO: PLU-192 Batch function_ids from the same analysis_id together before making the API call.
        # TODO: PLU-192 Make the API call and import the types using the matched function data.
        # TODO: PLU-192 Attempt to apply these but using the original effective address. This means we need a way of going back from matched function to src ea.

        response = self._get_data_types(analysis_id, function_ids)
        if response:
            idt : ImportDataTypes = ImportDataTypes()
            idt.execute(response)

    def _get_data_types(self, analysis_id: int, function_ids: list[int] | None = None) -> FunctionDataTypesList | None:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            client = FunctionsDataTypesApi(api_client=api_client)
            response: BaseResponseFunctionDataTypesList = (
                client.list_function_data_types_for_analysis(analysis_id, function_ids=function_ids)
            )
            if response.status:
                return response.data

