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


class ImportDataTypesService(IThreadService):
    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration) -> None:
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def import_data_types(self, matches: dict[int, int]) -> None:
        idt : ImportDataTypes = ImportDataTypes()

        matched_function_ids: list[int] = list(matches.keys())

        # Attempt to retrieve the data types from the API and apply them to our analysis.
        try:
            response: FunctionDataTypesList | None = self._get_data_types(matched_function_ids)
        except NotFoundException as e:
            logger.warning(f"failed to apply data types for {matched_function_ids} due to: {e}")
        else:
            if response:
                idt.execute(response, matched_function_mapping=matches)

    def _get_data_types(self, function_ids: list[int] | None = None) -> FunctionDataTypesList | None:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            client = FunctionsDataTypesApi(api_client=api_client)
            response: BaseResponseFunctionDataTypesList = (
                client.list_function_data_types_for_functions(function_ids=function_ids) # type: ignore
            )
            if response.status:
                return response.data

