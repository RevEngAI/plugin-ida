from revengai import ApiException, Configuration
from revengai.exceptions import NotFoundException

from loguru import logger

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from revengai import (
    FunctionsDataTypesApi,
    FunctionDataTypesList,
    BaseResponseFunctionDataTypesList
)

from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.transformations.import_data_types import ImportDataTypes


FUNCTION_IDS_BATCH_SIZE = 50


class ImportDataTypesService(IThreadService):
    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration) -> None:
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def import_data_types(self, matches: dict[int, int]) -> str | None:
        if len(matches) == 0:
            return None

        idt: ImportDataTypes = ImportDataTypes()
        matched_function_ids: list[int] = list(matches.keys())

        try:
            response: FunctionDataTypesList | None = self._get_data_types(matched_function_ids)
        except NotFoundException as e:
            logger.warning(f"failed to apply data types for {len(matched_function_ids)} functions: {e}")
            return None
        except ApiException as e:
            logger.error(f"RevEng.AI: failed to sync function data types: HTTP {e.status} {e.reason}")
            return f"Failed to sync function data types: HTTP {e.status} {e.reason}"
        except Exception as e:
            logger.error(f"RevEng.AI: failed to sync function data types: {e}")
            return f"Failed to sync function data types: {e}"

        if response:
            idt.execute(response, matched_function_mapping=matches)
        return None

    def _get_data_types(self, function_ids: list[int] | None = None) -> FunctionDataTypesList | None:
        if not function_ids:
            return None

        items = []
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            client = FunctionsDataTypesApi(api_client=api_client)
            for start in range(0, len(function_ids), FUNCTION_IDS_BATCH_SIZE):
                chunk = function_ids[start:start + FUNCTION_IDS_BATCH_SIZE]
                response: BaseResponseFunctionDataTypesList = (
                    client.list_function_data_types_for_functions(function_ids=chunk)  # type: ignore
                )
                if response.status and response.data:
                    items.extend(response.data.items)

        return FunctionDataTypesList(items=items)
