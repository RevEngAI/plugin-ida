import threading
from typing import Callable

from libbs.decompilers.ida.compat import execute_write, execute_read
import idc

import idautils
import idaapi
import ida_name

from loguru import logger
from revengai import (
    AnalysesCoreApi,
    BaseResponseAnalysisFunctionMapping,
    BaseResponseBasic,
    Configuration,
)

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.analysis_sync.schema import MatchedFunctionSummary
from reai_toolkit.app.services.data_types.data_types_service import ImportDataTypesService
from reai_toolkit.app.services.rename.rename_service import RenameService
from reai_toolkit.app.services.rename.schema import RenameInput
from reai_toolkit.app.services.variable_sync.variable_sync_service import VariableSyncService

from revengai.models.function_mapping import FunctionMapping


class AnalysisSyncService(IThreadService):
    def __init__(
        self,
        data_types_service: ImportDataTypesService,
        rename_service: RenameService,
        variable_sync_service: VariableSyncService,
        netstore_service: SimpleNetStore,
        sdk_config: Configuration,
    ):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)
        self.data_types_service: ImportDataTypesService = data_types_service
        self.rename_service: RenameService = rename_service
        self.variable_sync_service: VariableSyncService = variable_sync_service

    def thread_in_progress(self) -> bool:
        """
        Notify that the thread is still in progress.
        """
        return self.is_worker_running()

    def start_syncing(self, func_map: FunctionMapping, callback: Callable[[GenericApiReturn[MatchedFunctionSummary]], None]) -> None:
        """
        Starts syncing the analysis data as a background job.
        """
        # Ensure any existing worker is stopped before starting a new one
        self.stop_worker()
        self.start_worker(
            target=self._sync_analysis_data,
            args=(func_map, callback),
        )

    def get_function_matches(self, callback: Callable[[FunctionMapping], None]) -> None:
        analysis_id: int | None = self.netstore_service.get_analysis_id()
        if analysis_id is None:
            return

        response = self.api_request_returning(
            fn=lambda: self._fetch_model_id(analysis_id=analysis_id)
        )

        if response.success is False:
            logger.error("failed to retrieve model id")
            return

        response: GenericApiReturn[FunctionMapping] = self.api_request_returning(
            fn=lambda: self._fetch_function_map(analysis_id=analysis_id)
        )

        if response.success is False:
            logger.error("failed to retrieve function map")
            return
        
        if response.data:
            callback(response.data)


    def _fetch_model_id(self, analysis_id: int) -> int:
        """
        Fetches the model ID for the given analysis ID.
        """
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)

            analysis_details: BaseResponseBasic = analyses_client.get_analysis_basic_info(analysis_id)
            model_id = analysis_details.data.model_id
            self.netstore_service.put_model_id(model_id)
            model_name = analysis_details.data.model_name
            self.netstore_service.put_model_name(model_name)

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

            function_map: BaseResponseAnalysisFunctionMapping = analyses_client.get_analysis_function_map(analysis_id=analysis_id)
            if function_map.data:
                func_map: FunctionMapping = function_map.data.function_maps
                self.netstore_service.put_function_mapping(func_map)

            return func_map

    @execute_write
    def _perform_function_sync(
        self,
        func_map: FunctionMapping,
    ) -> tuple[GenericApiReturn[MatchedFunctionSummary], list[RenameInput], list[tuple[int, int | None, str]]]:
        local_vaddr_to_matched_name: dict[str, str] = func_map.name_map
        addr_to_function_id: dict[int, int] = {
            int(addr): int(fid) for fid, addr in func_map.function_map.items()
        }

        logger.info(f"RevEng.AI: Retrieved {len(local_vaddr_to_matched_name)} functions from analysis")

        matched_function_count: int = 0
        unmatched_function_count: int = 0
        total_function_count: int = 0
        deduped_name_count: int = 0

        name_pushbacks: list[RenameInput] = []
        needs_canonical: list[tuple[int, int | None, str]] = []

        local_vaddr: int
        for local_vaddr in idautils.Functions():
            local_vaddr_str: str = str(local_vaddr)
            new_name: str | None = local_vaddr_to_matched_name.get(local_vaddr_str)
            old_name: str | None = idc.get_func_name(local_vaddr)

            if new_name:
                matched_function_count += 1
                if new_name != old_name:
                    fid: int | None = addr_to_function_id.get(local_vaddr)
                    if self.update_function_name(local_vaddr, new_name, check_user_flags=True):
                        self.tag_function_as_renamed(new_name)
                    elif self.is_protected_user_name(local_vaddr):
                        pass
                    else:
                        holder: int = ida_name.get_name_ea(idaapi.BADADDR, new_name)
                        if holder != idaapi.BADADDR and holder != local_vaddr:
                            final: str | None = self.apply_deduped_name(local_vaddr, new_name)
                            if final:
                                deduped_name_count += 1
                                self.tag_function_as_renamed(final)
                                if fid is not None:
                                    name_pushbacks.append(
                                        RenameInput(ea=local_vaddr, new_name=final, function_id=fid)
                                    )
                        else:
                            needs_canonical.append((local_vaddr, fid, new_name))
            else:
                unmatched_function_count += 1

            total_function_count += 1

        logger.info(f"RevEng.AI: Matched {matched_function_count} functions")
        logger.info(f"RevEng.AI: {unmatched_function_count} functions not matched")

        summary: MatchedFunctionSummary = MatchedFunctionSummary(
            matched_function_count=matched_function_count,
            unmatched_function_count=unmatched_function_count,
            total_function_count=total_function_count,
            deduped_name_count=deduped_name_count,
        )
        return GenericApiReturn(success=True, data=summary), name_pushbacks, needs_canonical

    def _match_functions(
        self, func_map: FunctionMapping
    ) -> tuple[GenericApiReturn[MatchedFunctionSummary], list[RenameInput], list[tuple[int, int | None, str]]]:
        try:
            return self._perform_function_sync(func_map=func_map)
        except Exception as e:
            logger.error(f"RevEng.AI: Exception during function sync: {e}")
            return (
                GenericApiReturn(success=False, error_message=f"Exception during function sync: {e}"),
                [],
                [],
            )

    def _apply_canonical_names(
        self,
        needs_canonical: list[tuple[int, int | None, str]],
        name_pushbacks: list[RenameInput],
    ) -> int:
        if not needs_canonical:
            return 0

        mapping: dict[str, str] = self.rename_service.canonicalize_names(
            [name for _, _, name in needs_canonical]
        )

        canonicalized: int = 0
        for ea, fid, original in needs_canonical:
            canonical: str = mapping.get(original, original)
            final: str | None = self.apply_deduped_name(ea, canonical)
            if final:
                canonicalized += 1
                self.tag_function_as_renamed(final)
                if fid is not None:
                    name_pushbacks.append(RenameInput(ea=ea, new_name=final, function_id=fid))
        return canonicalized

    def _sync_analysis_data(self, _: threading.Event, func_map: FunctionMapping, on_complete_callback: Callable[[GenericApiReturn[MatchedFunctionSummary]], None]) -> None:
        response, name_pushbacks, needs_canonical = self._match_functions(func_map)
        if response.success is False:
            logger.error(f"failed to sync analysis data due to {response.error_message}")
            on_complete_callback(response)
            return

        canonicalized: int = self._apply_canonical_names(needs_canonical, name_pushbacks)
        if response.data is not None:
            response.data.canonicalized_name_count = canonicalized

        if name_pushbacks:
            pushed: int = self.rename_service.push_remote_names(name_pushbacks)
            if response.data is not None:
                response.data.pushed_name_count = pushed
            if pushed < len(name_pushbacks):
                logger.warning(
                    f"RevEng.AI: pushed {pushed}/{len(name_pushbacks)} corrected name(s); "
                    f"{len(name_pushbacks) - pushed} rejected (functions not editable on the platform)"
                )

        matches: dict[int, int] = {int(k): v for k, v in func_map.function_map.items()}
        dt_result = self.data_types_service.import_data_types(matches)
        if response.data is not None:
            response.data.data_types_error = dt_result.error

            surviving: set[int] = {
                int(fid)
                for fid, vaddr in func_map.function_map.items()
                if str(vaddr) in func_map.name_map
            }
            push_ids: set[int] = (dt_result.remote_absent_ids | dt_result.apply_failed_ids) & surviving
            targets: dict[int, int] = {fid: matches[fid] for fid in push_ids if fid in matches}
            if targets:
                analysis_id: int | None = self.netstore_service.get_analysis_id()
                response.data.pushed_type_count = self.variable_sync_service.push_local_function_types_batch(
                    targets, analysis_id
                )

        on_complete_callback(response)