from typing import TYPE_CHECKING

from revengai import Symbols

from libbs.decompilers.ida.compat import execute_ui

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.services.analysis_sync.analysis_sync import AnalysisSyncService
from reai_toolkit.app.services.analysis_sync.schema import MatchedFunctionSummary
from reai_toolkit.app.components.dialogs.import_functions_dialog import (
    ImportFunctionsWindow,
    MatchedFunction,
)
from reai_toolkit.app.core.utils import collect_symbols_from_ida

from revengai.models.function_mapping import FunctionMapping

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class AnalysisSyncCoordinator(BaseCoordinator):
    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
        analysis_sync_service: AnalysisSyncService,
    ) -> None:
        super().__init__(app=app, factory=factory, log=log)

        self.analysis_sync_service: AnalysisSyncService = analysis_sync_service
        self._attach_to_existing_analysis: bool = False

    @execute_ui
    def run_dialog(self, matched_functions: dict[int, MatchedFunction], remote_mapping: FunctionMapping) -> None:
        importFuncsWindow = ImportFunctionsWindow(
            matched_functions, remote_mapping
        )

        success: bool
        subset: FunctionMapping
        success, subset = importFuncsWindow.open_modal() # type: ignore
        if success:
            self._execute_sync_task(subset)

    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()

    def is_active_worker(self) -> bool:
        """Check if the analysis sync worker is active."""
        return self.analysis_sync_service.is_worker_running()

    def sync_analysis(self, attach_to_existing_analysis: bool = False) -> None:
        """
        Sync Flow:

            AnalysisSyncCoordinator.sync_analysis          <- Entrypoint
                            │
                            ▼
            AnalysisSyncService.get_function_matches       <- Query API for function matches
                            │
                            ▼
            AnalysisSyncCoordinator._on_receive_function_map   <- Process matches for dialog
                            │
                            ▼
            AnalysisSyncCoordinator.run_dialog             <- Safely launch modal in UI thread
                            │
                            ▼
            ImportFunctionsWindow.open_modal               <- User selects functions
                            │
                            ▼
            AnalysisSyncCoordinator._execute_sync          <- Callback wrapper
                            │
                            ▼
            AnalysisSyncService.start_syncing              <- Rename functions & import types
                            │
                            ▼
            AnalysisSyncCoordinator.on_complete            <- Notify user of completion
        """
        self._attach_to_existing_analysis = attach_to_existing_analysis

        self.analysis_sync_service.get_function_matches(
            callback=self._on_receive_function_map
        )
        self.refresh_disassembly_view()

    def _on_complete(
        self, generic_return: GenericApiReturn[MatchedFunctionSummary]
    ) -> None:
        """
        Handle completion of analysis syncing.
        """
        if generic_return.success:
            self.show_info_dialog(
                msg=f"Analysis data synced successfully. \n\nSynced {generic_return.data.matched_function_count} functions with remote analysis."
                + f"\n{generic_return.data.unmatched_function_count} local functions not present in remote analysis."
            )
        else:
            self.show_error_dialog(message=generic_return.error_message)

        self.refresh_disassembly_view()

    def _execute_sync_task(self, remote_mapping: FunctionMapping) -> None:
        self.analysis_sync_service.start_syncing(
            remote_mapping, callback=self._on_complete
        )

    def _on_receive_function_map(self, remote_mapping: FunctionMapping) -> None:
        matched_functions: dict[int, MatchedFunction] = {}

        symbols: Symbols | None = collect_symbols_from_ida()
        if symbols is None or symbols.function_boundaries is None:
            return

        for func_boundary in symbols.function_boundaries:
            old_name: str = func_boundary.mangled_name
            start_addr: str = str(func_boundary.start_address)
            new_name: str | None = remote_mapping.name_map.get(start_addr)
            if new_name:
                entry: MatchedFunction = MatchedFunction(
                    old_name=old_name,
                    new_name=new_name,
                    vaddr=func_boundary.start_address,
                    enabled=True,
                )
                matched_functions[func_boundary.start_address] = entry

        # If we are syncing from an existing analysis, present a modal to the user to select which functions they wish to import.
        if self._attach_to_existing_analysis:
            self.run_dialog(matched_functions, remote_mapping)
        else:
            self._execute_sync_task(remote_mapping)