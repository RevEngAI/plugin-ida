from typing import TYPE_CHECKING

from revengai import Symbols

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.services.analysis_sync.analysis_sync import AnalysisSyncService
from reai_toolkit.app.services.analysis_sync.schema import MatchedFunctionSummary
from reai_toolkit.app.components.dialogs.import_functions_dialog import ImportFunctionsWindow, MatchedFunction
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
        self._import_funcs_window: ImportFunctionsWindow | None = None

    def run_dialog(self) -> None:
        pass

    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()

    def is_active_worker(self) -> bool:
        """Check if the analysis sync worker is active."""
        return self.analysis_sync_service.is_worker_running()

    def sync_analysis(self) -> None:
        """
        AnalysisSyncCoordinator.sync_analysis - Entrypoint
                       |
                       v
        AnalysisSyncService.get_function_matches - Query the API for function matches
                       |
                       v
        AnalysisSyncCoordinator._on_receive_function_map - Process the function matches in preparation for presenting in a dialog window
                       |
                       v
        ImportFunctionsWindow.show - Present matches in a dialog window for user to subset
                       |
                       v
        AnalysisSyncCoordinator._execute_sync - Callback wrapper
                       |
                       v
        AnalysisSyncService.start_syncing - Execute renaming and importing of data types for selected matched functions.
                       |
                       v
        AnalysisSyncCoordinator.on_complete - Sync complete
        """
        self.analysis_sync_service.get_function_matches(callback=self._on_receive_function_map)
        self.safe_refresh()

    def _on_complete(
        self, generic_return: GenericApiReturn[MatchedFunctionSummary]
    ) -> None:
        """
        Handle completion of analysis syncing.
        """
        if generic_return.success:
            self.safe_info(
                msg=f"Analysis data synced successfully. \n\nSynced {generic_return.data.matched_function_count} functions with remote analysis."
                + f"\n{generic_return.data.unmatched_function_count} local functions not present in remote analysis."
            )
        else:
            self.safe_error(message=generic_return.error_message)

        self.safe_refresh()

    def _execute_sync(self, remote_mapping: FunctionMapping) -> None:
        self.analysis_sync_service.start_syncing(remote_mapping, callback=self._on_complete)

    def _on_receive_function_map(self, remote_mapping: FunctionMapping) -> None:
        out: dict[int, MatchedFunction] = {}

        symbols: Symbols | None = collect_symbols_from_ida()
        if symbols is None or symbols.function_boundaries is None:
            return

        for func_boundary in symbols.function_boundaries:
            old_name: str = func_boundary.mangled_name
            start_addr: str = str(func_boundary.start_address)
            new_name: str | None = remote_mapping.name_map.get(start_addr)
            if new_name:
                entry: MatchedFunction = MatchedFunction(old_name=old_name, new_name=new_name, vaddr=func_boundary.start_address, enabled=True)
                out[func_boundary.start_address] = entry

        importFuncsWindow = ImportFunctionsWindow(
            out, remote_mapping, self._execute_sync
        )
        
        importFuncsWindow.show()
