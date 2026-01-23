from typing import TYPE_CHECKING

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.services.analysis_sync.analysis_sync import AnalysisSyncService
from reai_toolkit.app.services.analysis_sync.schema import MatchedFunctionSummary

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
        # TODO: Add SelectFunctionsWindow as member variable from PLU-231

    def run_dialog(self) -> None:
        pass

    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()

    def is_active_worker(self) -> bool:
        """Check if the analysis sync worker is active."""
        return self.analysis_sync_service.is_worker_running()

    def sync_analysis(self) -> None:
        """Sync the analysis data."""
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

    def _on_receive_function_map(self, func_map: FunctionMapping) -> None:
        # TODO: Present window for select subset of functions. Use existing SelectFunctionsWindow from PLU-231
        self.analysis_sync_service.start_syncing(func_map, callback=self._on_complete)
