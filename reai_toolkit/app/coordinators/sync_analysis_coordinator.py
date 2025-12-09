from typing import TYPE_CHECKING

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.services.analysis_sync.analysis_sync import AnalysisSyncService
from reai_toolkit.app.services.analysis_sync.schema import MatchedFunctionSummary

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class AnalysisSyncCoordinator(BaseCoordinator):
    analysis_sync_service: AnalysisSyncService

    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
        analysis_sync_service: AnalysisSyncService,
    ):
        super().__init__(app=app, factory=factory, log=log)

        self.analysis_sync_service = analysis_sync_service

    def run_dialog(self) -> None:
        pass

    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()

    def is_active_worker(self) -> bool:
        """Check if the analysis sync worker is active."""
        return self.analysis_sync_service.is_worker_running()

    def sync_analysis(self) -> None:
        """Sync the analysis data."""
        self.analysis_sync_service.start_syncing(thread_callback=self._on_complete)
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
