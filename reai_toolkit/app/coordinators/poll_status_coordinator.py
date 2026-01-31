from typing import TYPE_CHECKING

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.coordinators.sync_analysis_coordinator import (
    AnalysisSyncCoordinator,
)
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.services.analysis_status.analysis_status import (
    AnalysisStatusService,
)

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class AnalysisStatusCoordinator(BaseCoordinator):
    analysis_status_service: AnalysisStatusService
    analysis_sync_coord: AnalysisSyncCoordinator

    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
        analysis_status_service: AnalysisStatusService,
        analysis_sync_coord: AnalysisSyncCoordinator,
    ):
        super().__init__(app=app, factory=factory, log=log)

        self.analysis_status_service = analysis_status_service
        self.analysis_sync_coord = analysis_sync_coord

    def run_dialog(self) -> None:
        pass

    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()

    def is_active_worker(self) -> bool:
        """Check if the analysis sync worker is active."""
        return self.analysis_status_service.is_worker_running()

    def poll_status(self, analysis_id: str) -> None:
        """Poll the status of an analysis until completion."""
        self.analysis_status_service.start_polling(
            analysis_id=analysis_id, thread_callback=self._on_complete
        )
        self.refresh_disassembly_view()

    def _on_complete(self, generic_return: GenericApiReturn[int]) -> None:
        """
        Handle completion of analysis status polling.
        """
        if not generic_return.success:
            self.show_error_dialog(message=generic_return.error_message)

        self.analysis_sync_coord.sync_analysis()

        self.refresh_disassembly_view()
