from typing import TYPE_CHECKING

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.coordinators.sync_analysis_coordinator import (
    AnalysisSyncCoordinator,
)
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.services.auto_unstrip_status.auto_unstrip_status import (
    AutoUnstripStatusService,
)

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class AutoUnstripStatusCoordinator(BaseCoordinator):
    auto_unstrip_status_service: AutoUnstripStatusService
    analysis_sync_coord: AnalysisSyncCoordinator

    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
        auto_unstrip_status_service: AutoUnstripStatusService,
        analysis_sync_coord: AnalysisSyncCoordinator,
    ):
        super().__init__(app=app, factory=factory, log=log)

        self.auto_unstrip_status_service = auto_unstrip_status_service
        self.analysis_sync_coord = analysis_sync_coord

    def run_dialog(self) -> None:
        pass

    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()

    def is_active_worker(self) -> bool:
        return self.auto_unstrip_status_service.is_worker_running()

    def poll_and_resync(
        self, analysis_id: int, attach_to_existing_analysis: bool = False
    ) -> None:
        self.auto_unstrip_status_service.start_polling(
            analysis_id=analysis_id,
            thread_callback=lambda generic_return: self._on_complete(
                generic_return, attach_to_existing_analysis
            ),
            resync_if_already_complete=not attach_to_existing_analysis,
        )

    def _on_complete(
        self, generic_return: GenericApiReturn[int], attach_to_existing_analysis: bool
    ) -> None:
        if generic_return.success is False:
            self.log.warning(
                generic_return.error_message or "failed to poll auto-unstrip status"
            )
            return

        self.show_info_dialog(
            msg="Auto-unstrip has finished. Re-syncing recovered function names and data types."
        )
        self.analysis_sync_coord.sync_analysis(
            attach_to_existing_analysis=attach_to_existing_analysis
        )
