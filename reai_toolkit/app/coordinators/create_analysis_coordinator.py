from typing import TYPE_CHECKING

from revengai import AnalysisCreateResponse
from libbs.decompilers.ida.compat import execute_ui

from reai_toolkit.app.components.dialogs.analyse_dialog import AnalyseDialog
from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.coordinators.poll_status_coordinator import (
    AnalysisStatusCoordinator,
)
from reai_toolkit.app.core.shared_schema import GenericApiReturn

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class CreateAnalysisCoordinator(BaseCoordinator):
    analysis_status_coord: AnalysisStatusCoordinator

    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
        analysis_status_coord: AnalysisStatusCoordinator,
    ):
        super().__init__(app=app, factory=factory, log=log)

        self.analysis_status_coord = analysis_status_coord

    @execute_ui
    def run_dialog(self) -> None:
        dialog: AnalyseDialog = self.factory.create_analysis(service_callback=self._on_complete)
        dialog.open_modal()
        self.refresh_disassembly_view()

    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()

    def _on_complete(self, service_response: GenericApiReturn) -> None:
        """Handle completion of analysis creation."""
        if service_response.success:
            self.show_info_dialog(
                msg="Analysis created successfully, please wait while it is processed."
            )
        else:
            self.show_error_dialog(message=service_response.error_message)

        data: AnalysisCreateResponse = service_response.data

        # Should have analysis id - refresh to update menu options
        self.refresh_disassembly_view()

        # Call Sync Task to poll status
        self.analysis_status_coord.poll_status(analysis_id=data.analysis_id)
