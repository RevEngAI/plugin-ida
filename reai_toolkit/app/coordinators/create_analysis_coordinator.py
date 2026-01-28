from typing import TYPE_CHECKING
import re
from http import HTTPStatus

from revengai import AnalysisCreateResponse

from reai_toolkit.app.components.dialogs.analyse_dialog import AnalyseDialog
from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.coordinators.poll_status_coordinator import (
    AnalysisStatusCoordinator,
)
from reai_toolkit.app.core.shared_schema import GenericApiReturn

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


# TODO: PRO-2090 We should query this via an endpoint rather than hard-coding the limit here.
MAX_SIZE_LIMIT_MB = 10


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

    def run_dialog(self) -> None:
        dialog: AnalyseDialog = self.factory.create_analysis(service_callback=self._on_complete)
        # only call open_modal safely on the UI thread
        self.safe_ui_exec(lambda: dialog.open_modal())
        self.safe_refresh()

    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()

    def _on_complete(self, service_response: GenericApiReturn) -> None:
        """Handle completion of analysis creation."""
        if service_response.success and isinstance(service_response.data, AnalysisCreateResponse):
            self.safe_info(
                msg="Analysis created successfully, please wait while it is processed."
            )
            # Should have analysis id - refresh to update menu options
            self.safe_refresh()

            # Call Sync Task to poll status
            self.analysis_status_coord.poll_status(analysis_id=service_response.data.analysis_id)
        else:
            error_message: str = service_response.error_message or "Unknown error"
            match: re.Match[str] | None = re.search(r'API Exception: \((\d+)\)', error_message)
            http_error_code: int | None = int(match.group(1)) if match else None
            if http_error_code == HTTPStatus.CONTENT_TOO_LARGE:
                error_message = f"Failed to upload binary due to it exceeding maximum size limit of {MAX_SIZE_LIMIT_MB}MB"

            self.safe_error(error_message)



