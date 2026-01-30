from typing import TYPE_CHECKING, List

import idaapi

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.coordinators.sync_analysis_coordinator import (
    AnalysisSyncCoordinator,
)
from reai_toolkit.app.services.existing_analyses.existing_analyses_service import (
    ExistingAnalysesService,
)

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory

from revengai.models import AnalysisRecord


class ExistingAnalysesCoordinator(BaseCoordinator):
    existing_analyses_service: ExistingAnalysesService
    analysis_sync_coord: AnalysisSyncCoordinator

    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
        existing_analyses_service: ExistingAnalysesService,
        analysis_sync_coord: AnalysisSyncCoordinator,
    ):
        super().__init__(app=app, factory=factory, log=log)

        self.existing_analyses_service = existing_analyses_service
        self.analysis_sync_coord = analysis_sync_coord

    def run_dialog(self) -> None:
        response = self.existing_analyses_service.fetch_analyses_same_hash(
            file_path=idaapi.get_input_file_path()
        )

        if not response.success:
            self.safe_error(message=response.error_message)
            return

        analyses_list: List[AnalysisRecord] = response.data

        if not analyses_list:
            self.safe_info(msg="No existing analyses found for this binary.")
            return

        ok, data = self.factory.existing_analysis(
            analysis_list=analyses_list
        ).open_modal()

        if not ok:
            return

        data: AnalysisRecord

        self.existing_analyses_service.safe_put_analysis_id(
            analysis_id=data.analysis_id
        )
        self.existing_analyses_service.safe_put_binary_id(binary_id=data.binary_id)
        self.safe_refresh()

        self.analysis_sync_coord.sync_analysis(attach_to_existing_analysis=True)


    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()
