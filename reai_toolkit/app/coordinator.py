import ida_funcs
import ida_kernwin

from reai_toolkit.app.coordinators.about_coordinator import AboutCoordinator
from reai_toolkit.app.coordinators.ai_decomp_coordinator import AiDecompCoordinator
from reai_toolkit.app.coordinators.auth_coordinator import AuthCoordinator
from reai_toolkit.app.coordinators.auto_unstrip_coordinator import (
    AutoUnstripCoordinator,
)
from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.coordinators.create_analysis_coordinator import (
    CreateAnalysisCoordinator,
)
from reai_toolkit.app.coordinators.detach_coordinator import DetachCoordinator
from reai_toolkit.app.coordinators.existing_analysis_coordinator import (
    ExistingAnalysesCoordinator,
)
from reai_toolkit.app.coordinators.matching_coordinator import MatchingCoordinator
from reai_toolkit.app.coordinators.poll_status_coordinator import (
    AnalysisStatusCoordinator,
)
from reai_toolkit.app.coordinators.sync_analysis_coordinator import (
    AnalysisSyncCoordinator,
)
from reai_toolkit.app.core.qt_compat import QtCore, QtGui


class Coordinator(BaseCoordinator):
    """Root orchestrator — entry point for all coordinators."""

    def __init__(self, app, factory, log):
        super().__init__(app=app, factory=factory, log=log)

        # Initialize feature coordinators
        self.authc: AuthCoordinator = AuthCoordinator(app=app, factory=factory, log=log)
        self.aboutc: AboutCoordinator = AboutCoordinator(
            app=app, factory=factory, log=log
        )
        self.sync_analysisc: AnalysisSyncCoordinator = AnalysisSyncCoordinator(
            app=app,
            factory=factory,
            log=log,
            analysis_sync_service=app.analysis_sync_service,
        )
        self.poll_statusc: AnalysisStatusCoordinator = AnalysisStatusCoordinator(
            app=app,
            factory=factory,
            log=log,
            analysis_status_service=app.analysis_status_service,
            analysis_sync_coord=self.sync_analysisc,
        )
        self.create_analysisc: CreateAnalysisCoordinator = CreateAnalysisCoordinator(
            app=app, factory=factory, log=log, analysis_status_coord=self.poll_statusc
        )

        self.detachc: DetachCoordinator = DetachCoordinator(
            app=app, factory=factory, log=log
        )

        self.existing_analysisc: ExistingAnalysesCoordinator = (
            ExistingAnalysesCoordinator(
                app=app,
                factory=factory,
                log=log,
                existing_analyses_service=app.existing_analyses_service,
                analysis_sync_coord=self.sync_analysisc,
            )
        )

        self.auto_unstripc: AutoUnstripCoordinator = AutoUnstripCoordinator(
            app=app,
            factory=factory,
            log=log,
            auto_unstrip_service=app.auto_unstrip_service,
            rename_service=app.rename_service,
        )

        self.ai_decompc: AiDecompCoordinator = AiDecompCoordinator(
            app=app,
            factory=factory,
            log=log,
            ai_decomp_service=app.ai_decomp_service,
        )

        self.matchingc: MatchingCoordinator = MatchingCoordinator(
            app=app,
            factory=factory,
            log=log,
            matching_service=app.matching_service,
            rename_service=app.rename_service,
        )

    def run_dialog(self):
        """Run all necessary dialogs at startup."""
        pass

    def redirect_analysis_portal(self):
        binary_id = self.app.netstore_service.get_binary_id()
        portal_url = self.app.config_service.portal_url + f"/analyses/{binary_id}"
        QtGui.QDesktopServices.openUrl(QtCore.QUrl(portal_url))

    def redirect_function_portal(self):
        func_map = self.app.analysis_sync_service.safe_get_function_mapping_local()
        current_ea = ida_kernwin.get_screen_ea()
        current_func = ida_funcs.get_func(current_ea)
        function_id = func_map.inverse_function_map.get(
            str(current_func.start_ea), None
        )
        portal_url = self.app.config_service.portal_url + f"/function/{function_id}"
        QtGui.QDesktopServices.openUrl(QtCore.QUrl(portal_url))
