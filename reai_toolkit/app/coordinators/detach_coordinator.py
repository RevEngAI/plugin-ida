from typing import TYPE_CHECKING

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.core.qt_compat import QtWidgets

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class DetachCoordinator(BaseCoordinator):
    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
    ):
        super().__init__(app=app, factory=factory, log=log)

    def _detach_analysis(self) -> None:
        self.app.analysis_sync_service.stop_worker()
        self.app.analysis_status_service.stop_worker()
        self.app.ai_decomp_service.stop_worker()
        self.app.auto_unstrip_service.stop_worker()
        self.app.rename_service.stop_worker()
        self.app.matching_service.stop_worker()
        self.app.existing_analyses_service.stop_worker()

        self.app.netstore_service.clear_all_ns()

        self.safe_info(msg="Analysis detached successfully.")
        self.safe_refresh()

    def run_dialog(self) -> None:
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Warning)
        msg.setWindowTitle("Confirm Detach")
        msg.setText("Are you sure you want to detach the analysis?")
        msg.setInformativeText("All queues and analysis data will be cleared.")
        msg.setStandardButtons(QtWidgets.QMessageBox.Cancel | QtWidgets.QMessageBox.Ok)
        msg.setDefaultButton(QtWidgets.QMessageBox.Cancel)
        result = msg.exec_()

        if result == QtWidgets.QMessageBox.Ok:
            self.log.info("RevEng.AI: Detaching analysis.")
            self._detach_analysis()

    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()
