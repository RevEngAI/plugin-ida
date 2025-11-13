import ida_kernwin
from revengai.models import AutoUnstripResponse

from reai_toolkit.app.app import App
from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.factory import DialogFactory
from reai_toolkit.app.services.auto_unstrip.auto_unstrip_service import (
    AutoUnstripService,
)
from reai_toolkit.app.services.rename.rename_service import RenameService
from reai_toolkit.app.services.rename.schema import RenameInput


class AutoUnstripCoordinator(BaseCoordinator):
    auto_unstrip_service: AutoUnstripService = None
    rename_service: RenameService = None
    last_response: GenericApiReturn[AutoUnstripResponse] = None

    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
        auto_unstrip_service: AutoUnstripService,
        rename_service: RenameService,
    ):
        super().__init__(app=app, factory=factory, log=log)
        self.auto_unstrip_service = auto_unstrip_service
        self.rename_service = rename_service

    def run_dialog(self) -> None:
        if self.auto_unstrip_service.is_worker_running():
            self.safe_info(msg="Auto-unstrip is already running.")
            return

        if self.last_response:
            self._open_auto_unstrip_dialog()
            return
        self.safe_info(msg="Starting auto-unstrip process, may take a while.")
        self.auto_unstrip_service.start_unstrip_polling(callback=self._on_complete)

        pass

    def _open_auto_unstrip_dialog(self) -> None:
        self.factory.auto_unstrip(response=self.last_response.data).open_modal()

    def _on_complete(self, response: GenericApiReturn[AutoUnstripResponse]):
        print("Auto-unstrip process completed.")

        if not response.success:
            self.safe_error(message=response.error_message)
            return

        rename_list = []

        self.last_response = response

        for function in response.data.matches:
            rename_list.append(
                RenameInput(
                    function_id=function.function_id,
                    ea=function.function_vaddr,
                    new_name=function.suggested_demangled_name,
                )
            )

        self.rename_service.enqueue_rename(rename_list=rename_list)

        ida_kernwin.execute_ui_requests([self._open_auto_unstrip_dialog])

        self.safe_refresh()
