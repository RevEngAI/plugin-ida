from typing import TYPE_CHECKING

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from libbs.decompilers.ida.compat import execute_ui

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class AuthCoordinator(BaseCoordinator):
    def __init__(self, *, app: "App", factory: "DialogFactory", log):
        super().__init__(app=app, factory=factory, log=log)

    @execute_ui
    def run_dialog(self) -> None:
        self.factory.auth().open_modal()
        self.refresh_disassembly_view()

    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()
