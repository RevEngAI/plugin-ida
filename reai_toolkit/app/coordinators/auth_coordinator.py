from typing import TYPE_CHECKING

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class AuthCoordinator(BaseCoordinator):
    def __init__(self, *, app: "App", factory: "DialogFactory", log):
        super().__init__(app=app, factory=factory, log=log)

    def run_dialog(self) -> None:
        self.safe_ui_exec(lambda: self.factory.auth().open_modal())
        # After dialog closes, update auth status
        self.safe_refresh()

    def is_authed(self) -> bool:
        return self.app.auth_service.is_authenticated()
