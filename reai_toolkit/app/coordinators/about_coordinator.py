from typing import TYPE_CHECKING

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class AboutCoordinator(BaseCoordinator):
    def __init__(self, *, app: "App", factory: "DialogFactory", log):
        super().__init__(app=app, factory=factory, log=log)

    def run_dialog(self) -> None:
        self.safe_ui_exec(lambda: self.factory.about_dialog().open_modal())
