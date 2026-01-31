from abc import ABC, abstractmethod
from logging import Logger
from typing import TYPE_CHECKING

from libbs.decompilers.ida.compat import execute_ui
import ida_kernwin

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class BaseCoordinator(ABC):
    """
    Base class providing:
      - Common references (app, factory, log)
      - Authentication helpers (require_auth)
    """

    def __init__(self, *, app: "App", factory: "DialogFactory", log: Logger) -> None:
        self.app: "App" = app
        self.factory: "DialogFactory" = factory
        self.log: Logger = log

    @execute_ui
    def show_info_dialog(self, msg: str) -> None:
        """Display an info dialog safely."""
        try:
            ida_kernwin.info(msg)
        except Exception:
            self.log.warning(f"Failed to show info: {msg}")


    @execute_ui
    def refresh_disassembly_view(self) -> None:
        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            self.log.warning("Failed to refresh IDA view.")

    @execute_ui
    def show_error_dialog(self, message: str) -> None:
        """Show an error dialog safely."""
        try:
            self.factory.error_dialog(message=message).open_modal()
        except Exception:
            self.log.warning(f"Failed to show error dialog: {message}")


    # ======================================================
    # Authentication helper
    # ======================================================
    def fetch_sdk_config(self) -> bool:
        """Ensure the user is authenticated; show info if not."""
        # TODO: implement authentication check
        self.app.auth_service.get_sdk_config()
        return False

    # ======================================================
    # Abstract UI actions
    # ======================================================

    @abstractmethod
    def run_dialog(self): ...
