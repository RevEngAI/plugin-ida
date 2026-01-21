from abc import ABC, abstractmethod
from logging import Logger
from typing import TYPE_CHECKING, Any, Callable

import ida_kernwin

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class BaseCoordinator(ABC):
    """
    Base class providing:
      - Common references (app, factory, log)
      - Thread-safe UI helpers (safe_* methods)
      - Authentication helpers (require_auth)
    """

    def __init__(self, *, app: "App", factory: "DialogFactory", log: Logger) -> None:
        self.app: "App" = app
        self.factory: "DialogFactory" = factory
        self.log: Logger = log

    # ======================================================
    # IDA-safe helpers — executed on the UI thread safely
    # ======================================================

    def safe_ui_exec(self, fn: Callable[[], Any], fast: bool = True) -> Any:
        """Run a function safely on IDA’s main UI thread."""
        try:
            flags = ida_kernwin.MFF_FAST if fast else ida_kernwin.MFF_NOWAIT
            return ida_kernwin.execute_sync(fn, flags)
        except Exception as e:
            print(f"[Coordinator] safe_ui_exec failed: {e}")
            self.log.error(f"[Coordinator] safe_ui_exec failed: {e}")
            return None

    def safe_info(self, msg: str) -> None:
        """Display an info dialog safely."""

        def _do():
            try:
                ida_kernwin.info(msg)
            except Exception:
                self.log.warning(f"Failed to show info: {msg}")

        self.safe_ui_exec(_do)

    def safe_refresh(self) -> None:
        """Safely refresh the disassembly view."""

        def _do():
            try:
                ida_kernwin.refresh_idaview_anyway()
            except Exception:
                self.log.warning("Failed to refresh IDA view.")

        self.safe_ui_exec(_do)

    def safe_error(self, message: str) -> None:
        """Show an error dialog safely."""

        def _do():
            try:
                self.factory.error_dialog(message=message).open_modal()
            except Exception:
                self.log.warning(f"Failed to show error dialog: {message}")

        self.safe_ui_exec(_do)

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
