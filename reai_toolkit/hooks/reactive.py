import time

import ida_funcs
import ida_kernwin as kw
import idaapi
from loguru import logger

from reai_toolkit.app.app import App
from reai_toolkit.app.services.rename.schema import RenameInput

# ---- Add this: a small event router ----
def _is_func_ea(ea: int) -> bool:
    return ida_funcs.get_func(ea) is not None


# Reactive Hooks to function changes
class FuncChangeHooks(idaapi.IDB_Hooks):
    def __init__(self, app: App):
        super().__init__()
        self.app: App = app

    # Hook called when a function is renamed
    def renamed(self, ea, new_name, local_name):
        if _is_func_ea(ea):
            self._function_rename(ea, new_name)
        return 0

    def _function_rename(self, ea: int, new_name: str):
        if not self.app.analysis_sync_service.is_worker_running():
            self.app.rename_service.enqueue_rename(
                [RenameInput(ea=ea, new_name=new_name)]
            )


class AiDecompFunctionViewHooks(kw.UI_Hooks):
    """
    Hook that tracks when the screen EA changes (user moves between functions),
    with debounce to avoid excessive refreshes.

    Works entirely on the IDA main thread.
    """

    # AiDecompCoordinator - cannot import due to circular dependency

    def __init__(self, coordinator, debounce_ms: int = 200):
        super().__init__()
        self.coordinator = coordinator
        self._debounce_ms = debounce_ms
        self._last_func_start = None
        self._pending_ea = None
        self._last_change_time = 0.0
        self._timer_id = None
        self._is_hooked = False

    # --------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------

    def hook(self) -> bool:
        """Register this UI hook."""
        if self._is_hooked:
            return False
        ok = super().hook()
        if ok:
            # First hook, does not trigger event. Manual call to coordinator.
            self._is_hooked = True
            ea = kw.get_screen_ea()
            func = ida_funcs.get_func(ea)
            self.coordinator.start_decompilation(ea=func.start_ea)
            logger.info("[FunctionViewHooks] Hook registered.")
        else:
            logger.error("[FunctionViewHooks] Failed to register.")
        return ok

    def unhook(self) -> None:
        """Unregister the hook and clear any timers."""
        if self._timer_id:
            idaapi.unregister_timer(self._timer_id)
            self._timer_id = None
        if self._is_hooked:
            super().unhook()
            self._is_hooked = False
            logger.info("[FunctionViewHooks] Hook removed.")
        self._pending_ea = None
        self._last_func_start = None

    # --------------------------------------------------------
    # Event Handling
    # --------------------------------------------------------

    def screen_ea_changed(self, ea: int, prev_ea: int) -> None:
        """
        Triggered when the user moves the cursor to a new address.
        Debounced to detect actual function changes only.
        """
        func = ida_funcs.get_func(ea)
        if not func:
            return

        start = func.start_ea
        if start == self._last_func_start:
            return  # same function, ignore

        # record and schedule debounce check
        self._pending_ea = start
        self._last_change_time = time.time()

        if not self._timer_id:
            self._timer_id = idaapi.register_timer(
                self._debounce_ms, self._check_debounce
            )

    def _check_debounce(self):
        """Timer callback; runs on the main thread."""
        now = time.time()

        # Wait until no changes for the debounce interval
        if self._pending_ea and (now - self._last_change_time) >= (
            self._debounce_ms / 1000.0
        ):
            ea = self._pending_ea
            self._pending_ea = None
            self._timer_id = None
            self._last_func_start = ea

            logger.debug(f"[FunctionViewHooks] Function changed (debounced): {hex(ea)}")

            try:
                # Delegate to coordinator
                self.coordinator.start_decompilation(ea=ea)
            except Exception as e:
                logger.error(f"[FunctionViewHooks] Callback failed: {e}")
            return -1  # stop timer

        return 1  # keep timer alive until debounce passes
