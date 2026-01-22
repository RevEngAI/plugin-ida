import time
from typing import TYPE_CHECKING

from loguru import logger
import idaapi
import ida_funcs
import ida_kernwin as kw


from reai_toolkit.app.components.tabs.similarity_tab import SimilarityTab
from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.services.matching.similarity_service import SimilarityService
from revengai.models.matched_function import MatchedFunction
from revengai import FunctionMapping

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class SimilarityCoordinator(BaseCoordinator):
    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
        similarity_service: SimilarityService,
    ) -> None:
        super().__init__(app=app, factory=factory, log=log)

        self._similarity_service: SimilarityService = similarity_service
        self._similarity_tab: SimilarityTab | None = None
        self._hook: FunctionSimilarityHook | None = None

    def find_similar_functions(self) -> None:
        logger.debug("find_similar_functions called")
        func_map: FunctionMapping | None = self._similarity_service.safe_get_function_mapping_local()
        if func_map is None:
            return
        
        inverse_map: dict[str, int] = func_map.inverse_function_map
        ea: int = kw.get_screen_ea()
        current_func: ida_funcs.func_t | None = ida_funcs.get_func(ea)
        if current_func is None:
            return
        
        function_id: int | None = inverse_map.get(str(current_func.start_ea), None)
        if function_id is None:
            return

        # TODO: Handle the case where tab is already opened.
        # TODO: Ensure that tab remains in focus if already opened, similar to AI Decomp.
        if self._similarity_service.is_worker_running() is False:
            self._similarity_service.fetch_similar_functions(
                function_id, ea, self._launch_similarity_tab
            )

    def enable_function_tracking(self):
        if self._hook is None:
            self._hook = FunctionSimilarityHook(self) # type: ignore
            self._hook.hook()

    def disable_function_tracking(self):
        if self._hook is not None:
            self._hook.unhook()
            self._hook = None

    def _launch_similarity_tab(self, ea, functions: list[MatchedFunction]) -> None:
        logger.debug("_launch_similarity_tab called")

        def _show_tab() -> None:
            self._similarity_tab = SimilarityTab(self._on_pane_closed) # type: ignore
            self._similarity_tab.Create()
            self._similarity_tab.update_for_function(ea, functions)

        kw.execute_ui_requests([_show_tab])

    def _on_pane_closed(self) -> None:
        self._similarity_tab = None
        self.disable_function_tracking()

    def run_dialog(self) -> None:
        pass


class FunctionSimilarityHook(kw.UI_Hooks):
    def __init__(self, coordinator: SimilarityCoordinator, debounce_ms: int = 200) -> None:
        super().__init__()
        self.coordinator: SimilarityCoordinator = coordinator
        self._debounce_ms = debounce_ms
        self._last_func_start = None
        self._pending_ea = None
        self._last_change_time = 0.0
        self._timer_id = None
        self._is_hooked = False

    def hook(self) -> bool:
        if self._is_hooked:
            return False
        ok = super().hook()
        if ok:
            # First hook, does not trigger event. Manual call to coordinator.
            self._is_hooked = True
            self.coordinator.find_similar_functions()
            logger.info("[FunctionSimilarityHook] Hook registered.")
        else:
            logger.error("[FunctionSimilarityHook] Failed to register.")
        return ok

    def unhook(self) -> None:
        if self._timer_id:
            idaapi.unregister_timer(self._timer_id)
            self._timer_id = None
        if self._is_hooked:
            super().unhook()
            self._is_hooked = False
            logger.info("[FunctionSimilarityHook] Hook removed.")
        self._pending_ea = None
        self._last_func_start = None

    def screen_ea_changed(self, ea: int, prev_ea: int) -> None:
        func: ida_funcs.func_t = ida_funcs.get_func(ea)
        if not func:
            return

        start = func.start_ea
        if start == self._last_func_start:
            return  # same function, ignore

        self._pending_ea = start
        self._last_change_time = time.time()

        if not self._timer_id:
            self._timer_id = idaapi.register_timer(
                self._debounce_ms, self._check_debounce
            )

    def _check_debounce(self):
        now = time.time()

        # Wait until no changes for the debounce interval
        if self._pending_ea and (now - self._last_change_time) >= (
            self._debounce_ms / 1000.0
        ):
            ea = self._pending_ea
            self._pending_ea = None
            self._timer_id = None
            self._last_func_start = ea

            logger.debug(f"[FunctionSimilarityHook] Function changed (debounced): {hex(ea)}")

            try:
                self.coordinator.find_similar_functions()
            except Exception as e:
                logger.error(f"[FunctionSimilarityHook] Callback failed: {e}")
            return -1  # stop timer

        return 1  # keep timer alive until debounce passes