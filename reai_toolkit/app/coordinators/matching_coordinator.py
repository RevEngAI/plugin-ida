from typing import TYPE_CHECKING

import ida_funcs
import ida_kernwin as kw
from revengai import FunctionMapping

from reai_toolkit.app.components.dialogs.matching_dialog import MatchingDialog
from reai_toolkit.app.components.tabs.similarity_tab import SimilarityTab
from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.services.matching.matching_service import MatchingService
from reai_toolkit.app.services.matching.schema import ValidFunction
from reai_toolkit.app.services.rename.rename_service import RenameService

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class MatchingCoordinator(BaseCoordinator):
    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
        matching_service: MatchingService,
        rename_service: RenameService,
    ) -> None:
        super().__init__(app=app, factory=factory, log=log)

        self.matching_service: MatchingService = matching_service
        self.rename_service: RenameService = rename_service

    def fetch_functions(self, restrict_function_id: bool = False) -> None:
        function_id = None

        if restrict_function_id:
            func_map: FunctionMapping | None = self.matching_service.safe_get_function_mapping_local()
            if func_map is None:
                return
            
            inverse_map: dict[str, int] = func_map.inverse_function_map
            ea: int = kw.get_screen_ea()
            current_func: ida_funcs.func_t | None = ida_funcs.get_func(ea)
            if current_func is None:
                return
            
            function_id: int | None = inverse_map.get(str(current_func.start_ea), None)

        self.safe_info(msg="Fetching function information, this may take a while.")
        if self.matching_service.is_worker_running() is False:
            self.matching_service.start_function_fetch(
                callback=self._launch_dialog, restrict_function_id=function_id
            )

    def _launch_dialog(self, functions: list[ValidFunction]) -> None:
        func_map: FunctionMapping | None = self.matching_service.safe_get_function_mapping_local()
        if func_map is None:
            return

        def _show_dialog() -> None:
            dialog: MatchingDialog = self.factory.function_matching(
                valid_functions=functions, func_map=func_map.function_map
            )
            dialog.open_modal()

        kw.execute_ui_requests([_show_dialog])


    def run_dialog(self) -> None:
        pass
