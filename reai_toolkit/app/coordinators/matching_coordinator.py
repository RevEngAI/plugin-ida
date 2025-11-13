from typing import TYPE_CHECKING, List

import ida_funcs
import ida_kernwin as kw

from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.services.matching.matching_service import MatchingService
from reai_toolkit.app.services.matching.schema import ValidFunction
from reai_toolkit.app.services.rename.rename_service import RenameService

if TYPE_CHECKING:
    from reai_toolkit.app.app import App
    from reai_toolkit.app.factory import DialogFactory


class MatchingCoordinator(BaseCoordinator):
    matching_service: MatchingService
    rename_service: RenameService

    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
        matching_service: MatchingService,
        rename_service: RenameService,
    ):
        super().__init__(app=app, factory=factory, log=log)

        self.matching_service = matching_service
        self.rename_service = rename_service

    def fetch_functions(self, restrict_function_id: bool = False) -> None:
        function_id = None

        if restrict_function_id:
            func_map = self.matching_service.safe_get_function_mapping_local()
            inverse_map = func_map.inverse_function_map
            ea = kw.get_screen_ea()
            current_func = ida_funcs.get_func(ea)
            function_id = inverse_map.get(str(current_func.start_ea), None)

        self.safe_info(msg="Fetching function information, this may take a while.")
        if not self.matching_service.is_worker_running():
            self.matching_service.start_function_fetch(
                callback=self._launch_dialog, restrict_function_id=function_id
            )

    def _launch_dialog(self, functions: List[ValidFunction]) -> None:
        func_map = self.matching_service.safe_get_function_mapping_local()

        def _show_dialog():
            dialog = self.factory.function_matching(
                valid_functions=functions, func_map=func_map.function_map
            )
            dialog.open_modal()

        kw.execute_ui_requests([_show_dialog])

        pass

    def run_dialog(self) -> None:
        pass
