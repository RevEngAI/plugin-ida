from collections.abc import Callable
from typing import Any

from reai_toolkit.app.app import App
from reai_toolkit.app.components.dialogs import ErrorDialog
from reai_toolkit.app.components.tabs.ai_decomp_tab import AIDecompView
from reai_toolkit.app.services.matching.schema import ValidFunction


class DialogFactory:
    def __init__(self, app: App, parent=None):
        self.app: App = app
        self.parent = parent

    def error_dialog(self, message: str):
        return ErrorDialog(error_message=message, parent=self.parent)

    def about_dialog(self):
        from reai_toolkit.app.components.dialogs import AboutDialog

        return AboutDialog(parent=self.parent)

    def auth(self):
        from reai_toolkit.app.components.dialogs import AuthDialog

        return AuthDialog(
            cfg=self.app.config_service,
            auth_service=self.app.auth_service,
            parent=self.parent,
        )

    def create_analysis(self, service_callback: Callable[..., Any]):
        from reai_toolkit.app.components.dialogs import AnalyseDialog

        return AnalyseDialog(
            upload_service=self.app.upload_service,
            auth_service=self.app.auth_service,
            parent=self.parent,
            callback=service_callback,
        )

    def existing_analysis(self, analysis_list):
        from reai_toolkit.app.components.dialogs import ExistingAnalysisDialog

        return ExistingAnalysisDialog(
            fetched_analyses=analysis_list, parent=self.parent
        )

    def ai_decomp(self, on_closed: Callable[..., Any]) -> AIDecompView:
        from reai_toolkit.app.components.tabs.ai_decomp_tab import AIDecompView

        return AIDecompView(on_closed=on_closed)

    def chat(self, on_closed: Callable[..., Any]):
        from reai_toolkit.app.components.tabs.chat_tab import ChatPanel

        return ChatPanel(on_closed=on_closed)

    def function_matching(
        self, valid_functions: list[ValidFunction], func_map: dict[str, int]
    ):
        from reai_toolkit.app.components.dialogs.matching_dialog import MatchingDialog

        return MatchingDialog(
            valid_functions=valid_functions,
            func_map=func_map,
            matching_service=self.app.matching_service,
            rename_service=self.app.rename_service,
            data_types_service=self.app.data_types_service,
            parent=self.parent,
        )