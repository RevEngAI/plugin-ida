from collections.abc import Callable
from typing import Any

from revengai.models.auto_unstrip_response import AutoUnstripResponse

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
            parent=self.parent,
            callback=service_callback,
        )

    def existing_analysis(self, analysis_list):
        from reai_toolkit.app.components.dialogs import ExistingAnalysisDialog

        return ExistingAnalysisDialog(
            fetched_analyses=analysis_list, parent=self.parent
        )

    def auto_unstrip(self, response: AutoUnstripResponse):
        from reai_toolkit.app.components.dialogs import AutoUnstripDialog

        return AutoUnstripDialog(
            auto_unstrip_response=response,
            parent=self.parent,
        )

    def ai_decomp(self, on_closed: Callable[..., Any]) -> AIDecompView:
        from reai_toolkit.app.components.tabs.ai_decomp_tab import AIDecompView

        return AIDecompView(on_closed=on_closed)

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

    #
    # def existing_analysis(self):
    #     if not self._validate_sdk_config():
    #         return self.error_dialog(
    #             message="Invalid SDK configuration. Please check your API Key and URL."
    #         )
    #
    #     from reai_toolkit.app.components.dialogs import ExistingAnalysisDialog
    #
    #     return ExistingAnalysisDialog(
    #         analyse_service=self.app.analyse_service, parent=self.parent
    #     )
    #
    # def auto_unstrip(self):
    #     if not self._validate_sdk_config():
    #         return self.error_dialog(
    #             message="Invalid SDK configuration. Please check your API Key and URL."
    #         )
    #
    #     from reai_toolkit.app.components.dialogs import AutoUnstripDialog
    #
    #     return AutoUnstripDialog(
    #         auto_unstrip_service=self.app.auto_unstrip_service,
    #         rename_service=self.app.rename_service,
    #         parent=self.parent,
    #     )
    #
    # def ann_dialog(self, single_function_id: Optional[int] = None):
    #     if not self._validate_sdk_config():
    #         return self.error_dialog(
    #             message="Invalid SDK configuration. Please check your API Key and URL."
    #         )
    #
    #     from reai_toolkit.app.components.dialogs import AnnDialog
    #
    #     return AnnDialog(
    #         analysis_id=self.app.netstore_service.get_analysis_id(),
    #         single_function_id=single_function_id,
    #         ann_service=self.app.ann_service,
    #         rename_service=self.app.rename_service,
    #         function_map=self.app.netstore_service.get_function_mapping().function_map,
    #         parent=self.parent,
    #     )
    #
    # def ai_decomp_dialog(self, message: str, function_id: int):
    #     if not self._validate_sdk_config():
    #         return self.error_dialog(
    #             message="Invalid SDK configuration. Please check your API Key and URL."
    #         )
    #
    #     from reai_toolkit.app.components.dialogs import AiDecompDialog
    #
    #     return AiDecompDialog(
    #         message=message,
    #         function_id=function_id,
    #         ai_decomp_service=self.app.ai_decomp_service,
    #         parent=self.parent,
    #     )
