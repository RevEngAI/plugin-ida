from logging import Logger

import ida_kernwin
from revengai.models.get_ai_decompilation_task import GetAiDecompilationTask

from reai_toolkit.app.app import App
from reai_toolkit.app.components.tabs.ai_decomp_tab import AIDecompView
from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.factory import DialogFactory
from reai_toolkit.app.services.ai_decomp.ai_decomp_service import AiDecompService
from reai_toolkit.hooks.reactive import AiDecompFunctionViewHooks


class AiDecompCoordinator(BaseCoordinator):
    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log: Logger,
        ai_decomp_service: AiDecompService,
    ) -> None:
        super().__init__(app=app, factory=factory, log=log)
        self.ai_decomp_service: AiDecompService = ai_decomp_service
        self._decomp_view: AIDecompView | None = None
        self._decomp_hooks: AiDecompFunctionViewHooks | None = None

    def enable_function_tracking(self) -> None:
        if self._decomp_hooks is None:
            self._decomp_hooks = AiDecompFunctionViewHooks(self)  # type: ignore
            self._decomp_hooks.hook()

    def disable_function_tracking(self) -> None:
        if self._decomp_hooks:
            self._decomp_hooks.unhook()
            self._decomp_hooks = None

    def run_dialog(self) -> None:
        self._decomp_view = self.factory.ai_decomp(on_closed=self._on_pane_closed)
        self._decomp_view.Create(self._decomp_view.TITLE)

    def start_decompilation(self, ea: int) -> None:
        if self._decomp_view:
            self._decomp_view.set_code("Please wait, decompilation in progress...")

        self.ai_decomp_service.start_ai_decomp_task(
            ea=ea, thread_callback=self._on_decomp_complete
        )

    def _on_decomp_complete(
        self, response: GenericApiReturn[GetAiDecompilationTask]
    ) -> None:
        if response.success is False:
            if response.error_message:
                self.safe_error(message=response.error_message)

                if self._decomp_view:
                    self._decomp_view.set_code(code="//" + response.error_message)

                # Disable future decomp attempts for unsupported models (stop error modal spam)
                if "model_not_supported" in response.error_message:
                    self.disable_function_tracking()
            return

        # Open a dialog to show the decompilation result
        if self._decomp_view is None:
            ida_kernwin.execute_sync(self.run_dialog, ida_kernwin.MFF_FAST)
            return

        # Otherwise just update contents
        if response.data and response.data.decompilation:
            self._decomp_view.set_code(response.data.decompilation)

    def _on_pane_closed(self) -> None:
        """Called when the decompilation view is closed."""
        self._decomp_view = None
        self.disable_function_tracking()
        self.log.info("AI Decomp view closed, reference cleared.")
