from typing import Optional

import ida_kernwin
from revengai.models import GetAiDecompilationTask

from reai_toolkit.app.app import App
from reai_toolkit.app.components.tabs.ai_decomp_tab import AIDecompView
from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.factory import DialogFactory
from reai_toolkit.app.services.ai_decomp.ai_decomp_service import AiDecompService
from reai_toolkit.hooks.reactive import AiDecompFunctionViewHooks


class AiDecompCoordinator(BaseCoordinator):
    ai_decomp_service: AiDecompService = None
    _current_pane: Optional[AIDecompView] = None
    _decomp_hooks: Optional[AiDecompFunctionViewHooks] = None

    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log,
        ai_decomp_service: AiDecompService,
    ):
        super().__init__(app=app, factory=factory, log=log)
        self.ai_decomp_service = ai_decomp_service

    def enable_function_tracking(self):
        if self._decomp_hooks is None:
            self._decomp_hooks = AiDecompFunctionViewHooks(self)
            self._decomp_hooks.hook()

    def disable_function_tracking(self):
        if self._decomp_hooks is not None:
            self._decomp_hooks.unhook()
            self._decomp_hooks = None

    def run_dialog(self) -> None:
        self._current_pane = self.factory.ai_decomp(on_closed=self._on_pane_closed)
        self._current_pane.Create(self._current_pane.TITLE)
        pass

    def start_decompilation(self, ea: int) -> None:
        if self.is_pane_active():
            self._current_pane.set_code("Please wait, decompilation in progress...")

        self.ai_decomp_service.start_ai_decomp_task(
            ea=ea, thread_callback=self._on_decomp_complete
        )

    def _on_decomp_complete(self, response: GenericApiReturn[GetAiDecompilationTask]):
        if not response.success:
            self.safe_error(message=response.error_message)
            if self._current_pane:
                self._current_pane.set_code(code="//" + response.error_message)
            # Disable future decomp attempts for unsupported models (stop error modal spam)
            if response.error_message.__contains__("model_not_supported"):
                self.disable_function_tracking()
            return

        # Open a dialog to show the decompilation result
        if not self._current_pane:
            ida_kernwin.execute_sync(self.run_dialog, ida_kernwin.MFF_FAST)

        # Otherwise jsut update contents
        self._current_pane.set_code(response.data.decompilation)

    def _on_pane_closed(self):
        """Called when the decompilation view is closed."""
        self._current_pane = None
        self.disable_function_tracking()
        self.log.info("AI Decomp view closed, reference cleared.")

    # Quick check to see if pane is active - required for background decomp work (on func view change)
    def is_pane_active(self) -> bool:
        return self._current_pane is not None
