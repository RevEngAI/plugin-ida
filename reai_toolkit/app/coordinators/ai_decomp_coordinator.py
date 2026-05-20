from logging import Logger

from libbs.decompilers.ida.compat import execute_ui
from revengai.models.tokenised_data import TokenisedData

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
        self._current_func_vaddr: int | None = None

    def enable_function_tracking(self) -> None:
        if self._decomp_hooks is None:
            self._decomp_hooks = AiDecompFunctionViewHooks(self)  # type: ignore
            self._decomp_hooks.hook()

    def disable_function_tracking(self) -> None:
        if self._decomp_hooks:
            self._decomp_hooks.unhook()
            self._decomp_hooks = None

    @execute_ui
    def run_dialog(self) -> None:
        self._decomp_view = self.factory.ai_decomp(on_closed=self._on_pane_closed)
        self._decomp_view.Create(self._decomp_view.TITLE)

    def start_decompilation(self, ea: int) -> None:
        if self._decomp_view:
            self._decomp_view.update_view_content(
                "Please wait, decompilation in progress..."
            )
            self._current_func_vaddr = ea

        self.ai_decomp_service.start_ai_decomp_task(
            ea=ea, thread_callback=self._on_decomp_complete
        )

    def _on_decomp_complete(
        self, response: GenericApiReturn[TokenisedData]
    ) -> None:
        if response.success is False:
            if response.error_message:
                self.show_error_dialog(message=response.error_message)

                if self._decomp_view:
                    self._decomp_view.update_view_content(
                        code="//" + response.error_message
                    )

                if "model_not_supported" in response.error_message:
                    self.disable_function_tracking()
            return

        if self._decomp_view is None:
            self.run_dialog()

        if response.data is None or response.data.tokenised_decompilation is None:
            return

        if self._decomp_view is None:
            return

        rendered = render_tokenised_for_view(response.data)
        self._decomp_view.update_view_content(rendered)

    def _on_pane_closed(self) -> None:
        self._decomp_view = None
        self.disable_function_tracking()
        self.log.info("AI Decomp view closed, reference cleared.")


def render_tokenised_for_view(tokenised: TokenisedData) -> str:
    code: str = tokenised.tokenised_decompilation or ""
    if code.startswith("/*"):
        return code
    if tokenised.predicted_function_name:
        header = _format_summary_as_comment(
            f"Suggested function name: {tokenised.predicted_function_name}"
        )
        return f"{header}\n{code}"
    return code


def _format_summary_as_comment(summary: str) -> str:
    prefix = " * "
    max_comment_width: int = 100
    content_width: int = max_comment_width - len(prefix)

    lines: list[str] = ["/*"]

    for paragraph in summary.split("\n"):
        if not paragraph.strip():
            lines.append(" *")
            continue

        words: list[str] = paragraph.split()
        current_line: str = ""

        for word in words:
            if not current_line:
                current_line = word
            elif len(current_line) + 1 + len(word) <= content_width:
                current_line += " " + word
            else:
                lines.append(prefix + current_line)
                current_line = word

        if current_line:
            lines.append(prefix + current_line)

    lines.append(" */")
    return "\n".join(lines)
