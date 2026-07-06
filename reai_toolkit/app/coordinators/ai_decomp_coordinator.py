from logging import Logger

import ida_funcs
import ida_kernwin
from libbs.decompilers.ida.compat import execute_read, execute_ui
from revengai.models.comments_data import CommentsData
from revengai.models.decompilation_data import DecompilationData
from revengai.models.inline_comment import InlineComment
from revengai.models.summary_data import SummaryData

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
        self._current_decomp: DecompilationData | None = None
        self._current_summary: SummaryData | None = None
        self._current_comments: CommentsData | None = None

    def enable_function_tracking(self) -> None:
        if self._decomp_hooks is None:
            self._decomp_hooks = AiDecompFunctionViewHooks(self)  # type: ignore
            self._decomp_hooks.hook()

    def disable_function_tracking(self) -> None:
        if self._decomp_hooks:
            self._decomp_hooks.unhook()
            self._decomp_hooks = None

    def is_tracking(self) -> bool:
        return self._decomp_hooks is not None

    @execute_ui
    def ensure_tracking(self) -> None:
        self.enable_function_tracking()

    @execute_ui
    def run_dialog(self) -> None:
        if self._decomp_view is None:
            self._decomp_view = self.factory.ai_decomp(on_closed=self._on_pane_closed)
            self._decomp_view.Create(self._decomp_view.TITLE)

    def start_decompilation(self, ea: int) -> None:
        self._current_decomp = None
        self._current_summary = None
        self._current_comments = None
        self._current_func_vaddr = ea

        self.run_dialog()

        cached = self.ai_decomp_service.peek_decomp(ea)
        if self._decomp_view is not None:
            if cached is not None and cached.decompilation:
                self._current_decomp = cached
                self._rerender()
            else:
                self._decomp_view.update_view_content(
                    "Please wait, decompilation in progress..."
                )

        self._dispatch_task(ea)

    def prefetch_decompilation(self, ea: int) -> None:
        self._dispatch_task(ea)

    def follow_function(self, ea: int, prefetch_if_closed: bool = False) -> None:
        if self._decomp_view is not None:
            if self._screen_function_start() == ea:
                self.start_decompilation(ea)
            else:
                self.prefetch_decompilation(ea)
        elif prefetch_if_closed:
            self.prefetch_decompilation(ea)

    @execute_read
    def _screen_function_start(self) -> int | None:
        func = ida_funcs.get_func(ida_kernwin.get_screen_ea())
        return func.start_ea if func else None

    def _dispatch_task(self, ea: int) -> None:
        self.ai_decomp_service.start_ai_decomp_task(
            ea=ea,
            on_decomp=lambda response: self._on_decomp_complete(ea, response),
            on_summary=lambda response: self._on_summary_complete(ea, response),
            on_comments=lambda response: self._on_comments_complete(ea, response),
        )

    def _on_decomp_complete(
        self, ea: int, response: GenericApiReturn[DecompilationData]
    ) -> None:
        if ea != self._current_func_vaddr:
            return

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

        if response.data is None or response.data.decompilation is None:
            return

        if self._decomp_view is None:
            self.run_dialog()

        if self._decomp_view is None:
            return

        self._current_decomp = response.data
        self._rerender()

    def _on_summary_complete(
        self, ea: int, response: GenericApiReturn[SummaryData]
    ) -> None:
        if ea != self._current_func_vaddr:
            return
        if not response.success:
            self.log.warning(f"AI summary fetch failed: {response.error_message}")
            return
        if response.data is None:
            return
        self._current_summary = response.data
        self._rerender()

    def _on_comments_complete(
        self, ea: int, response: GenericApiReturn[CommentsData]
    ) -> None:
        if ea != self._current_func_vaddr:
            return
        if not response.success:
            self.log.warning(f"Inline comments fetch failed: {response.error_message}")
            return
        if response.data is None:
            return
        self._current_comments = response.data
        self._rerender()

    def _rerender(self) -> None:
        if self._decomp_view is None or self._current_decomp is None:
            return
        rendered = render_view(
            decomp=self._current_decomp,
            summary=self._current_summary,
            comments=self._current_comments,
        )
        self._decomp_view.update_view_content(rendered)

    def _on_pane_closed(self) -> None:
        self._decomp_view = None
        self.disable_function_tracking()
        self.log.info("AI Decomp view closed, reference cleared.")


def render_view(
    decomp: DecompilationData,
    summary: SummaryData | None,
    comments: CommentsData | None,
) -> str:
    code: str = decomp.decompilation or ""

    header_parts: list[str] = []
    if summary is not None and summary.ai_summary:
        header_parts.append(_format_summary_as_comment(summary.ai_summary))

    body = code
    if comments is not None and comments.inline_comments:
        body = _inject_inline_comments(code, comments.inline_comments)

    if header_parts:
        return "\n".join(header_parts + [body])
    return body


def _inject_inline_comments(code: str, comments: list[InlineComment]) -> str:
    lines = code.split("\n")
    for c in sorted(comments, key=lambda x: x.line, reverse=True):
        idx = c.line - 1
        if idx < 0 or idx >= len(lines):
            continue
        target = lines[idx]
        indent = target[: len(target) - len(target.lstrip())]
        lines.insert(idx, f"{indent}// {c.comment}")
    return "\n".join(lines)


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
