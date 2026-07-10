from logging import Logger

import ida_funcs
import ida_kernwin
from libbs.decompilers.ida.compat import execute_read, execute_ui
from revengai.models.comments_data import CommentsData
from revengai.models.decompilation_data import DecompilationData
from revengai.models.summary_data import SummaryData
from revengai.models.tokenised_data import TokenisedData

from reai_toolkit.app.app import App
from reai_toolkit.app.components.tabs.ai_decomp_tab import AIDecompView
from reai_toolkit.app.coordinators.ai_decomp_render import (
    EditParse,
    RenderModel,
    detect_identifier_change,
    parse_edited_buffer,
    render_view_with_map,
    resolve_token,
)
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
        self._current_tokenised: TokenisedData | None = None
        self._baseline: RenderModel | None = None
        self._baseline_text: str = ""

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
            self._decomp_view.on_refresh = self.refresh_current
            self._decomp_view.on_commit_edits = self.commit_edits
            self._decomp_view.Create(self._decomp_view.TITLE)

    def start_decompilation(self, ea: int) -> None:
        self._current_decomp = None
        self._current_summary = None
        self._current_comments = None
        self._current_tokenised = None
        self._baseline = None
        self._baseline_text = ""
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
            on_tokenised=lambda response: self._on_tokenised_complete(ea, response),
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

    def _on_tokenised_complete(
        self, ea: int, response: GenericApiReturn[TokenisedData]
    ) -> None:
        if ea != self._current_func_vaddr:
            return
        if not response.success or response.data is None:
            return
        self._current_tokenised = response.data

    def refresh_current(self) -> None:
        ea = self._current_func_vaddr
        if ea is None:
            return
        self.ai_decomp_service.invalidate_ea(ea)
        self.start_decompilation(ea)

    def commit_edits(self, text: str) -> None:
        if self._baseline is None or self._current_func_vaddr is None:
            return
        if text == self._baseline_text:
            return

        ea = self._current_func_vaddr
        parse = parse_edited_buffer(text, self._baseline)

        if len(parse.current_code_lines) != len(self._baseline.code_lines):
            self._rerender()
            self.show_info_dialog(
                message="Only identifier renames and inline comments are synced; "
                "structural code edits were reverted."
            )
            return

        self._apply_renames(ea, parse)
        self._apply_comment_edits(ea, parse)

    def _apply_renames(self, ea: int, parse: EditParse) -> None:
        if self._current_tokenised is None or self._baseline is None:
            return
        overrides: dict[str, str] = {}
        for i, new_line in enumerate(parse.current_code_lines):
            old_line = self._baseline.code_lines[i]
            if old_line == new_line:
                continue
            change = detect_identifier_change(old_line, new_line)
            if change is None:
                continue
            ident_index, old_ident, new_ident = change
            resolved = resolve_token(
                self._current_tokenised, i, ident_index, old_ident
            )
            if resolved is None:
                continue
            token, _category = resolved
            overrides[token] = new_ident
        if overrides:
            self.ai_decomp_service.apply_overrides(
                ea=ea,
                overrides=overrides,
                on_decomp=lambda response: self._on_decomp_complete(ea, response),
                on_tokenised=lambda response: self._on_tokenised_complete(ea, response),
            )

    def _apply_comment_edits(self, ea: int, parse: EditParse) -> None:
        if self._baseline is None:
            return
        for i in range(len(parse.current_code_lines)):
            source_line = i + 1
            baseline_comment = self._baseline.comment_by_source.get(source_line)
            current_comment = parse.current_comment_by_index.get(i)
            if current_comment == baseline_comment:
                continue
            if current_comment:
                self.ai_decomp_service.set_comment(
                    ea=ea,
                    line=source_line,
                    comment=current_comment,
                    on_result=lambda response: self._on_comments_updated(ea, response),
                )
            elif baseline_comment is not None:
                self.ai_decomp_service.remove_comment(
                    ea=ea,
                    line=source_line,
                    on_result=lambda response: self._on_comments_updated(ea, response),
                )

    def _on_comments_updated(
        self, ea: int, response: GenericApiReturn[CommentsData]
    ) -> None:
        if ea != self._current_func_vaddr:
            return
        if not response.success:
            if response.error_message:
                self.show_error_dialog(message=response.error_message)
            return
        if response.data is None:
            return
        self._current_comments = response.data
        self._rerender()

    def _rerender(self) -> None:
        if self._decomp_view is None or self._current_decomp is None:
            return
        rendered, self._baseline = render_view_with_map(
            decomp=self._current_decomp,
            summary=self._current_summary,
            comments=self._current_comments,
        )
        self._baseline_text = rendered
        self._decomp_view.update_view_content(rendered)

    def _on_pane_closed(self) -> None:
        self._decomp_view = None
        self.disable_function_tracking()
        self.log.info("AI Decomp view closed, reference cleared.")
