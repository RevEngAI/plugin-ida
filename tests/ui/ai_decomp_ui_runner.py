import json
import os
import sys
import traceback


def _add_paths() -> None:
    root = os.environ["REAI_UI_ROOT"]
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    suffixes = [
        "vendor",
        "vendor/site-packages",
        "vendor/Lib/site-packages",
        f"vendor/lib/{pyver}/site-packages",
        f"vendor/{pyver}/site-packages",
    ]
    for base in (root, os.path.join(root, "reai_toolkit")):
        for suffix in suffixes:
            path = os.path.join(base, suffix)
            if os.path.isdir(path) and path not in sys.path:
                sys.path.insert(0, path)
    if root not in sys.path:
        sys.path.insert(0, root)


CODE = "int f(int a1) {\n    int v5 = a1;\n    return v5;\n}"
TOK = "int @@F@@(int @@A@@) {\n    int @@V@@ = @@A@@;\n    return @@V@@;\n}"


def _run(report: dict) -> None:
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    import idautils

    from revengai.models.ai_decomp_function_mapping import AIDecompFunctionMapping
    from revengai.models.comments_data import CommentsData
    from revengai.models.decompilation_data import DecompilationData
    from revengai.models.inline_comment import InlineComment
    from revengai.models.replacement_value import ReplacementValue
    from revengai.models.tokenised_data import TokenisedData

    from reai_toolkit.app.components.tabs.ai_decomp_tab import AIDecompView
    from reai_toolkit.app.coordinators.ai_decomp_coordinator import AiDecompCoordinator
    from reai_toolkit.app.core.qt_compat import QtWidgets
    from reai_toolkit.app.core.shared_schema import GenericApiReturn

    ea = next(iter(idautils.Functions()), 0x1000)

    decomp = DecompilationData.model_construct(status="COMPLETED", decompilation=CODE)
    mapping = AIDecompFunctionMapping.model_construct(
        unmatched_vars={
            "@@A@@": ReplacementValue.model_construct(value="a1"),
            "@@V@@": ReplacementValue.model_construct(value="v5"),
        },
        user_override_mappings={},
    )
    tokenised = TokenisedData.model_construct(
        status="COMPLETED",
        tokenised_decompilation=TOK,
        predicted_function_name="f",
        function_mapping=mapping,
    )

    service = MagicMock()
    service.peek_decomp.return_value = None
    factory = SimpleNamespace(
        ai_decomp=lambda on_closed: AIDecompView(on_closed=on_closed)
    )
    coord = AiDecompCoordinator(
        app=MagicMock(), factory=factory, log=MagicMock(), ai_decomp_service=service
    )
    infos: list = []
    errors_shown: list = []
    coord.show_info_dialog = lambda **kw: infos.append(kw)
    coord.show_error_dialog = lambda **kw: errors_shown.append(kw)

    qapp = QtWidgets.QApplication.instance()

    def pump() -> None:
        if qapp is not None:
            for _ in range(5):
                qapp.processEvents()

    coord.run_dialog()
    pump()
    view = coord._decomp_view
    if view is None or view._editor is None:
        report["errors"].append("AIDecompView editor was not created")
        return

    report["view_created"] = True

    def seed_plain() -> None:
        service.reset_mock()
        service.peek_decomp.return_value = None
        coord._current_func_vaddr = ea
        coord._current_summary = None
        coord._current_comments = None
        coord._current_decomp = decomp
        coord._current_tokenised = tokenised
        coord._rerender()
        pump()

    def commit(edited: str) -> None:
        view._editor.setPlainText(edited)
        view._editor.editsCommitted.emit(view._editor.toPlainText())
        pump()

    seed_plain()
    report["render_shows_code"] = CODE in view._editor.toPlainText()

    seed_plain()
    commit(CODE.replace("    int v5 = a1;", "    int count = a1;"))
    report["rename_calls_apply_overrides"] = service.apply_overrides.called
    if service.apply_overrides.called:
        report["rename_overrides_correct"] = (
            service.apply_overrides.call_args.kwargs.get("overrides") == {"@@V@@": "count"}
        )

    seed_plain()
    lines = CODE.split("\n")
    lines.insert(1, "    // hello")
    commit("\n".join(lines))
    report["comment_add_calls_set"] = service.set_comment.called
    if service.set_comment.called:
        kw = service.set_comment.call_args.kwargs
        report["comment_add_args_correct"] = kw.get("line") == 2 and kw.get("comment") == "hello"

    service.reset_mock()
    service.peek_decomp.return_value = None
    coord._current_func_vaddr = ea
    coord._current_summary = None
    coord._current_decomp = decomp
    coord._current_tokenised = tokenised
    coord._on_comments_complete(
        ea,
        GenericApiReturn(
            success=True,
            data=CommentsData.model_construct(
                inline_comments=[InlineComment.model_construct(comment="hola", line=2)],
                task_status="COMPLETED",
            ),
        ),
    )
    pump()
    commit(CODE)
    report["comment_remove_calls_delete"] = service.remove_comment.called
    if service.remove_comment.called:
        report["comment_remove_args_correct"] = (
            service.remove_comment.call_args.kwargs.get("line") == 2
        )

    seed_plain()
    commit(CODE + "\n    extra();")
    report["structural_reverts"] = view._editor.toPlainText() == CODE
    report["structural_no_mutation"] = not service.apply_overrides.called and not service.set_comment.called
    report["structural_info_shown"] = len(infos) >= 1

    seed_plain()
    commit(view._editor.toPlainText())
    report["unchanged_noop"] = (
        not service.apply_overrides.called
        and not service.set_comment.called
        and not service.remove_comment.called
    )

    service.reset_mock()
    service.peek_decomp.return_value = None
    view._refresh_btn.click()
    pump()
    report["refresh_button_invalidates"] = service.invalidate_ea.called

    report["ok"] = not report["errors"]


def main() -> None:
    import ida_auto
    import ida_pro

    report = {
        "ok": False,
        "errors": [],
        "view_created": False,
        "render_shows_code": False,
        "rename_calls_apply_overrides": False,
        "rename_overrides_correct": False,
        "comment_add_calls_set": False,
        "comment_add_args_correct": False,
        "comment_remove_calls_delete": False,
        "comment_remove_args_correct": False,
        "structural_reverts": False,
        "structural_no_mutation": False,
        "structural_info_shown": False,
        "unchanged_noop": False,
        "refresh_button_invalidates": False,
    }
    ida_auto.auto_wait()
    try:
        _add_paths()
        _run(report)
    except Exception:
        report["errors"].append(traceback.format_exc())
    with open(os.environ["REAI_UI_REPORT"], "w") as fh:
        json.dump(report, fh)
    ida_pro.qexit(0)


main()
