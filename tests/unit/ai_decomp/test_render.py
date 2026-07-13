from revengai.models.ai_decomp_function_mapping import AIDecompFunctionMapping
from revengai.models.comments_data import CommentsData
from revengai.models.decompilation_data import DecompilationData
from revengai.models.inline_comment import InlineComment
from revengai.models.progress_message import ProgressMessage
from revengai.models.replacement_value import ReplacementValue
from revengai.models.summary_data import SummaryData
from revengai.models.tokenised_data import TokenisedData
from revengai.models.workflow_progress import WorkflowProgress

from reai_toolkit.app.coordinators.ai_decomp_render import (
    index_of_identifier,
    render_progress,
    render_view,
    render_view_with_map,
    resolve_token,
)


CODE = "int f(int a1) {\n    int v5 = a1;\n    return v5;\n}"
TOK = "int @@F1@@(int @@V_a1@@) {\n    int @@V_v5@@ = @@V_a1@@;\n    return @@V_v5@@;\n}"


def _dd(code=CODE):
    return DecompilationData.model_construct(status="COMPLETED", decompilation=code)


def _summary(text):
    return SummaryData.model_construct(ai_summary=text, summary=text, task_status="COMPLETED")


def _comments(pairs):
    items = [InlineComment.model_construct(comment=c, line=ln) for ln, c in pairs]
    return CommentsData.model_construct(inline_comments=items, task_status="COMPLETED")


def _mapping(**cats):
    base = dict(
        fields={},
        inverse_function_map={},
        inverse_string_map={},
        unmatched_custom_function_pointers={},
        unmatched_custom_types={},
        unmatched_enums={},
        unmatched_external_vars={},
        unmatched_functions={},
        unmatched_global_vars={},
        unmatched_go_to_labels={},
        unmatched_strings={},
        unmatched_variadic_lists={},
        unmatched_vars={},
        user_override_mappings={},
    )
    base.update(cats)
    return AIDecompFunctionMapping.model_construct(**base)


def _rv(value):
    return ReplacementValue.model_construct(value=value)


def _tokenised(tok=TOK, mapping=None):
    return TokenisedData.model_construct(
        status="COMPLETED",
        tokenised_decompilation=tok,
        predicted_function_name="f",
        function_mapping=mapping if mapping is not None else _mapping(),
    )


def test_render_matches_legacy_and_builds_model():
    comments = _comments([(2, "local copy"), (99, "out of range")])
    text, model = render_view_with_map(_dd(), _summary("Adds one."), comments)

    assert render_view(_dd(), _summary("Adds one."), comments) == text
    assert text.splitlines()[0] == "/*"
    assert "    // local copy" in text
    assert model.summary_line_count == 3
    assert model.code_lines == CODE.split("\n")
    assert model.comment_by_source == {2: "local copy"}


def test_display_maps_align_lines_to_source():
    text, model = render_view_with_map(_dd(), _summary("S."), _comments([(2, "note")]))
    lines = text.split("\n")

    assert len(model.display_source) == len(lines)
    assert len(model.display_is_code) == len(lines)

    for i in range(model.summary_line_count):
        assert model.display_source[i] is None
        assert model.display_is_code[i] is False

    comment_rows = [i for i, s in enumerate(lines) if s.strip().startswith("//")]
    code_rows = [i for i, c in enumerate(model.display_is_code) if c]

    assert len(code_rows) == len(CODE.split("\n"))
    for row in comment_rows:
        assert model.display_is_code[row] is False
        assert model.display_source[row] == 2

    v5_row = next(i for i, s in enumerate(lines) if "int v5" in s)
    assert model.display_is_code[v5_row] is True
    assert model.display_source[v5_row] == 2


def test_no_summary_no_comments_is_raw_code():
    text, model = render_view_with_map(_dd(), None, None)
    assert text == CODE
    assert model.summary_line_count == 0
    assert model.comment_by_source == {}
    assert all(model.display_is_code)
    assert model.display_source == [1, 2, 3, 4]


def test_multiline_comment_renders_as_two_comment_lines():
    text, model = render_view_with_map(_dd(), None, _comments([(2, "line one\nline two")]))
    lines = text.split("\n")
    assert "    // line one" in lines
    assert "    // line two" in lines
    assert model.comment_by_source == {2: "line one\nline two"}


def test_index_of_identifier():
    assert index_of_identifier("    int v5 = a1;", "v5") == 1
    assert index_of_identifier("    int v5 = a1;", "a1") == 2
    assert index_of_identifier("    int v5 = a1;", "missing") == -1


def test_resolve_token_positional_variable():
    tokd = _tokenised(mapping=_mapping(unmatched_vars={"@@V_v5@@": _rv("v5"), "@@V_a1@@": _rv("a1")}))
    assert resolve_token(tokd, 1, 1, "v5") == ("@@V_v5@@", "variable")


def test_resolve_token_type_category():
    tok = "@@T_S@@ *x = 0;"
    tokd = _tokenised(tok=tok, mapping=_mapping(unmatched_custom_types={"@@T_S@@": _rv("Foo")}))
    assert resolve_token(tokd, 0, 0, "Foo") == ("@@T_S@@", "type")


def test_resolve_token_honours_user_override():
    mapping = _mapping(
        unmatched_vars={"@@V_v5@@": _rv("v5")},
        user_override_mappings={"@@V_v5@@": "tmp"},
    )
    tokd = _tokenised(mapping=mapping)
    assert resolve_token(tokd, 1, 1, "tmp") == ("@@V_v5@@", "variable")


def test_resolve_token_unknown_returns_none():
    tokd = _tokenised(mapping=_mapping(unmatched_vars={"@@V_v5@@": _rv("v5")}))
    assert resolve_token(tokd, 1, 1, "not_a_var") is None


def test_resolve_token_value_fallback_when_line_unaligned():
    tokd = _tokenised(tok="", mapping=_mapping(unmatched_vars={"@@V_v5@@": _rv("v5")}))
    assert resolve_token(tokd, 1, 1, "v5") == ("@@V_v5@@", "variable")


def _pm(text, level="INFO", step="DECOMPILING", timestamp=None):
    return ProgressMessage.model_construct(
        level=level, step=step, text=text, timestamp=timestamp
    )


def _wp(status="RUNNING", step="DECOMPILING", step_index=1, steps_total=3, messages=None):
    return WorkflowProgress.model_construct(
        status=status,
        step=step,
        step_index=step_index,
        steps_total=steps_total,
        messages=messages or [],
    )


def test_render_progress_shows_step_and_status():
    text = render_progress(_wp())
    lines = text.split("\n")
    assert lines[0].startswith("// RevEng.AI")
    assert "// Step 2/3: DECOMPILING [RUNNING]" in lines


def test_render_progress_lists_messages_as_comment_lines():
    text = render_progress(_wp(messages=[_pm("fetching bytes"), _pm("done", level="WARN")]))
    assert "// [INFO] fetching bytes" in text
    assert "// [WARN] done" in text
    assert all(line.startswith("//") for line in text.split("\n"))


def test_render_progress_without_steps_falls_back_to_status():
    text = render_progress(_wp(step="", step_index=0, steps_total=0, status="PENDING"))
    assert "// PENDING" in text.split("\n")
