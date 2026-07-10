from revengai.models.ai_decomp_function_mapping import AIDecompFunctionMapping
from revengai.models.comments_data import CommentsData
from revengai.models.decompilation_data import DecompilationData
from revengai.models.inline_comment import InlineComment
from revengai.models.replacement_value import ReplacementValue
from revengai.models.summary_data import SummaryData
from revengai.models.tokenised_data import TokenisedData

from reai_toolkit.app.coordinators.ai_decomp_render import (
    detect_identifier_change,
    parse_edited_buffer,
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


def test_render_matches_legacy_and_builds_map():
    comments = _comments([(2, "local copy"), (99, "out of range")])
    text, model = render_view_with_map(_dd(), _summary("Adds one."), comments)

    assert render_view(_dd(), _summary("Adds one."), comments) == text
    assert text.splitlines()[0] == "/*"
    assert "    // local copy" in text
    assert model.summary_line_count == 3
    assert model.code_lines == CODE.split("\n")
    assert model.comment_by_source == {2: "local copy"}


def test_no_summary_no_comments_is_raw_code():
    text, model = render_view_with_map(_dd(), None, None)
    assert text == CODE
    assert model.summary_line_count == 0
    assert model.comment_by_source == {}


def test_unedited_buffer_round_trips_to_zero_changes():
    comments = _comments([(2, "local copy")])
    text, model = render_view_with_map(_dd(), _summary("Adds one."), comments)

    parse = parse_edited_buffer(text, model)
    assert parse.current_code_lines == model.code_lines
    assert parse.current_comment_by_index == {1: "local copy"}


def test_multiline_comment_round_trips():
    comments = _comments([(2, "line one\nline two")])
    text, model = render_view_with_map(_dd(), None, comments)
    parse = parse_edited_buffer(text, model)
    assert parse.current_code_lines == model.code_lines
    assert parse.current_comment_by_index == {1: "line one\nline two"}


def test_structural_edit_changes_code_line_count():
    text, model = render_view_with_map(_dd(), None, None)
    parse = parse_edited_buffer(text + "\n    extra();", model)
    assert len(parse.current_code_lines) != len(model.code_lines)


def test_detect_identifier_change():
    assert detect_identifier_change("    int v5 = a1;", "    int buf = a1;") == (1, "v5", "buf")
    assert detect_identifier_change("    int v5 = a1;", "    int v5 = a1;") is None
    assert detect_identifier_change("    int v5 = a1;", "    int buf = tmp;") is None
    assert detect_identifier_change("    int v5;", "    int v5 = a1;") is None


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
