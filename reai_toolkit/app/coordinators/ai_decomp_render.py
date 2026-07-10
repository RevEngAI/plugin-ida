from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from revengai.models.ai_decomp_function_mapping import AIDecompFunctionMapping
    from revengai.models.comments_data import CommentsData
    from revengai.models.decompilation_data import DecompilationData
    from revengai.models.inline_comment import InlineComment
    from revengai.models.summary_data import SummaryData
    from revengai.models.tokenised_data import TokenisedData


_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_VARIABLE_CATEGORIES = (
    "unmatched_vars",
    "unmatched_global_vars",
    "unmatched_external_vars",
)
_TYPE_CATEGORIES = ("unmatched_custom_types", "unmatched_enums")


@dataclass
class RenderModel:
    summary_line_count: int
    code_lines: list[str]
    comment_by_source: dict[int, str]


@dataclass
class EditParse:
    current_code_lines: list[str]
    current_comment_by_index: dict[int, str]


def render_view(
    decomp: "DecompilationData",
    summary: "Optional[SummaryData]",
    comments: "Optional[CommentsData]",
) -> str:
    text, _ = render_view_with_map(decomp, summary, comments)
    return text


def render_view_with_map(
    decomp: "DecompilationData",
    summary: "Optional[SummaryData]",
    comments: "Optional[CommentsData]",
) -> tuple[str, RenderModel]:
    code: str = decomp.decompilation or ""
    code_lines: list[str] = code.split("\n")

    summary_block: str | None = None
    if summary is not None and summary.ai_summary:
        summary_block = _format_summary_as_comment(summary.ai_summary)
    summary_line_count = len(summary_block.split("\n")) if summary_block is not None else 0

    inline = comments.inline_comments if comments is not None else None

    comment_by_source: dict[int, str] = {}
    if inline:
        for c in inline:
            if 1 <= c.line <= len(code_lines):
                comment_by_source[c.line] = c.comment

    body = _inject_inline_comments(code, inline) if inline else code

    text = "\n".join([summary_block, body]) if summary_block is not None else body

    return text, RenderModel(
        summary_line_count=summary_line_count,
        code_lines=code_lines,
        comment_by_source=comment_by_source,
    )


def _inject_inline_comments(code: str, comments: "list[InlineComment]") -> str:
    lines = code.split("\n")
    for c in sorted(comments, key=lambda x: x.line, reverse=True):
        idx = c.line - 1
        if idx < 0 or idx >= len(lines):
            continue
        target = lines[idx]
        indent = target[: len(target) - len(target.lstrip())]
        rendered = [f"{indent}// {part}" for part in c.comment.split("\n")]
        lines[idx:idx] = rendered
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


def parse_edited_buffer(text: str, baseline: RenderModel) -> EditParse:
    lines = text.split("\n")
    body = lines[baseline.summary_line_count :]

    code_lines: list[str] = []
    comment_by_index: dict[int, str] = {}
    pending: list[str] = []

    for line in body:
        if line.lstrip().startswith("//"):
            pending.append(_strip_comment_marker(line))
        else:
            if pending:
                comment_by_index[len(code_lines)] = "\n".join(pending)
                pending = []
            code_lines.append(line)

    return EditParse(
        current_code_lines=code_lines,
        current_comment_by_index=comment_by_index,
    )


def _strip_comment_marker(line: str) -> str:
    rest = line.lstrip()[2:]
    if rest.startswith(" "):
        rest = rest[1:]
    return rest


def detect_identifier_change(
    old_line: str, new_line: str
) -> Optional[tuple[int, str, str]]:
    old_idents = _IDENT_RE.findall(old_line)
    new_idents = _IDENT_RE.findall(new_line)
    if len(old_idents) != len(new_idents):
        return None
    diffs = [i for i in range(len(old_idents)) if old_idents[i] != new_idents[i]]
    if len(diffs) != 1:
        return None
    i = diffs[0]
    return i, old_idents[i], new_idents[i]


def resolve_token(
    tokenised: "TokenisedData",
    source_index: int,
    ident_index: int,
    old_ident: str,
) -> Optional[tuple[str, str]]:
    mapping = tokenised.function_mapping
    if mapping is None:
        return None

    tok_lines = (tokenised.tokenised_decompilation or "").split("\n")
    if 0 <= source_index < len(tok_lines):
        tok_idents = _IDENT_RE.findall(tok_lines[source_index])
        if 0 <= ident_index < len(tok_idents):
            candidate = tok_idents[ident_index]
            cat, eff = _category_of_token(mapping, candidate)
            if cat is not None and eff == old_ident:
                return candidate, cat

    matches = [
        (token, cat)
        for token, rv, cat in _iter_category_tokens(mapping)
        if _effective_value(mapping, token, rv) == old_ident
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _iter_category_tokens(mapping: "AIDecompFunctionMapping"):
    for cat in _VARIABLE_CATEGORIES:
        for token, rv in (getattr(mapping, cat, None) or {}).items():
            yield token, rv, "variable"
    for cat in _TYPE_CATEGORIES:
        for token, rv in (getattr(mapping, cat, None) or {}).items():
            yield token, rv, "type"


def _category_of_token(
    mapping: "AIDecompFunctionMapping", token: str
) -> tuple[Optional[str], Optional[str]]:
    for t, rv, cat in _iter_category_tokens(mapping):
        if t == token:
            return cat, _effective_value(mapping, t, rv)
    return None, None


def _effective_value(mapping: "AIDecompFunctionMapping", token: str, replacement) -> str:
    overrides = mapping.user_override_mappings or {}
    return overrides.get(token, replacement.value)
