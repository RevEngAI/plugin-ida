from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from revengai.models.ai_decomp_function_mapping import AIDecompFunctionMapping
    from revengai.models.comments_data import CommentsData
    from revengai.models.decompilation_data import DecompilationData
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
    display_source: list[Optional[int]]
    display_is_code: list[bool]


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

    display_lines: list[str] = []
    display_source: list[Optional[int]] = []
    display_is_code: list[bool] = []

    if summary_block is not None:
        for sline in summary_block.split("\n"):
            display_lines.append(sline)
            display_source.append(None)
            display_is_code.append(False)

    for idx, code_line in enumerate(code_lines):
        source_line = idx + 1
        comment = comment_by_source.get(source_line)
        if comment is not None:
            indent = code_line[: len(code_line) - len(code_line.lstrip())]
            for part in comment.split("\n"):
                display_lines.append(f"{indent}// {part}")
                display_source.append(source_line)
                display_is_code.append(False)
        display_lines.append(code_line)
        display_source.append(source_line)
        display_is_code.append(True)

    text = "\n".join(display_lines)
    return text, RenderModel(
        summary_line_count=summary_line_count,
        code_lines=code_lines,
        comment_by_source=comment_by_source,
        display_source=display_source,
        display_is_code=display_is_code,
    )


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


def index_of_identifier(line: str, word: str) -> int:
    idents = _IDENT_RE.findall(line)
    return idents.index(word) if word in idents else -1


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
