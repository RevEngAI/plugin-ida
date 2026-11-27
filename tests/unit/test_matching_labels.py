import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "reai_toolkit"
LEGACY = re.compile(r"\b(ANN|Ann)\b")


def _sources():
    for path in ROOT.rglob("*"):
        if "vendor" not in path.parts and path.suffix in (".py", ".ui"):
            yield path


def _strings(path: Path):
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".ui":
        yield from re.findall(r"<string>(.*?)</string>", text, re.S)
        return
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value


def test_no_legacy_labels_in_user_facing_strings():
    hits = [
        f"{p.relative_to(ROOT)}: {s!r}"
        for p in _sources()
        for s in _strings(p)
        if LEGACY.search(s)
    ]
    assert not hits, "\n".join(hits)
