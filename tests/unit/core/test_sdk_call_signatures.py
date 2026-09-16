"""
Guard against revengai SDK drift.

The service tests mock the SDK's API classes with plain MagicMocks, which accept
any keyword and return an object with any attribute. A parameter or field the SDK
drops therefore passes the suite and only fails at runtime — as `context_aware`
did when the SDK went from 3.x to 4.x. These checks read the real signatures and
model fields instead.

Both checks resolve the receiver of a call back to an SDK API class, so a plugin
method that merely shares a name with an SDK one (netstore_service.get_analysis_status,
matching_service.search_binaries) is neither falsely flagged nor able to mask a
real call.
"""

import ast
import importlib
import inspect
import pkgutil
import typing
from pathlib import Path

import pydantic
import revengai.api as sdk_api

PLUGIN_ROOT = Path(__file__).resolve().parents[3] / "reai_toolkit"

# Attributes every generated model carries that are not declared fields.
MODEL_EXTRA = {
    "to_dict", "to_json", "to_str", "from_json", "from_dict", "model_dump",
    "model_dump_json", "model_fields", "model_construct", "model_copy",
    "additional_properties", "model_fields_set",
}


def _api_classes() -> dict[str, type]:
    classes: dict[str, type] = {}
    for module in pkgutil.iter_modules(sdk_api.__path__):
        mod = importlib.import_module(f"revengai.api.{module.name}")
        for name, cls in vars(mod).items():
            if inspect.isclass(cls) and name.endswith("Api"):
                classes[name] = cls
    return classes


API_CLASSES = _api_classes()


def _signature(api_name: str, method: str):
    cls = API_CLASSES.get(api_name)
    fn = getattr(cls, method, None) if cls else None
    if fn is None or not callable(fn):
        return None
    try:
        return inspect.signature(fn)
    except (TypeError, ValueError):
        return None


def _model_in(annotation):
    """Pull the model class out of Optional[X], List[X], Union[...]."""
    seen, stack = set(), [annotation]
    while stack:
        candidate = stack.pop()
        if inspect.isclass(candidate) and issubclass(candidate, pydantic.BaseModel):
            return candidate
        if id(candidate) in seen:
            continue
        seen.add(id(candidate))
        stack.extend(typing.get_args(candidate))
    return None


def _chain(node: ast.Attribute) -> tuple[ast.AST, list[str]]:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return node, list(reversed(parts))


def _constructed_api(node) -> str | None:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in API_CLASSES:
            return node.func.id
    return None


def _plugin_functions():
    for path in sorted(PLUGIN_ROOT.rglob("*.py")):
        if "vendor" in path.parts:
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield path, node


def _sdk_calls(fn_node):
    """Every call in this function that lands on an SDK API class."""
    clients, rebound = {}, set()
    for node in ast.walk(fn_node):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            api = _constructed_api(node.value)
            if api:
                clients[target.id] = api
            else:
                rebound.add(target.id)

    def receiver(node) -> str | None:
        if isinstance(node, ast.Name) and node.id in clients and node.id not in rebound:
            return clients[node.id]
        return _constructed_api(node)

    calls = {}
    for node in ast.walk(fn_node):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        api = receiver(node.func.value)
        if not api:
            continue
        signature = _signature(api, node.func.attr)
        if signature is not None:
            calls[node] = (api, node.func.attr, signature)
    return calls


def _relative(path: Path) -> str:
    return str(path.relative_to(PLUGIN_ROOT.parent))


def test_every_keyword_the_plugin_passes_is_an_sdk_parameter():
    offenders = []
    for path, fn_node in _plugin_functions():
        for call, (api, method, signature) in _sdk_calls(fn_node).items():
            for keyword in call.keywords:
                if keyword.arg and keyword.arg not in signature.parameters:
                    offenders.append(
                        f"{_relative(path)}:{call.lineno} "
                        f"{api}.{method}({keyword.arg}=...) is not a parameter"
                    )
    assert sorted(set(offenders)) == []


def test_every_attribute_read_off_an_sdk_response_is_a_model_field():
    offenders = []
    for path, fn_node in _plugin_functions():
        calls = _sdk_calls(fn_node)

        typed, rebound = {}, set()
        for node in ast.walk(fn_node):
            target = value = None
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                target, value = node.target.id, node.value
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target, value = node.targets[0].id, node.value
            elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                target, value = node.target.id, node.value
            if target is None:
                continue
            call = calls.get(value)
            model = _model_in(call[2].return_annotation) if call else None
            if model is None:
                rebound.add(target)
                continue
            if target in typed and typed[target][1] is not model:
                rebound.add(target)
            typed[target] = (f"{call[0]}.{call[1]}", model)

        for node in ast.walk(fn_node):
            if not isinstance(node, ast.Attribute):
                continue
            base, parts = _chain(node)
            origin = label = None
            if isinstance(base, ast.Name) and base.id not in rebound:
                origin, label = typed.get(base.id), base.id
            elif isinstance(base, ast.Call) and base in calls:
                api, method, signature = calls[base]
                model = _model_in(signature.return_annotation)
                if model:
                    origin, label = (f"{api}.{method}", model), f"{method}(...)"
            if not origin:
                continue

            source, model = origin
            walked = label
            for part in parts:
                if model is None or part in MODEL_EXTRA or part.startswith("_"):
                    break
                if part not in model.model_fields:
                    offenders.append(
                        f"{_relative(path)}:{node.lineno} {walked}.{part} — "
                        f"{source}() returns {model.__name__}, which has no '{part}' "
                        f"(fields: {', '.join(sorted(model.model_fields))})"
                    )
                    break
                walked = f"{walked}.{part}"
                model = _model_in(model.model_fields[part].annotation)

    assert sorted(set(offenders)) == []
