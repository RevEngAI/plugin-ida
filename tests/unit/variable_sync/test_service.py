import queue
from unittest.mock import MagicMock

import pytest
from libbs.artifacts import Function, FunctionArgument, FunctionHeader, StackVariable
from revengai import (
    Argument,
    FunctionInfo,
    FunctionType,
)
from revengai.models.function_header import FunctionHeader as SdkFunctionHeader
from revengai.models.stack_variable import StackVariable as SdkStackVariable

from reai_toolkit.app.services.variable_sync import variable_sync_service as svc_mod
from reai_toolkit.app.services.variable_sync.variable_sync_service import (
    VariableSyncService,
)


@pytest.fixture
def netstore():
    return MagicMock()


@pytest.fixture
def service(netstore):
    svc = VariableSyncService(netstore_service=netstore, sdk_config=MagicMock())
    VariableSyncService._q = queue.Queue()
    VariableSyncService._last_ts = {}
    return svc


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(VariableSyncService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "FunctionsDataTypesApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    return api_inst


def _sdk_stack_var(offset: int, name: str, type_: str) -> SdkStackVariable:
    return SdkStackVariable.model_construct(
        last_change=None, offset=offset, name=name, type=type_, size=8, addr=0x1000
    )


def _sdk_arg(offset: int, name: str, type_: str) -> Argument:
    return Argument.model_construct(
        last_change=None, offset=offset, name=name, type=type_, size=8
    )


def _function_info(stack_vars=None, args=None, ret_type="void") -> FunctionInfo:
    header = SdkFunctionHeader.model_construct(
        last_change=None,
        name="f",
        addr=0x1000,
        type=ret_type,
        args=args or {},
    )
    func_types = FunctionType.model_construct(
        last_change=None,
        addr=0x1000,
        size=10,
        header=header,
        stack_vars=stack_vars or {},
        name="f",
        type=ret_type,
        artifact_type="Function",
    )
    return FunctionInfo.model_construct(func_types=func_types, func_deps=[])


def test_patch_stack_var_matches_by_offset(service):
    info = _function_info(stack_vars={"-0x20": _sdk_stack_var(-32, "local_20", "char")})

    changed = service._patch(info, StackVariable(stack_offset=-32, name="counter", type_="int", size=4, addr=0x0))

    assert changed is True
    entry = info.func_types.stack_vars["-0x20"]
    assert entry.name == "counter"
    assert entry.type == "int"


def test_patch_stack_var_no_offset_match_is_noop(service):
    info = _function_info(stack_vars={"-0x20": _sdk_stack_var(-32, "local_20", "char")})

    changed = service._patch(info, StackVariable(stack_offset=-99, name="x", type_="int", size=4, addr=0x0))

    assert changed is False
    assert info.func_types.stack_vars["-0x20"].name == "local_20"


def test_patch_header_updates_arg_and_return_type(service):
    info = _function_info(args={"0x0": _sdk_arg(0, "a1", "int")}, ret_type="void")
    fheader = FunctionHeader(
        name="f", addr=0x0, type_="int", args={0: FunctionArgument(offset=0, name="count", type_="size_t", size=8)}
    )

    changed = service._patch(info, fheader)

    assert changed is True
    assert info.func_types.header.args["0x0"].name == "count"
    assert info.func_types.header.args["0x0"].type == "size_t"
    assert info.func_types.header.type == "int"
    assert info.func_types.type == "int"


def test_patch_stack_var_type_change_keeps_name(service):
    info = _function_info(stack_vars={"-0x20": _sdk_stack_var(-32, "local_20", "char")})

    changed = service._patch(info, StackVariable(stack_offset=-32, name=None, type_="int", size=4, addr=0x0))

    assert changed is True
    entry = info.func_types.stack_vars["-0x20"]
    assert entry.name == "local_20"
    assert entry.type == "int"


def test_patch_header_arg_type_change_keeps_name(service):
    info = _function_info(args={"0x0": _sdk_arg(0, "oldfile", "char *")}, ret_type="int")
    fheader = FunctionHeader(
        name=None, addr=0x0, type_=None, args={0: FunctionArgument(offset=0, name=None, type_="wchar_t *", size=8)}
    )

    changed = service._patch(info, fheader)

    assert changed is True
    assert info.func_types.header.args["0x0"].name == "oldfile"
    assert info.func_types.header.args["0x0"].type == "wchar_t *"


def test_patch_header_identical_is_noop(service):
    info = _function_info(args={"0x0": _sdk_arg(0, "a1", "int")}, ret_type="void")
    fheader = FunctionHeader(
        name="f", addr=0x0, type_="void", args={0: FunctionArgument(offset=0, name="a1", type_="int", size=8)}
    )

    assert service._patch(info, fheader) is False


def test_push_change_fetches_patches_and_pushes(service, sdk, netstore):
    netstore.get_analysis_id.return_value = 7
    info = _function_info(stack_vars={"-0x20": _sdk_stack_var(-32, "local_20", "char")})
    fetched = MagicMock()
    fetched.status = True
    fetched.data.items = [
        MagicMock(function_id=42, data_types=info, data_types_version=3)
    ]
    sdk.list_function_data_types_for_functions.return_value = fetched
    sdk.batch_update_function_data_types.return_value = MagicMock(
        results=[MagicMock(status="updated")]
    )

    service._push_change(42, 0x2668, StackVariable(stack_offset=-32, name="n", type_="int", size=4, addr=0x0))

    sdk.batch_update_function_data_types.assert_called_once()
    body = sdk.batch_update_function_data_types.call_args.kwargs[
        "batch_update_data_types_input_body"
    ]
    item = body.functions[0]
    assert item.function_id == 42
    assert item.data_types_version == 3


def test_push_change_skips_push_when_unchanged(service, sdk, netstore):
    netstore.get_analysis_id.return_value = 7
    info = _function_info(stack_vars={"-0x20": _sdk_stack_var(-32, "local_20", "char")})
    fetched = MagicMock()
    fetched.status = True
    fetched.data.items = [
        MagicMock(function_id=42, data_types=info, data_types_version=3)
    ]
    sdk.list_function_data_types_for_functions.return_value = fetched

    service._push_change(42, 0x2668, StackVariable(stack_offset=-999, name="n", type_="int", size=4, addr=0x0))

    sdk.batch_update_function_data_types.assert_not_called()


def test_push_change_retries_on_version_conflict(service, sdk, netstore):
    netstore.get_analysis_id.return_value = 7

    def fresh_response():
        info = _function_info(stack_vars={"-0x20": _sdk_stack_var(-32, "local_20", "char")})
        resp = MagicMock()
        resp.status = True
        resp.data.items = [MagicMock(function_id=42, data_types=info, data_types_version=3)]
        return resp

    sdk.list_function_data_types_for_functions.side_effect = lambda function_ids: fresh_response()
    sdk.batch_update_function_data_types.side_effect = [
        MagicMock(results=[MagicMock(status="version_conflict")]),
        MagicMock(results=[MagicMock(status="updated")]),
    ]

    service._push_change(42, 0x2668, StackVariable(stack_offset=-32, name="n", type_="int", size=4, addr=0x0))

    assert sdk.batch_update_function_data_types.call_count == 2


def test_push_change_builds_object_when_no_stored_types(service, sdk, netstore, mocker):
    netstore.get_analysis_id.return_value = 7
    empty = MagicMock()
    empty.status = True
    empty.data.items = []
    sdk.list_function_data_types_for_functions.return_value = empty
    sdk.batch_update_function_data_types.return_value = MagicMock(
        results=[MagicMock(status="updated")]
    )

    func = Function(
        addr=0x2668,
        size=10,
        name="relink",
        header=FunctionHeader(
            name="relink",
            addr=0x2668,
            type_="int",
            args={0: FunctionArgument(offset=0, name="oldfile", type_="wchar_t *", size=8)},
        ),
        stack_vars={-32: StackVariable(stack_offset=-32, name="v2", type_="dev_t", size=8, addr=0x2668)},
    )
    service.attach_decompiler(MagicMock())
    mocker.patch.object(svc_mod, "_read_decompiler_function", return_value=func)

    service._push_change(
        2015112411,
        0x2668,
        FunctionHeader(name=None, addr=0x2668, type_=None, args={0: FunctionArgument(offset=0, name=None, type_="wchar_t *", size=8)}),
    )

    sdk.batch_update_function_data_types.assert_called_once()
    body = sdk.batch_update_function_data_types.call_args.kwargs[
        "batch_update_data_types_input_body"
    ]
    item = body.functions[0]
    assert item.function_id == 2015112411
    assert item.data_types_version == 0
    assert item.data_types["func_types"]["header"]["args"]["0x0"]["name"] == "oldfile"
    assert item.data_types["func_types"]["header"]["args"]["0x0"]["type"] == "wchar_t *"
    assert item.data_types["func_types"]["stack_vars"]["-0x20"]["name"] == "v2"


def test_push_change_skips_build_when_no_decompiler(service, sdk, netstore):
    netstore.get_analysis_id.return_value = 7
    empty = MagicMock()
    empty.status = True
    empty.data.items = []
    sdk.list_function_data_types_for_functions.return_value = empty

    service._push_change(42, 0x2668, StackVariable(stack_offset=-32, name="n", type_="int", size=4, addr=0x0))

    sdk.batch_update_function_data_types.assert_not_called()


def test_collect_func_deps_resolves_typedef_chain(service, mocker):
    from libbs.artifacts import Typedef

    service.attach_decompiler(MagicMock())
    func_type = _function_info(args={"0x0": _sdk_arg(0, "d", "dev_t")}, ret_type="int").func_types

    chain = {
        "dev_t": Typedef(name="dev_t", type_="__dev_t"),
        "__dev_t": Typedef(name="__dev_t", type_="unsigned long"),
    }
    mocker.patch.object(svc_mod, "_read_named_type", side_effect=lambda deci, name: chain.get(name))

    deps = service._collect_func_deps(func_type)

    assert sorted(d.actual_instance.name for d in deps) == ["__dev_t", "dev_t"]
    assert all(d.actual_instance.to_dict()["artifact_type"] == "Typedef" for d in deps)


def test_collect_func_deps_resolves_struct_members(service, mocker):
    from libbs.artifacts import Struct, StructMember, Typedef

    service.attach_decompiler(MagicMock())
    func_type = _function_info(args={"0x0": _sdk_arg(0, "p", "mystruct *")}, ret_type="int").func_types

    types = {
        "mystruct": Struct(
            name="mystruct", size=8, members={0: StructMember(name="x", offset=0, type_="myint", size=4)}
        ),
        "myint": Typedef(name="myint", type_="int"),
    }
    mocker.patch.object(svc_mod, "_read_named_type", side_effect=lambda deci, name: types.get(name))

    deps = service._collect_func_deps(func_type)

    by_name = {d.actual_instance.name: d.actual_instance for d in deps}
    assert set(by_name) == {"mystruct", "myint"}
    assert by_name["mystruct"].members["0x0"].type == "myint"


def test_push_change_no_analysis_id_does_nothing(service, sdk, netstore):
    netstore.get_analysis_id.return_value = None

    service._push_change(42, 0x2668, StackVariable(stack_offset=-32, name="n", type_="int", size=4, addr=0x0))

    sdk.list_function_data_types_for_functions.assert_not_called()


def test_enqueue_change_debounces_rapid_duplicates(service, mocker):
    mocker.patch.object(service, "_start_worker_if_needed")
    svar = StackVariable(stack_offset=-32, name="a", type_="int", size=4, addr=0x0)

    service.enqueue_change(42, 0x2668, svar)
    service.enqueue_change(42, 0x2668, svar)

    assert service._q.qsize() == 1
