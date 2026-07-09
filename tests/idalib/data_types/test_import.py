import pytest

import ida_typeinf
import idaapi
import idc
from revengai import (
    FunctionArgument,
    FunctionDataTypesList,
    FunctionDataTypesListItem,
    FunctionHeader,
    FunctionInfo,
    FunctionType,
)

from reai_toolkit.app.transformations.import_data_types import ImportDataTypes

pytestmark = pytest.mark.idalib


@pytest.fixture
def func_ea(loaded_binary):
    ea = idc.get_name_ea_simple("sub_401020")
    assert ea != idaapi.BADADDR
    original = ida_typeinf.tinfo_t()
    had_type = idaapi.get_tinfo(original, ea)
    yield ea
    if had_type:
        ida_typeinf.apply_tinfo(ea, original, ida_typeinf.TINFO_DEFINITE)
    else:
        idc.SetType(ea, "")


def _arg(offset: int, name: str, type_str: str) -> FunctionArgument:
    return FunctionArgument(name=name, offset=offset, size=8, type=type_str)


def _func_types(ea: int, ret: str = "int", args: tuple = ()) -> FunctionType:
    return FunctionType(
        addr=ea,
        header=FunctionHeader(
            addr=ea,
            args={hex(arg.offset): arg for arg in args},
            name="reai_test_func",
            type=ret,
        ),
        name="reai_test_func",
        size=16,
        type=ret,
    )


def _item(function_id: int, func_types: FunctionType) -> FunctionDataTypesListItem:
    return FunctionDataTypesListItem.model_construct(
        function_id=function_id,
        data_types=FunctionInfo.model_construct(func_deps=[], func_types=func_types),
    )


def test_apply_function_type_sets_prototype_with_named_args(func_ea):
    idt = ImportDataTypes()
    func = _func_types(func_ea, ret="int", args=(_arg(0, "count", "int"), _arg(1, "buf", "char *")))

    assert idt.apply_function_type(func, func_ea) is True

    printed = ida_typeinf.print_type(func_ea, ida_typeinf.PRTYPE_1LINE)
    assert "count" in printed
    assert "buf" in printed
    assert "char *" in printed


def test_apply_function_type_normalises_dwarf_types(func_ea):
    idt = ImportDataTypes()
    func = _func_types(func_ea, ret="uchar", args=(_arg(0, "n", "DWARF/stdint.h::qword"),))

    assert idt.apply_function_type(func, func_ea) is True

    printed = ida_typeinf.print_type(func_ea, ida_typeinf.PRTYPE_1LINE)
    assert "unsigned __int8" in printed
    assert "unsigned __int64 n" in printed


def test_apply_function_type_keeps_args_when_remote_has_none(func_ea):
    idt = ImportDataTypes()
    assert idt.apply_function_type(
        _func_types(func_ea, ret="int", args=(_arg(0, "count", "int"),)), func_ea
    )

    assert idt.apply_function_type(_func_types(func_ea, ret="void", args=()), func_ea) is True

    printed = ida_typeinf.print_type(func_ea, ida_typeinf.PRTYPE_1LINE)
    assert "void" in printed
    assert "count" in printed


def test_apply_function_type_rejects_unparseable_arg(func_ea):
    idt = ImportDataTypes()
    func = _func_types(func_ea, args=(_arg(0, "x", "totally bogus type!!"),))

    assert idt.apply_function_type(func, func_ea) is False


def test_apply_function_type_missing_function(loaded_binary):
    idt = ImportDataTypes()

    assert idt.apply_function_type(_func_types(0x1), 0x1) is False


def test_execute_applies_via_mapping_and_reports_failures(func_ea):
    items = [
        _item(1, _func_types(func_ea, ret="int", args=(_arg(0, "count", "int"),))),
        _item(2, _func_types(func_ea, args=(_arg(0, "x", "totally bogus type!!"),))),
        _item(3, _func_types(0x1)),
        _item(4, _func_types(func_ea)),
    ]
    mapping = {1: func_ea, 2: func_ea, 3: 0x1}

    failed = ImportDataTypes().execute(
        FunctionDataTypesList.model_construct(items=items), matched_function_mapping=mapping
    )

    assert failed == {2, 3, 4}
    printed = ida_typeinf.print_type(func_ea, ida_typeinf.PRTYPE_1LINE)
    assert "count" in printed
