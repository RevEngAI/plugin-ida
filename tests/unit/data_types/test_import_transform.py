from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from reai_toolkit.app.transformations import import_data_types as mod
from reai_toolkit.app.transformations.import_data_types import (
    APPLY_CHUNK_SIZE,
    ImportDataTypes,
)
from revengai import (
    Enumeration,
    FunctionDataTypesList,
    FunctionInfo,
    Structure,
    StructureMember,
    TypeDefinition,
)


@pytest.fixture
def deci(mocker):
    instance = MagicMock()
    instance.art_lifter.lift_addr.side_effect = lambda addr: addr
    mocker.patch.object(mod.DecompilerInterface, "discover", return_value=instance)
    return instance


def _item(function_id: int, func_types=None, func_deps=None):
    return SimpleNamespace(
        function_id=function_id,
        data_types=FunctionInfo.model_construct(
            func_deps=[SimpleNamespace(actual_instance=d) for d in (func_deps or [])],
            func_types=func_types,
        ),
    )


def _functions(items):
    return FunctionDataTypesList.model_construct(items=items)


def _struct(name: str, member_type: str = "int") -> Structure:
    return Structure(
        name=name,
        size=8,
        members={"0x0": StructureMember(name="field0", offset=0, type=member_type, size=8)},
    )


def test_execute_no_items_skips_everything(deci):
    idt = ImportDataTypes()

    assert idt.execute(_functions([SimpleNamespace(function_id=1, data_types=None)])) == set()
    mod.DecompilerInterface.discover.assert_not_called()


def test_execute_skips_discover_without_dependencies(deci, mocker):
    apply = mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)
    idt = ImportDataTypes()

    failed = idt.execute(_functions([_item(1, func_types=MagicMock(addr=0x1000))]))

    assert failed == set()
    apply.assert_called_once()
    mod.DecompilerInterface.discover.assert_not_called()


def test_execute_applies_shared_dependency_once(deci, mocker):
    mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)
    shared = _struct("SharedStruct")
    items = [
        _item(1, func_types=MagicMock(addr=0x1000), func_deps=[shared]),
        _item(2, func_types=MagicMock(addr=0x2000), func_deps=[shared]),
    ]

    ImportDataTypes().execute(_functions(items))

    struct_writes = [c for c in deci.structs.mock_calls if "__setitem__" in str(c)]
    assert len(struct_writes) == 1


def test_execute_applies_subdependency_before_parent(deci, mocker):
    mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)
    typedef = TypeDefinition(name="td_t", type="int")
    parent = _struct("Parent", member_type="td_t")
    enum = Enumeration(name="Colors", members={"RED": 0})
    items = [_item(1, func_types=MagicMock(addr=0x1000), func_deps=[parent, typedef, enum])]

    ImportDataTypes().execute(_functions(items))

    writes = [c[0] for c in deci.mock_calls if "__setitem__" in c[0]]
    assert writes.index("typedefs.__setitem__") < writes.index("structs.__setitem__")
    assert "enums.__setitem__" in writes


def test_execute_survives_dependency_failure(deci, mocker):
    apply = mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)
    deci.enums.__setitem__.side_effect = RuntimeError("til write failed")
    enum = Enumeration(name="Colors", members={"RED": 0})
    items = [_item(1, func_types=MagicMock(addr=0x1000), func_deps=[enum])]

    failed = ImportDataTypes().execute(_functions(items))

    assert failed == set()
    apply.assert_called_once()


def test_execute_chunks_and_aggregates_failures(deci, mocker):
    total = APPLY_CHUNK_SIZE + 5
    apply = mocker.patch.object(
        ImportDataTypes, "apply_function_type", side_effect=lambda func, ea: ea % 2 == 0
    )
    items = [_item(fid, func_types=MagicMock(addr=fid)) for fid in range(total)]

    failed = ImportDataTypes().execute(_functions(items))

    assert apply.call_count == total
    assert failed == {fid for fid in range(total) if fid % 2 == 1}


def test_execute_uses_mapping_and_fails_unmapped(deci, mocker):
    seen: list[int] = []

    def record(func, ea):
        seen.append(ea)
        return True

    mocker.patch.object(ImportDataTypes, "apply_function_type", side_effect=record)
    items = [
        _item(1, func_types=MagicMock(addr=0x1000)),
        _item(2, func_types=MagicMock(addr=0x2000)),
    ]

    failed = ImportDataTypes().execute(_functions(items), matched_function_mapping={1: 0x9000})

    assert seen == [0x9000]
    assert failed == {2}


def test_execute_skips_items_without_func_types(deci, mocker):
    apply = mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)

    failed = ImportDataTypes().execute(_functions([_item(1, func_types=None)]))

    assert failed == set()
    apply.assert_not_called()


_HASH = "259156281adba01eb86070f77a039e7054f268c973326adcee5fe4533f14b292"


@pytest.mark.parametrize(
    "raw,expected",
    [
        (f"{_HASH}::Candidate *", "Candidate *"),
        (f"{_HASH}/std::vector<Block_*,std::allocator<Block_*>_>", "std::vector<Block_*,std::allocator<Block_*>_>"),
        (f"{_HASH}::_Tree_node<x>::_Node *", "_Tree_node<x>::_Node *"),
        ("DWARF/stdint.h::uint32_t", "uint32_t"),
        ("std::vector<int>", "std::vector<int>"),
        ("int", "int"),
    ],
)
def test_normalise_type_strips_analysis_scope(raw, expected):
    assert ImportDataTypes.normalise_type(raw) == expected


def _svar(offset: int, name: str, type_str: str, size: int = 4):
    return SimpleNamespace(offset=offset, name=name, type=type_str, size=size)


def test_apply_stack_variables_writes_function_with_normalised_types(deci, mocker):
    mocker.patch.object(ImportDataTypes, "_probe_decompiler", return_value=True)
    func = SimpleNamespace(
        stack_vars={
            "0x4": _svar(4, "lhs", "int"),
            "0x8": _svar(8, "rhs", f"{_HASH}::Candidate *"),
        }
    )

    ImportDataTypes().apply_stack_variables(func, 0x1000)

    deci.functions.__setitem__.assert_called_once()
    ea, written = deci.functions.__setitem__.call_args.args
    assert ea == 0x1000
    assert set(written.stack_vars) == {4, 8}
    assert written.stack_vars[4].name == "lhs"
    assert written.stack_vars[8].type == "Candidate *"


def test_apply_stack_variables_noop_without_stack_vars(deci):
    ImportDataTypes().apply_stack_variables(SimpleNamespace(stack_vars=None), 0x1000)
    ImportDataTypes().apply_stack_variables(SimpleNamespace(stack_vars={}), 0x1000)

    mod.DecompilerInterface.discover.assert_not_called()
    deci.functions.__setitem__.assert_not_called()


def test_execute_applies_stack_vars_only_when_enabled(deci, mocker):
    mocker.patch.object(ImportDataTypes, "apply_function_type", return_value=True)
    svapply = mocker.patch.object(ImportDataTypes, "apply_stack_variables")
    items = [_item(1, func_types=MagicMock(addr=0x1000))]

    ImportDataTypes().execute(_functions(items))
    svapply.assert_not_called()

    ImportDataTypes().execute(_functions(items), apply_stack_vars=True)
    svapply.assert_called_once()


def test_apply_stack_variables_skips_when_decompiler_unavailable(deci, mocker):
    mocker.patch.object(ImportDataTypes, "_probe_decompiler", return_value=False)

    ImportDataTypes().apply_stack_variables(
        SimpleNamespace(stack_vars={"0x4": _svar(4, "lhs", "int")}), 0x1000
    )

    mod.DecompilerInterface.discover.assert_not_called()
    deci.functions.__setitem__.assert_not_called()
