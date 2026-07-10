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
