from unittest.mock import MagicMock

import pytest

import ida_name
import idaapi
import idautils
import idc
from revengai.models.function_mapping import FunctionMapping

from reai_toolkit.app.services.analysis_sync.analysis_sync import AnalysisSyncService

pytestmark = pytest.mark.idalib


@pytest.fixture
def service():
    return AnalysisSyncService(
        data_types_service=MagicMock(),
        rename_service=MagicMock(),
        variable_sync_service=MagicMock(),
        netstore_service=MagicMock(),
        sdk_config=MagicMock(),
    )


@pytest.fixture
def auto_func(loaded_binary):
    ea = idc.get_name_ea_simple("sub_401020")
    assert ea != idaapi.BADADDR
    original = ida_name.get_name(ea)
    yield ea
    ida_name.set_name(ea, original, ida_name.SN_CHECK | ida_name.SN_AUTO)


@pytest.fixture
def two_funcs(loaded_binary):
    eas = list(idautils.Functions())
    assert len(eas) >= 2
    a, b = eas[0], eas[1]
    originals = (ida_name.get_name(a), ida_name.get_name(b))
    yield a, b
    ida_name.set_name(a, originals[0], ida_name.SN_CHECK | ida_name.SN_AUTO)
    ida_name.set_name(b, originals[1], ida_name.SN_CHECK | ida_name.SN_AUTO)


def test_perform_function_sync_renames_matched_functions(service, auto_func):
    func_map = FunctionMapping(
        function_map={},
        inverse_function_map={},
        name_map={str(auto_func): "synced_fn"},
    )

    result, pushbacks, needs_canonical = service._perform_function_sync(func_map)

    assert result.success is True
    assert result.data.matched_function_count >= 1
    assert ida_name.get_name(auto_func) == "synced_fn"
    assert pushbacks == []
    assert needs_canonical == []


def test_perform_function_sync_no_matches(service, loaded_binary):
    func_map = FunctionMapping(
        function_map={}, inverse_function_map={}, name_map={}
    )

    result, pushbacks, needs_canonical = service._perform_function_sync(func_map)

    assert result.success is True
    assert result.data.matched_function_count == 0
    assert result.data.total_function_count >= 1


def test_perform_function_sync_counts_missing_symbol_names(service, auto_func):
    func_map = FunctionMapping(
        function_map={},
        inverse_function_map={},
        name_map={str(auto_func): ""},
    )

    result, pushbacks, needs_canonical = service._perform_function_sync(func_map)

    assert result.success is True
    assert result.data.missing_symbol_name_count >= 1
    assert result.data.matched_function_count == 0
    assert ida_name.get_name(auto_func) != ""
    assert pushbacks == []
    assert needs_canonical == []


def test_perform_function_sync_classifies_invalid_name(service, auto_func):
    func_map = FunctionMapping(
        function_map={"7": auto_func},
        inverse_function_map={},
        name_map={str(auto_func): "bad::name!!"},
    )

    result, pushbacks, needs_canonical = service._perform_function_sync(func_map)

    assert (auto_func, 7, "bad::name!!") in needs_canonical
    assert pushbacks == []


def test_perform_function_sync_dedupes_duplicate_name(service, two_funcs):
    ea_a, ea_b = two_funcs
    assert ida_name.set_name(ea_a, "dupname", ida_name.SN_CHECK | ida_name.SN_AUTO)

    func_map = FunctionMapping(
        function_map={"9": ea_b},
        inverse_function_map={},
        name_map={str(ea_b): "dupname"},
    )

    result, pushbacks, needs_canonical = service._perform_function_sync(func_map)

    assert result.data.deduped_name_count >= 1
    assert ida_name.get_name(ea_b) == "dupname_1"
    assert [(p.function_id, p.new_name) for p in pushbacks] == [(9, "dupname_1")]
    assert needs_canonical == []


def test_apply_canonical_names_applies_and_collects_pushback(service, auto_func):
    service.rename_service.canonicalize_names.return_value = {"bad::name!!": "cleanname"}
    pushbacks = []

    count = service._apply_canonical_names([(auto_func, 7, "bad::name!!")], pushbacks)

    assert count == 1
    assert ida_name.get_name(auto_func) == "cleanname"
    assert [(p.function_id, p.new_name) for p in pushbacks] == [(7, "cleanname")]
