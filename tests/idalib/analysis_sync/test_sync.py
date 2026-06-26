from unittest.mock import MagicMock

import pytest

import ida_name
import idaapi
import idc
from revengai.models.function_mapping import FunctionMapping

from reai_toolkit.app.services.analysis_sync.analysis_sync import AnalysisSyncService

pytestmark = pytest.mark.idalib


@pytest.fixture
def service():
    return AnalysisSyncService(
        data_types_service=MagicMock(),
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


def test_perform_function_sync_renames_matched_functions(service, auto_func):
    func_map = FunctionMapping(
        function_map={},
        inverse_function_map={},
        name_map={str(auto_func): "synced_fn"},
    )

    result = service._perform_function_sync(func_map)

    assert result.success is True
    assert result.data.matched_function_count >= 1
    assert ida_name.get_name(auto_func) == "synced_fn"


def test_perform_function_sync_no_matches(service, loaded_binary):
    func_map = FunctionMapping(
        function_map={}, inverse_function_map={}, name_map={}
    )

    result = service._perform_function_sync(func_map)

    assert result.success is True
    assert result.data.matched_function_count == 0
    assert result.data.total_function_count >= 1
