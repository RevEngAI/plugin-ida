from unittest.mock import MagicMock

import pytest

import ida_hexrays
import idaapi
import idc

from reai_toolkit.app.services.variable_sync.variable_sync_service import (
    _read_decompiler_function,
)

pytestmark = pytest.mark.idalib


@pytest.fixture
def deci():
    fake = MagicMock()
    fake.decompiler_available = ida_hexrays.init_hexrays_plugin()
    fake.art_lifter.lower_addr.side_effect = lambda addr: addr
    fake.art_lifter.lift.side_effect = lambda func: func
    return fake


def test_read_function_headless(loaded_binary, deci):
    ea = idc.get_name_ea_simple("sub_401020")
    assert ea != idaapi.BADADDR

    func = _read_decompiler_function(deci, ea)

    assert func is not None
    assert func.header is not None
    assert func.header.name == "sub_401020"
    if deci.decompiler_available:
        assert func.dec_obj is not None


def test_read_function_missing_returns_none(loaded_binary, deci):
    assert _read_decompiler_function(deci, 0x1) is None


def test_read_function_without_decompiler(loaded_binary, deci):
    deci.decompiler_available = False
    ea = idc.get_name_ea_simple("sub_401020")

    func = _read_decompiler_function(deci, ea)

    assert func is not None
    assert func.header is not None
