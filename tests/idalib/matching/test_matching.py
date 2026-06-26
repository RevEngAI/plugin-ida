import threading
from unittest.mock import MagicMock

import pytest

import idaapi
import idc
from revengai.models.function_mapping import FunctionMapping

from reai_toolkit.app.services.matching.matching_service import MatchingService
from reai_toolkit.app.services.matching.schema import ValidFunction

pytestmark = pytest.mark.idalib


@pytest.fixture
def add_ea(loaded_binary):
    ea = idc.get_name_ea_simple("add")
    assert ea != idaapi.BADADDR
    return ea


@pytest.fixture
def service(add_ea):
    netstore = MagicMock()
    netstore.get_function_mapping.return_value = FunctionMapping(
        function_map={"42": add_ea},
        inverse_function_map={str(add_ea): 42},
        name_map={},
    )
    return MatchingService(netstore_service=netstore, sdk_config=MagicMock())


def test_demangle_passthrough(service):
    assert service.demangle("main") == "main"


def test_function_id_to_local_name_resolves(service):
    assert service.function_id_to_local_name(42) == "add"


def test_function_id_to_local_name_unknown_returns_none(service):
    assert service.function_id_to_local_name(999) is None


def test_fetch_valid_functions_collects_mapped_functions(service, add_ea):
    collected = []
    service._thread_callback = collected.append

    service._fetch_valid_functions(threading.Event())

    assert len(collected) == 1
    funcs = collected[0]
    assert any(
        isinstance(f, ValidFunction)
        and f.function_id == 42
        and f.vaddr == add_ea
        for f in funcs
    )
