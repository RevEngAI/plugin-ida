import queue
from unittest.mock import MagicMock

import pytest
from revengai import BaseResponse
from revengai.models.function_mapping import FunctionMapping

from reai_toolkit.app.services.rename.rename_service import RenameService
from reai_toolkit.app.services.rename.schema import RenameInput


@pytest.fixture
def netstore():
    return MagicMock()


@pytest.fixture
def service(netstore):
    svc = RenameService(netstore_service=netstore, sdk_config=MagicMock())
    RenameService._rename_q = queue.Queue()
    RenameService._rename_last_ts = {}
    return svc


@pytest.fixture
def ida_calls(mocker):
    update = mocker.patch.object(RenameService, "update_function_name", return_value=True)
    remote = mocker.patch.object(
        RenameService,
        "_rename_remote_function",
        return_value=BaseResponse.model_construct(status=True),
    )
    return update, remote


def _mapping(function_map, inverse):
    return FunctionMapping.model_construct(
        function_map=function_map, inverse_function_map=inverse, name_map={}
    )


def test_function_id_to_vaddr_resolves_and_misses(service, netstore):
    netstore.get_function_mapping.return_value = _mapping({"1": 0x401000}, {})

    assert service.function_id_to_vaddr(1) == 0x401000
    assert service.function_id_to_vaddr(2) is None


def test_function_id_to_vaddr_no_mapping(service, netstore):
    netstore.get_function_mapping.return_value = None
    assert service.function_id_to_vaddr(1) is None


def test_rename_function_local_and_remote_success(service, ida_calls):
    update, remote = ida_calls

    errors = service._rename_function(
        [RenameInput(ea=0x10, new_name="foo", function_id=1)]
    )

    assert errors == 0
    update.assert_called_once()
    sent = remote.call_args[0][0]
    assert [r.function_id for r in sent] == [1]


def test_rename_function_counts_local_failure_and_skips_remote(service, ida_calls):
    update, remote = ida_calls
    update.return_value = False

    errors = service._rename_function(
        [RenameInput(ea=0x10, new_name="foo", function_id=1)]
    )

    assert errors == 1
    remote.assert_not_called()


def test_rename_function_counts_remote_failure(service, ida_calls):
    _, remote = ida_calls
    remote.return_value = BaseResponse.model_construct(status=False)

    errors = service._rename_function(
        [RenameInput(ea=0x10, new_name="foo", function_id=1)]
    )

    assert errors == 1


def test_rename_function_resolves_missing_function_id_from_mapping(
    service, ida_calls, netstore
):
    _, remote = ida_calls
    netstore.get_function_mapping.return_value = _mapping({}, {"16": 99})

    errors = service._rename_function([RenameInput(ea=0x10, new_name="foo")])

    assert errors == 0
    sent = remote.call_args[0][0]
    assert [r.function_id for r in sent] == [99]


def test_enqueue_rename_debounces_rapid_duplicates(service, mocker):
    mocker.patch.object(service, "_start_rename_worker_if_needed")

    service.enqueue_rename([RenameInput(ea=0x10, new_name="a")])
    service.enqueue_rename([RenameInput(ea=0x10, new_name="b")])

    first = service._rename_q.get_nowait()
    second = service._rename_q.get_nowait()
    assert [r.new_name for r in first] == ["a"]
    assert second == []
