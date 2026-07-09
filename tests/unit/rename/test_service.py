import queue
from types import SimpleNamespace
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


def test_push_remote_names_delegates_to_remote_rename(service, ida_calls):
    _, remote = ida_calls
    renames = [RenameInput(ea=0x10, new_name="foo", function_id=1)]

    resp = service.push_remote_names(renames)

    remote.assert_called_once_with(renames)
    assert resp.status is True


def test_canonicalize_names_maps_and_chunks_at_25(service, mocker):
    mocker.patch.object(RenameService, "yield_api_client")
    api_class = mocker.patch(
        "reai_toolkit.app.services.rename.rename_service.FunctionsCoreApi"
    )
    api = MagicMock()
    api_class.return_value = api

    def _canon(canonicalize_names_input_body):
        out = MagicMock()
        out.results = [
            SimpleNamespace(name=n, canonical_name=n.upper())
            for n in canonicalize_names_input_body.names
        ]
        return out

    api.v3_canonicalize_function_names.side_effect = _canon

    names = [f"n{i}" for i in range(30)]
    mapping = service.canonicalize_names(names)

    assert api.v3_canonicalize_function_names.call_count == 2
    assert mapping["n0"] == "N0"
    assert len(mapping) == 30


def test_canonicalize_names_skips_failed_chunk(service, mocker):
    mocker.patch.object(RenameService, "yield_api_client")
    api_class = mocker.patch(
        "reai_toolkit.app.services.rename.rename_service.FunctionsCoreApi"
    )
    api = MagicMock()
    api_class.return_value = api
    api.v3_canonicalize_function_names.side_effect = RuntimeError("boom")

    mapping = service.canonicalize_names(["a", "b"])

    assert mapping == {}
