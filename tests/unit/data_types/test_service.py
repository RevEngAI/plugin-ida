from unittest.mock import MagicMock

import pytest
from revengai import ApiException
from revengai.exceptions import ForbiddenException, NotFoundException
from revengai.models.function_data_types_list import FunctionDataTypesList
from revengai.models.function_data_types_list_item import FunctionDataTypesListItem

from reai_toolkit.app.services.data_types import data_types_service as svc_mod
from reai_toolkit.app.services.data_types.data_types_service import (
    FUNCTION_IDS_BATCH_SIZE,
    ImportDataTypesService,
)


@pytest.fixture
def service():
    return ImportDataTypesService(netstore_service=MagicMock(), sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(ImportDataTypesService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "FunctionsDataTypesApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    return api_inst


def _item(function_id: int) -> FunctionDataTypesListItem:
    return FunctionDataTypesListItem.model_construct(
        completed=True,
        status="success",
        data_types=None,
        data_types_version=1,
        function_id=function_id,
    )


def _response(items):
    resp = MagicMock()
    resp.status = True
    resp.data = FunctionDataTypesList.model_construct(
        total_count=len(items),
        total_data_types_count=len(items),
        items=items,
    )
    return resp


def test_single_batch_when_under_threshold(service, sdk):
    ids = list(range(1, 11))
    sdk.list_function_data_types_for_functions.return_value = _response(
        [_item(i) for i in ids]
    )

    result = service._get_data_types(ids)

    assert sdk.list_function_data_types_for_functions.call_count == 1
    sdk.list_function_data_types_for_functions.assert_called_once_with(function_ids=ids)
    assert [item.function_id for item in result.items] == ids


def test_chunks_large_id_list_to_avoid_uri_too_large(service, sdk):
    total = FUNCTION_IDS_BATCH_SIZE * 2 + 15
    ids = list(range(total))
    sdk.list_function_data_types_for_functions.side_effect = lambda function_ids: _response(
        [_item(i) for i in function_ids]
    )

    result = service._get_data_types(ids)

    calls = sdk.list_function_data_types_for_functions.call_args_list
    assert len(calls) == 3
    assert [len(c.kwargs["function_ids"]) for c in calls] == [
        FUNCTION_IDS_BATCH_SIZE,
        FUNCTION_IDS_BATCH_SIZE,
        15,
    ]
    for c in calls:
        assert len(c.kwargs["function_ids"]) <= FUNCTION_IDS_BATCH_SIZE
    assert [item.function_id for item in result.items] == ids


def test_empty_list_returns_none_without_calling_sdk(service, sdk):
    assert service._get_data_types([]) is None
    sdk.list_function_data_types_for_functions.assert_not_called()


def test_skips_unsuccessful_chunks(service, sdk):
    ok = _response([_item(1), _item(2)])
    bad = MagicMock(status=False, data=None)
    sdk.list_function_data_types_for_functions.side_effect = [ok, bad, ok]

    result = service._get_data_types(
        list(range(FUNCTION_IDS_BATCH_SIZE * 2 + 1))
    )

    assert [item.function_id for item in result.items] == [1, 2, 1, 2]


def test_import_data_types_returns_none_on_success(service, sdk, mocker):
    sdk.list_function_data_types_for_functions.return_value = _response([_item(1)])
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute")

    assert service.import_data_types({1: 0x1000}) is None
    apply.assert_called_once()


def test_import_data_types_returns_none_for_empty_matches(service, sdk):
    assert service.import_data_types({}) is None
    sdk.list_function_data_types_for_functions.assert_not_called()


def test_import_data_types_returns_single_error_on_forbidden(service, sdk, mocker):
    sdk.list_function_data_types_for_functions.side_effect = ForbiddenException(
        status=403, reason="Forbidden"
    )
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute")

    matches = {fid: fid * 16 for fid in range(FUNCTION_IDS_BATCH_SIZE * 3)}
    err = service.import_data_types(matches)

    assert err is not None
    assert "403" in err
    assert "Forbidden" in err
    apply.assert_not_called()
    assert sdk.list_function_data_types_for_functions.call_count == 1


def test_import_data_types_treats_not_found_as_warning(service, sdk, mocker):
    sdk.list_function_data_types_for_functions.side_effect = NotFoundException(
        status=404, reason="Not Found"
    )
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute")

    assert service.import_data_types({1: 0x1000}) is None
    apply.assert_not_called()


def test_import_data_types_returns_error_on_unexpected_exception(service, sdk, mocker):
    sdk.list_function_data_types_for_functions.side_effect = RuntimeError("boom")
    apply = mocker.patch.object(svc_mod.ImportDataTypes, "execute")

    err = service.import_data_types({1: 0x1000})

    assert err is not None
    assert "boom" in err
    apply.assert_not_called()
