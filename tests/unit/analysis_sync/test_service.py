from unittest.mock import MagicMock

import pytest
from revengai.models.function_mapping import FunctionMapping

from reai_toolkit.app.services.analysis_sync.analysis_sync import AnalysisSyncService
from reai_toolkit.app.services.analysis_sync.schema import MatchedFunctionSummary
from reai_toolkit.app.core.shared_schema import GenericApiReturn


@pytest.fixture
def netstore():
    ns = MagicMock()
    ns.get_analysis_id.return_value = 1234
    return ns


@pytest.fixture
def data_types_service():
    dts = MagicMock()
    dts.import_data_types.return_value = None
    return dts


@pytest.fixture
def service(netstore, data_types_service):
    return AnalysisSyncService(
        data_types_service=data_types_service,
        netstore_service=netstore,
        sdk_config=MagicMock(),
    )


def _summary() -> MatchedFunctionSummary:
    return MatchedFunctionSummary(
        matched_function_count=2, unmatched_function_count=1, total_function_count=3
    )


def _func_map() -> FunctionMapping:
    return FunctionMapping.model_construct(
        function_map={"1": 0x1000}, inverse_function_map={"4096": 1}, name_map={}
    )


def test_sync_success_imports_data_types_and_dispatches(service, data_types_service, mocker):
    mocker.patch.object(
        service,
        "_match_functions",
        return_value=GenericApiReturn(success=True, data=_summary()),
    )
    cb = MagicMock()

    service._sync_analysis_data(MagicMock(), _func_map(), cb)

    data_types_service.import_data_types.assert_called_once_with({1: 0x1000})
    cb.assert_called_once()
    result = cb.call_args[0][0]
    assert result.success is True
    assert result.data.data_types_error is None


def test_sync_propagates_data_types_error(service, data_types_service, mocker):
    data_types_service.import_data_types.return_value = "403: forbidden"
    mocker.patch.object(
        service,
        "_match_functions",
        return_value=GenericApiReturn(success=True, data=_summary()),
    )
    cb = MagicMock()

    service._sync_analysis_data(MagicMock(), _func_map(), cb)

    assert cb.call_args[0][0].data.data_types_error == "403: forbidden"


def test_sync_failure_skips_data_types_import(service, data_types_service, mocker):
    mocker.patch.object(
        service,
        "_match_functions",
        return_value=GenericApiReturn(success=False, error_message="boom"),
    )
    cb = MagicMock()

    service._sync_analysis_data(MagicMock(), _func_map(), cb)

    data_types_service.import_data_types.assert_not_called()
    assert cb.call_args[0][0].success is False


def test_match_functions_wraps_exception_as_failure(service, mocker):
    mocker.patch.object(
        service, "_perform_function_sync", side_effect=RuntimeError("kaboom")
    )

    result = service._match_functions(_func_map())

    assert result.success is False
    assert "kaboom" in result.error_message


def test_get_function_matches_invokes_callback_with_map(service, mocker):
    mocker.patch.object(service, "_fetch_model_id", return_value=7)
    func_map = _func_map()
    mocker.patch.object(service, "_fetch_function_map", return_value=func_map)
    cb = MagicMock()

    service.get_function_matches(cb)

    cb.assert_called_once_with(func_map)


def test_get_function_matches_aborts_when_model_id_fails(service, mocker):
    mocker.patch.object(service, "_fetch_model_id", side_effect=RuntimeError("nope"))
    fetch_map = mocker.patch.object(service, "_fetch_function_map")
    cb = MagicMock()

    service.get_function_matches(cb)

    fetch_map.assert_not_called()
    cb.assert_not_called()
