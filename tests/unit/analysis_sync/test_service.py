from unittest.mock import MagicMock

import pytest
from revengai.models.function_mapping import FunctionMapping

from reai_toolkit.app.services.analysis_sync.analysis_sync import AnalysisSyncService
from reai_toolkit.app.services.analysis_sync.schema import MatchedFunctionSummary
from reai_toolkit.app.services.data_types.data_types_service import DataTypesImportResult
from reai_toolkit.app.services.rename.schema import RenameInput
from reai_toolkit.app.core.shared_schema import GenericApiReturn


@pytest.fixture
def netstore():
    ns = MagicMock()
    ns.get_analysis_id.return_value = 1234
    return ns


@pytest.fixture
def data_types_service():
    dts = MagicMock()
    dts.import_data_types.return_value = DataTypesImportResult()
    return dts


@pytest.fixture
def rename_service():
    rs = MagicMock()
    rs.canonicalize_names.return_value = {}
    rs.push_remote_names.return_value = MagicMock(status=True)
    return rs


@pytest.fixture
def variable_sync_service():
    vs = MagicMock()
    vs.push_local_function_types_batch.return_value = 0
    return vs


@pytest.fixture
def service(netstore, data_types_service, rename_service, variable_sync_service):
    return AnalysisSyncService(
        data_types_service=data_types_service,
        rename_service=rename_service,
        variable_sync_service=variable_sync_service,
        netstore_service=netstore,
        sdk_config=MagicMock(),
    )


def _summary() -> MatchedFunctionSummary:
    return MatchedFunctionSummary(
        matched_function_count=2, unmatched_function_count=1, total_function_count=3
    )


def _func_map() -> FunctionMapping:
    return FunctionMapping.model_construct(
        function_map={"1": 0x1000}, inverse_function_map={"4096": 1}, name_map={"4096": "fn"}
    )


def _matched(name_pushbacks=None, needs_canonical=None):
    return (
        GenericApiReturn(success=True, data=_summary()),
        name_pushbacks or [],
        needs_canonical or [],
    )


def test_sync_success_imports_data_types_and_dispatches(service, data_types_service, mocker):
    mocker.patch.object(service, "_match_functions", return_value=_matched())
    cb = MagicMock()

    service._sync_analysis_data(MagicMock(), _func_map(), cb)

    data_types_service.import_data_types.assert_called_once_with({1: 0x1000})
    cb.assert_called_once()
    result = cb.call_args[0][0]
    assert result.success is True
    assert result.data.data_types_error is None


def test_sync_propagates_data_types_error(service, data_types_service, mocker):
    data_types_service.import_data_types.return_value = DataTypesImportResult(
        error="403: forbidden"
    )
    mocker.patch.object(service, "_match_functions", return_value=_matched())
    cb = MagicMock()

    service._sync_analysis_data(MagicMock(), _func_map(), cb)

    assert cb.call_args[0][0].data.data_types_error == "403: forbidden"


def test_sync_failure_skips_data_types_import(service, data_types_service, mocker):
    mocker.patch.object(
        service,
        "_match_functions",
        return_value=(GenericApiReturn(success=False, error_message="boom"), [], []),
    )
    cb = MagicMock()

    service._sync_analysis_data(MagicMock(), _func_map(), cb)

    data_types_service.import_data_types.assert_not_called()
    assert cb.call_args[0][0].success is False


def test_match_functions_wraps_exception_as_failure(service, mocker):
    mocker.patch.object(
        service, "_perform_function_sync", side_effect=RuntimeError("kaboom")
    )

    result, pushbacks, needs_canonical = service._match_functions(_func_map())

    assert result.success is False
    assert "kaboom" in result.error_message
    assert pushbacks == []
    assert needs_canonical == []


def test_sync_pushes_deduped_names(service, rename_service, mocker):
    pushbacks = [RenameInput(ea=0x1000, new_name="fn_1", function_id=1)]
    mocker.patch.object(
        service, "_match_functions", return_value=_matched(name_pushbacks=pushbacks)
    )
    cb = MagicMock()

    service._sync_analysis_data(MagicMock(), _func_map(), cb)

    rename_service.push_remote_names.assert_called_once_with(pushbacks)
    assert cb.call_args[0][0].data.pushed_name_count == 1


def test_sync_canonicalizes_invalid_names(service, rename_service, mocker):
    needs = [(0x1000, 1, "bad::name")]
    mocker.patch.object(
        service, "_match_functions", return_value=_matched(needs_canonical=needs)
    )
    mocker.patch.object(service, "apply_deduped_name", return_value="badname")
    mocker.patch.object(service, "tag_function_as_renamed")
    rename_service.canonicalize_names.return_value = {"bad::name": "badname"}
    cb = MagicMock()

    service._sync_analysis_data(MagicMock(), _func_map(), cb)

    rename_service.canonicalize_names.assert_called_once_with(["bad::name"])
    pushed = rename_service.push_remote_names.call_args[0][0]
    assert [r.new_name for r in pushed] == ["badname"]
    assert cb.call_args[0][0].data.canonicalized_name_count == 1


def test_sync_pushes_local_types_for_absent_and_failed(
    service, data_types_service, variable_sync_service, mocker
):
    data_types_service.import_data_types.return_value = DataTypesImportResult(
        remote_absent_ids={1}, apply_failed_ids=set()
    )
    mocker.patch.object(service, "_match_functions", return_value=_matched())
    cb = MagicMock()

    service._sync_analysis_data(MagicMock(), _func_map(), cb)

    variable_sync_service.push_local_function_types_batch.assert_called_once()
    targets, analysis_id = variable_sync_service.push_local_function_types_batch.call_args[0]
    assert targets == {1: 0x1000}
    assert analysis_id == 1234
    assert cb.call_args[0][0].data.pushed_type_count == 0


def test_sync_skips_type_pushback_for_deselected_functions(
    service, data_types_service, variable_sync_service, mocker
):
    func_map = FunctionMapping.model_construct(
        function_map={"1": 0x1000}, inverse_function_map={"4096": 1}, name_map={}
    )
    data_types_service.import_data_types.return_value = DataTypesImportResult(
        remote_absent_ids={1}
    )
    mocker.patch.object(service, "_match_functions", return_value=_matched())
    cb = MagicMock()

    service._sync_analysis_data(MagicMock(), func_map, cb)

    variable_sync_service.push_local_function_types_batch.assert_not_called()


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
