import threading
from unittest.mock import MagicMock

import pytest
from revengai import ApiException
from revengai.models.create_metadata import CreateMetadata
from revengai.models.get_analysis_logs_output_body import GetAnalysisLogsOutputBody
from revengai.models.operation_create_metadata_create_result import (
    OperationCreateMetadataCreateResult,
)

from reai_toolkit.app.services.analysis_status import analysis_status as svc_mod
from reai_toolkit.app.services.analysis_status.analysis_status import (
    AnalysisStatusService,
)

ANALYSIS_ID = 4242
BINARY_ID = 77


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(svc_mod.time, "sleep", lambda *_: None)


@pytest.fixture
def netstore():
    return MagicMock()


@pytest.fixture
def service(netstore):
    return AnalysisStatusService(netstore_service=netstore, sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(AnalysisStatusService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "AnalysesCoreApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    api_inst.v3_get_analysis_logs.return_value = GetAnalysisLogsOutputBody.model_construct(
        entries=[]
    )
    return api_inst


def _operation(status: str):
    return OperationCreateMetadataCreateResult(
        done=status in ("Complete", "Error"),
        name=f"operations/analyses/{ANALYSIS_ID}",
        metadata=CreateMetadata(
            analysis_id=ANALYSIS_ID, binary_id=BINARY_ID, status=status
        ),
    )


def _operation_without_metadata():
    return OperationCreateMetadataCreateResult(
        done=False,
        name=f"operations/analyses/{ANALYSIS_ID}",
        metadata=None,
    )


def _poll(service):
    cb = MagicMock()
    service._thread_callback = cb
    service._poll_analysis_status(threading.Event(), ANALYSIS_ID)
    return cb


def test_complete_status_reports_analysis_id(service, sdk, netstore):
    sdk.v3_get_analysis_operation.return_value = _operation("Complete")

    cb = _poll(service)

    cb.assert_called_once()
    result = cb.call_args[0][0]
    assert result.success is True
    assert result.data == ANALYSIS_ID
    netstore.put_analysis_status.assert_called_with("Complete")


def test_status_is_read_from_operation_metadata(service, sdk):
    sdk.v3_get_analysis_operation.return_value = _operation("Complete")

    _poll(service)

    sdk.v3_get_analysis_operation.assert_called_with(analysis_id=ANALYSIS_ID)


def test_error_status_reports_failure(service, sdk):
    sdk.v3_get_analysis_operation.return_value = _operation("Error")

    cb = _poll(service)

    result = cb.call_args[0][0]
    assert result.success is False
    assert "failed" in result.error_message.lower()


def test_status_request_failure_surfaces_error(service, sdk):
    sdk.v3_get_analysis_operation.side_effect = ApiException(status=500, reason="boom")

    cb = _poll(service)

    result = cb.call_args[0][0]
    assert result.success is False
    sdk.v3_get_analysis_logs.assert_not_called()


def test_in_progress_status_keeps_polling_until_complete(service, sdk, netstore):
    sdk.v3_get_analysis_operation.side_effect = [
        _operation("Processing"),
        _operation("Complete"),
    ]

    cb = _poll(service)

    assert sdk.v3_get_analysis_operation.call_count == 2
    assert cb.call_args[0][0].success is True
    assert [call.args[0] for call in netstore.put_analysis_status.call_args_list] == [
        "Processing",
        "Complete",
    ]


def test_missing_metadata_keeps_polling_without_recording_status(service, sdk, netstore):
    sdk.v3_get_analysis_operation.side_effect = [
        _operation_without_metadata(),
        _operation("Complete"),
    ]

    cb = _poll(service)

    assert sdk.v3_get_analysis_operation.call_count == 2
    assert cb.call_args[0][0].success is True
    netstore.put_analysis_status.assert_called_once_with("Complete")
