import threading
from unittest.mock import MagicMock

import pytest
from revengai import ApiException
from revengai.models.logs import Logs
from revengai.models.status_output import StatusOutput

from reai_toolkit.app.services.analysis_status import analysis_status as svc_mod
from reai_toolkit.app.services.analysis_status.analysis_status import (
    AnalysisStatusService,
)

ANALYSIS_ID = 4242


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
    api_inst.get_analysis_logs.return_value = MagicMock(data=Logs.model_construct(logs=""))
    return api_inst


def _status(value: str):
    return MagicMock(
        data=StatusOutput.model_construct(analysis_id=ANALYSIS_ID, analysis_status=value)
    )


def _poll(service):
    cb = MagicMock()
    service._thread_callback = cb
    service._poll_analysis_status(threading.Event(), ANALYSIS_ID)
    return cb


def test_complete_status_reports_analysis_id(service, sdk, netstore):
    sdk.get_analysis_status.return_value = _status("Complete")

    cb = _poll(service)

    cb.assert_called_once()
    result = cb.call_args[0][0]
    assert result.success is True
    assert result.data == ANALYSIS_ID
    netstore.put_analysis_status.assert_called_with("Complete")


def test_error_status_reports_failure(service, sdk):
    sdk.get_analysis_status.return_value = _status("Error")

    cb = _poll(service)

    result = cb.call_args[0][0]
    assert result.success is False
    assert "failed" in result.error_message.lower()


def test_status_request_failure_surfaces_error(service, sdk):
    sdk.get_analysis_status.side_effect = ApiException(status=500, reason="boom")

    cb = _poll(service)

    result = cb.call_args[0][0]
    assert result.success is False
    sdk.get_analysis_logs.assert_not_called()


def test_in_progress_status_keeps_polling_until_complete(service, sdk):
    sdk.get_analysis_status.side_effect = [_status("Processing"), _status("Complete")]

    cb = _poll(service)

    assert sdk.get_analysis_status.call_count == 2
    assert cb.call_args[0][0].success is True
