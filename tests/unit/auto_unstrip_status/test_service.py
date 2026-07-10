import threading
from unittest.mock import MagicMock

import pytest
from revengai import ApiException
from revengai.models.auto_unstrip_status_output_body import (
    AutoUnstripStatusOutputBody,
)

from reai_toolkit.app.services.auto_unstrip_status import (
    auto_unstrip_status as svc_mod,
)
from reai_toolkit.app.services.auto_unstrip_status.auto_unstrip_status import (
    AutoUnstripStatusService,
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
    return AutoUnstripStatusService(netstore_service=netstore, sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(AutoUnstripStatusService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "AnalysesCoreApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    return api_inst


def _status(value):
    return AutoUnstripStatusOutputBody.model_construct(status=value)


def _poll(service, resync_if_already_complete=True):
    cb = MagicMock()
    service._thread_callback = cb
    service._poll_auto_unstrip_status(
        threading.Event(), ANALYSIS_ID, resync_if_already_complete
    )
    return cb


def test_completed_requests_resync(service, sdk):
    sdk.v3_get_analysis_auto_unstrip_status.return_value = _status("COMPLETED")

    cb = _poll(service, resync_if_already_complete=True)

    cb.assert_called_once()
    result = cb.call_args[0][0]
    assert result.success is True
    assert result.data == ANALYSIS_ID


def test_already_complete_skips_resync_when_attaching(service, sdk):
    sdk.v3_get_analysis_auto_unstrip_status.return_value = _status("COMPLETED")

    cb = _poll(service, resync_if_already_complete=False)

    cb.assert_not_called()


def test_failed_status_reports_failure(service, sdk):
    sdk.v3_get_analysis_auto_unstrip_status.return_value = _status("FAILED")

    cb = _poll(service)

    result = cb.call_args[0][0]
    assert result.success is False


def test_running_keeps_polling_until_completed(service, sdk):
    sdk.v3_get_analysis_auto_unstrip_status.side_effect = [
        _status("RUNNING"),
        _status("COMPLETED"),
    ]

    cb = _poll(service, resync_if_already_complete=False)

    assert sdk.v3_get_analysis_auto_unstrip_status.call_count == 2
    result = cb.call_args[0][0]
    assert result.success is True
    assert result.data == ANALYSIS_ID


def test_status_request_failure_surfaces_error(service, sdk):
    sdk.v3_get_analysis_auto_unstrip_status.side_effect = ApiException(
        status=500, reason="boom"
    )

    cb = _poll(service)

    result = cb.call_args[0][0]
    assert result.success is False
