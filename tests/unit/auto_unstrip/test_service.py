import threading
from unittest.mock import MagicMock

import pytest
from revengai import ApiException
from revengai.models.auto_unstrip_response import AutoUnstripResponse

from reai_toolkit.app.services.auto_unstrip import auto_unstrip_service as svc_mod
from reai_toolkit.app.services.auto_unstrip.auto_unstrip_service import AutoUnstripService

ANALYSIS_ID = 99


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(svc_mod.time, "sleep", lambda *_: None)


@pytest.fixture
def netstore():
    ns = MagicMock()
    ns.get_analysis_id.return_value = ANALYSIS_ID
    return ns


@pytest.fixture
def service(netstore):
    return AutoUnstripService(netstore_service=netstore, sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(AutoUnstripService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "FunctionsCoreApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    return api_inst


def _resp(progress: int) -> AutoUnstripResponse:
    return AutoUnstripResponse.model_construct(progress=progress, status="success")


def _poll(service):
    cb = MagicMock()
    service._thread_callback = cb
    service._poll_unstrip_status(threading.Event())
    return cb


def test_missing_analysis_id_does_not_call_back(service, sdk, netstore):
    netstore.get_analysis_id.return_value = None

    cb = _poll(service)

    cb.assert_not_called()
    sdk.auto_unstrip.assert_not_called()


def test_progress_complete_dispatches_result(service, sdk):
    sdk.auto_unstrip.return_value = _resp(100)

    cb = _poll(service)

    cb.assert_called_once()
    result = cb.call_args[0][0]
    assert result.success is True
    assert result.data.progress == 100
    assert sdk.auto_unstrip.call_args.kwargs["analysis_id"] == ANALYSIS_ID
    assert sdk.auto_unstrip.call_args.kwargs["auto_unstrip_request"].apply is True


def test_polls_until_complete(service, sdk):
    sdk.auto_unstrip.side_effect = [_resp(40), _resp(100)]

    cb = _poll(service)

    assert sdk.auto_unstrip.call_count == 2
    assert cb.call_args[0][0].data.progress == 100


def test_request_failure_surfaces_error(service, sdk):
    sdk.auto_unstrip.side_effect = ApiException(status=500, reason="boom")

    cb = _poll(service)

    cb.assert_called_once()
    assert cb.call_args[0][0].success is False
