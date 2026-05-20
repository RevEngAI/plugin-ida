import threading
import time
from unittest.mock import MagicMock

import pytest
from revengai import ApiException
from revengai.models.task_status import TaskStatus
from revengai.models.tokenised_data import TokenisedData
from revengai.models.workflow_progress import WorkflowProgress

from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.services.ai_decomp import ai_decomp_service as svc_mod
from reai_toolkit.app.services.ai_decomp.ai_decomp_service import AiDecompService


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch):
    monkeypatch.setattr(svc_mod, "POLL_INTERVAL_SECONDS", 0.01)


@pytest.fixture
def netstore():
    netstore = MagicMock()
    fm = MagicMock()
    fm.inverse_function_map = {"4096": 42}
    netstore.get_function_mapping.return_value = fm
    return netstore


@pytest.fixture
def service(netstore):
    return AiDecompService(netstore_service=netstore, sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    # yield_api_client would build a real revengai ApiClient from the MagicMock
    # config; stub it so only the API surface below is exercised.
    mocker.patch.object(svc_mod.AiDecompService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "FunctionsAIDecompilationApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    return api_inst


def _wp(status, messages=None) -> WorkflowProgress:
    return WorkflowProgress.model_construct(
        status=status if isinstance(status, str) else status.value,
        step="x",
        step_index=0,
        steps_total=1,
        messages=messages or [],
    )


def _td(text: str = "code", name: str | None = "func") -> TokenisedData:
    return TokenisedData.model_construct(
        status="success",
        tokenised_decompilation=text,
        predicted_function_name=name,
        function_mapping=None,
    )


def _wait(thread: threading.Thread | None, timeout: float = 5.0) -> None:
    if thread is None:
        return
    thread.join(timeout=timeout)
    assert not thread.is_alive(), "worker thread did not exit"


def test_happy_path_uninitialised_running_completed(service, sdk):
    sdk.create_ai_decompilation.return_value = MagicMock(status=True)
    sdk.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.UNINITIALISED),
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]
    sdk.get_ai_decompilation_tokenised.return_value = _td("code-body", "guessed_name")

    cb = MagicMock()
    service.start_ai_decomp_task(ea=4096, thread_callback=cb)
    _wait(service._worker_thread)

    cb.assert_called_once()
    result = cb.call_args[0][0]
    assert result.success is True
    assert result.data.tokenised_decompilation == "code-body"
    assert result.data.predicted_function_name == "guessed_name"
    sdk.get_ai_decompilation_tokenised.assert_called_once_with(function_id=42)
    assert service._decomp_cache[42] is result.data


def test_409_on_create_keeps_polling(service, sdk):
    sdk.create_ai_decompilation.side_effect = ApiException(status=409)
    sdk.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]
    sdk.get_ai_decompilation_tokenised.return_value = _td()

    cb = MagicMock()
    service.start_ai_decomp_task(ea=4096, thread_callback=cb)
    _wait(service._worker_thread)

    cb.assert_called_once()
    assert cb.call_args[0][0].success is True
    sdk.get_ai_decompilation_tokenised.assert_called_once()


def test_failed_status_surfaces_message(service, sdk):
    sdk.create_ai_decompilation.return_value = MagicMock(status=True)
    msg = MagicMock()
    msg.text = "model exploded"
    sdk.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.FAILED, messages=[msg]),
    ]

    cb = MagicMock()
    service.start_ai_decomp_task(ea=4096, thread_callback=cb)
    _wait(service._worker_thread)

    result = cb.call_args[0][0]
    assert result.success is False
    assert "model exploded" in result.error_message
    sdk.get_ai_decompilation_tokenised.assert_not_called()


def test_uninitialised_loop_bounded_by_max_requeues(service, sdk):
    sdk.create_ai_decompilation.return_value = MagicMock(status=True)
    sdk.get_ai_decompilation_status.return_value = _wp(TaskStatus.UNINITIALISED)

    cb = MagicMock()
    service.start_ai_decomp_task(ea=4096, thread_callback=cb)
    _wait(service._worker_thread)

    result = cb.call_args[0][0]
    assert result.success is False
    assert "uninitialised" in result.error_message.lower()
    assert sdk.create_ai_decompilation.call_count == 1 + svc_mod.MAX_REQUEUE_ATTEMPTS


def test_safe_callback_suppresses_when_stop_set(service):
    cb = MagicMock()
    service._thread_callback = cb
    evt = threading.Event()
    evt.set()
    service._safe_callback(evt, GenericApiReturn(success=True))
    cb.assert_not_called()


def test_safe_callback_fires_when_stop_not_set(service):
    cb = MagicMock()
    service._thread_callback = cb
    evt = threading.Event()
    service._safe_callback(evt, GenericApiReturn(success=True))
    cb.assert_called_once()


def test_unknown_function_id_returns_empty_success(service, sdk, netstore):
    netstore.get_function_mapping.return_value.inverse_function_map = {}

    cb = MagicMock()
    service.start_ai_decomp_task(ea=4096, thread_callback=cb)
    _wait(service._worker_thread)

    cb.assert_called_once()
    assert cb.call_args[0][0].success is True
    assert cb.call_args[0][0].data is None
    sdk.create_ai_decompilation.assert_not_called()


def test_second_run_serves_from_cache_without_calling_sdk(service, sdk):
    sdk.create_ai_decompilation.return_value = MagicMock(status=True)
    sdk.get_ai_decompilation_status.return_value = _wp(TaskStatus.COMPLETED)
    sdk.get_ai_decompilation_tokenised.return_value = _td("body", "myfunc")

    cb1 = MagicMock()
    service.start_ai_decomp_task(ea=4096, thread_callback=cb1)
    _wait(service._worker_thread)
    first = cb1.call_args[0][0].data

    cb2 = MagicMock()
    service.start_ai_decomp_task(ea=4096, thread_callback=cb2)
    _wait(service._worker_thread)
    second = cb2.call_args[0][0].data

    assert first is second
    assert first.tokenised_decompilation == "body"
    assert sdk.create_ai_decompilation.call_count == 1
    assert sdk.get_ai_decompilation_tokenised.call_count == 1


def test_stop_mid_poll_drops_callback(service, sdk):
    """A worker stopped via stop_worker() must not fire its callback."""
    sdk.create_ai_decompilation.return_value = MagicMock(status=True)

    started = threading.Event()
    release = threading.Event()

    def stall_status(*a, **kw):
        started.set()
        release.wait(timeout=2.0)
        return _wp(TaskStatus.COMPLETED)

    sdk.get_ai_decompilation_status.side_effect = stall_status
    sdk.get_ai_decompilation_tokenised.return_value = _td()

    cb = MagicMock()
    service.start_ai_decomp_task(ea=4096, thread_callback=cb)
    assert started.wait(timeout=2.0)

    service.stop_worker()
    release.set()
    time.sleep(0.2)
    cb.assert_not_called()
