import threading
import time
from unittest.mock import MagicMock

import pytest
from revengai import ApiException
from revengai.models.comments_data import CommentsData
from revengai.models.decompilation_data import DecompilationData
from revengai.models.summary_data import SummaryData
from revengai.models.task_status import TaskStatus
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
    mocker.patch.object(svc_mod.AiDecompService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "FunctionsAIDecompilationApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    api_inst.get_ai_decompilation_summary.return_value = _summary()
    api_inst.get_ai_decompilation_inline_comments.return_value = _comments(
        status=TaskStatus.COMPLETED.value
    )
    return api_inst


def _wp(status, messages=None) -> WorkflowProgress:
    return WorkflowProgress.model_construct(
        status=status if isinstance(status, str) else status.value,
        step="x",
        step_index=0,
        steps_total=1,
        messages=messages or [],
    )


def _dd(status=TaskStatus.COMPLETED.value, code: str | None = "code") -> DecompilationData:
    return DecompilationData.model_construct(status=status, decompilation=code)


def _summary(ai="", raw="", status=TaskStatus.COMPLETED.value) -> SummaryData:
    return SummaryData.model_construct(ai_summary=ai, summary=raw, task_status=status)


def _comments(items=None, status=TaskStatus.COMPLETED.value) -> CommentsData:
    return CommentsData.model_construct(inline_comments=items or [], task_status=status)


def _wait(thread: threading.Thread | None, timeout: float = 5.0) -> None:
    if thread is None:
        return
    thread.join(timeout=timeout)
    assert not thread.is_alive(), "worker thread did not exit"


def _run(service, ea: int = 4096):
    on_decomp, on_summary, on_comments = MagicMock(), MagicMock(), MagicMock()
    service.start_ai_decomp_task(
        ea=ea,
        on_decomp=on_decomp,
        on_summary=on_summary,
        on_comments=on_comments,
    )
    _wait(service._worker_thread)
    return on_decomp, on_summary, on_comments


def test_fast_path_completed_on_first_get(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="resolved code")

    on_decomp, _, _ = _run(service)

    on_decomp.assert_called_once()
    result = on_decomp.call_args[0][0]
    assert result.success is True
    assert result.data.decompilation == "resolved code"
    sdk.get_ai_decompilation.assert_called_once_with(function_id=42)
    sdk.create_ai_decompilation.assert_not_called()
    sdk.get_ai_decompilation_status.assert_not_called()
    assert service._decomp_cache[42] is result.data


def test_uninitialised_triggers_queue_then_poll(service, sdk):
    sdk.get_ai_decompilation.side_effect = [
        _dd(status=TaskStatus.UNINITIALISED.value, code=None),
        _dd(code="ready"),
    ]
    sdk.create_ai_decompilation.return_value = MagicMock(status=True)
    sdk.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]

    on_decomp, _, _ = _run(service)

    result = on_decomp.call_args[0][0]
    assert result.success is True
    assert result.data.decompilation == "ready"
    sdk.create_ai_decompilation.assert_called_once()
    assert sdk.get_ai_decompilation.call_count == 2


def test_pending_polls_without_queuing(service, sdk):
    sdk.get_ai_decompilation.side_effect = [
        _dd(status=TaskStatus.PENDING.value, code=None),
        _dd(code="done"),
    ]
    sdk.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]

    on_decomp, _, _ = _run(service)

    assert on_decomp.call_args[0][0].success is True
    sdk.create_ai_decompilation.assert_not_called()
    sdk.get_ai_decompilation_status.assert_called()


def test_409_on_create_treated_as_already_queued(service, sdk):
    sdk.get_ai_decompilation.side_effect = [
        _dd(status=TaskStatus.UNINITIALISED.value, code=None),
        _dd(code="ready"),
    ]
    sdk.create_ai_decompilation.side_effect = ApiException(status=409)
    sdk.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]

    on_decomp, _, _ = _run(service)

    assert on_decomp.call_args[0][0].success is True


def test_failed_status_surfaces_message(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(
        status=TaskStatus.PENDING.value, code=None
    )
    msg = MagicMock()
    msg.text = "model exploded"
    sdk.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.FAILED, messages=[msg]),
    ]

    on_decomp, _, _ = _run(service)

    result = on_decomp.call_args[0][0]
    assert result.success is False
    assert "model exploded" in result.error_message


def test_uninitialised_loop_bounded_by_max_requeues(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(
        status=TaskStatus.UNINITIALISED.value, code=None
    )
    sdk.create_ai_decompilation.return_value = MagicMock(status=True)
    sdk.get_ai_decompilation_status.return_value = _wp(TaskStatus.UNINITIALISED)

    on_decomp, _, _ = _run(service)

    result = on_decomp.call_args[0][0]
    assert result.success is False
    assert "uninitialised" in result.error_message.lower()
    assert sdk.create_ai_decompilation.call_count == 1 + svc_mod.MAX_REQUEUE_ATTEMPTS


def test_unknown_function_id_returns_empty_success(service, sdk, netstore):
    netstore.get_function_mapping.return_value.inverse_function_map = {}

    on_decomp, on_summary, on_comments = _run(service)

    on_decomp.assert_called_once()
    result = on_decomp.call_args[0][0]
    assert result.success is True
    assert result.data is None
    sdk.get_ai_decompilation.assert_not_called()
    sdk.create_ai_decompilation.assert_not_called()
    on_summary.assert_not_called()
    on_comments.assert_not_called()


def test_first_get_api_exception_surfaces_error(service, sdk):
    sdk.get_ai_decompilation.side_effect = ApiException(status=500, reason="boom")

    on_decomp, _, _ = _run(service)

    result = on_decomp.call_args[0][0]
    assert result.success is False
    assert "API Exception" in result.error_message or result.error_message
    sdk.create_ai_decompilation.assert_not_called()


def test_cache_hit_skips_all_network_calls(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="first run")

    on_decomp_1, _, _ = _run(service)
    first = on_decomp_1.call_args[0][0].data

    sdk.reset_mock()
    sdk.get_ai_decompilation_summary.return_value = _summary()
    sdk.get_ai_decompilation_inline_comments.return_value = _comments()

    on_decomp_2, _, _ = _run(service)
    second = on_decomp_2.call_args[0][0].data

    assert first is second
    sdk.get_ai_decompilation.assert_not_called()
    sdk.create_ai_decompilation.assert_not_called()


def test_summary_phase_dispatches_on_completed_decomp(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="ok")
    sdk.get_ai_decompilation_summary.return_value = _summary(ai="It does X.")

    _, on_summary, _ = _run(service)

    on_summary.assert_called_once()
    assert on_summary.call_args[0][0].data.ai_summary == "It does X."


def test_comments_phase_skips_regenerate_when_completed(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="ok")
    sdk.get_ai_decompilation_inline_comments.return_value = _comments(
        status=TaskStatus.COMPLETED.value
    )

    _, _, on_comments = _run(service)

    on_comments.assert_called_once()
    sdk.regenerate_ai_decompilation_inline_comments.assert_not_called()
    sdk.get_ai_decompilation_inline_comments_status.assert_not_called()


def test_comments_phase_regenerates_when_uninitialised(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(code="ok")
    sdk.get_ai_decompilation_inline_comments.side_effect = [
        _comments(status=TaskStatus.UNINITIALISED.value),
        _comments(status=TaskStatus.COMPLETED.value),
    ]
    sdk.regenerate_ai_decompilation_inline_comments.return_value = MagicMock(status=True)
    sdk.get_ai_decompilation_inline_comments_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]

    _, _, on_comments = _run(service)

    sdk.regenerate_ai_decompilation_inline_comments.assert_called_once()
    on_comments.assert_called_once()
    assert on_comments.call_args[0][0].success is True


def test_safe_dispatch_suppresses_when_stop_set():
    cb = MagicMock()
    evt = threading.Event()
    evt.set()
    AiDecompService._safe_dispatch(evt, cb, "payload")
    cb.assert_not_called()


def test_safe_dispatch_fires_when_stop_not_set():
    cb = MagicMock()
    evt = threading.Event()
    AiDecompService._safe_dispatch(evt, cb, "payload")
    cb.assert_called_once_with("payload")


def test_safe_dispatch_no_op_when_callback_none():
    evt = threading.Event()
    AiDecompService._safe_dispatch(evt, None, "payload")


def test_stop_mid_poll_drops_callback(service, sdk):
    sdk.get_ai_decompilation.return_value = _dd(
        status=TaskStatus.PENDING.value, code=None
    )

    started = threading.Event()
    release = threading.Event()

    def stall_status(*a, **kw):
        started.set()
        release.wait(timeout=2.0)
        return _wp(TaskStatus.COMPLETED)

    sdk.get_ai_decompilation_status.side_effect = stall_status

    on_decomp = MagicMock()
    service.start_ai_decomp_task(
        ea=4096,
        on_decomp=on_decomp,
        on_summary=MagicMock(),
        on_comments=MagicMock(),
    )
    assert started.wait(timeout=2.0)

    service.stop_worker()
    release.set()
    time.sleep(0.2)
    on_decomp.assert_not_called()
