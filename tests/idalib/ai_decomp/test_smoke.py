import time
from unittest.mock import MagicMock

import pytest

import idautils
from revengai.models.comments_data import CommentsData
from revengai.models.decompilation_data import DecompilationData
from revengai.models.summary_data import SummaryData
from revengai.models.task_status import TaskStatus

from reai_toolkit.app.services.ai_decomp import ai_decomp_service as svc_mod
from reai_toolkit.app.services.ai_decomp.ai_decomp_service import AiDecompService

pytestmark = pytest.mark.idalib


def test_service_runs_to_completion_under_idalib(loaded_binary, mocker):
    ea = next(iter(idautils.Functions()), None)
    assert ea is not None, "no functions in fixture binary"

    mocker.patch.object(svc_mod.AiDecompService, "yield_api_client")
    api_inst = MagicMock()
    mocker.patch.object(svc_mod, "FunctionsAIDecompilationApi", return_value=api_inst)
    api_inst.get_ai_decompilation.return_value = DecompilationData.model_construct(
        status=TaskStatus.COMPLETED.value, decompilation="int sub() { return 0; }"
    )
    api_inst.get_ai_decompilation_summary.return_value = SummaryData.model_construct(
        ai_summary="recovered summary", summary="", task_status=TaskStatus.COMPLETED.value
    )
    api_inst.get_ai_decompilation_inline_comments.return_value = (
        CommentsData.model_construct(
            inline_comments=[], task_status=TaskStatus.COMPLETED.value
        )
    )

    netstore = MagicMock()
    netstore.get_function_mapping.return_value.inverse_function_map = {str(ea): 7}

    service = AiDecompService(netstore_service=netstore, sdk_config=MagicMock())
    mocker.patch.object(svc_mod, "POLL_INTERVAL_SECONDS", 0.01)

    on_decomp, on_summary, on_comments = MagicMock(), MagicMock(), MagicMock()
    service.start_ai_decomp_task(
        ea=ea, on_decomp=on_decomp, on_summary=on_summary, on_comments=on_comments
    )
    deadline = time.monotonic() + 10.0
    while service.is_worker_running() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not service.is_worker_running(), "worker deadlocked under idalib"

    on_decomp.assert_called_once()
    result = on_decomp.call_args[0][0]
    assert result.success is True
    assert result.data.decompilation == "int sub() { return 0; }"
    api_inst.get_ai_decompilation.assert_called_once_with(function_id=7)
