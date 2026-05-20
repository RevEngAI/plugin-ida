import os
import threading
from unittest.mock import MagicMock

import pytest

import idapro
import idautils
from revengai.models.task_status import TaskStatus
from revengai.models.tokenised_data import TokenisedData
from revengai.models.workflow_progress import WorkflowProgress

from reai_toolkit.app.services.ai_decomp import ai_decomp_service as svc_mod
from reai_toolkit.app.services.ai_decomp.ai_decomp_service import AiDecompService

pytestmark = pytest.mark.idalib

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "hello.elf")


@pytest.fixture(scope="module")
def loaded_binary():
    if not os.path.isfile(FIXTURE):
        pytest.skip(f"missing fixture {FIXTURE} (see tests/README.md to rebuild)")
    idapro.enable_console_messages(True)
    if idapro.open_database(os.path.abspath(FIXTURE), True) != 0:
        pytest.fail("idapro.open_database failed")
    try:
        yield
    finally:
        idapro.close_database(False)


def _wp(status: TaskStatus) -> WorkflowProgress:
    return WorkflowProgress.model_construct(
        status=status.value, step="x", step_index=0, steps_total=1, messages=[]
    )


def test_service_runs_to_completion_under_idalib(loaded_binary, mocker):
    ea = next(iter(idautils.Functions()), None)
    assert ea is not None, "no functions in fixture binary"

    mocker.patch.object(svc_mod.AiDecompService, "yield_api_client")
    api_inst = MagicMock()
    mocker.patch.object(
        svc_mod, "FunctionsAIDecompilationApi", return_value=api_inst
    )
    api_inst.create_ai_decompilation.return_value = MagicMock(status=True)
    api_inst.get_ai_decompilation_status.side_effect = [
        _wp(TaskStatus.RUNNING),
        _wp(TaskStatus.COMPLETED),
    ]
    api_inst.get_ai_decompilation_tokenised.return_value = TokenisedData.model_construct(
        status="success",
        tokenised_decompilation="int sub() { return 0; }",
        predicted_function_name="recovered_name",
        function_mapping=None,
    )

    netstore = MagicMock()
    netstore.get_function_mapping.return_value.inverse_function_map = {str(ea): 7}

    service = AiDecompService(netstore_service=netstore, sdk_config=MagicMock())
    mocker.patch.object(svc_mod, "POLL_INTERVAL_SECONDS", 0.01)

    cb = MagicMock()
    service.start_ai_decomp_task(ea=ea, thread_callback=cb)
    service._worker_thread.join(timeout=10.0)
    assert not service._worker_thread.is_alive(), "worker deadlocked under idalib"

    cb.assert_called_once()
    result = cb.call_args[0][0]
    assert result.success is True
    assert result.data.predicted_function_name == "recovered_name"
    api_inst.get_ai_decompilation_tokenised.assert_called_once_with(function_id=7)
