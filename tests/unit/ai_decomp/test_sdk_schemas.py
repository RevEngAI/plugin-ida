"""
Schema-shape assertions: fail loudly when the revengai SDK shape drifts.
"""

from revengai.models.create_ai_decomp_output_body import CreateAIDecompOutputBody
from revengai.models.task_status import TaskStatus
from revengai.models.tokenised_data import TokenisedData
from revengai.models.workflow_progress import WorkflowProgress


def test_workflow_progress_has_expected_fields():
    fields = set(WorkflowProgress.model_fields.keys())
    assert {"status", "step", "step_index", "steps_total", "messages"} <= fields


def test_tokenised_data_has_expected_fields():
    fields = set(TokenisedData.model_fields.keys())
    assert {
        "status",
        "tokenised_decompilation",
        "predicted_function_name",
        "function_mapping",
    } <= fields


def test_create_output_body_has_status():
    assert "status" in CreateAIDecompOutputBody.model_fields


def test_task_status_enum_covers_state_machine():
    members = set(TaskStatus.__members__)
    assert {"UNINITIALISED", "PENDING", "RUNNING", "COMPLETED", "FAILED"} <= members


def test_workflow_progress_accepts_uppercase_status_values():
    for status in ("UNINITIALISED", "PENDING", "RUNNING", "COMPLETED", "FAILED"):
        WorkflowProgress.model_construct(
            status=status, step="x", step_index=0, steps_total=1, messages=[]
        )
