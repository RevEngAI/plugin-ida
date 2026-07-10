"""
Schema-shape assertions: fail loudly when the revengai SDK shape drifts.
"""

from revengai.models.ai_decomp_function_mapping import AIDecompFunctionMapping
from revengai.models.comments_data import CommentsData
from revengai.models.create_ai_decomp_output_body import CreateAIDecompOutputBody
from revengai.models.inline_comment import InlineComment
from revengai.models.patch_comment_body import PatchCommentBody
from revengai.models.replacement_value import ReplacementValue
from revengai.models.task_status import TaskStatus
from revengai.models.tokenised_data import TokenisedData
from revengai.models.upsert_overrides_data import UpsertOverridesData
from revengai.models.upsert_overrides_input_body import UpsertOverridesInputBody
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


def test_upsert_overrides_input_body_round_trips():
    body = UpsertOverridesInputBody.from_json('{"overrides": {"@@V@@": "buf", "@@T@@": ""}}')
    assert body.overrides == {"@@V@@": "buf", "@@T@@": ""}
    assert "overrides" in UpsertOverridesInputBody.model_fields


def test_upsert_overrides_data_exposes_merged_map():
    data = UpsertOverridesData.from_json('{"user_override_mappings": {"@@V@@": "buf"}}')
    assert data.user_override_mappings == {"@@V@@": "buf"}


def test_patch_comment_body_round_trips():
    body = PatchCommentBody.from_json('{"comment": "note", "line": 7}')
    assert body.comment == "note"
    assert body.line == 7
    assert {"comment", "line"} <= set(PatchCommentBody.model_fields.keys())


def test_inline_comment_and_comments_data_shapes():
    assert {"comment", "line"} <= set(InlineComment.model_fields.keys())
    assert {"inline_comments", "task_status"} <= set(CommentsData.model_fields.keys())


def test_replacement_value_carries_value():
    assert ReplacementValue.from_json('{"value": "count"}').value == "count"


def test_function_mapping_has_variable_and_type_categories():
    fields = set(AIDecompFunctionMapping.model_fields.keys())
    assert {
        "unmatched_vars",
        "unmatched_global_vars",
        "unmatched_external_vars",
        "unmatched_custom_types",
        "unmatched_enums",
        "user_override_mappings",
    } <= fields
