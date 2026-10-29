import pytest
from pydantic import ValidationError

from revengai import (
    BinarySearchResultBody,
    CollectionListItemBody,
    FunctionMapping,
    FunctionMatch,
    GetMatchesOutputBody,
    GetMatchesStatusOutputBody,
    MatchFilters,
    StartMatchingForFunctionsInputBody,
    StartMatchingOutputBody,
)
from revengai.models.matched_function import MatchedFunction

from reai_toolkit.app.core.shared_schema import TaskStatus


def test_function_match_fields():
    assert {"function_id", "matched_functions", "confidences"} <= set(
        FunctionMatch.model_fields
    )


def test_start_matching_input_fields():
    assert {"filters", "function_ids", "min_similarity", "results_per_function"} <= set(
        StartMatchingForFunctionsInputBody.model_fields
    )


def test_match_filters_fields():
    assert {"binary_ids", "collection_ids", "debug_types"} <= set(
        MatchFilters.model_fields
    )


def test_get_matches_output_fields():
    assert {"status", "matches"} <= set(GetMatchesOutputBody.model_fields)


def test_get_matches_status_output_fields():
    assert {"status", "step", "step_index", "steps_total", "messages"} <= set(
        GetMatchesStatusOutputBody.model_fields
    )


def test_start_matching_output_fields():
    assert {"status", "step", "step_index", "steps_total", "messages"} <= set(
        StartMatchingOutputBody.model_fields
    )


def test_every_task_status_the_plugin_holds_is_one_the_status_body_accepts():
    for status in TaskStatus:
        body = GetMatchesStatusOutputBody.model_validate(
            {
                "messages": [],
                "percent": 0,
                "status": status.value,
                "step": "x",
                "step_index": 0,
                "step_share": 0,
                "steps_total": 1,
            }
        )
        assert body.status == status.value


def test_the_status_body_still_rejects_a_status_the_plugin_does_not_know():
    with pytest.raises(ValidationError):
        GetMatchesStatusOutputBody.model_validate(
            {
                "messages": [],
                "percent": 0,
                "status": "HALTED",
                "step": "x",
                "step_index": 0,
                "step_share": 0,
                "steps_total": 1,
            }
        )


def test_matched_function_fields():
    assert {"function_id", "function_vaddr", "similarity"} <= set(
        MatchedFunction.model_fields
    )


def test_search_result_fields():
    assert {"binary_id", "binary_name", "sha_256_hash"} <= set(
        BinarySearchResultBody.model_fields
    )
    assert {"collection_id", "collection_name"} <= set(
        CollectionListItemBody.model_fields
    )


def test_function_mapping_fields():
    assert {"function_map", "inverse_function_map", "name_map"} <= set(
        FunctionMapping.model_fields
    )
