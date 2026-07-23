from revengai import (
    BinarySearchResult,
    CollectionListItemBody,
    FunctionMapping,
    FunctionMatch,
    GetMatchesOutputBody,
    GetMatchesStatusOutputBody,
    MatchFilters,
    StartMatchingForFunctionsInputBody,
    StartMatchingOutputBody,
    TaskStatus,
)
from revengai.models.matched_function import MatchedFunction


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


def test_task_status_values():
    assert {"UNINITIALISED", "PENDING", "RUNNING", "COMPLETED", "FAILED"} <= {
        s.value for s in TaskStatus
    }


def test_matched_function_fields():
    assert {"function_id", "function_vaddr", "similarity"} <= set(
        MatchedFunction.model_fields
    )


def test_search_result_fields():
    assert {"binary_id", "binary_name", "sha_256_hash"} <= set(
        BinarySearchResult.model_fields
    )
    assert {"collection_id", "collection_name"} <= set(
        CollectionListItemBody.model_fields
    )


def test_function_mapping_fields():
    assert {"function_map", "inverse_function_map", "name_map"} <= set(
        FunctionMapping.model_fields
    )
