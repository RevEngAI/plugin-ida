from revengai import (
    AnalysisFunctionMatchingRequest,
    BinarySearchResult,
    CollectionSearchResult,
    FunctionMapping,
    FunctionMatch,
    FunctionMatchingFilters,
    FunctionMatchingResponse,
)
from revengai.models.function_matching_request import FunctionMatchingRequest
from revengai.models.matched_function import MatchedFunction


def test_function_match_fields():
    assert {"function_id", "matched_functions", "confidences"} <= set(
        FunctionMatch.model_fields
    )


def test_matching_response_fields():
    assert {"progress", "status", "matches", "error_message"} <= set(
        FunctionMatchingResponse.model_fields
    )


def test_matching_filters_fields():
    assert {"binary_ids", "collection_ids", "debug_types"} <= set(
        FunctionMatchingFilters.model_fields
    )


def test_analysis_matching_request_fields():
    assert {"min_similarity", "filters", "results_per_function", "page", "page_size"} <= set(
        AnalysisFunctionMatchingRequest.model_fields
    )


def test_function_matching_request_fields():
    assert {"model_id", "function_ids", "min_similarity", "results_per_function"} <= set(
        FunctionMatchingRequest.model_fields
    )


def test_matched_function_fields():
    assert {"function_id", "function_vaddr", "similarity"} <= set(
        MatchedFunction.model_fields
    )


def test_search_result_fields():
    assert {"binary_id", "binary_name", "sha_256_hash"} <= set(
        BinarySearchResult.model_fields
    )
    assert {"collection_id", "collection_name"} <= set(
        CollectionSearchResult.model_fields
    )


def test_function_mapping_fields():
    assert {"function_map", "inverse_function_map", "name_map"} <= set(
        FunctionMapping.model_fields
    )
