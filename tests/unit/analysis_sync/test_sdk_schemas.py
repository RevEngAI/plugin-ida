from revengai import (
    AnalysisBasicInfoOutputBody,
    FunctionsCoreApi,
    GetFunctionMapsOutputBody,
)


def test_basic_info_carries_model_and_base_address():
    assert {"model_id", "model_name", "base_address"} <= set(
        AnalysisBasicInfoOutputBody.model_fields
    )


def test_func_maps_output_is_flat():
    assert {"function_map", "inverse_function_map", "name_map"} <= set(
        GetFunctionMapsOutputBody.model_fields
    )
    assert "data" not in GetFunctionMapsOutputBody.model_fields
    assert "function_maps" not in GetFunctionMapsOutputBody.model_fields


def test_func_maps_lives_on_functions_core_api():
    assert hasattr(FunctionsCoreApi, "v3_get_analysis_func_maps")
