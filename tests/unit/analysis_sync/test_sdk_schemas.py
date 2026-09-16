from revengai import (
    AnalysisBasicInfoOutputBody,
    BaseResponseAnalysisFunctionMapping,
    FunctionMapping,
)
from revengai.models.analysis_function_mapping import AnalysisFunctionMapping


def test_basic_info_carries_model_and_base_address():
    assert {"model_id", "model_name", "base_address"} <= set(
        AnalysisBasicInfoOutputBody.model_fields
    )


def test_function_mapping_envelope_carries_function_maps():
    assert {"status", "data"} <= set(BaseResponseAnalysisFunctionMapping.model_fields)
    assert "function_maps" in AnalysisFunctionMapping.model_fields


def test_function_mapping_fields():
    assert {"function_map", "inverse_function_map", "name_map"} <= set(
        FunctionMapping.model_fields
    )
