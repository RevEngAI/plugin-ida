import inspect

from revengai import AnalysesCoreApi
from revengai.models.analysis_record_body import AnalysisRecordBody
from revengai.models.list_analyses_output_body import ListAnalysesOutputBody


def test_analysis_record_body_fields():
    assert {"analysis_id", "status", "base_address", "sha_256_hash"} <= set(
        AnalysisRecordBody.model_fields
    )


def test_list_analyses_output_is_flat():
    assert {"results", "page_size", "next_page_token"} <= set(
        ListAnalysesOutputBody.model_fields
    )
    assert "data" not in ListAnalysesOutputBody.model_fields


def test_v3_list_analyses_accepts_expected_filters():
    params = inspect.signature(AnalysesCoreApi.v3_list_analyses).parameters
    assert {"analysis_scope", "status", "sha256_hash", "order_by", "order"} <= set(params)
    assert "workspace" not in params
