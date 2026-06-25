from revengai.models import (
    AppApiRestV2AnalysesEnumsOrderBy,
    Order,
    StatusInput,
    Workspace,
)
from revengai.models.analysis_record import AnalysisRecord


def test_analysis_record_fields():
    assert {"analysis_id", "status", "base_address", "sha_256_hash"} <= set(
        AnalysisRecord.model_fields
    )


def test_list_analyses_enums_have_expected_members():
    assert "PERSONAL" in Workspace.__members__
    assert "COMPLETE" in StatusInput.__members__
    assert "DESC" in Order.__members__
    assert "CREATED" in AppApiRestV2AnalysesEnumsOrderBy.__members__
