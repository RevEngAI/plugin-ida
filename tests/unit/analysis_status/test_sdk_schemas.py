from revengai import (
    AnalysisLogEntry,
    BaseResponseStatus,
    GetAnalysisLogsOutputBody,
    StatusOutput,
)


def test_status_output_fields():
    assert {"analysis_id", "analysis_status"} <= set(StatusOutput.model_fields)


def test_logs_output_carries_entries():
    assert "entries" in GetAnalysisLogsOutputBody.model_fields


def test_log_entry_fields():
    assert {"text", "level", "timestamp"} <= set(AnalysisLogEntry.model_fields)


def test_base_response_status_envelope():
    assert {"status", "data", "errors"} <= set(BaseResponseStatus.model_fields)
