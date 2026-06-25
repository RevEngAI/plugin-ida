from revengai import BaseResponseStatus, Logs, StatusOutput


def test_status_output_fields():
    assert {"analysis_id", "analysis_status"} <= set(StatusOutput.model_fields)


def test_logs_field():
    assert "logs" in Logs.model_fields


def test_base_response_status_envelope():
    assert {"status", "data", "errors"} <= set(BaseResponseStatus.model_fields)
