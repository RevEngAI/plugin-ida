from revengai import AutoUnstripRequest, AutoUnstripResponse


def test_auto_unstrip_request_has_apply():
    assert "apply" in AutoUnstripRequest.model_fields


def test_auto_unstrip_response_has_progress_and_status():
    assert {"progress", "status"} <= set(AutoUnstripResponse.model_fields)
