from revengai import AutoUnstripStatusOutputBody


def test_auto_unstrip_status_output_body_fields():
    assert "status" in AutoUnstripStatusOutputBody.model_fields
