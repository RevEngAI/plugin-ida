import inspect

from revengai import BinariesApi, UploadOutputBody


def test_upload_output_body_is_flat():
    assert {
        "sha_256_hash",
        "file_type",
        "filename",
        "mime",
        "is_archive",
        "can_sandbox",
        "can_extract",
        "analysis_requirements",
    } <= set(UploadOutputBody.model_fields)
    assert "data" not in UploadOutputBody.model_fields


def test_upload_lives_on_binaries_api():
    assert hasattr(BinariesApi, "v3_upload_file")


def test_v3_upload_file_has_no_packed_password():
    params = inspect.signature(BinariesApi.v3_upload_file).parameters
    assert {"file", "upload_file_type", "force_overwrite"} <= set(params)
    assert "packed_password" not in params
