from unittest.mock import MagicMock

import pytest
from revengai.models.upload_file_type import UploadFileType

from reai_toolkit.app.services.upload import upload_service as svc_mod
from reai_toolkit.app.services.upload.upload_service import UploadService


@pytest.fixture
def service():
    return UploadService(netstore_service=MagicMock(), sdk_config=MagicMock())


@pytest.fixture
def api_client(mocker):
    client = MagicMock()
    client.param_serialize.return_value = ("POST", "url", {}, None, [])
    response_data = MagicMock()
    client.call_api.return_value = response_data
    client.response_deserialize.return_value = MagicMock(data="parsed-upload-response")

    ctx = mocker.patch.object(svc_mod.UploadService, "yield_api_client")
    ctx.return_value.__enter__.return_value = client
    ctx.return_value.__exit__.return_value = False
    return client


def test_upload_file_routes_file_into_files_not_form_params(service, api_client):
    result = service._upload_file_req(
        upload_file_type=UploadFileType.BINARY,
        file=("binary.elf", b"\x7fELF\x02\x01"),
        force_overwrite=True,
    )

    api_client.param_serialize.assert_called_once()
    kwargs = api_client.param_serialize.call_args.kwargs

    assert kwargs["resource_path"] == "/v2/upload"
    assert kwargs["method"] == "POST"
    assert kwargs["files"] == {"file": ("binary.elf", b"\x7fELF\x02\x01")}

    post_param_keys = [k for k, _ in kwargs["post_params"]]
    assert "file" not in post_param_keys
    assert ("upload_file_type", UploadFileType.BINARY) in kwargs["post_params"]
    assert ("force_overwrite", True) in kwargs["post_params"]

    assert kwargs["auth_settings"] == ["APIKey"]
    assert kwargs["header_params"]["Content-Type"] == "multipart/form-data"
    assert result == "parsed-upload-response"


def test_upload_file_passes_packed_password_as_query(service, api_client):
    service._upload_file_req(
        upload_file_type=UploadFileType.BINARY,
        file=("x", b""),
        packed_password="hunter2",
    )

    kwargs = api_client.param_serialize.call_args.kwargs
    assert ("packed_password", "hunter2") in kwargs["query_params"]


def test_upload_file_omits_packed_password_when_none(service, api_client):
    service._upload_file_req(
        upload_file_type=UploadFileType.BINARY,
        file=("x", b""),
        packed_password=None,
    )

    kwargs = api_client.param_serialize.call_args.kwargs
    assert kwargs["query_params"] == []
