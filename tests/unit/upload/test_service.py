from unittest.mock import MagicMock

import pytest
from revengai.models.upload_file_type import UploadFileType

from reai_toolkit.app.services.upload import upload_service as svc_mod
from reai_toolkit.app.services.upload.upload_service import UploadService


@pytest.fixture
def service():
    return UploadService(netstore_service=MagicMock(), sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(UploadService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "AnalysesCoreApi")
    api_inst = MagicMock()
    api_inst.upload_file.return_value = "parsed-upload-response"
    api_class.return_value = api_inst
    return api_inst


def test_upload_file_passes_tuple_to_sdk(service, sdk):
    result = service._upload_file_req(
        upload_file_type=UploadFileType.BINARY,
        file=("binary.elf", b"\x7fELF\x02\x01"),
        force_overwrite=True,
    )

    sdk.upload_file.assert_called_once_with(
        upload_file_type=UploadFileType.BINARY,
        force_overwrite=True,
        packed_password=None,
        file=("binary.elf", b"\x7fELF\x02\x01"),
    )
    assert result == "parsed-upload-response"


def test_upload_file_forwards_packed_password(service, sdk):
    service._upload_file_req(
        upload_file_type=UploadFileType.BINARY,
        file=("x", b""),
        packed_password="hunter2",
    )

    assert sdk.upload_file.call_args.kwargs["packed_password"] == "hunter2"


def test_upload_file_defaults_force_overwrite_false(service, sdk):
    service._upload_file_req(
        upload_file_type=UploadFileType.BINARY,
        file=("x", b""),
    )

    assert sdk.upload_file.call_args.kwargs["force_overwrite"] is False
