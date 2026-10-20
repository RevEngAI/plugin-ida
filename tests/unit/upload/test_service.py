from unittest.mock import MagicMock

import pytest
from revengai import GetConfigOutputBody, UploadOutputBody
from revengai.models.function_boundary import FunctionBoundary
from revengai.models.symbols import Symbols
from revengai.models.tag import Tag
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
    api_class.return_value = api_inst
    return api_inst


@pytest.fixture
def binaries(mocker):
    mocker.patch.object(UploadService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "BinariesApi")
    api_inst = MagicMock()
    api_inst.v3_upload_file.return_value = "parsed-upload-response"
    api_class.return_value = api_inst
    return api_inst


@pytest.fixture
def config(mocker):
    mocker.patch.object(UploadService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "ConfigApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    return api_inst


@pytest.fixture
def symbols():
    return Symbols(
        base_address=0,
        function_boundaries=[
            FunctionBoundary(mangled_name="main", start_address=0, end_address=16)
        ],
    )


def test_upload_file_passes_tuple_to_v3_sdk(service, binaries):
    result = service._upload_file_req(
        upload_file_type=UploadFileType.BINARY,
        file=("binary.elf", b"\x7fELF\x02\x01"),
        force_overwrite=True,
    )

    binaries.v3_upload_file.assert_called_once_with(
        upload_file_type="BINARY",
        force_overwrite=True,
        file=("binary.elf", b"\x7fELF\x02\x01"),
    )
    assert result == "parsed-upload-response"


def test_upload_file_sends_plain_string_file_type(service, binaries):
    service._upload_file_req(
        upload_file_type=UploadFileType.DEBUG,
        file=("x", b""),
    )

    sent = binaries.v3_upload_file.call_args.kwargs["upload_file_type"]
    assert sent == "DEBUG"
    assert type(sent) is str


def test_upload_file_defaults_force_overwrite_false(service, binaries):
    service._upload_file_req(
        upload_file_type=UploadFileType.BINARY,
        file=("x", b""),
    )

    assert binaries.v3_upload_file.call_args.kwargs["force_overwrite"] is False


def test_upload_user_file_returns_flat_v3_body(service, binaries, mocker, tmp_path):
    mocker.patch.object(UploadService, "_get_max_upload_size", return_value=1024)
    binaries.v3_upload_file.return_value = UploadOutputBody(
        analysis_requirements=[],
        can_extract=False,
        can_sandbox=False,
        file_type="BINARY",
        filename="binary.elf",
        is_archive=False,
        mime="application/x-executable",
        sha_256_hash="deadbeef",
    )
    target = tmp_path / "binary.elf"
    target.write_bytes(b"\x7fELF")

    response = service.upload_user_file(
        str(target),
        upload_file_type=UploadFileType.BINARY,
        force_overwrite=True,
    )

    assert response.success
    assert response.data.sha_256_hash == "deadbeef"
    assert response.data.file_type == "BINARY"
    assert not hasattr(response.data, "data")


@pytest.mark.parametrize(
    "tags, expected",
    [
        (["malware", "linux", "trojan"], ["malware", "linux", "trojan"]),
        (["solo"], ["solo"]),
        ([], []),
        (None, []),
    ],
)
def test_analyse_converts_tags_to_tag_models(service, sdk, symbols, tags, expected):
    service.analyse(
        file_name="binary.elf",
        binary_sha256="deadbeef",
        symbols=symbols,
        tags=tags,
    )

    request = sdk.create_analysis.call_args.kwargs["analysis_create_request"]
    assert request.tags == [Tag(name=name) for name in expected]


@pytest.mark.parametrize("no_cache", [True, False])
def test_analyse_sets_no_cache_on_analysis_config(service, sdk, symbols, no_cache):
    service.analyse(
        file_name="binary.elf",
        binary_sha256="deadbeef",
        symbols=symbols,
        no_cache=no_cache,
    )

    request = sdk.create_analysis.call_args.kwargs["analysis_create_request"]
    assert request.analysis_config.no_cache is no_cache


def test_analyse_defaults_no_cache_false(service, sdk, symbols):
    service.analyse(
        file_name="binary.elf",
        binary_sha256="deadbeef",
        symbols=symbols,
    )

    request = sdk.create_analysis.call_args.kwargs["analysis_create_request"]
    assert request.analysis_config.no_cache is False


def test_max_upload_size_reads_flat_v3_config(service, config):
    config.v3_get_config.return_value = GetConfigOutputBody(
        ai_decompiler_unsupported_languages=[],
        max_file_size_bytes=42 * 1024 * 1024,
    )

    assert service._get_max_upload_size() == 42 * 1024 * 1024
    config.v3_get_config.assert_called_once_with()


def test_max_upload_size_falls_back_to_default(service, config):
    config.v3_get_config.return_value = GetConfigOutputBody(
        ai_decompiler_unsupported_languages=[],
        max_file_size_bytes=0,
    )

    assert service._get_max_upload_size() == svc_mod.MAX_DEFAULT_FILE_SIZE_BYTES
