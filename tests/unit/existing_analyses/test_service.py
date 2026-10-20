from unittest.mock import MagicMock

import pytest
from revengai import ApiException
from revengai.models.analysis_record_body import AnalysisRecordBody

from reai_toolkit.app.services.existing_analyses import (
    existing_analyses_service as svc_mod,
)
from reai_toolkit.app.services.existing_analyses.existing_analyses_service import (
    ExistingAnalysesService,
)


@pytest.fixture
def service():
    return ExistingAnalysesService(netstore_service=MagicMock(), sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(ExistingAnalysesService, "yield_api_client")
    mocker.patch.object(svc_mod, "sha256_file", return_value="deadbeef")
    api_class = mocker.patch.object(svc_mod, "AnalysesCoreApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    return api_inst


def _record(analysis_id: int) -> AnalysisRecordBody:
    return AnalysisRecordBody.model_construct(
        analysis_id=analysis_id, status="Complete"
    )


def test_returns_records_and_passes_expected_filters(service, sdk):
    records = [_record(1), _record(2)]
    sdk.v3_list_analyses.return_value = MagicMock(results=records)

    result = service.fetch_analyses_same_hash("/path/to/binary.elf")

    assert result.success is True
    assert result.data == records
    kwargs = sdk.v3_list_analyses.call_args.kwargs
    assert kwargs["sha256_hash"] == "deadbeef"
    assert kwargs["analysis_scope"] == ["PRIVATE"]
    assert kwargs["status"] == ["Complete"]
    assert kwargs["order_by"] == "created"
    assert kwargs["order"] == "DESC"


def test_empty_page_returns_empty_list(service, sdk):
    sdk.v3_list_analyses.return_value = MagicMock(results=None)

    result = service.fetch_analyses_same_hash("/path/to/binary.elf")

    assert result.success is True
    assert result.data == []


def test_api_failure_is_passed_through(service, sdk):
    sdk.v3_list_analyses.side_effect = ApiException(status=500, reason="boom")

    result = service.fetch_analyses_same_hash("/path/to/binary.elf")

    assert result.success is False
    assert result.data is None
