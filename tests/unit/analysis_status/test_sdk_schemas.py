import typing

from revengai import (
    AnalysisLogEntry,
    CreateMetadata,
    GetAnalysisLogsOutputBody,
    OperationCreateMetadataCreateResult,
)


def test_create_metadata_fields():
    assert {"analysis_id", "binary_id", "status"} <= set(CreateMetadata.model_fields)


def test_logs_output_carries_entries():
    assert "entries" in GetAnalysisLogsOutputBody.model_fields


def test_log_entry_fields():
    assert {"text", "level", "timestamp"} <= set(AnalysisLogEntry.model_fields)


def test_operation_fields():
    assert {"done", "error", "metadata", "name", "response"} <= set(
        OperationCreateMetadataCreateResult.model_fields
    )


def test_operation_metadata_is_optional_create_metadata():
    annotation = OperationCreateMetadataCreateResult.model_fields["metadata"].annotation
    assert set(typing.get_args(annotation)) == {CreateMetadata, type(None)}
