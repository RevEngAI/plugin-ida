from revengai import (
    BatchRenameInputBody,
    BatchRenameItem,
    BatchRenameOutputBody,
)


def test_batch_rename_item_fields():
    assert {"function_id", "new_name", "new_mangled_name"} <= set(
        BatchRenameItem.model_fields
    )


def test_batch_rename_input_body_wraps_functions():
    assert "functions" in BatchRenameInputBody.model_fields


def test_batch_rename_output_reports_renamed_count():
    assert "renamed_count" in BatchRenameOutputBody.model_fields
