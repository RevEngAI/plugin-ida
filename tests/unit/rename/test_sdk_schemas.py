from revengai import (
    BaseResponse,
    FunctionRenameMap,
    FunctionsListRename,
)


def test_function_rename_map_fields():
    assert {"function_id", "new_name", "new_mangled_name"} <= set(
        FunctionRenameMap.model_fields
    )


def test_functions_list_rename_wraps_functions():
    assert "functions" in FunctionsListRename.model_fields


def test_base_response_envelope():
    assert {"status", "data"} <= set(BaseResponse.model_fields)
