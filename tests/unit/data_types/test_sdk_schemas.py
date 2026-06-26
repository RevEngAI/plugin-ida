"""Schema-shape assertions for the data-types models the plugin imports.

These guard the names/fields exercised by
reai_toolkit.app.transformations.import_data_types — the surface that broke on
the 3.93 -> 3.96 SDK bump (FunctionInfoOutput -> FunctionInfo).
"""

from revengai import (
    Argument,
    Enumeration,
    FunctionDataTypesList,
    FunctionDataTypesListItem,
    FunctionHeader,
    FunctionInfo,
    FunctionInfoFuncDepsInner,
    FunctionType,
    Structure,
    TypeDefinition,
)


def test_function_info_has_func_types_and_deps():
    assert {"func_types", "func_deps"} <= set(FunctionInfo.model_fields)


def test_function_type_fields():
    assert {"addr", "size", "header", "name", "type"} <= set(FunctionType.model_fields)


def test_func_deps_inner_exposes_actual_instance():
    assert "actual_instance" in FunctionInfoFuncDepsInner.model_fields


def test_dependency_models_expose_name_and_type():
    assert {"name", "size", "members"} <= set(Structure.model_fields)
    assert {"name", "members"} <= set(Enumeration.model_fields)
    assert {"name", "type"} <= set(TypeDefinition.model_fields)


def test_function_header_and_argument_fields():
    assert {"name", "type", "args"} <= set(FunctionHeader.model_fields)
    assert {"offset", "name", "type"} <= set(Argument.model_fields)


def test_data_types_list_item_fields():
    assert {"completed", "status", "data_types", "function_id"} <= set(
        FunctionDataTypesListItem.model_fields
    )
    assert "items" in FunctionDataTypesList.model_fields
