from typing import cast

import libbs.artifacts
from libbs.api import DecompilerInterface
from libbs.decompilers.ida.compat import execute_ui
from loguru import logger
from revengai import (
    Argument,
    Enumeration,
    FunctionDataTypesList,
    FunctionDataTypesListItem,
    FunctionHeader,
    FunctionInfoInputFuncDepsInner,
    FunctionInfoOutput,
    FunctionTypeOutput,
    GlobalVariable,
    StackVariable,
    Structure,
    TypeDefinition,
)


class TaggedDependency:
    def __init__(self, dependency: Structure | Enumeration | TypeDefinition | GlobalVariable):
        self.dependency: Structure | Enumeration | TypeDefinition | GlobalVariable = dependency
        self.processed: bool = False
        self.name: str = self.dependency.name

    def __repr__(self):
        return self.dependency.__repr__()


class ImportDataTypes:
    def __init__(self):
        self.deci: DecompilerInterface

    @execute_ui
    def execute(self, functions: FunctionDataTypesList):
        # TODO: PLU-192 do we even need a class here? Could arguably pass the decompiler around
        self.deci = DecompilerInterface.discover(force_decompiler="ida")

        # TODO: PLU-192 If we already have debug symbols, do we want to skip this? I think we should!
        function: FunctionDataTypesListItem

        lookup: dict[str, TaggedDependency] = {}
        for function in functions.items:
            # Skip if data types are still being extracted.
            if function.completed is False:
                logger.warning(
                    f"extracting data types for {function.function_id} is still in progress..."
                )
                continue

            data_types = function.data_types
            if data_types is None:
                continue

            # Build the lookup, this will allow us to check if we have processed a dependency before and stop us clobbering existing types and breaking xrefs.
            for dependency in data_types.func_deps:
                lookup[dependency.actual_instance.name] = TaggedDependency(
                    dependency.actual_instance
                )

        logger.debug("processing function dependencies")
        for function in functions.items:
            data_types: FunctionInfoOutput = function.data_types

            # No additional type information to import so we can skip.
            if data_types is None:
                continue

            # Enumerate function dependencies and check we have imported the associated type information.
            dependency: FunctionInfoInputFuncDepsInner
            for dependency in data_types.func_deps:
                tagged_dependency = lookup.get(dependency.actual_instance.name)
                self.process_dependency(tagged_dependency, lookup)

        logger.debug(f"processing {len(functions.items)} functions")
        for function in functions.items:
            data_types: FunctionInfoOutput = function.data_types

            if data_types:
                func: FunctionTypeOutput | None = data_types.func_types
                if func:
                    self.update_function(func)

    def process_dependency(
        self, tagged_dependency: TaggedDependency, lookup: dict[str, TaggedDependency]
    ) -> None:
        if tagged_dependency.processed:
            return

        dependency = tagged_dependency.dependency
        match dependency:
            case Structure():
                self.update_struct(cast(Structure, dependency), lookup)
            case Enumeration():
                self.update_enum(cast(Enumeration, dependency))
            case TypeDefinition():
                self.update_typedef(cast(TypeDefinition, dependency), lookup)
            case GlobalVariable():
                self.update_global_var(cast(GlobalVariable, dependency), lookup)
            case _:
                logger.warning(f"unrecognised dependency type: {dependency}")

        tagged_dependency.processed = True

    def update_struct(self, imported_struct: Structure, lookup: dict[str, TaggedDependency]) -> None:
        for member in imported_struct.members.values():
            subdependency = lookup.get(member.type)
            if subdependency:
                self.process_dependency(subdependency, lookup)
            member.type = self.normalise_type(member.type)

        self.deci.structs[imported_struct.name] = libbs.artifacts.Struct(
            name=imported_struct.name, size=imported_struct.size, members={v.offset: v for v in imported_struct.members.values()}
        )

    def update_enum(self, imported_enum: Enumeration) -> None:
        self.deci.enums[imported_enum.name] = libbs.artifacts.Enum(name=imported_enum.name, members=imported_enum.members)

    def update_typedef(self, imported_typedef: TypeDefinition, lookup: dict[str, TaggedDependency]) -> None:
        subdependency = lookup.get(imported_typedef.type)
        if subdependency:
            self.process_dependency(subdependency, lookup)

        normalized_type: str = self.normalise_type(imported_typedef.type)
        self.deci.typedefs[imported_typedef.name] = libbs.artifacts.Typedef(
            name=imported_typedef.name, type_=normalized_type
        )

    def update_global_var(self, imported_global_var: GlobalVariable, lookup: dict[str, TaggedDependency]) -> None:
        subdependency = lookup.get(imported_global_var.type)
        if subdependency:
            self.process_dependency(subdependency, lookup)

        normalized_type = self.normalise_type(imported_global_var.type)
        self.deci.global_vars[imported_global_var.addr] = libbs.artifacts.GlobalVariable(
            addr=imported_global_var.addr, name=imported_global_var.name, type_=normalized_type, size=imported_global_var.size
        )

    def update_function(self, func: FunctionTypeOutput) -> None:
        base_address: int = self.deci.binary_base_addr
        rva: int = func.addr - base_address

        target_func: libbs.artifacts.Function | None = self.deci.functions.get(rva)
        if target_func is None:
            return

        target_func.name = func.name
        target_func.size = func.size
        target_func.type = func.type

        # Check if we extracted stack variable data and import if so.
        if func.stack_vars:
            self.update_stack_variables(func.stack_vars, target_func)

        # Check the target function has a header.
        if target_func.header:
            self.update_header(func.header, target_func)

        self.deci.functions[rva] = target_func

    def update_stack_variables(
        self,
        imported_stack_variables: dict[str, StackVariable],
        target_function: libbs.artifacts.Function,
    ) -> None:
        # TODO: PLU-192 What do we want to do if a stack variable does not exist at the specified offset?
        stack_var: StackVariable
        for stack_var in imported_stack_variables.values():
            target_stack_var: libbs.artifacts.StackVariable | None = target_function.stack_vars.get(
                stack_var.offset
            )

            if target_stack_var is None:
                continue

            target_stack_var.name = stack_var.name
            target_stack_var.type = self.normalise_type(stack_var.type)
            target_stack_var.size = stack_var.size

    def update_header(
        self, imported_header: FunctionHeader, target_function: libbs.artifacts.Function
    ) -> None:
        target_function.header.name = imported_header.name
        target_function.header.type = self.normalise_type(imported_header.type)
        self.update_function_arguments(imported_header.args, target_function)

    def update_function_arguments(
        self, imported_args: dict[str, Argument], target_function: libbs.artifacts.Function
    ) -> None:
        for arg in imported_args.values():
            arg.type = self.normalise_type(arg.type)

        target_function.header.args = {v.offset: v for v in imported_args.values()}

    @staticmethod
    def normalise_type(type: str) -> str:
        # TODO: Do we need namespace information here? Observing discrepancies where sometimes namespace is used, and other times it isn't.
        # I think we will have problems with C++ demangled symbol names using this approach. Needs investigating...
        split_type: list[str] = type.split("::")
        normalized: str = split_type[-1]

        # It would appear this is a Ghidra-ism and IDA is unaware of this type.
        # TODO: Auto add Ghidra typedef for primitives so we don't need to bother doing this...
        if normalized == "uchar":
            normalized = "unsigned char"
        elif normalized == "qword":
            normalized = "unsigned __int64"
        elif normalized == "sqword":
            normalized = "__int64"

        return normalized
