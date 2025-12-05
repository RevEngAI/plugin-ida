from typing import cast

import libbs.artifacts
from libbs.api import DecompilerInterface
from libbs.decompilers.ida.compat import execute_ui
from loguru import logger
from revengai import (
    Argument,
    Enumeration,
    FunctionDataTypesList,
    FunctionHeader,
    FunctionInfoInputFuncDepsInner,
    FunctionInfoOutput,
    FunctionTypeOutput,
    Structure,
    TypeDefinition,
)


class TaggedDependency:
    def __init__(self, dependency: Structure | Enumeration | TypeDefinition) -> None:
        self.dependency: Structure | Enumeration | TypeDefinition = dependency
        self.processed: bool = False
        self.name: str = self.dependency.name

    def __repr__(self) -> str:
        return self.dependency.__repr__()


class ImportDataTypes:
    def __init__(self) -> None:
        self.deci: DecompilerInterface

    @execute_ui
    def execute(self, functions: FunctionDataTypesList) -> None:
        self.deci = DecompilerInterface.discover(force_decompiler="ida") # type: ignore
        lookup: dict[str, TaggedDependency] = {}

        for function in functions.items:
            data_types: FunctionInfoOutput | None = function.data_types

            if data_types is None:
                continue
            
            logger.debug(f"importing data types for {function.function_id}")

            # Track processed dependencies to prevent duplicate imports.
            # Without this:
            # - Shared dependencies get re-processed, breaking references (shows as invalid ordinals in IDA)
            # - Cannot resolve subdependencies (e.g. struct fields that reference other imported types)
            for dep in data_types.func_deps:
                if dep.actual_instance is None:
                    continue

                if dep.actual_instance.name not in lookup:
                    lookup.update({dep.actual_instance.name: TaggedDependency(dep.actual_instance)}) # type: ignore

            dependency: FunctionInfoInputFuncDepsInner
            for dependency in data_types.func_deps:
                if dependency.actual_instance is None:
                    continue

                tagged_dependency: TaggedDependency | None = lookup.get(dependency.actual_instance.name)
                if tagged_dependency:
                    self.process_dependency(tagged_dependency, lookup)

            func: FunctionTypeOutput | None = data_types.func_types
            if func:
                self.update_function(func)


    def process_dependency(
        self, tagged_dependency: TaggedDependency, lookup: dict[str, TaggedDependency]
    ) -> None:
        if tagged_dependency.processed:
            return
        
        dependency: Structure | Enumeration | TypeDefinition = tagged_dependency.dependency
        match dependency:
            case Structure():
                self.update_struct(cast(Structure, dependency), lookup)
            case Enumeration():
                self.update_enum(cast(Enumeration, dependency))
            case TypeDefinition():
                self.update_typedef(cast(TypeDefinition, dependency), lookup)
            case _:
                logger.warning(f"unsupported dependency type: {dependency}")

        tagged_dependency.processed = True

    def update_struct(self, imported_struct: Structure, lookup: dict[str, TaggedDependency]) -> None:
        if imported_struct.size is None:
            return
        
        for member in imported_struct.members.values():
            subdependency: TaggedDependency | None = lookup.get(member.type)
            if subdependency:
                self.process_dependency(subdependency, lookup)
            member.type = self.normalise_type(member.type)

        self.deci.structs[imported_struct.name] = libbs.artifacts.Struct(
            name=imported_struct.name, size=imported_struct.size, members={v.offset: v for v in imported_struct.members.values()} # type: ignore
        )

    def update_enum(self, imported_enum: Enumeration) -> None:
        self.deci.enums[imported_enum.name] = libbs.artifacts.Enum(name=imported_enum.name, members=imported_enum.members)

    def update_typedef(self, imported_typedef: TypeDefinition, lookup: dict[str, TaggedDependency]) -> None:
        subdependency: TaggedDependency | None = lookup.get(imported_typedef.type)
        if subdependency:
            self.process_dependency(subdependency, lookup)

        normalized_type: str = self.normalise_type(imported_typedef.type)
        self.deci.typedefs[imported_typedef.name] = libbs.artifacts.Typedef(
            name=imported_typedef.name, type_=normalized_type
        )

    def update_function(self, func: FunctionTypeOutput) -> None:
        base_address: int = self.deci.binary_base_addr
        rva: int = func.addr - base_address

        target_func: libbs.artifacts.Function | None = self.deci.functions.get(rva) # type: ignore
        if target_func is None:
            return

        target_func.name = func.name
        target_func.size = func.size
        target_func.type = func.type

        # Check the target function has a header.
        if target_func.header:
            self.update_header(func.header, target_func)

        self.deci.functions[rva] = target_func

    def update_header(
        self, imported_header: FunctionHeader, target_function: libbs.artifacts.Function
    ) -> None:
        if target_function.header is None:
            return
        
        target_function.header.name = imported_header.name
        target_function.header.type = self.normalise_type(imported_header.type)
        self.update_function_arguments(imported_header.args, target_function)

    def update_function_arguments(
        self, imported_args: dict[str, Argument], target_function: libbs.artifacts.Function
    ) -> None:
        if target_function.header is None:
            return

        for arg in imported_args.values():
            arg.type = self.normalise_type(arg.type)

        target_function.header.args = {v.offset: v for v in imported_args.values()}

    @staticmethod
    def normalise_type(type: str) -> str:
        # TODO: PLU-214 There are inconsistencies with how types are presented, sometimes with a namespace and sometimes without.
        # Need to investigate further as we need to retain namespace information otherwise potential for symbols clashing.
        split_type: list[str] = type.split("::")
        normalized: str = split_type[-1]

        # TODO: PLU-213 Add IDA typedefs for Ghidra primitives so we don't need to bother doing this...
        if normalized == "uchar":
            normalized = "unsigned char"
        elif normalized == "qword":
            normalized = "unsigned __int64"
        elif normalized == "sqword":
            normalized = "__int64"

        return normalized
