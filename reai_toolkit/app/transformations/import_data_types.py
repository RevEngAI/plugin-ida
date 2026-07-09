from typing import cast

import libbs.artifacts
from libbs.api import DecompilerInterface
from libbs.decompilers.ida.compat import execute_ui, convert_type_str_to_ida_type
from loguru import logger
from revengai import (
    FunctionArgument,
    Enumeration,
    FunctionDataTypesList,
    FunctionHeader,
    V2FunctionInfoFuncDepsInner,
    FunctionInfo,
    FunctionType,
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
    def execute(self, functions: FunctionDataTypesList, matched_function_mapping: dict[int, int] = {}) -> set[int]:
        self.deci = DecompilerInterface.discover(force_decompiler="ida") # type: ignore
        lookup: dict[str, TaggedDependency] = {}
        failed: set[int] = set()

        for function in functions.items:
            data_types: FunctionInfo | None = function.data_types

            if data_types is None:
                continue
            
            # Track processed dependencies to prevent duplicate imports.
            # Without this:
            # - Shared dependencies get re-processed, breaking references (shows as invalid ordinals in IDA)
            # - Cannot resolve subdependencies (e.g. struct fields that reference other imported types)
            for dep in data_types.func_deps:
                if dep.actual_instance is None:
                    continue

                if dep.actual_instance.name not in lookup:
                    lookup.update({dep.actual_instance.name: TaggedDependency(dep.actual_instance)}) # type: ignore

            dependency: V2FunctionInfoFuncDepsInner
            for dependency in data_types.func_deps:
                if dependency.actual_instance is None:
                    continue

                tagged_dependency: TaggedDependency | None = lookup.get(dependency.actual_instance.name)
                if tagged_dependency:
                    try:
                        self.process_dependency(tagged_dependency, lookup)
                    except Exception as e:
                        logger.warning(
                            f"RevEng.AI: skipped dependency {tagged_dependency.name!r}: {e!r}"
                        )
                        tagged_dependency.processed = True

            func: FunctionType | None = data_types.func_types
            if func:
                try:
                    if matched_function_mapping:
                        ea: int = matched_function_mapping[function.function_id]
                    else:
                        ea: int = func.addr

                    if not self.update_function(func, ea) or self._function_types_unparseable(func):
                        failed.add(function.function_id)
                except Exception as e:
                    logger.warning(
                        f"RevEng.AI: skipped data types for function {function.function_id}: {e!r}"
                    )
                    failed.add(function.function_id)

        return failed


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

    def update_function(self, func: FunctionType, ea: int) -> bool:
        base_address: int = self.deci.binary_base_addr
        rva: int = ea - base_address

        target_func: libbs.artifacts.Function | None = self.deci.functions.get(rva) # type: ignore
        if target_func is None:
            logger.warning(f"failed to update function: {func.name} at rva: 0x{rva:0x}")
            return False

        target_func.name = func.name
        target_func.size = func.size
        target_func.type = func.type

        # Check the target function has a header.
        if target_func.header:
            self.update_header(func.header, target_func)

        self.deci.functions[rva] = target_func
        return True

    def _function_types_unparseable(self, func: FunctionType) -> bool:
        if not (func.header and func.header.args):
            return False
        for arg in func.header.args.values():
            type_str: str = self.normalise_type(arg.type) if arg.type else ""
            if type_str and convert_type_str_to_ida_type(type_str) is None:
                return True
        return False

    def update_header(
        self, imported_header: FunctionHeader, target_function: libbs.artifacts.Function
    ) -> None:
        if target_function.header is None:
            return
        
        target_function.header.name = imported_header.name
        target_function.header.type = self.normalise_type(imported_header.type)
        self.update_function_arguments(imported_header.args, target_function)

    def update_function_arguments(
        self, imported_args: dict[str, FunctionArgument], target_function: libbs.artifacts.Function
    ) -> None:
        if target_function.header is None:
            return

        for arg in imported_args.values():
            arg.type = self.normalise_type(arg.type)

        target_function.header.args = {v.offset: v for v in imported_args.values()}

    @staticmethod
    def normalise_type(data_type: str) -> str:
        # When we obtain a type from DWARF information, it often looks something like `DWARF/stdint-uintn.h::uint32_t`
        # Let's remove the DWARF/*.h prefix
        if data_type.startswith("DWARF/"):
            # Find the first occurence of `::`
            delimiter: str = "::"
            pos: int = data_type.find(delimiter)
            data_type = data_type[pos+len(delimiter):]

        # TODO: PLU-213 Add IDA typedefs for Ghidra primitives so we don't need to bother doing this...
        if data_type == "uchar":
            data_type = "unsigned char"
        elif data_type == "qword":
            data_type = "unsigned __int64"
        elif data_type == "sqword":
            data_type = "__int64"

        return data_type
