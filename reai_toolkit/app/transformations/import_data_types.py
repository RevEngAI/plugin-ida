import re
from typing import cast

import ida_funcs
import ida_typeinf
import idaapi

import libbs.artifacts
from libbs.api import DecompilerInterface
from libbs.decompilers.ida.compat import execute_write, convert_type_str_to_ida_type
from loguru import logger
from revengai import (
    Enumeration,
    FunctionArgument,
    FunctionDataTypesList,
    FunctionDataTypesListItem,
    FunctionType,
    Structure,
    TypeDefinition,
)

APPLY_CHUNK_SIZE = 50
_ANALYSIS_SCOPE_RE = re.compile(r"^[0-9a-fA-F]{64}(?:::|/)")


class TaggedDependency:
    def __init__(self, dependency: Structure | Enumeration | TypeDefinition) -> None:
        self.dependency: Structure | Enumeration | TypeDefinition = dependency
        self.processed: bool = False
        self.name: str = self.dependency.name

    def __repr__(self) -> str:
        return self.dependency.__repr__()


class ImportDataTypes:
    def __init__(self) -> None:
        self.deci: DecompilerInterface | None = None
        self._stack_vars_ok: bool | None = None

    def execute(
        self,
        functions: FunctionDataTypesList,
        matched_function_mapping: dict[int, int] = {},
        apply_stack_vars: bool = False,
    ) -> set[int]:
        items: list[FunctionDataTypesListItem] = [
            item for item in functions.items if item.data_types is not None
        ]
        if not items:
            return set()

        # Track processed dependencies to prevent duplicate imports.
        # Without this:
        # - Shared dependencies get re-processed, breaking references (shows as invalid ordinals in IDA)
        # - Cannot resolve subdependencies (e.g. struct fields that reference other imported types)
        lookup: dict[str, TaggedDependency] = self._build_lookup(items)
        if lookup:
            self._apply_dependencies(lookup)

        failed: set[int] = set()
        total: int = len(items)
        for start in range(0, total, APPLY_CHUNK_SIZE):
            chunk: list[FunctionDataTypesListItem] = items[start:start + APPLY_CHUNK_SIZE]
            failed |= self._apply_chunk(chunk, matched_function_mapping, apply_stack_vars)
            logger.info(
                f"RevEng.AI: applied data types to {min(start + APPLY_CHUNK_SIZE, total)}/{total} functions"
            )

        return failed

    def _build_lookup(self, items: list[FunctionDataTypesListItem]) -> dict[str, TaggedDependency]:
        lookup: dict[str, TaggedDependency] = {}
        for item in items:
            for dep in item.data_types.func_deps or []:
                if dep.actual_instance is None:
                    continue

                if dep.actual_instance.name not in lookup:
                    lookup[dep.actual_instance.name] = TaggedDependency(dep.actual_instance) # type: ignore

        return lookup

    def _ensure_deci(self) -> None:
        if self.deci is None:
            self.deci = DecompilerInterface.discover(force_decompiler="ida")  # type: ignore

    def _stack_vars_available(self, ea: int) -> bool:
        if self._stack_vars_ok is None:
            self._stack_vars_ok = self._probe_decompiler(ea)
            if not self._stack_vars_ok:
                logger.info(
                    "RevEng.AI: decompiler unavailable for this binary; skipping stack variable sync"
                )
        return self._stack_vars_ok

    @staticmethod
    def _probe_decompiler(ea: int) -> bool:
        try:
            import ida_hexrays

            if not ida_hexrays.init_hexrays_plugin():
                return False
            return ida_hexrays.decompile(ea, ida_hexrays.hexrays_failure_t()) is not None
        except Exception:
            return False

    @execute_write
    def _apply_dependencies(self, lookup: dict[str, TaggedDependency]) -> None:
        self._ensure_deci()
        for tagged_dependency in lookup.values():
            try:
                self.process_dependency(tagged_dependency, lookup)
            except Exception as e:
                logger.warning(
                    f"RevEng.AI: skipped dependency {tagged_dependency.name!r}: {e!r}"
                )
                tagged_dependency.processed = True

    @execute_write
    def _apply_chunk(
        self,
        chunk: list[FunctionDataTypesListItem],
        matched_function_mapping: dict[int, int],
        apply_stack_vars: bool = False,
    ) -> set[int]:
        failed: set[int] = set()
        for item in chunk:
            func: FunctionType | None = item.data_types.func_types
            if func is None:
                continue

            try:
                if matched_function_mapping:
                    ea: int = matched_function_mapping[item.function_id]
                else:
                    ea: int = func.addr

                if not self.apply_function_type(func, ea):
                    failed.add(item.function_id)
                if apply_stack_vars:
                    self.apply_stack_variables(func, ea)
            except Exception as e:
                logger.warning(
                    f"RevEng.AI: skipped data types for function {item.function_id}: {e!r}"
                )
                failed.add(item.function_id)

        return failed

    def apply_function_type(self, func: FunctionType, ea: int) -> bool:
        if ida_funcs.get_func(ea) is None:
            logger.warning(f"failed to update function: {func.name} at 0x{ea:x}")
            return False

        args: list[FunctionArgument] = sorted(func.header.args.values(), key=lambda a: a.offset)
        arg_types: list[tuple[str, ida_typeinf.tinfo_t]] = []
        for arg in args:
            arg_tif = convert_type_str_to_ida_type(self.normalise_type(arg.type)) if arg.type else None
            if arg_tif is None:
                return False
            arg_types.append((arg.name, arg_tif))

        details: ida_typeinf.func_type_data_t = self._current_func_details(ea)

        ret_type: str = self.normalise_type(func.header.type) if func.header.type else ""
        if ret_type:
            ret_tif = convert_type_str_to_ida_type(ret_type)
            if ret_tif is None:
                return False
            details.rettype = ret_tif
        elif details.rettype.empty():
            details.rettype = convert_type_str_to_ida_type("void")

        if arg_types:
            details.clear()
            for name, arg_tif in arg_types:
                funcarg = ida_typeinf.funcarg_t()
                funcarg.name = name
                funcarg.type = arg_tif
                details.push_back(funcarg)

        proto = ida_typeinf.tinfo_t()
        if not proto.create_func(details):
            return False

        return bool(ida_typeinf.apply_tinfo(ea, proto, ida_typeinf.TINFO_DEFINITE))

    def apply_stack_variables(self, func: FunctionType, ea: int) -> None:
        stack_vars = getattr(func, "stack_vars", None)
        if not isinstance(stack_vars, dict) or not stack_vars:
            return

        if not self._stack_vars_available(ea):
            return

        self._ensure_deci()
        if self.deci is None:
            return

        try:
            lifted_ea: int = self.deci.art_lifter.lift_addr(ea)
            svars: dict[int, libbs.artifacts.StackVariable] = {
                svar.offset: libbs.artifacts.StackVariable(
                    stack_offset=svar.offset,
                    name=svar.name,
                    type_=self.normalise_type(svar.type) if svar.type else None,
                    size=svar.size,
                    addr=lifted_ea,
                )
                for svar in stack_vars.values()
            }
            self.deci.functions[lifted_ea] = libbs.artifacts.Function(
                addr=lifted_ea,
                header=libbs.artifacts.FunctionHeader(addr=lifted_ea),
                stack_vars=svars,
            )
        except Exception as e:
            logger.warning(f"RevEng.AI: skipped stack variables for 0x{ea:x}: {e!r}")

    @staticmethod
    def _current_func_details(ea: int) -> "ida_typeinf.func_type_data_t":
        details = ida_typeinf.func_type_data_t()
        existing = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(existing, ea) and existing.is_func() and existing.get_func_details(details):
            return details

        if (
            ida_typeinf.guess_tinfo(existing, ea) != ida_typeinf.GUESS_FUNC_FAILED
            and existing.is_func()
            and existing.get_func_details(details)
        ):
            return details

        details = ida_typeinf.func_type_data_t()
        details.cc = ida_typeinf.CM_CC_UNKNOWN
        return details

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

    @staticmethod
    def normalise_type(data_type: str) -> str:
        # When we obtain a type from DWARF information, it often looks something like `DWARF/stdint-uintn.h::uint32_t`
        # Let's remove the DWARF/*.h prefix
        if data_type.startswith("DWARF/"):
            # Find the first occurence of `::`
            delimiter: str = "::"
            pos: int = data_type.find(delimiter)
            data_type = data_type[pos+len(delimiter):]

        data_type = _ANALYSIS_SCOPE_RE.sub("", data_type)

        # TODO: PLU-213 Add IDA typedefs for Ghidra primitives so we don't need to bother doing this...
        if data_type == "uchar":
            data_type = "unsigned char"
        elif data_type == "qword":
            data_type = "unsigned __int64"
        elif data_type == "sqword":
            data_type = "__int64"

        return data_type
