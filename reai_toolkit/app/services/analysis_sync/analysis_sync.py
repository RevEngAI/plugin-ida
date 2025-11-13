import threading
from typing import Any, Callable, cast

import ida_kernwin
from libbs.api import DecompilerInterface
import libbs.artifacts
from libbs.decompilers.ida.compat import execute_ui, execute_write, execute_read

import idautils
import idaapi

from loguru import logger
from revengai import (
    AnalysesCoreApi,
    ApiClient,
    Configuration,
    FunctionMapping,
    FunctionDataTypesList,
    FunctionsDataTypesApi,
    BaseResponseFunctionDataTypesList,
    FunctionDataTypesListItem,
    FunctionInfoOutput,
    FunctionInfoInputFuncDepsInner,
    Structure,
    TypeDefinition,
    Enumeration,
    GlobalVariable,
    FunctionTypeOutput,
    StackVariable,
)

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.analysis_sync.schema import MatchedFunctionSummary
from revengai import BaseResponseBasic


class TaggedDependency:
    def __init__(self, dependency: Structure | Enumeration | TypeDefinition | GlobalVariable):
        self.dependency: Structure | Enumeration | TypeDefinition | GlobalVariable = dependency
        self.processed: bool = False
        self.name: str = self.dependency.name

    def __repr__(self):
        return self.dependency.__repr__()


class AnalysisSyncService(IThreadService):
    _thread_callback: Callable[..., Any] = None

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)
        self.deci: DecompilerInterface = DecompilerInterface.discover(force_decompiler="ida")

    def call_callback(self, generic_return: GenericApiReturn) -> None:
        self._thread_callback(generic_return)

    def thread_in_progress(self) -> bool:
        """
        Notify that the thread is still in progress.
        """
        return self.is_worker_running()

    def start_syncing(self, thread_callback: Callable[..., Any]) -> None:
        """
        Starts syncing the analysis data as a background job.
        """
        analysis_id = self.safe_get_analysis_id_local()
        self._thread_callback = thread_callback
        # Ensure any existing worker is stopped before starting a new one
        self.stop_worker()
        self.start_worker(
            target=self._sync_analysis_data,
            args=(analysis_id,),
        )

    def _fetch_model_id(self, analysis_id: int) -> int:
        """
        Fetches the model ID for the given analysis ID.
        """
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)

            analysis_details = analyses_client.get_analysis_basic_info(analysis_id=analysis_id)
            model_id = analysis_details.data.model_id
            self.safe_put_model_id(model_id=model_id)
            model_name = analysis_details.data.model_name
            self.safe_put_model_name_local(model_name=model_name)

            local_base_address: int = self._get_current_base_address()

            if analysis_details.data and analysis_details.data.base_address is not None:
                remote_base_address: int = analysis_details.data.base_address

                if local_base_address != remote_base_address:
                    base_address_delta: int = remote_base_address - local_base_address
                    self._rebase_program(base_address_delta)

            return model_id

    @execute_read
    def _get_current_base_address(self) -> int:
        return idaapi.get_imagebase()

    @execute_write
    def _rebase_program(self, base_address_delta: int) -> None:
        idaapi.rebase_program(base_address_delta, idaapi.MSF_FIXONCE)

    def _fetch_function_map(self, analysis_id: int) -> FunctionMapping:
        """
        Fetches the function map for the given analysis ID.
        """
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)

            function_map = analyses_client.get_analysis_function_map(analysis_id=analysis_id)
            func_map = function_map.data.function_maps
            self.safe_put_function_mapping(func_map=func_map)
            return func_map

    def _match_functions(
        self,
        func_map: FunctionMapping,
    ) -> GenericApiReturn[MatchedFunctionSummary]:
        function_map = func_map.function_map
        inverse_function_map = func_map.inverse_function_map

        logger.info(f"RevEng.AI: Retrieved {len(function_map)} function mappings from analysis")

        # Compute which IDA functions match the revengai analysis functions
        matched_functions = []
        unmatched_local_functions = []
        unmatched_remote_functions = []

        # Track local functions matched
        local_function_vaddrs_matched = set()
        fun_count = 0
        for key, value in func_map.name_map.items():
            if "FUN_" in value:
                fun_count += 1

        for start_ea in idautils.Functions():
            if str(start_ea) in inverse_function_map:
                new_name: str | None = func_map.name_map.get(str(start_ea), None)
                if new_name is None:
                    continue
                
                self.safe_set_name(start_ea, new_name, check_user_flags=True)
                matched_functions.append((int(inverse_function_map[str(start_ea)]), start_ea))
                local_function_vaddrs_matched.add(start_ea)
            else:
                unmatched_local_functions.append(start_ea)

        unmatched_portal_map = {}
        # Track remote functions not matched
        for func_id_str, func_vaddr in function_map.items():
            if int(func_vaddr) not in local_function_vaddrs_matched:
                unmatched_remote_functions.append((int(func_vaddr), int(func_id_str)))
                unmatched_portal_map[int(func_vaddr)] = int(func_id_str)

        logger.info(f"RevEng.AI: Matched {len(matched_functions)} functions")
        logger.info(f"RevEng.AI: {len(unmatched_local_functions)} local functions not matched")
        logger.info(f"RevEng.AI: {len(unmatched_remote_functions)} remote functions not matched")

        return GenericApiReturn(
            success=True,
            data=MatchedFunctionSummary(
                matched_local_function_count=len(matched_functions),
                unmatched_local_function_count=len(unmatched_local_functions),
                unmatched_remote_function_count=len(unmatched_remote_functions),
                total_function_count=len(function_map),
            ),
        )

    def _get_data_types(self, analysis_id: int) -> FunctionDataTypesList | None:
        with ApiClient(configuration=self.sdk_config) as api_client:
            client = FunctionsDataTypesApi(api_client=api_client)
            response: BaseResponseFunctionDataTypesList = (
                client.list_function_data_types_for_analysis(analysis_id)
            )
            if response.status:
                return response.data

    def _normalize_type(self, type: str) -> str:
        # TODO: Do we need namespace information here? Observing discrepancies where sometimes namespace is used, and other times it isn't.
        # I think we will have problems with C++ demangled symbol names using this approach. Needs investigating...
        split_type: list[str] = type.split("::")
        normalized: str = split_type[-1]
        # normalized = type

        # It would appear this is a Ghidra-ism and IDA is unaware of this type.
        # TODO: Auto add Ghidra typedef for primitives so we don't need to bother doing this...
        if normalized == "uchar":
            normalized = "unsigned char"
        elif normalized == "qword":
            normalized = "unsigned __int64"
        elif normalized == "sqword":
            normalized = "__int64"

        return normalized

    def _process_dependency(
        self, tagged_dependency: TaggedDependency, lookup: dict[str, TaggedDependency]
    ) -> None:
        if tagged_dependency.processed:
            logger.debug(f"skipping {tagged_dependency.name} as already processed")
            return

        logger.debug(f"processing {tagged_dependency.name}...")
        dependency = tagged_dependency.dependency
        match dependency:
            case Structure():
                s: Structure = cast(Structure, dependency)
                for member in s.members.values():
                    subdependency = lookup.get(member.type)
                    if subdependency:
                        self._process_dependency(subdependency, lookup)
                    member.type = self._normalize_type(member.type)

                self.deci.structs[s.name] = libbs.artifacts.Struct(
                    name=s.name, size=s.size, members={v.offset: v for v in s.members.values()}
                )
            case Enumeration():
                e: Enumeration = cast(Enumeration, dependency)
                self.deci.enums[e.name] = libbs.artifacts.Enum(name=e.name, members=e.members)
            case TypeDefinition():
                t: TypeDefinition = cast(TypeDefinition, dependency)

                subdependency = lookup.get(t.type)
                if subdependency:
                    self._process_dependency(subdependency, lookup)

                normalized_type: str = self._normalize_type(t.type)
                self.deci.typedefs[t.name] = libbs.artifacts.Typedef(
                    name=t.name, type_=normalized_type
                )
            case GlobalVariable():
                g: GlobalVariable = cast(GlobalVariable, dependency)
                subdependency = lookup.get(g.type)
                if subdependency:
                    self._process_dependency(subdependency, lookup)

                normalized_type = self._normalize_type(g.type)
                self.deci.global_vars[g.addr] = libbs.artifacts.GlobalVariable(
                    addr=g.addr, name=g.name, type_=normalized_type, size=g.size
                )
            case _:
                logger.warning(f"unrecognised type: {dependency}")

        logger.debug(f"finished processing {dependency.name}")
        tagged_dependency.processed = True

    @execute_ui
    def _modify_function(self, func: FunctionTypeOutput) -> None:
        # IDA expects an RVA so we need to subtract the base address.
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
            stack_var: StackVariable
            for stack_var in func.stack_vars.values():
                # TODO: PLU-192 What do we want to do if a stack variable does not exist at the specified offset?
                target_stack_var: libbs.artifacts.StackVariable | None = target_func.stack_vars.get(
                    stack_var.offset
                )

                if target_stack_var is None:
                    continue

                target_stack_var.name = stack_var.name
                target_stack_var.type = self._normalize_type(stack_var.type)
                target_stack_var.size = stack_var.size

        # Check the target function has a header.
        if target_func.header:
            target_func.header.name = func.header.name
            target_func.header.type = self._normalize_type(func.header.type)

            for arg in func.header.args.values():
                arg.type = self._normalize_type(arg.type)

            target_func.header.args = {v.offset: v for v in func.header.args.values()}
            
        self.deci.functions[rva] = target_func

    def _import_data_types(self, functions: FunctionDataTypesList) -> None:
        # TODO: PLU-192 If we already have debug symbols, do we want to skip this? I think we should!
        # TODO: PLU-192 Factor this all out into it's own class as we are going to reuse it for both function matching and autounstrip
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
                self._process_dependency(tagged_dependency, lookup)

        logger.debug(f"processing {len(functions.items)} functions")
        for i, function in enumerate(functions.items):
            data_types: FunctionInfoOutput = function.data_types

            # No additional type information to import so we can skip.
            if data_types:
                # If we have info on the function signature, we can now apply it as we should have imported all dependencies.
                func: FunctionTypeOutput | None = data_types.func_types
                if func:
                    logger.debug(f"processing {func.to_dict()}")
                    self._modify_function(func)
                    logger.debug(f"processed {i+1} out of {len(functions.items)} functions")
                else:
                    logger.debug(f"skipping function {i+1} as no func")
            else:
                logger.debug(f"skipping function {i+1} as no data types")

    def _safe_match_functions(
        self, func_map: FunctionMapping
    ) -> GenericApiReturn[MatchedFunctionSummary]:
        data = GenericApiReturn(success=False, error_message="Failed to match functions.")

        def _do():
            try:
                nonlocal data
                data = self._match_functions(func_map=func_map)
            except Exception as e:
                logger.error(f"RevEng.AI: Exception during function sync: {e}")
                data = GenericApiReturn(
                    success=False, error_message=f"Exception during function sync: {e}"
                )

        ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST)

        return data

    def _sync_analysis_data(self, _: threading.Event, analysis_id: int) -> None:
        """
        Syncs the analysis data until completion or failure.
        """

        # Fetch Model ID - Used for function matching
        response = self.api_request_returning(
            fn=lambda: self._fetch_model_id(analysis_id=analysis_id)
        )

        if not response.success:
            self.call_callback(generic_return=response)
            return

        response = self.api_request_returning(
            fn=lambda: self._fetch_function_map(analysis_id=analysis_id)
        )

        if not response.success:
            self.call_callback(generic_return=response)
            return

        function_mapping: FunctionMapping = response.data

        response = self._safe_match_functions(func_map=function_mapping)
        if not response.success:
            self.call_callback(generic_return=response)
            return

        result: FunctionDataTypesList | None = self._get_data_types(analysis_id)
        if result and result.total_data_types_count:
            logger.debug(f"applying type information for {analysis_id}...")
            self._import_data_types(result)
        else:
            logger.debug(f"found no type information for {analysis_id}")

        self.call_callback(generic_return=response)
