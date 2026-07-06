import queue
import threading
import time
from typing import Optional, Tuple

from libbs.artifacts import Enum, FunctionHeader, StackVariable, Struct, Typedef
from libbs.decompilers.ida.compat import execute_read
from loguru import logger

from revengai import (
    FunctionArgument,
    BaseResponseFunctionDataTypesList,
    BatchUpdateDataTypesInputBody,
    BatchUpdateDataTypesItem,
    BatchUpdateDataTypesOutputBody,
    Configuration,
    Enumeration,
    FunctionInfo,
    V2FunctionInfoFuncDepsInner,
    FunctionsDataTypesApi,
    FunctionType,
    Structure,
    TypeDefinition,
)
from revengai import ApiException
from revengai.models.function_header import FunctionHeader as SdkFunctionHeader
from revengai.models.function_stack_variable import FunctionStackVariable as SdkStackVariable
from revengai.models.structure_member import StructureMember

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.interfaces.thread_service import IThreadService


@execute_read
def _read_decompiler_function(deci, func_addr: int):
    return deci.functions.get(func_addr)


@execute_read
def _read_named_type(deci, name: str):
    for store in (deci.typedefs, deci.structs, deci.enums):
        try:
            artifact = store.get(name)
        except Exception:
            artifact = None
        if artifact is not None:
            return artifact
    return None


class VariableSyncService(IThreadService):
    _q: queue.Queue[Tuple[int, int, object]] = queue.Queue()
    _last_ts: dict[tuple, float] = {}
    _debounce_ms: int = 400
    _max_retries: int = 3

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)
        self._deci = None

    def attach_decompiler(self, deci) -> None:
        self._deci = deci

    def enqueue_change(self, function_id: int, func_addr: int, artifact: object) -> None:
        key = self._debounce_key(function_id, artifact)
        now = time.time()
        last = self._last_ts.get(key, 0.0)
        self._last_ts[key] = now
        if (now - last) * 1000.0 <= self._debounce_ms:
            logger.debug(f"RevEng.AI: debounced data types change for function {function_id}")
            return
        logger.debug(f"RevEng.AI: queued data types change for function {function_id}")
        self._q.put((function_id, func_addr, artifact))
        self._start_worker_if_needed()

    @staticmethod
    def _debounce_key(function_id: int, artifact: object) -> tuple:
        if isinstance(artifact, StackVariable):
            return (function_id, "sv", artifact.offset)
        return (function_id, "hdr")

    def _start_worker_if_needed(self) -> None:
        if self._worker_thread and self._worker_thread.is_alive():
            return
        self.stop_worker()
        self.start_worker(target=self._worker)

    def _worker(self, stop_event: Optional[threading.Event] = None) -> None:
        while not (stop_event and stop_event.is_set()):
            try:
                function_id, func_addr, artifact = self._q.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                self._push_change(function_id, func_addr, artifact)
            except ApiException as e:
                logger.error(f"RevEng.AI: failed to push data types: HTTP {e.status} {e.reason}")
            except Exception as e:
                logger.error(f"RevEng.AI: failed to push data types: {e}")
            finally:
                self._q.task_done()

    def _push_change(self, function_id: int, func_addr: int, artifact: object) -> None:
        logger.debug(f"RevEng.AI: processing data types change for function {function_id}")
        analysis_id: int | None = self.netstore_service.get_analysis_id()
        if analysis_id is None:
            logger.debug("RevEng.AI: no analysis id; skipping data types push")
            return

        for _ in range(self._max_retries):
            fetched = self._fetch_function_info(function_id)
            if fetched is None:
                # First write for this function: build the object from current state.
                info = self._build_function_info(func_addr)
                if info is None:
                    logger.debug(f"RevEng.AI: could not build data types for function {function_id}; skipping push")
                    return
                version = 0
            else:
                info, version = fetched
                if not self._patch(info, artifact):
                    logger.debug(f"RevEng.AI: no data types change for function {function_id}; skipping push")
                    return

            status: str = self._push(function_id, analysis_id, info, version)
            # A concurrent edit moved the stored version on; re-fetch and reapply.
            if status == "version_conflict":
                time.sleep(0.2)
                continue
            if status == "updated":
                logger.info(f"RevEng.AI: pushed data types for function {function_id}")
            else:
                logger.warning(
                    f"RevEng.AI: data types update for function {function_id} returned {status}"
                )
            return

    def _fetch_function_info(self, function_id: int) -> Optional[Tuple[FunctionInfo, int]]:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            client = FunctionsDataTypesApi(api_client)
            resp: BaseResponseFunctionDataTypesList = (
                client.list_function_data_types_for_functions(function_ids=[function_id])  # type: ignore
            )

        if not resp.status or not resp.data:
            return None

        for item in resp.data.items:
            if item.function_id == function_id and item.data_types is not None:
                return item.data_types, (item.data_types_version or 0)

        return None

    def _build_function_info(self, func_addr: int) -> Optional[FunctionInfo]:
        if self._deci is None:
            return None

        func = _read_decompiler_function(self._deci, func_addr)
        if func is None or func.header is None:
            return None

        header = func.header
        args = {
            hex(offset): FunctionArgument(
                offset=offset, name=arg.name or "", type=arg.type or "", size=arg.size or 0
            )
            for offset, arg in (header.args or {}).items()
        }
        stack_vars = {
            hex(offset): SdkStackVariable(
                offset=offset,
                name=svar.name or "",
                type=svar.type or "",
                size=svar.size or 0,
                addr=svar.addr or func.addr,
            )
            for offset, svar in (func.stack_vars or {}).items()
        }
        func_type = FunctionType(
            addr=func.addr,
            size=func.size or 0,
            header=SdkFunctionHeader(
                name=header.name or "", addr=header.addr or func.addr, type=header.type or "", args=args
            ),
            stack_vars=stack_vars,
            name=getattr(func, "name", None) or header.name or "",
            type=header.type or "",
            artifact_type="Function",
        )
        return FunctionInfo(func_types=func_type, func_deps=self._collect_func_deps(func_type))

    def _collect_func_deps(self, func_type: FunctionType) -> list:
        pending: list[str] = [func_type.type]
        pending.extend(arg.type for arg in (func_type.header.args or {}).values())
        pending.extend(svar.type for svar in (func_type.stack_vars or {}).values())

        deps: dict[str, V2FunctionInfoFuncDepsInner] = {}
        seen: set[str] = set()
        while pending and len(deps) < 200:
            name = self._base_type_name(pending.pop())
            if not name or name in seen:
                continue
            seen.add(name)
            dep, referenced = self._resolve_type(name)
            if dep is None:
                continue
            deps[name] = dep
            pending.extend(referenced)

        return list(deps.values())

    def _resolve_type(self, name: str) -> Tuple[Optional[V2FunctionInfoFuncDepsInner], list]:
        artifact = _read_named_type(self._deci, name)
        if isinstance(artifact, Typedef):
            return (
                V2FunctionInfoFuncDepsInner(
                    TypeDefinition(name=artifact.name, type=artifact.type or "", artifact_type="Typedef")
                ),
                [artifact.type],
            )
        if isinstance(artifact, Struct):
            members = {
                hex(member.offset): StructureMember(
                    name=member.name or "",
                    offset=member.offset,
                    type=member.type or "",
                    size=member.size or 0,
                )
                for member in artifact.members.values()
            }
            referenced = [member.type for member in artifact.members.values()]
            return (
                V2FunctionInfoFuncDepsInner(
                    Structure(name=artifact.name, size=artifact.size, members=members, artifact_type="Struct")
                ),
                referenced,
            )
        if isinstance(artifact, Enum):
            members = {str(key): int(value) for key, value in (artifact.members or {}).items()}
            return (
                V2FunctionInfoFuncDepsInner(
                    Enumeration(name=artifact.name, members=members, artifact_type="Enum")
                ),
                [],
            )
        return None, []

    @staticmethod
    def _base_type_name(type_str: Optional[str]) -> Optional[str]:
        if not type_str:
            return None
        cleaned = type_str.replace("*", " ").replace("[", " ").replace("]", " ")
        keywords = {"const", "volatile", "struct", "union", "enum", "unsigned", "signed"}
        tokens = [tok for tok in cleaned.split() if tok not in keywords]
        return tokens[-1] if tokens else None

    def _push(self, function_id: int, analysis_id: int, info: FunctionInfo, version: int) -> str:
        body = BatchUpdateDataTypesInputBody(
            functions=[
                BatchUpdateDataTypesItem(
                    function_id=function_id,
                    data_types=info.to_dict(),
                    data_types_version=version,
                )
            ]
        )
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            client = FunctionsDataTypesApi(api_client)
            out: BatchUpdateDataTypesOutputBody = client.batch_update_function_data_types(
                analysis_id=analysis_id,
                batch_update_data_types_input_body=body,
            )

        if out.results:
            return out.results[0].status
        return "error"

    def _patch(self, info: FunctionInfo, artifact: object) -> bool:
        ft = info.func_types
        if ft is None:
            return False

        before = ft.to_dict()
        if isinstance(artifact, StackVariable):
            self._patch_stack_var(ft, artifact)
        elif isinstance(artifact, FunctionHeader):
            self._patch_header(ft, artifact)
        # Skip the push when nothing actually changed: pure function renames also
        # raise a header event but are owned by the rename service, and sync-applied
        # edits already match the stored blob.
        return ft.to_dict() != before

    @staticmethod
    def _patch_stack_var(ft: object, svar: StackVariable) -> None:
        if not ft.stack_vars:
            return
        for entry in ft.stack_vars.values():
            if entry.offset == svar.offset:
                if svar.name is not None:
                    entry.name = svar.name
                if svar.type is not None:
                    entry.type = svar.type
                return

    @staticmethod
    def _patch_header(ft: object, fheader: FunctionHeader) -> None:
        header = ft.header
        if header is None:
            return
        if fheader.type:
            header.type = fheader.type
            ft.type = fheader.type
        if header.args and fheader.args:
            for offset, arg in fheader.args.items():
                for entry in header.args.values():
                    if entry.offset == offset:
                        if arg.name is not None:
                            entry.name = arg.name
                        if arg.type is not None:
                            entry.type = arg.type
                        break
