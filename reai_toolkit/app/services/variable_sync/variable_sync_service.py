import queue
import threading
import time
from typing import Optional, Tuple

from libbs.artifacts import FunctionHeader, StackVariable
from loguru import logger

from revengai import (
    BaseResponseFunctionDataTypesList,
    BatchUpdateDataTypesInputBody,
    BatchUpdateDataTypesItem,
    BatchUpdateDataTypesOutputBody,
    Configuration,
    FunctionInfo,
    FunctionsDataTypesApi,
)
from revengai import ApiException

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.interfaces.thread_service import IThreadService


class VariableSyncService(IThreadService):
    _q: queue.Queue[Tuple[int, object]] = queue.Queue()
    _last_ts: dict[tuple, float] = {}
    _debounce_ms: int = 400
    _max_retries: int = 3

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def enqueue_change(self, function_id: int, artifact: object) -> None:
        key = self._debounce_key(function_id, artifact)
        now = time.time()
        last = self._last_ts.get(key, 0.0)
        self._last_ts[key] = now
        if (now - last) * 1000.0 <= self._debounce_ms:
            return
        self._q.put((function_id, artifact))
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
                function_id, artifact = self._q.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                self._push_change(function_id, artifact)
            except ApiException as e:
                logger.error(f"RevEng.AI: failed to push data types: HTTP {e.status} {e.reason}")
            except Exception as e:
                logger.error(f"RevEng.AI: failed to push data types: {e}")
            finally:
                self._q.task_done()

    def _push_change(self, function_id: int, artifact: object) -> None:
        analysis_id: int | None = self.netstore_service.get_analysis_id()
        if analysis_id is None:
            return

        for _ in range(self._max_retries):
            fetched = self._fetch_function_info(function_id)
            if fetched is None:
                return
            info, version = fetched

            if not self._patch(info, artifact):
                return

            status: str = self._push(function_id, analysis_id, info, version)
            # A concurrent edit moved the stored version on; re-fetch and reapply.
            if status == "version_conflict":
                time.sleep(0.2)
                continue
            if status != "updated":
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
                entry.name = svar.name
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
                        entry.name = arg.name
                        entry.type = arg.type
                        break
