import queue
import threading
import time
from dataclasses import dataclass
from typing import List, Optional

from libbs.decompilers.ida.compat import execute_write
from loguru import logger

from revengai import (
    ApiException,
    BatchRenameInputBody,
    BatchRenameItem,
    BatchRenameOutputBody,
    CanonicalizeNamesInputBody,
    Configuration,
    FunctionMapping,
    FunctionsCoreApi,
    FunctionsRenamingHistoryApi,
)

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.utils import (
    demangle,
)
from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.rename.schema import RenameInput


@dataclass
class RemoteRenameOutcome:
    status: bool
    renamed_count: int = 0
    server_error: bool = False


class RenameService(IThreadService):
    _rename_q: queue.Queue[List[RenameInput]] = queue.Queue()
    _rename_last_ts: dict[int, float] = {}
    _rename_debounce_ms: int = 300  # ignore bursts within 300ms per ea
    _rename_max_retries: int = 5
    _canonicalize_batch_size: int = 25
    _rename_batch_size: int = 50

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def function_id_to_vaddr(self, function_id: int) -> int | None:
        maps: FunctionMapping | None = self.netstore_service.get_function_mapping()
        if maps is None:
            return None
        id_vaddr_map: dict[str, int] = maps.function_map
        vaddr: int | None = id_vaddr_map.get(str(function_id), None)
        if vaddr is None:
            return None
        return vaddr

    def enqueue_rename(self, rename_list: List[RenameInput]) -> None:
        valid_list = []
        for func in rename_list:
            now = time.time()
            last = self._rename_last_ts.get(func.ea, 0.0)
            if (now - last) * 1000.0 > self._rename_debounce_ms:
                valid_list.append(func)
            self._rename_last_ts[func.ea] = now

        self._rename_q.put(valid_list)
        self._start_rename_worker_if_needed()

    def _start_rename_worker_if_needed(self) -> None:
        """Ensure the background worker is running."""
        if self._worker_thread and self._worker_thread.is_alive():
            return
        # stop any zombie
        self.stop_worker()
        self.start_worker(target=self._rename_worker)

    def _rename_worker(self, stop_event: Optional[threading.Event] = None) -> None:
        """Background worker to process rename requests."""
        while not (stop_event and stop_event.is_set()):
            try:
                # Use a timeout so we can exit promptly when stopping
                function_list: List[RenameInput] = self._rename_q.get(timeout=0.25)
            except queue.Empty:
                continue

            attempt = 0

            total_errors = None

            while attempt < self._rename_max_retries and not (
                stop_event and stop_event.is_set()
            ):
                try:
                    total_errors = self._rename_function(function_list=function_list)
                except Exception as e:
                    logger.error(f"RevEng.AI: failed to rename functions: {e}")
                    total_errors = len(function_list)
                if total_errors == 0:
                    break
                attempt += 1
                time.sleep(0.2)

            # Do before for execute sync, if fails may not be called.
            self._rename_q.task_done()

    def _rename_function(self, function_list: List[RenameInput]) -> int:
        """
        Rename functions both locally and remotely.
        Returns the number of errors encountered during renaming.
        """
        total_errors = 0
        new_func_list: list[RenameInput] = []
        for function in function_list:
            # Rename local function
            success: bool = self.update_function_name(ea=function.ea, new_name=function.new_name)

            if not success:
                total_errors += 1
            else:
                new_func_list.append(function)

        # Now remote renames for function that exist in portal & locally
        matched_func_list = []
        for func in new_func_list:
            if func.function_id is not None:
                matched_func_list.append(func)
            else:
                # Fetch function ID
                maps: FunctionMapping | None = self.netstore_service.get_function_mapping()
                if maps is None:
                    continue
                vaddr_id_map: dict[str, int] = maps.inverse_function_map
                function_id: int | None = vaddr_id_map.get(str(func.ea), None)
                if function_id is not None:
                    matched_func_list.append(
                        RenameInput(
                            ea=func.ea, new_name=func.new_name, function_id=function_id
                        )
                    )
            

        if not matched_func_list:
            return total_errors

        # Rename remote functions
        response = self._rename_remote_function(matched_func_list)

        if not getattr(response, "status", False):
            total_errors += len(matched_func_list)

        return total_errors

    @execute_write
    def _rename_remote_function(
        self, function_list: list[RenameInput]
    ) -> RemoteRenameOutcome:
        function_rename_list: list[BatchRenameItem] = []
        for func in function_list:
            if func.function_id is None:
                continue

            function_rename_list.append(
                BatchRenameItem(
                    function_id=func.function_id,
                    new_mangled_name=func.new_name,
                    new_name=demangle(func.new_name),
                )
            )
            self.tag_function_as_renamed(func.new_name)

        if not function_rename_list:
            return RemoteRenameOutcome(status=True)

        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            functions_api = FunctionsRenamingHistoryApi(api_client=api_client)

            try:
                response: BatchRenameOutputBody = functions_api.batch_rename_functions(
                    batch_rename_input_body=BatchRenameInputBody(
                        functions=function_rename_list
                    )
                )
            except ApiException as e:
                logger.error(
                    f"RevEng.AI: failed to rename {len(function_rename_list)} function(s) "
                    f"remotely: HTTP {e.status} {e.reason}"
                )
                return RemoteRenameOutcome(
                    status=False, server_error=bool(e.status and e.status >= 500)
                )
            except Exception as e:
                logger.error(f"RevEng.AI: failed to rename functions remotely: {e}")
                return RemoteRenameOutcome(status=False)

            return RemoteRenameOutcome(
                status=True, renamed_count=getattr(response, "renamed_count", 0)
            )

    def push_remote_names(self, renames: list[RenameInput]) -> int:
        pushed: int = 0
        for start in range(0, len(renames), self._rename_batch_size):
            chunk: list[RenameInput] = renames[start:start + self._rename_batch_size]
            outcome = self._rename_remote_function(chunk)
            if getattr(outcome, "status", False):
                pushed += getattr(outcome, "renamed_count", 0)
                continue
            if getattr(outcome, "server_error", False):
                logger.error(
                    f"RevEng.AI: abandoning the push of {len(renames) - pushed} name(s); "
                    "the platform failed to process the request"
                )
                break
            for rename in chunk:
                single = self._rename_remote_function([rename])
                if getattr(single, "status", False):
                    pushed += getattr(single, "renamed_count", 0)
        return pushed

    def canonicalize_names(self, names: list[str]) -> dict[str, str]:
        mapping: dict[str, str] = {}
        unique: list[str] = [n for n in dict.fromkeys(names) if n]

        for start in range(0, len(unique), self._canonicalize_batch_size):
            chunk: list[str] = unique[start:start + self._canonicalize_batch_size]
            try:
                with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
                    client = FunctionsCoreApi(api_client)
                    out = client.v3_canonicalize_function_names(
                        canonicalize_names_input_body=CanonicalizeNamesInputBody(names=chunk)
                    )
            except Exception as e:
                logger.error(f"RevEng.AI: failed to canonicalize names: {e}")
                continue

            for result in (out.results or []):
                mapping[result.name] = result.canonical_name

        return mapping
