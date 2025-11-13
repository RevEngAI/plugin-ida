import queue
import threading
import time
from typing import List, Optional

import ida_kernwin
from loguru import logger
from revengai import (
    Configuration,
    FunctionRenameMap,
    FunctionsListRename,
    FunctionsRenamingHistoryApi,
)

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.core.utils import (
    demangle,
)
from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.rename.schema import RenameInput


class RenameService(IThreadService):
    _rename_q: queue.Queue[List[RenameInput]] = queue.Queue()
    _rename_last_ts: dict[int, float] = {}
    _rename_debounce_ms: int = 300  # ignore bursts within 300ms per ea
    _rename_max_retries: int = 5

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def function_id_to_vaddr(self, function_id: int) -> Optional[int]:
        maps = self.safe_get_function_mapping_local()
        if maps is None:
            return None
        id_vaddr_map = maps.function_map
        vaddr = id_vaddr_map.get(str(function_id), None)
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

            while attempt < self._rename_max_retries and not stop_event.is_set():
                total_errors = self._rename_function(function_list=function_list)
                if total_errors == 0:
                    break
                attempt += 1
                time.sleep(0.2)

            # Do before for execute sync, if fails may not be called.
            self._rename_q.task_done()

            # Display the total success/failure
            ida_kernwin.execute_sync(
                lambda: logger.info(
                    f"RevEng.AI: Renaming Batch Completed - Success: {len(function_list) - (total_errors or 0)}, Failures: {total_errors or 0}"
                ),
                ida_kernwin.MFF_FAST,
            )

    def _rename_remote_function_safe(self, matched_func_list) -> GenericApiReturn:
        data = GenericApiReturn(success=False)

        def _do():
            nonlocal data
            data = self.api_request_returning(
                fn=lambda: self._rename_remote_function(function_list=matched_func_list)
            )

        ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST)
        return data

    def _rename_function(self, function_list: List[RenameInput]) -> int:
        """
        Rename functions both locally and remotely.
        Returns the number of errors encountered during renaming.
        """

        total_errors = 0
        new_func_list = []
        for function in function_list:
            # Rename local function
            success = self.safe_set_name(ea=function.ea, new_name=function.new_name)

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
                maps = self.safe_get_function_mapping_local()
                if maps is None:
                    continue
                vaddr_id_map = maps.inverse_function_map
                function_id = vaddr_id_map.get(str(func.ea), None)
                if function_id is not None:
                    matched_func_list.append(
                        RenameInput(
                            ea=func.ea, new_name=func.new_name, function_id=function_id
                        )
                    )

        if not matched_func_list:
            return total_errors

        # Rename remote functions
        response = self._rename_remote_function_safe(
            matched_func_list=matched_func_list
        )

        if not response.success:
            total_errors += len(matched_func_list)

        return total_errors

    def _rename_remote_function(self, function_list: List[RenameInput]) -> None:
        function_rename_list = []
        for func in function_list:
            function_rename_list.append(
                FunctionRenameMap(
                    function_id=func.function_id,
                    new_mangled_name=func.new_name,
                    new_name=demangle(func.new_name),
                )
            )

        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            functions_api = FunctionsRenamingHistoryApi(api_client=api_client)

            functions_api.batch_rename_function(
                functions_list_rename=FunctionsListRename(
                    functions=function_rename_list
                )
            )
