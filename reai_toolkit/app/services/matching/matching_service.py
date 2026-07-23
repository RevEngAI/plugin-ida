import threading
import time
from typing import Any, Callable, Generator, List, Optional

import ida_funcs
import idautils
import idc
from libbs.decompilers.ida.compat import execute_read

from loguru import logger
from revengai import (
    BinarySearchResult,
    CollectionListItemBody,
    CollectionsApi,
    Configuration,
    FunctionMapping,
    FunctionMatch,
    FunctionsCoreApi,
    GetMatchesOutputBody,
    GetMatchesStatusOutputBody,
    MatchFilters,
    ProgressMessage,
    SearchApi,
    StartMatchingForFunctionsInputBody,
    TaskStatus,
)

from reai_toolkit.app.core import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.matching.schema import (
    BatchDoneEvent,
    MatchEvent,
    StartEvent,
    SummaryEvent,
    ValidFunction,
)


class MatchingService(IThreadService):
    _thread_callback: Optional[callable] = None

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    @staticmethod
    def demangle(mangled_name: str, attr: int = idc.INF_SHORT_DN) -> str:
        demangled_name = idc.demangle_name(mangled_name, idc.get_inf_attr(attr))

        return demangled_name if demangled_name else mangled_name

    def function_id_to_local_name(self, function_id: int) -> Optional[str]:
        function_map: FunctionMapping = self.netstore_service.get_function_mapping()
        if str(function_id) not in function_map.function_map:
            return None

        vaddr = int(function_map.function_map[str(function_id)])
        name = self.demangle(idc.get_func_name(vaddr))
        return name

    def _search_collections(self, text_input: str) -> List[CollectionListItemBody]:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            collections_client = CollectionsApi(api_client)

            response = collections_client.v3_list_collections(
                search_term=text_input or None,
                limit=50,
                offset=0,
            )

            return response.results or []

    def search_collections(
        self, text_input: str
    ) -> GenericApiReturn[List[CollectionListItemBody]]:
        response = self.api_request_returning(
            lambda: self._search_collections(text_input)
        )
        # If the search fails, return an empty list instead of an error
        if not response.success:
            return GenericApiReturn(
                success=True,
                data=[],
            )
        return response

    def _search_binaries(self, text_input: str) -> List[BinarySearchResult]:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            search_client = SearchApi(api_client)

            model_name: str | None = self.netstore_service.get_model_name()
            current_binary_id: int | None = self.netstore_service.get_binary_id()

            return_list: List[BinarySearchResult] = []

            response = search_client.search_binaries(
                partial_name=text_input,
                partial_sha256=None,
                page_size=5,
                page=1,
                model_name=model_name,
                exclude_binary_id=current_binary_id,
            )

            return_list.extend(response.data.results)

            response = search_client.search_binaries(
                partial_name=None,
                partial_sha256=text_input,
                page_size=5,
                page=1,
                model_name=model_name,
                exclude_binary_id=current_binary_id,
            )

            return_list.extend(response.data.results)

            return return_list

    def search_binaries(
        self, text_input: str
    ) -> GenericApiReturn[List[BinarySearchResult]]:
        response = self.api_request_returning(lambda: self._search_binaries(text_input))
        # If the search fails, return an empty list instead of an error
        if not response.success:
            return GenericApiReturn(
                success=True,
                data=[],
            )
        return response

    def _call_callback(self, functions: List[ValidFunction]) -> None:
        self._thread_callback(functions)

    def start_function_fetch(
        self, callback: Callable[..., Any], restrict_function_id: Optional[int] = None
    ) -> None:
        if self.is_worker_running():
            return

        self._thread_callback = callback

        self.start_worker(
            target=self._fetch_valid_functions,
            args=(restrict_function_id,),
        )

    @execute_read
    def _fetch_valid_functions(
        self, stop_event: threading.Event, restrict_function_id: Optional[int] = None
    ) -> None:
        valid_funcs: list[ValidFunction] = []

        function_map: FunctionMapping | None = self.netstore_service.get_function_mapping()
        if function_map:
            inverse_map: dict[str, int] = function_map.inverse_function_map

            for start_ea in idautils.Functions():
                if stop_event.is_set():
                    break

                try:
                    f: ida_funcs.func_t | None = ida_funcs.get_func(start_ea)
                    if f is None:
                        continue

                    key = str(int(start_ea))
                    if key not in inverse_map:
                        continue

                    function_id = inverse_map[key]

                    if (
                        restrict_function_id is not None
                        and function_id != restrict_function_id
                    ):
                        continue

                    mangled = idc.get_func_name(start_ea) or ""
                    demangled = self.demangle(mangled or "") or mangled

                    valid_funcs.append(
                        ValidFunction(
                            function_id=function_id,
                            mangled_name=mangled,
                            demangled_name=demangled,
                            vaddr=f.start_ea,
                        )
                    )

                except Exception as inner:
                    logger.error(
                        f"Error processing function at {start_ea}: {inner}"
                    )
                    continue

        try:
            self._call_callback(valid_funcs)
        except Exception as cb_err:
            logger.error(f"Error in function fetch callback: {cb_err}")
        finally:
            self._thread_callback = None

    _POLL_INTERVAL: float = 1.0
    _POLL_TIMEOUT: float = 1200.0

    @staticmethod
    def _debug_types(user_debug_only: bool, debug_all: bool) -> Optional[List[str]]:
        if user_debug_only:
            return ["USER"]
        if debug_all:
            return ["USER", "SYSTEM"]
        return None

    @staticmethod
    def _progress_pct(body: GetMatchesStatusOutputBody) -> int:
        if body.steps_total and body.steps_total > 0:
            return int((body.step_index / body.steps_total) * 100)
        return 0

    @staticmethod
    def _messages_text(messages: Optional[List[ProgressMessage]]) -> str:
        if not messages:
            return "Function matching failed."
        errs = [m.text for m in messages if (m.level or "").upper() == "ERROR"]
        return "; ".join(errs or [messages[-1].text])

    def _start_matching(
        self,
        function_ids: List[int],
        min_similarity: int,
        results_per_function: int,
        binary_ids: Optional[List[int]],
        collection_ids: Optional[List[int]],
        debug_types: Optional[List[str]],
    ) -> None:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            FunctionsCoreApi(api_client).start_functions_matching(
                StartMatchingForFunctionsInputBody(
                    function_ids=function_ids,
                    min_similarity=min_similarity,
                    results_per_function=results_per_function,
                    filters=MatchFilters(
                        binary_ids=binary_ids,
                        collection_ids=collection_ids,
                        debug_types=debug_types,
                    ),
                )
            )

    def _matching_status(
        self, function_ids: List[int]
    ) -> GetMatchesStatusOutputBody:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            return FunctionsCoreApi(api_client).get_functions_matching_status(
                function_ids=function_ids
            )

    def _get_matches(self, function_ids: List[int]) -> GetMatchesOutputBody:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            return FunctionsCoreApi(api_client).get_functions_matches(
                function_ids=function_ids
            )

    def perform_matching(
        self,
        function_ids: list[int],
        analysis_func_count: int,
        min_similarity: int,
        binary_ids: Optional[List[int]] = None,
        collection_ids: Optional[List[int]] = None,
        user_debug_only: bool = False,
        debug_all: bool = False,
    ) -> Generator[MatchEvent, None, None]:
        nns = 1 if len(function_ids) > 1 else 10
        debug_types = self._debug_types(user_debug_only, debug_all)

        total = 100
        errors: List[str] = []

        yield StartEvent(total=total)

        start: GenericApiReturn[None] = self.api_request_returning(
            lambda: self._start_matching(
                function_ids=function_ids,
                min_similarity=min_similarity,
                results_per_function=nns,
                binary_ids=binary_ids,
                collection_ids=collection_ids,
                debug_types=debug_types,
            )
        )
        if not start.success:
            yield BatchDoneEvent(
                completed=0, total=total, ok=False, error=start.error_message
            )
            yield SummaryEvent(
                ok=False,
                completed=0,
                total=0,
                errors=[start.error_message],
                results=[],
            )
            return

        completed_pct = 0
        done = False
        elapsed = 0.0
        while elapsed < self._POLL_TIMEOUT:
            status: GenericApiReturn[GetMatchesStatusOutputBody] = (
                self.api_request_returning(
                    lambda: self._matching_status(function_ids)
                )
            )
            if not status.success:
                errors.append(status.error_message)
                yield BatchDoneEvent(
                    completed=completed_pct,
                    total=total,
                    ok=False,
                    error=status.error_message,
                )
                break

            completed_pct = self._progress_pct(status.data)

            if status.data.status == TaskStatus.COMPLETED:
                yield BatchDoneEvent(completed=total, total=total, ok=True)
                done = True
                break
            if status.data.status == TaskStatus.FAILED:
                message = self._messages_text(status.data.messages)
                errors.append(message)
                yield BatchDoneEvent(
                    completed=completed_pct,
                    total=total,
                    ok=False,
                    error=message,
                )
                break

            yield BatchDoneEvent(completed=completed_pct, total=total, ok=True)
            time.sleep(self._POLL_INTERVAL)
            elapsed += self._POLL_INTERVAL
        else:
            timeout_msg = (
                f"Function matching timed out after {self._POLL_TIMEOUT:.0f}s."
            )
            errors.append(timeout_msg)
            yield BatchDoneEvent(
                completed=completed_pct, total=total, ok=False, error=timeout_msg
            )

        matches: List[FunctionMatch] = []
        if done:
            fetch: GenericApiReturn[GetMatchesOutputBody] = self.api_request_returning(
                lambda: self._get_matches(function_ids)
            )
            if fetch.success:
                matches = fetch.data.matches or []
            else:
                errors.append(fetch.error_message)

        final_results: List[FunctionMatch] = [
            match for match in matches if match.function_id in function_ids
        ]

        yield SummaryEvent(
            ok=len(errors) == 0,
            completed=completed_pct,
            total=len(final_results),
            errors=errors,
            results=final_results,
        )
