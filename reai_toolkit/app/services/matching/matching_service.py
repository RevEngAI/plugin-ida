import threading
from typing import Any, Callable, Generator, List, Optional

import ida_funcs
import ida_kernwin as kw
import idautils
import idc
from loguru import logger
from revengai import (
    AnalysisFunctionMatchingRequest,
    BinarySearchResult,
    CollectionSearchResult,
    Configuration,
    FunctionMapping,
    FunctionMatchingResponse,
    FunctionMatchingFilters,
    FunctionMatch,
    FunctionsCoreApi,
    SearchApi,
)

from reai_toolkit.app.core import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.interfaces.thread_service import IThreadService
from reai_toolkit.app.services.matching.schema import (
    APIProgressStatus,
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

    def _search_collections(self, text_input: str) -> List[CollectionSearchResult]:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            search_client = SearchApi(api_client)

            return_list: List[CollectionSearchResult] = []

            response = search_client.search_collections(
                model_name=self.safe_get_model_name_local(),
                partial_collection_name=text_input,
                page_size=10,
                page=1,
            )

            return_list.extend(response.data.results)

            return return_list
        pass

    def search_collections(
        self, text_input: str
    ) -> GenericApiReturn[List[CollectionSearchResult]]:
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

            model_name = self.safe_get_model_name_local()

            return_list: List[BinarySearchResult] = []

            response = search_client.search_binaries(
                partial_name=text_input,
                partial_sha256=None,
                page_size=5,
                page=1,
                model_name=model_name,
            )

            return_list.extend(response.data.results)

            response = search_client.search_binaries(
                partial_name=None,
                partial_sha256=text_input,
                page_size=5,
                page=1,
                model_name=model_name,
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

    def _fetch_valid_functions(
        self, stop_event: threading.Event, restrict_function_id: Optional[int] = None
    ) -> None:
        valid_funcs: List[ValidFunction] = []

        def _main_thread_task():
            nonlocal valid_funcs
            try:
                try:
                    function_map: FunctionMapping = (
                        self.safe_get_function_mapping_local()
                    )
                    inverse_map = (
                        getattr(function_map, "inverse_function_map", {}) or {}
                    )
                except Exception as e:
                    logger.error(f"Error fetching function mapping: {e}")
                    valid_funcs = []
                    return

                for start_ea in idautils.Functions():
                    if stop_event.is_set():
                        break

                    try:
                        f = ida_funcs.get_func(start_ea)
                        if not f:
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

                # Success
                return

            except Exception as e:
                logger.error(f"Error fetching valid functions: {e}")
                valid_funcs = []
                return

        # --- run on main thread ---
        try:
            kw.execute_sync(_main_thread_task, kw.MFF_READ)
        except Exception as e:
            logger.error(f"Error executing function fetch on main thread: {e}")
            valid_funcs = []

        # Always call callback safely
        try:
            self._call_callback(valid_funcs or [])
        except Exception as cb_err:
            logger.error(f"Error in function fetch callback: {cb_err}")
            pass
        finally:
            self._thread_callback = None

    def _match_request(
        self,
        nns: int,
        min_similarity: int,
        binary_ids: Optional[List[int]] = None,
        collection_ids: Optional[List[int]] = None,
        debug_flags: Optional[List[str]] = None,
        page: int = 1,
        page_size: int = 1000,
    ) -> FunctionMatchingResponse:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            functions_client = FunctionsCoreApi(api_client)

            result = functions_client.analysis_function_matching(
                analysis_id=self.safe_get_analysis_id_local(),
                analysis_function_matching_request=AnalysisFunctionMatchingRequest(
                    min_similarity=min_similarity,
                    results_per_function=nns,
                    page_size=page_size,
                    page=page,
                    filters=FunctionMatchingFilters(
                        binary_ids=binary_ids,
                        collection_ids=collection_ids,
                        debug_types=debug_flags,
                    ),
                ),
            )

            return result

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

        debug_flags = []
        if user_debug_only:
            debug_flags.append("USER")
        elif debug_all:
            debug_flags.extend(["USER", "EXTERNAL", "SYSTEM"])

        # Prep progress tracking
        total = 100
        errors: List[str] = []

        # Initial "start" event
        yield StartEvent(total=total)

        while True:
            response: GenericApiReturn[FunctionMatchingResponse] = (
                self.api_request_returning(
                    lambda: self._match_request(
                        nns=nns,
                        min_similarity=min_similarity,
                        binary_ids=binary_ids,
                        collection_ids=collection_ids,
                        debug_flags=debug_flags,
                    )
                )
            )

            if response.success:
                if response.data.status == APIProgressStatus.COMPLETED:
                    yield BatchDoneEvent(
                        completed=response.data.progress,
                        total=total,
                        ok=True,
                    )
                    break
                elif response.data.status == APIProgressStatus.ERROR:
                    yield BatchDoneEvent(
                        completed=response.data.progress,
                        total=total,
                        ok=False,
                        error=response.data.error_message,
                    )
                    errors.append(response.data.error_message)
                    break
                else:
                    yield BatchDoneEvent(
                        completed=response.data.progress,
                        total=total,
                        ok=True,
                    )

            else:
                yield BatchDoneEvent(
                    completed=0, total=total, ok=False, error=response.error_message
                )
                errors.append(response.error_message)
                break

        matches: List[FunctionMatch] = []
        if analysis_func_count >= 1000:
            for page in range(1, (analysis_func_count // 1000) + 2):
                print(f"Fetching matching results page {page}...")
                paged_response: GenericApiReturn[FunctionMatchingResponse] = (
                    self.api_request_returning(
                        lambda: self._match_request(
                            nns=nns,
                            min_similarity=min_similarity,
                            binary_ids=binary_ids,
                            collection_ids=collection_ids,
                            debug_flags=debug_flags,
                            page=page,
                        )
                    )
                )

                if (
                    paged_response.success
                    and paged_response.data.status == APIProgressStatus.COMPLETED
                ):
                    print(len(paged_response.data.matches))
                    matches.extend(paged_response.data.matches)
                else:
                    break

        else:
            matches = response.data.matches if response.success else []

        # Reduce final results - based on iput function list
        final_results: List[FunctionMatch] = [
            match for match in matches if match.function_id in function_ids
        ]

        yield SummaryEvent(
            ok=len(errors) == 0,
            completed=response.data.progress,
            total=len(final_results),
            errors=errors,
            results=final_results,
        )
