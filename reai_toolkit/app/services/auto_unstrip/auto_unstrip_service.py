import threading
import time
from typing import Any, Callable

from loguru import logger
from revengai import (
    AutoUnstripRequest,
    AutoUnstripResponse,
    Configuration,
    FunctionsCoreApi,
)

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.interfaces.thread_service import IThreadService


class AutoUnstripService(IThreadService):
    _thread_callback: Callable[..., Any] = None

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def call_callback(
        self, generic_return: GenericApiReturn[AutoUnstripResponse]
    ) -> None:
        self._thread_callback(generic_return)

    def thread_in_progress(self) -> bool:
        """
        Notify that the thread is still in progress.
        """
        return self.is_worker_running()

    def start_unstrip_polling(self, callback: Callable[..., Any]) -> None:
        """
        Starts polling for unstrip status in a separate thread.
        """
        self._thread_callback = callback
        self.start_worker(self._poll_unstrip_status)

    def _poll_unstrip_status(self, stop_event: threading.Event) -> None:
        analysis_id = self.safe_get_analysis_id_local()

        while not stop_event.is_set():
            logger.info("RevEng.AI: Polling auto unstrip status...")

            response = self.api_request_returning(
                lambda: self._fetch_unstrip_status(analysis_id=analysis_id)
            )

            response: GenericApiReturn[AutoUnstripResponse]

            if not response.success:
                self.call_callback(response)
                return

            logger.info(f"RevEng.AI: Auto unstrip progress: {response.data.progress}%")

            if response.data.progress == 100:
                self.call_callback(response)
                return

            # Sleep between polls without blocking IDA’s UI
            for _ in range(50):  # 50 * 0.1s = 5s; allows quicker cancellation
                if stop_event.is_set():
                    return
                time.sleep(0.5)

    def _fetch_unstrip_status(self, analysis_id: int) -> AutoUnstripResponse:
        """
        Polls the unstrip status for the given analysis ID.
        """
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            functions_api = FunctionsCoreApi(api_client=api_client)

            result = functions_api.auto_unstrip(
                analysis_id=analysis_id,
                auto_unstrip_request=AutoUnstripRequest(
                    min_similarity=0.9,
                    apply=True,  # Will not let the users pick names if enabled.
                ),
            )

            return result
