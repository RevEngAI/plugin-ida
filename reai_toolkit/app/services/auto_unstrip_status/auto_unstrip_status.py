import threading
import time
from typing import Any, Callable

from loguru import logger
from revengai import AnalysesCoreApi, AutoUnstripStatusOutputBody, Configuration

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.interfaces.thread_service import IThreadService

POLL_INTERVAL_SECONDS = 5
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"


class AutoUnstripStatusService(IThreadService):
    _thread_callback: Callable[..., Any] = None

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def call_callback(self, generic_return: GenericApiReturn) -> None:
        self._thread_callback(generic_return)

    def start_polling(
        self,
        analysis_id: int,
        thread_callback: Callable[..., Any],
        resync_if_already_complete: bool,
    ) -> None:
        self._thread_callback = thread_callback
        self.stop_worker()
        self.start_worker(
            target=self._poll_auto_unstrip_status,
            args=(analysis_id, resync_if_already_complete),
        )

    def _api_get_status(self, analysis_id: int) -> str | None:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)
            body: AutoUnstripStatusOutputBody = (
                analyses_client.v3_get_analysis_auto_unstrip_status(analysis_id=analysis_id)
            )
            return body.status if body else None

    def _poll_auto_unstrip_status(
        self,
        stop_event: threading.Event,
        analysis_id: int,
        resync_if_already_complete: bool,
    ) -> None:
        first_poll: bool = True
        while not stop_event.is_set():
            status_response = self.api_request_returning(
                fn=lambda: self._api_get_status(analysis_id)
            )

            if not status_response.success:
                self.call_callback(generic_return=status_response)
                return

            status: str | None = status_response.data
            logger.info(f"RevEng.AI: Auto-unstrip status - {status}")

            if status == STATUS_COMPLETED:
                if first_poll and not resync_if_already_complete:
                    return
                self.call_callback(
                    generic_return=GenericApiReturn(success=True, data=analysis_id)
                )
                return

            if status == STATUS_FAILED:
                self.call_callback(
                    generic_return=GenericApiReturn(
                        success=False,
                        error_message="RevEng.AI auto-unstrip failed.",
                    )
                )
                return

            first_poll = False
            time.sleep(POLL_INTERVAL_SECONDS)
