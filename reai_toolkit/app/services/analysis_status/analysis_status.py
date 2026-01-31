import re
import threading
import time
from typing import Any, Callable

from loguru import logger
from revengai import AnalysesCoreApi, BaseResponseStatus, Configuration, Logs, StatusOutput

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.interfaces.thread_service import IThreadService


class AnalysisStatusService(IThreadService):
    _thread_callback: Callable[..., Any] = None

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def call_callback(self, generic_return: GenericApiReturn) -> None:
        self._thread_callback(generic_return)

    def start_polling(self, analysis_id: str, thread_callback: Callable[..., Any]) -> None:
        """
        Starts polling the analysis status as a background job.
        """
        self._thread_callback = thread_callback
        # Ensure any existing worker is stopped before starting a new one
        self.stop_worker()
        self.start_worker(
            target=self._poll_analysis_status,
            args=(analysis_id,),
        )

    def _api_get_status(self, analysis_id: int) -> StatusOutput | None:
        """
        Calls the API to get the analysis status.
        Returns GenericApiReturn with status string on success.
        """
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)

            analysis_status: BaseResponseStatus = analyses_client.get_analysis_status(analysis_id=analysis_id)
            status: StatusOutput | None = analysis_status.data
            if status:
                self.netstore_service.put_analysis_status(status.analysis_status)

            return analysis_status.data

    def _api_get_logs(self, analysis_id: int) -> Logs | None:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)
            response = analyses_client.get_analysis_logs(analysis_id)
            return response.data

    def _poll_analysis_status(self, stop_event: threading.Event, analysis_id: int) -> None:
        """
        Polls the analysis status until completion or failure.
        """
        while not stop_event.is_set():
            while True:
                # Sleep between polls without blocking IDA’s UI
                time.sleep(5)

                get_status_response = self.api_request_returning(
                    fn=lambda: self._api_get_status(analysis_id)
                )

                if not get_status_response.success:
                    self.call_callback(generic_return=get_status_response)
                    return

                get_logs_response = self.api_request_returning(
                    fn=lambda: self._api_get_logs(analysis_id)
                )

                logs: Logs | None
                if get_logs_response.success and (logs := get_logs_response.data):
                    for line in logs.logs.splitlines():
                        line_without_timestamp = re.sub(r"^[\d\-]+ [\d:]+ - ", "", line)
                        logger.debug(f"RevEng.AI Remote Analysis - {line_without_timestamp}")

                if get_status_response.data and (status := get_status_response.data.analysis_status):
                    logger.info(f"RevEng.AI: Status - {status}")
                    if status == "Complete":
                        self.call_callback(
                            generic_return=GenericApiReturn(
                                success=True,
                                data=analysis_id,
                            )
                        )
                        return
                    elif status == "Error":
                        self.call_callback(
                            generic_return=GenericApiReturn(
                                success=False,
                                error_message="RevEng analysis failed! Please retry the analysis.",
                            )
                        )
                        return
