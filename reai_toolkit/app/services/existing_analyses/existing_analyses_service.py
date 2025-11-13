from pathlib import Path
from typing import List, Optional

from revengai import AnalysesCoreApi, Configuration
from revengai.models import (
    AnalysisRecord,
    AppApiRestV2AnalysesEnumsOrderBy,
    Order,
    StatusInput,
    Workspace,
)

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.core.utils import get_function_boundaries_hash, sha256_file
from reai_toolkit.app.interfaces.thread_service import IThreadService


class ExistingAnalysesService(IThreadService):
    _thread_callback: Optional[callable] = None

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def _fetch_analysis_records(self, sha256_hash: str) -> List[AnalysisRecord]:
        """
        Helper method to fetch analysis records by SHA256 hash.
        Returns a list of AnalysisRecord.
        """

        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)

            result = analyses_client.list_analyses(
                workspace=[Workspace.PERSONAL],
                status=[StatusInput.COMPLETE],
                sha256_hash=sha256_hash,
                order_by=AppApiRestV2AnalysesEnumsOrderBy.CREATED,
                order=Order.DESC,
            )

            return result.data.results

    def fetch_analyses_same_hash(
        self, file_path: str
    ) -> GenericApiReturn[List[AnalysisRecord]]:
        """
        Fetches analyses with the same hash as the given file.
        Returns a list of analysis summaries.
        """

        file_path = Path(file_path)

        binary_sha256 = sha256_file(file_path)
        boundary_hash = get_function_boundaries_hash()

        response = self.api_request_returning(
            lambda: self._fetch_analysis_records(binary_sha256)
        )

        if not response.success:
            return response

        data: List[AnalysisRecord] = response.data

        # Filter analyses by boundary hash
        filtered_analyses = [
            analysis
            for analysis in data
            if analysis.function_boundaries_hash == boundary_hash
        ]

        return GenericApiReturn(
            success=True,
            data=filtered_analyses,
        )
