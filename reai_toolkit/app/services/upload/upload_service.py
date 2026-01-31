import threading
from pathlib import Path
from typing import Optional, Tuple

from loguru import logger
from revengai import AnalysesCoreApi, Configuration, Symbols
from revengai.models import (
    AnalysisCreateRequest,
    AnalysisCreateResponse,
    AnalysisScope,
    UploadFileType,
)

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.core.utils import collect_symbols_from_ida, sha256_file
from reai_toolkit.app.interfaces.thread_service import IThreadService


class UploadService(IThreadService):
    _thread_callback: Optional[callable] = None

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)

    def start_analysis(
        self,
        file_name: str,
        file_path: str,
        symbols: Symbols,
        debug_file_path: str | None = None,
        tags: Optional[list[str]] = None,
        public: bool = True,
        thread_callback: Optional[callable] = None
    ) -> None:
        """
        Starts the analysis as a background job.
        """
        self._thread_callback = thread_callback
        self.start_worker(
            target=self.analyse_file,
            args=(
                file_name,
                file_path,
                symbols,
                debug_file_path,
                tags,
                public,
            ),
        )

    def call_callback(self, generic_return: GenericApiReturn) -> None:
        self._thread_callback(generic_return)

    def analyse_file(
        self,
        stop_event: threading.Event,
        file_name: str,
        file_path: str,
        symbols: Symbols,
        debug_file_path: str | None = None,
        tags: Optional[list[str]] = None,
        public: bool = True,
    ) -> None:
        """
        Uploads the binary (and optional debug file) and starts an analysis.
        Returns (Bool, Str, Int).
        Bool: True if successful, False if not.
        Str: Message - empty if successful, else error message.
        Int: Analysis ID if successful, else -1.
        """

        debug_sha256 = None

        p = Path(file_path)
        binary_sha256 = sha256_file(p)

        if debug_file_path:
            dp = Path(debug_file_path)
            debug_sha256 = sha256_file(dp)

        # First, upload the file
        upload_response = self.upload_user_file(
            file_path=file_path,
            upload_file_type=UploadFileType.BINARY,  # must match server UploadFileType
            force_overwrite=True,
        )

        if upload_response.success:
            logger.info("RevEng.AI: Uploaded binary file")
        else:
            logger.error(
                f"RevEng.AI: Failed to upload binary file: {upload_response.error_message}"
            )
            self.call_callback(generic_return=upload_response)
            return

        if debug_file_path:
            upload_response = self.upload_user_file(
                file_path=debug_file_path,
                upload_file_type=UploadFileType.DEBUG,  # must match server UploadFileType
                force_overwrite=True,
            )

            if upload_response.success:
                logger.info("RevEng.AI: Uploaded debug file")
            else:
                logger.error(
                    f"RevEng.AI: Failed to upload binary file: {upload_response.error_message}"
                )
                self.call_callback(generic_return=upload_response)

        final_response = self.analyse(
            file_name=file_name,
            binary_sha256=binary_sha256,
            debug_sha256=debug_sha256,
            tags=tags or [],
            public=public,
            symbols=symbols
        )
        self.call_callback(generic_return=final_response)

    def _upload_file_req(
        self,
        upload_file_type: UploadFileType,
        file: Tuple[str, bytes],
        packed_password: Optional[str] = None,
        force_overwrite: bool = False,
    ) -> None:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)
            analyses_client.upload_file(
                upload_file_type=UploadFileType(upload_file_type),
                force_overwrite=force_overwrite,
                packed_password=packed_password,
                file=file,
            )

    def upload_user_file(
        self,
        file_path: str,
        *,
        upload_file_type: UploadFileType,
        packed_password: Optional[str] = None,
        force_overwrite: bool = False,
    ) -> GenericApiReturn[None]:
        p = Path(file_path)
        if not p.is_file():
            return GenericApiReturn(success=False, error_message="File does not exist.")

        try:
            file_bytes = p.read_bytes()
        except Exception:
            return GenericApiReturn(success=False, error_message="File does not exist.")

        response = self.api_request_returning(
            lambda: self._upload_file_req(
                upload_file_type, (p.name, file_bytes), packed_password, force_overwrite
            )
        )

        return response

    def _create_analysis_req(
        self, analysis_request: AnalysisCreateRequest
    ) -> AnalysisCreateResponse:
        with self.yield_api_client(sdk_config=self.sdk_config) as api_client:
            analyses_client = AnalysesCoreApi(api_client)
            analysis_result = analyses_client.create_analysis(
                analysis_create_request=analysis_request
            )
            return analysis_result.data

    def analyse(
        self,
        file_name: str,
        binary_sha256: str,
        symbols: Symbols,
        debug_sha256: Optional[str] = None,
        tags: Optional[list[str]] = None,
        public: bool = True,
    ) -> GenericApiReturn[AnalysisCreateResponse]:
        if symbols.function_boundaries is None:
            return GenericApiReturn(
                success=False,
                error_message="Failed to collect symbols from IDA.",
            )

        logger.info(
            f"RevEng.AI: Collected {len(symbols.function_boundaries)} functions from IDA"
        )
        logger.info(f"RevEng.AI: Base address: 0x{symbols.base_address:X}")

        analysis_create_request = AnalysisCreateRequest(
            filename=file_name,
            sha_256_hash=binary_sha256,
            debug_hash=debug_sha256,
            tags=tags or [],
            analysis_scope=AnalysisScope.PUBLIC if public else AnalysisScope.PRIVATE,
            symbols=symbols,
        )

        response = self.api_request_returning(
            fn=lambda: self._create_analysis_req(analysis_create_request)
        )

        if response.success:
            data: AnalysisCreateResponse | None = response.data
            if data:
                self.netstore_service.put_analysis_id(data.analysis_id)
                self.netstore_service.put_binary_id(data.binary_id)

                logger.info(
                    f"RevEng.AI: Analysis started successfully. Analysis ID: {data.analysis_id}, Binary ID: {data.binary_id}"
                )

        return response
