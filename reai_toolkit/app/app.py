from reai_toolkit.app.core import ConfigService, SimpleNetStore
from reai_toolkit.app.services.ai_decomp.ai_decomp_service import AiDecompService
from reai_toolkit.app.services.analysis_status.analysis_status import (
    AnalysisStatusService,
)
from reai_toolkit.app.services.analysis_sync.analysis_sync import AnalysisSyncService
from reai_toolkit.app.services.auth.auth_service import AuthService
from reai_toolkit.app.services.auto_unstrip.auto_unstrip_service import (
    AutoUnstripService,
)
from reai_toolkit.app.services.existing_analyses.existing_analyses_service import (
    ExistingAnalysesService,
)
from reai_toolkit.app.services.matching.matching_service import MatchingService
from reai_toolkit.app.services.rename.rename_service import RenameService
from reai_toolkit.app.services.upload.upload_service import UploadService
from reai_toolkit.app.services.data_types.data_types_service import ImportDataTypesService


class App:
    _ida_version: str = "UNKNOWN"
    _plugin_version: str = "UNKNOWN"

    def __init__(self, ida_version: str = "UNKNOWN", plugin_version: str = "UNKNOWN"):
        self._ida_version = ida_version
        self._plugin_version = plugin_version

        """Initialize the application."""
        self.config_service: ConfigService = ConfigService()
        self.netstore_service: SimpleNetStore = SimpleNetStore()
        self.auth_service: AuthService = AuthService(
            cfg=self.config_service,
            ida_version=self._ida_version,
            plugin_version=self._plugin_version,
        )
        sdk_config = self.auth_service.get_sdk_config()
        self.upload_service = UploadService(
            netstore_service=self.netstore_service,
            sdk_config=sdk_config,
        )
        self.analysis_status_service = AnalysisStatusService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.data_types_service = ImportDataTypesService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.analysis_sync_service = AnalysisSyncService(data_types_service=self.data_types_service,
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.existing_analyses_service = ExistingAnalysesService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.rename_service = RenameService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.auto_unstrip_service = AutoUnstripService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.ai_decomp_service = AiDecompService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )
        self.matching_service = MatchingService(
            netstore_service=self.netstore_service, sdk_config=sdk_config
        )

