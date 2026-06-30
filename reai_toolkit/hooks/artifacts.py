from libbs.api import DecompilerInterface
from libbs.artifacts import FunctionHeader, StackVariable
from libbs.decompilers.ida.compat import execute_read
from loguru import logger

from reai_toolkit.app.app import App


@execute_read
def _to_ea(deci: DecompilerInterface, lifted_addr: int) -> int:
    return deci.art_lifter.lower_addr(lifted_addr)


class ArtifactChangeHooks:
    def __init__(self, app: App):
        self.app: App = app
        self._deci: DecompilerInterface | None = None

    def start(self) -> bool:
        if self._deci is not None:
            return True
        try:
            self._deci = DecompilerInterface.discover(
                force_decompiler="ida",
                artifact_change_callbacks={
                    StackVariable: [self._on_stack_variable_changed],
                    FunctionHeader: [self._on_function_header_changed],
                },
            )
            self._deci.start_artifact_watchers()
        except Exception as e:
            logger.error(f"[ArtifactChangeHooks] failed to start: {e}")
            self._deci = None
            return False
        logger.info("[ArtifactChangeHooks] Hook registered.")
        return True

    def stop(self) -> None:
        if self._deci is None:
            return
        try:
            self._deci.stop_artifact_watchers()
        except Exception as e:
            logger.error(f"[ArtifactChangeHooks] failed to stop: {e}")
        self._deci = None

    def _on_stack_variable_changed(self, svar: StackVariable, **kwargs) -> None:
        function_id = self._resolve_function_id(svar.addr)
        if function_id is not None:
            self.app.variable_sync_service.enqueue_change(function_id, svar)

    def _on_function_header_changed(self, fheader: FunctionHeader, **kwargs) -> None:
        function_id = self._resolve_function_id(fheader.addr)
        if function_id is not None:
            self.app.variable_sync_service.enqueue_change(function_id, fheader)

    def _resolve_function_id(self, lifted_addr: int | None) -> int | None:
        if lifted_addr is None or self.app.analysis_sync_service.is_worker_running():
            return None
        if self.app.netstore_service.get_analysis_id() is None:
            return None

        maps = self.app.netstore_service.get_function_mapping()
        if maps is None:
            return None

        ea: int = _to_ea(self._deci, lifted_addr)
        return maps.inverse_function_map.get(str(ea))
