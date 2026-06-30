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
        logger.debug("[ArtifactChangeHooks] starting...")
        try:
            deci = DecompilerInterface.discover(force_decompiler="ida")
            deci.artifact_change_callbacks[StackVariable].append(self._on_stack_variable_changed)
            deci.artifact_change_callbacks[FunctionHeader].append(self._on_function_header_changed)
            deci.start_artifact_watchers()
        except Exception as e:
            logger.error(f"[ArtifactChangeHooks] failed to start: {e}")
            return False
        self._deci = deci
        self.app.variable_sync_service.attach_decompiler(deci)
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
        logger.debug(f"[ArtifactChangeHooks] stack var changed @ {svar.addr}")
        function_id = self._resolve_function_id(svar.addr)
        if function_id is not None:
            self.app.variable_sync_service.enqueue_change(function_id, svar.addr, svar)

    def _on_function_header_changed(self, fheader: FunctionHeader, **kwargs) -> None:
        logger.debug(f"[ArtifactChangeHooks] function header changed @ {fheader.addr}")
        function_id = self._resolve_function_id(fheader.addr)
        if function_id is not None:
            self.app.variable_sync_service.enqueue_change(function_id, fheader.addr, fheader)

    def _resolve_function_id(self, lifted_addr: int | None) -> int | None:
        if lifted_addr is None:
            return None
        if self.app.analysis_sync_service.is_worker_running():
            logger.debug("[ArtifactChangeHooks] sync in progress; skipping")
            return None
        if self.app.netstore_service.get_analysis_id() is None:
            logger.debug("[ArtifactChangeHooks] no analysis id; skipping")
            return None

        maps = self.app.netstore_service.get_function_mapping()
        if maps is None:
            logger.debug("[ArtifactChangeHooks] no function mapping; skipping")
            return None

        ea: int = _to_ea(self._deci, lifted_addr)
        function_id = maps.inverse_function_map.get(str(ea))
        if function_id is None:
            logger.debug(f"[ArtifactChangeHooks] no function id for {hex(ea)}; skipping")
        else:
            logger.debug(f"[ArtifactChangeHooks] resolved function id {function_id} for {hex(ea)}")
        return function_id
