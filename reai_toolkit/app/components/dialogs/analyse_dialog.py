import os
from typing import Any, Callable

import idaapi
from loguru import logger

from revengai import Symbols
from revengai.models.function_boundary import FunctionBoundary

from reai_toolkit.app.components.dialogs.base_dialog import DialogBase
from reai_toolkit.app.core.qt_compat import QT_VER, QtCore, QtGui, QtWidgets
from reai_toolkit.app.services.auth.auth_service import AuthService
from reai_toolkit.app.services.upload.upload_service import UploadService
from reai_toolkit.app.core.utils import collect_symbols_from_ida
from reai_toolkit.app.components.dialogs.select_functions_dialog import (
    FunctionBoundaryEx,
    SelectFunctionsWindow,
)

if QT_VER == 6:
    from reai_toolkit.app.components.forms.analyse.analyse_panel_ui_uic6 import (
        Ui_AuthPanel,
    )
else:
    from reai_toolkit.app.components.forms.analyse.analyse_panel_ui_uic5 import (
        Ui_AuthPanel,
    )


ENTHUSIAST_PRIVATE_TOOLTIP = (
    "Private analyses are not available on the Enthusiast tier. "
    "Upgrade your plan to create private analyses."
)


class AnalyseDialog(DialogBase):
    """
    Modeless dialog using the compiled UI.
    DialogBase provides:
    - base_logo_path
    - _find_resource()
    - result_data

    AnalyseDialog:
        - Stores the analysis ID in result_data if successful (analysis queued)
        - Otherwise will display error message to user (will not close)

    'result_data' is returned from the dialog closure.

    """

    # We need these to persist between dialog windows, hence storing them as class member variables.
    cached_symbols: Symbols | None = None
    cached_function_boundaries: dict[int, FunctionBoundaryEx] = {}

    def __init__(
        self,
        *,
        upload_service: UploadService,
        auth_service: AuthService,
        callback: Callable[..., Any],
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent=parent)
        self.setWindowTitle("RevEng.AI — Analyse")
        self.setModal(False)
        self.upload_service: UploadService = upload_service
        self.auth_service: AuthService = auth_service
        self.callback: Callable[..., Any] = callback
        self.file_path: str = idaapi.get_input_file_path()
        self.file_name: str = idaapi.get_root_filename()
        self.debug_file_path: str | None = None
        self.ui: Ui_AuthPanel = Ui_AuthPanel()
        self.ui.setupUi(self)
        self.setFixedSize(self.size())

        logo_path: str | None = self._find_resource(self.base_logo_path)
        if logo_path:
            px: QtGui.QPixmap = QtGui.QPixmap(logo_path)
            self.ui.logoArea.setPixmap(px)  # type: ignore

        self.ui.apiFileName.setText(self.file_name)

        self.initialize_function_boundaries()

        # Wire buttons
        self.ui.okButton.clicked.connect(self._on_ok)
        self.ui.cancelButton.clicked.connect(self.reject)

        # Hook up the Browse button
        self.ui.btnBrowseDebug.clicked.connect(self.pick_debug_file)

        # Hook up radio buttons
        self.ui.radioButton.clicked.connect(self._on_private_click)  # Private
        self.ui.radioButton.setChecked(False)
        self.ui.radioButton_2.clicked.connect(self._on_public_click)  # Public
        self.ui.radioButton_2.setChecked(True)

        self.ui.horizontalLayout.setSpacing(24)
        self.ui.horizontalLayout.addStretch(1)

        self._apply_tier_restrictions()

        # Hook up button to subset functions submitted for upload
        self.ui.selectFuncs.clicked.connect(self._on_functions_click)

    def _apply_tier_restrictions(self) -> None:
        """
        Enthusiast-tier users cannot create private analyses, so disable the
        Private scope option, force Public, and explain why on hover.
        """
        if not self.auth_service.is_enthusiast():
            return

        self._on_public_click()
        self.ui.radioButton.setEnabled(False)
        self.ui.radioButton.setToolTip(ENTHUSIAST_PRIVATE_TOOLTIP)
        self.ui.labelScope.setToolTip(ENTHUSIAST_PRIVATE_TOOLTIP)
        # Qt suppresses tooltip display for disabled widgets, so surface it via
        # an event filter instead.
        self.ui.radioButton.installEventFilter(self)

    def eventFilter(self, obj: QtCore.QObject, event: QtCore.QEvent) -> bool:
        if (
            obj is self.ui.radioButton
            and event.type() == QtCore.QEvent.Type.ToolTip
            and not self.ui.radioButton.isEnabled()
        ):
            QtWidgets.QToolTip.showText(
                event.globalPos(), ENTHUSIAST_PRIVATE_TOOLTIP, self.ui.radioButton
            )
            return True
        return super().eventFilter(obj, event)

    def pick_debug_file(self) -> None:
        filters = (
            "Windows PDB (*.pdb);;"
            "Linux DWARF (separate) (*.debug *.debug.gz *.dwp *.dwo);;"
            "All Supported (*.pdb *.debug *.debug.gz *.dwp *.dwo)"
        )
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select Debug Symbols", "", filters
        )
        if path:
            self.debug_file_path = path
            self.ui.apiDebugFile.setText(os.path.basename(path))

    def _on_private_click(self) -> None:
        self.ui.radioButton_2.setChecked(False)  # Public
        self.ui.radioButton.setChecked(True)  # Private

    def _on_public_click(self) -> None:
        self.ui.radioButton.setChecked(False)  # Private
        self.ui.radioButton_2.setChecked(True)  # Public

    def _on_functions_click(self) -> None:
        selectFuncsWindow = SelectFunctionsWindow(
            AnalyseDialog.cached_function_boundaries, parent=self
        )
        selectFuncsWindow.show()

    def _on_ok(self) -> None:
        if AnalyseDialog.cached_symbols is None:
            return

        # Send all boundaries but mark which ones to include in analysis
        for entry in AnalyseDialog.cached_function_boundaries.values():
            entry["boundary"].include_in_analysis = entry["enabled"]

        AnalyseDialog.cached_symbols.function_boundaries = [
            x["boundary"]
            for x in AnalyseDialog.cached_function_boundaries.values()
        ]

        self.upload_service.start_analysis(
            file_name=self.ui.apiFileName.text().strip() or self.file_name,
            file_path=self.file_path,
            symbols=AnalyseDialog.cached_symbols,
            debug_file_path=self.debug_file_path,
            tags=[],
            public=self.ui.radioButton_2.isChecked(),
            thread_callback=self.callback,
        )

        self.accept()

    def initialize_function_boundaries(self) -> None:
        symbols: Symbols | None = collect_symbols_from_ida()
        if symbols is None:
            logger.warning("failed to obtain symbols from IDA database")
            return

        if symbols.function_boundaries is None:
            logger.warning(
                "failed to obtain function boundaries from symbols extracted from IDA database"
            )
            return

        if (
            AnalyseDialog.cached_symbols
            and AnalyseDialog.cached_symbols.base_address != symbols.base_address
        ):
            logger.debug(
                f"rebasing cached function boundaries as base address has been changed from 0x{AnalyseDialog.cached_symbols.base_address:0x} to 0x{symbols.base_address:0x}"
            )
            rebased_func_boundaries: dict[int, FunctionBoundaryEx] = (
                self._rebase_cached_function_boundaries(
                    AnalyseDialog.cached_symbols.base_address, symbols.base_address
                )
            )
            AnalyseDialog.cached_function_boundaries = rebased_func_boundaries

        AnalyseDialog.cached_symbols = symbols

        if len(AnalyseDialog.cached_function_boundaries) == 0:
            AnalyseDialog.cached_function_boundaries = {
                func.start_address: FunctionBoundaryEx(boundary=func, enabled=True)
                for func in symbols.function_boundaries
            }
        else:
            # Check if IDA has identified any new functions that have yet to be cached.
            self._update_cached_function_boundaries(symbols)

    def _update_cached_function_boundaries(self, new_symbols: Symbols) -> None:
        if new_symbols.function_boundaries is None:
            return

        for func_boundary in new_symbols.function_boundaries:
            if (
                AnalyseDialog.cached_function_boundaries.get(
                    func_boundary.start_address
                )
                is None
            ):
                logger.debug(
                    f"updating cached function boundaries with newly identified function: {func_boundary}"
                )
                AnalyseDialog.cached_function_boundaries[
                    func_boundary.start_address
                ] = FunctionBoundaryEx(boundary=func_boundary, enabled=True)

    def _rebase_cached_function_boundaries(
        self, old_base_addr: int, new_base_addr: int
    ) -> dict[int, FunctionBoundaryEx]:
        out: dict[int, FunctionBoundaryEx] = {}

        base_diff: int = new_base_addr - old_base_addr

        for func_boundary in AnalyseDialog.cached_function_boundaries.values():
            start_vaddr: int = func_boundary["boundary"].start_address + base_diff
            end_vaddr: int = func_boundary["boundary"].end_address + base_diff
            new_boundary: FunctionBoundary = FunctionBoundary(
                mangled_name=func_boundary["boundary"].mangled_name,
                start_address=start_vaddr,
                end_address=end_vaddr,
            )

            out[start_vaddr] = FunctionBoundaryEx(
                boundary=new_boundary, enabled=func_boundary["enabled"]
            )

        return out
