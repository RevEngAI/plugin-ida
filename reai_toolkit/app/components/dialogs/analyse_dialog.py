import os
from typing import Any, Callable, TypedDict

import idaapi
from loguru import logger
from PySide6.QtCore import Qt


from revengai import Symbols
from revengai.models.function_boundary import FunctionBoundary

from reai_toolkit.app.components.dialogs.base_dialog import DialogBase
from reai_toolkit.app.core.qt_compat import QT_VER, QtGui, QtWidgets
from reai_toolkit.app.services.upload.upload_service import UploadService
from reai_toolkit.app.core.utils import collect_symbols_from_ida

if QT_VER == 6:
    from reai_toolkit.app.components.forms.analyse.analyse_panel_ui_uic6 import (
        Ui_AuthPanel,
    )
else:
    from reai_toolkit.app.components.forms.analyse.analyse_panel_ui_uic5 import (
        Ui_AuthPanel,
    )


class FunctionBoundaryEx(TypedDict):
    boundary: FunctionBoundary
    enabled: bool


class SelectFunctionsWindow(QtWidgets.QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("RevEng.AI — Select Functions")
        self.setGeometry(200, 200, 500, 400)
        
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(QtWidgets.QLabel("Select Function Boundaries to upload to RevEng.AI"))

        # Create and configure table
        self.table = QtWidgets.QTableWidget()
        self.table.setRowCount(len(AnalyseDialog.cached_function_boundaries))

        headers: list[str] = ["Function", "Virtual Address", "Upload"]
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)

        self.select_all_checkbox = QtWidgets.QCheckBox("Select All")
        self.select_all_checkbox.stateChanged.connect(self.toggle_all)
        layout.addWidget(self.select_all_checkbox)

        # Populate the table
        for i, item in enumerate(AnalyseDialog.cached_function_boundaries.values()):
            boundary: FunctionBoundary = item["boundary"]
            self.table.setItem(i, 0, QtWidgets.QTableWidgetItem(boundary.mangled_name))
            self.table.setItem(i, 1, QtWidgets.QTableWidgetItem(f"0x{boundary.start_address:0x}"))

            checkbox_item = QtWidgets.QTableWidgetItem()
            checkbox_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)

            if item["enabled"]:
                checkbox_item.setCheckState(Qt.CheckState.Checked)
            else:
                checkbox_item.setCheckState(Qt.CheckState.Unchecked)

            self.table.setItem(i, 2, checkbox_item)

        self.table.resizeColumnsToContents()

        # Update "Select All" when individual checkboxes change
        self.table.itemChanged.connect(self.update_select_all_state)
        layout.addWidget(self.table)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()
        
        close_button = QtWidgets.QPushButton("Close")

        close_button.clicked.connect(self.select_function_boundary_subset)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
    
    def select_function_boundary_subset(self) -> None:
        for row in range(self.table.rowCount()):
            item: QtWidgets.QTableWidgetItem | None = self.table.item(row, 2)
            if item and item.checkState() != Qt.CheckState.Checked:
                vaddr_widget: QtWidgets.QTableWidgetItem | None = self.table.item(row, 1)
                if vaddr_widget is None:
                    continue

                # Convert from hexstring representation to int
                vaddr: int = int(vaddr_widget.text(), 16)

                entry: FunctionBoundaryEx | None = AnalyseDialog.cached_function_boundaries.get(vaddr)
                if entry:
                    entry["enabled"] = False
        
        self.close()

    def toggle_all(self, state) -> None:
        # Block signals to prevent itemChanged from firing for each row
        self.table.blockSignals(True)
        
        new_state = Qt.CheckState.Checked if state == 2 else Qt.CheckState.Unchecked
        for row in range(self.table.rowCount()):
            item: QtWidgets.QTableWidgetItem | None = self.table.item(row, 2)
            if item:
                item.setCheckState(new_state)
        
        self.table.blockSignals(False)

    def update_select_all_state(self, item: QtWidgets.QTableWidgetItem) -> None:
        # Only respond to checkbox column changes
        if item.column() != 2:
            return
        
        # Block signals to prevent recursive calls
        self.select_all_checkbox.blockSignals(True)
        
        # Count checked items
        checked_count = 0
        for row in range(self.table.rowCount()):
            checkbox: QtWidgets.QTableWidgetItem | None = self.table.item(row, 2)
            if checkbox and checkbox.checkState() == Qt.CheckState.Checked:
                checked_count += 1
        
        # Update Select All checkbox state
        if checked_count == 0:
            self.select_all_checkbox.setCheckState(Qt.CheckState.Unchecked)
        elif checked_count == self.table.rowCount():
            self.select_all_checkbox.setCheckState(Qt.CheckState.Checked)
        else:
            self.select_all_checkbox.setCheckState(Qt.CheckState.PartiallyChecked)
        
        self.select_all_checkbox.blockSignals(False)

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

    file_path: str = None
    file_name: str = None
    debug_file_path: str = None
    upload_service: UploadService = None
    callback: Callable[..., Any] = None

    # We need these to persist between dialog windows, hence storing them as class member variables.
    cached_symbols: Symbols | None = None
    cached_function_boundaries: dict[int, FunctionBoundaryEx] = {}

    def __init__(
        self,
        *,
        upload_service: UploadService,
        callback: Callable[..., Any],
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent=parent)
        self.setWindowTitle("RevEng.AI — Analyse")
        self.setModal(False)
        self.upload_service = upload_service
        self.callback = callback
        self.file_path = idaapi.get_input_file_path()
        self.file_name = idaapi.get_root_filename()
        self.ui = Ui_AuthPanel()
        self.ui.setupUi(self)
        self.setFixedSize(self.size())

        logo_path = self._find_resource(self.base_logo_path)
        px = QtGui.QPixmap(logo_path)
        self.ui.logoArea.setPixmap(px)

        self.ui.apiFileName.setText(self.file_name)

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
        
        symbols: Symbols | None = collect_symbols_from_ida()
        if symbols is None:
            logger.warning("failed to obtain symbols from IDA database when attempting to select functions to upload")
            return

        if symbols.function_boundaries is None:
            logger.warning("failed to obtain function boundaries from symbols extracted from IDA database when attempting to upload function")
            return
        
        if AnalyseDialog.cached_symbols and AnalyseDialog.cached_symbols.base_address != symbols.base_address:
            logger.debug(f"rebasing cached function boundaries as base address has been changed from 0x{AnalyseDialog.cached_symbols.base_address:0x} to 0x{symbols.base_address:0x}")
            rebased_func_boundaries: dict[int, FunctionBoundaryEx] = self._rebase_cached_function_boundaries(AnalyseDialog.cached_symbols.base_address, symbols.base_address)
            AnalyseDialog.cached_function_boundaries = rebased_func_boundaries

        AnalyseDialog.cached_symbols = symbols

        if len(AnalyseDialog.cached_function_boundaries) == 0:
            AnalyseDialog.cached_function_boundaries = {func.start_address: FunctionBoundaryEx(boundary=func, enabled=True) for func in symbols.function_boundaries}
        else:
            # Check if IDA has identified any new functions that have yet to be cached.
            self._update_cached_function_boundaries(symbols)

        # Hook up button to subset functions submitted for upload
        self.ui.selectFuncs.clicked.connect(self._on_functions_click)

    def pick_debug_file(self):
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

    def _on_private_click(self):
        self.ui.radioButton_2.setChecked(False)  # Public
        self.ui.radioButton.setChecked(True)  # Private

    def _on_public_click(self):
        self.ui.radioButton.setChecked(False)  # Private
        self.ui.radioButton_2.setChecked(True)  # Public

    def _on_functions_click(self) -> None:
        selectFuncsWindow = SelectFunctionsWindow(parent=self)
        selectFuncsWindow.show()

    def _update_cached_function_boundaries(self, new_symbols: Symbols) -> None:
        if new_symbols.function_boundaries is None:
            return
        
        for func_boundary in new_symbols.function_boundaries:
            if AnalyseDialog.cached_function_boundaries.get(func_boundary.start_address) is None:
                logger.debug(f"updating cached function boundaries with newly identified function: {func_boundary}")
                AnalyseDialog.cached_function_boundaries[func_boundary.start_address] = FunctionBoundaryEx(boundary=func_boundary, enabled=True)

    def _rebase_cached_function_boundaries(self, old_base_addr: int, new_base_addr: int) -> dict[int, FunctionBoundaryEx]:
        out: dict[int, FunctionBoundaryEx] = {}

        base_diff: int = new_base_addr - old_base_addr

        for func_boundary in AnalyseDialog.cached_function_boundaries.values():
            start_vaddr: int = func_boundary["boundary"].start_address + base_diff
            end_vaddr: int = func_boundary["boundary"].end_address + base_diff
            new_boundary: FunctionBoundary = FunctionBoundary(
                mangled_name=func_boundary["boundary"].mangled_name,
                start_address=start_vaddr,
                end_address=end_vaddr
                )
            
            out[start_vaddr] = FunctionBoundaryEx(boundary=new_boundary, enabled=func_boundary["enabled"])

        return out

    def _on_ok(self) -> None:
        if AnalyseDialog.cached_symbols is None:
            return

        # Pass only the subset of function boundaries selected by the user (by default, everything)  
        AnalyseDialog.cached_symbols.function_boundaries = [x["boundary"] for x in AnalyseDialog.cached_function_boundaries.values() if x["enabled"]]

        self.upload_service.start_analysis(
            file_name=self.ui.apiFileName.text().strip() or self.file_name,
            file_path=self.file_path,
            symbols=AnalyseDialog.cached_symbols,
            debug_file_path=self.debug_file_path,
            tags=[],
            public=True if self.ui.radioButton_2.isChecked() else False,
            thread_callback=self.callback,
        )

        self.accept()
