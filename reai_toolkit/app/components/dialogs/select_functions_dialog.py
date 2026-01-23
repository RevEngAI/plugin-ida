from enum import IntEnum
from typing import TypedDict
from functools import partial

from revengai.models.function_boundary import FunctionBoundary
from reai_toolkit.app.core.qt_compat import QtWidgets, QtCore


class SelectFunctionTableColumns(IntEnum):
    NAME = 0
    VADDR = 1
    CHECKBOX = 2


class FunctionBoundaryEx(TypedDict):
    boundary: FunctionBoundary
    enabled: bool


class SelectFunctionsWindow(QtWidgets.QDialog):
    def __init__(
        self, function_boundaries: dict[int, FunctionBoundaryEx], parent=None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("RevEng.AI — Select Functions")
        
        # Size relative to screen
        screen = QtWidgets.QApplication.primaryScreen().geometry()
        width = int(screen.width() * 0.5)
        height = int(screen.height() * 0.6)
        self.resize(width, height)
        self.setMinimumSize(500, 400)

        layout = QtWidgets.QVBoxLayout(self)
        
        # Header label - fixed height
        header_label = QtWidgets.QLabel("Select Functions to Analyse")
        header_label.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Fixed
        )
        layout.addWidget(header_label)

        # Select all checkbox - fixed height
        self.select_all_checkbox = QtWidgets.QCheckBox("Select All")
        self.select_all_checkbox.stateChanged.connect(self.toggle_all)
        layout.addWidget(self.select_all_checkbox)

        # Table - expands to fill available space
        self.table = QtWidgets.QTableWidget()
        self.table.setRowCount(len(function_boundaries))
        self.table.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Expanding
        )

        headers: list[str] = ["Function", "Virtual Address", "Upload"]
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)

        # Populate the table
        for row, item in enumerate(function_boundaries.values()):
            boundary: FunctionBoundary = item["boundary"]
            self.table.setItem(
                row,
                SelectFunctionTableColumns.NAME,
                QtWidgets.QTableWidgetItem(boundary.mangled_name),
            )
            self.table.setItem(
                row,
                SelectFunctionTableColumns.VADDR,
                QtWidgets.QTableWidgetItem(f"0x{boundary.start_address:0x}"),
            )

            checkbox_item = QtWidgets.QTableWidgetItem()
            checkbox_item.setFlags(
                QtCore.Qt.ItemFlag.ItemIsUserCheckable
                | QtCore.Qt.ItemFlag.ItemIsEnabled
            )

            if item["enabled"]:
                checkbox_item.setCheckState(QtCore.Qt.CheckState.Checked)
            else:
                checkbox_item.setCheckState(QtCore.Qt.CheckState.Unchecked)

            self.table.setItem(
                row, SelectFunctionTableColumns.CHECKBOX, checkbox_item
            )

        # Column sizing - make function name column stretch
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(
            SelectFunctionTableColumns.NAME,
            QtWidgets.QHeaderView.ResizeMode.Stretch
        )
        header.setSectionResizeMode(
            SelectFunctionTableColumns.VADDR,
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        header.setSectionResizeMode(
            SelectFunctionTableColumns.CHECKBOX,
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )

        # Update "Select All" when individual checkboxes change
        self.table.itemChanged.connect(self.update_select_all_state)
        layout.addWidget(self.table, stretch=1)  # Give table the stretch

        # Button layout - fixed height
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()

        close_button = QtWidgets.QPushButton("Close")
        close_button.clicked.connect(
            partial(self.select_function_boundary_subset, function_boundaries)
        )
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)
    def select_function_boundary_subset(
        self, function_boundaries: dict[int, FunctionBoundaryEx]
    ) -> None:
        for row in range(self.table.rowCount()):
            item: QtWidgets.QTableWidgetItem | None = self.table.item(
                row, SelectFunctionTableColumns.CHECKBOX
            )
            if item is None:
                continue

            vaddr_widget: QtWidgets.QTableWidgetItem | None = self.table.item(
                row, SelectFunctionTableColumns.VADDR
            )
            if vaddr_widget is None:
                continue

            # Convert from hexstring representation to int
            vaddr: int = int(vaddr_widget.text(), 16)

            entry: FunctionBoundaryEx | None = function_boundaries.get(vaddr)
            if entry:
                entry["enabled"] = item.checkState() == QtCore.Qt.CheckState.Checked

        self.close()

    def toggle_all(self, state) -> None:
        # Block signals to prevent itemChanged from firing for each row
        self.table.blockSignals(True)

        new_state: QtCore.Qt.CheckState | QtCore.Qt.CheckState = (
            QtCore.Qt.CheckState.Checked
            if state == SelectFunctionTableColumns.CHECKBOX
            else QtCore.Qt.CheckState.Unchecked
        )
        for row in range(self.table.rowCount()):
            item: QtWidgets.QTableWidgetItem | None = self.table.item(
                row, SelectFunctionTableColumns.CHECKBOX
            )
            if item:
                item.setCheckState(new_state)

        self.table.blockSignals(False)

    def update_select_all_state(self, item: QtWidgets.QTableWidgetItem) -> None:
        # Only respond to checkbox column changes
        if item.column() != SelectFunctionTableColumns.CHECKBOX:
            return

        # Block signals to prevent recursive calls
        self.select_all_checkbox.blockSignals(True)

        # Count checked items
        checked_count = 0
        for row in range(self.table.rowCount()):
            checkbox: QtWidgets.QTableWidgetItem | None = self.table.item(
                row, SelectFunctionTableColumns.CHECKBOX
            )
            if checkbox and checkbox.checkState() == QtCore.Qt.CheckState.Checked:
                checked_count += 1

        # Update Select All checkbox state
        if checked_count == 0:
            self.select_all_checkbox.setCheckState(QtCore.Qt.CheckState.Unchecked)
        elif checked_count == self.table.rowCount():
            self.select_all_checkbox.setCheckState(QtCore.Qt.CheckState.Checked)
        else:
            self.select_all_checkbox.setCheckState(
                QtCore.Qt.CheckState.PartiallyChecked
            )

        self.select_all_checkbox.blockSignals(False)
