from enum import IntEnum
from typing import Callable, TypedDict
from functools import partial

from reai_toolkit.app.core.qt_compat import QtWidgets, QtCore
from revengai.models.function_mapping import FunctionMapping


class ImportFunctionTableColumns(IntEnum):
    OLD_NAME = 0
    NEW_NAME = 1
    VADDR = 2
    CHECKBOX = 3


class MatchedFunction(TypedDict):
    old_name: str
    new_name: str
    vaddr: int
    enabled: bool


class ImportFunctionsWindow(QtWidgets.QDialog):
    def __init__(
        self, matched_functions: dict[int, MatchedFunction], mapping: FunctionMapping, function_sync_callback: Callable[[FunctionMapping], None], parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("RevEng.AI — Select Functions")
        self._function_sync_callback: Callable[[FunctionMapping], None] = function_sync_callback
        self._mapping: FunctionMapping = mapping

        # Size relative to screen
        screen: QtCore.QRect = QtWidgets.QApplication.primaryScreen().geometry()
        width = int(screen.width() * 0.4)
        height = int(screen.height() * 0.5)
        self.resize(width, height)
        self.setMinimumSize(500, 400)

        layout = QtWidgets.QVBoxLayout(self)

        # Header label - fixed height
        header_label = QtWidgets.QLabel("Select Functions to Import")
        header_label.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Fixed
        )
        layout.addWidget(header_label)

        # Select all checkbox - fixed height
        self.select_all_checkbox = QtWidgets.QCheckBox("Select All")
        self.select_all_checkbox.stateChanged.connect(self.toggle_all)
        layout.addWidget(self.select_all_checkbox)

        # Table - expands to fill available space
        self.table = QtWidgets.QTableWidget()
        self.table.setRowCount(len(matched_functions))
        self.table.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Expanding,
        )

        headers: list[str] = ["Old Name", "New Name", "Virtual Address", "Import"]

        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)

        # Populate the table
        for row, item in enumerate(matched_functions.values()):
            self.table.setItem(
                row,
                ImportFunctionTableColumns.OLD_NAME,
                QtWidgets.QTableWidgetItem(item["old_name"]),
            )
            self.table.setItem(
                row,
                ImportFunctionTableColumns.NEW_NAME,
                QtWidgets.QTableWidgetItem(item["new_name"]),
            )

            self.table.setItem(
                row,
                ImportFunctionTableColumns.VADDR,
                QtWidgets.QTableWidgetItem(f"0x{item['vaddr']:0x}")
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

            self.table.setItem(row, ImportFunctionTableColumns.CHECKBOX, checkbox_item)

        # Column sizing - make function name column stretch
        header: QtWidgets.QHeaderView = self.table.horizontalHeader()
        header.setSectionResizeMode(
            ImportFunctionTableColumns.OLD_NAME, QtWidgets.QHeaderView.ResizeMode.Stretch
        )

        header.setSectionResizeMode(
            ImportFunctionTableColumns.NEW_NAME, QtWidgets.QHeaderView.ResizeMode.Stretch
        )

        header.setSectionResizeMode(
            ImportFunctionTableColumns.VADDR,
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents,
        )

        header.setSectionResizeMode(
            ImportFunctionTableColumns.CHECKBOX,
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents,
        )

        # Update "Select All" when individual checkboxes change
        self.table.itemChanged.connect(self.update_select_all_state)
        layout.addWidget(self.table, stretch=1)  # Give table the stretch

        # Button layout - fixed height
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()

        close_button = QtWidgets.QPushButton("Close")
        close_button.clicked.connect(
            partial(self.subset_matched_functions, matched_functions)
        )
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)

    def subset_matched_functions(
        self, matched_funcs: dict[int, MatchedFunction]
    ) -> None:
        for row in range(self.table.rowCount()):
            item: QtWidgets.QTableWidgetItem | None = self.table.item(
                row, ImportFunctionTableColumns.CHECKBOX
            )
            if item is None:
                continue

            vaddr_widget: QtWidgets.QTableWidgetItem | None = self.table.item(
                row, ImportFunctionTableColumns.VADDR
            )
            if vaddr_widget is None:
                continue

            # Convert from hexstring representation to int
            vaddr: int = int(vaddr_widget.text(), 16)

            entry: MatchedFunction | None = matched_funcs.get(vaddr)
            if entry:
                entry["enabled"] = item.checkState() == QtCore.Qt.CheckState.Checked
                if entry["enabled"] is False:
                    del self._mapping.name_map[str(vaddr)]

        self.close()
        self._function_sync_callback(self._mapping)

    def toggle_all(self, state) -> None:
        self.table.blockSignals(True)

        new_state: QtCore.Qt.CheckState | QtCore.Qt.CheckState = (
            QtCore.Qt.CheckState.Checked
            if state == 2
            else QtCore.Qt.CheckState.Unchecked
        )
        for row in range(self.table.rowCount()):
            item: QtWidgets.QTableWidgetItem | None = self.table.item(
                row, ImportFunctionTableColumns.CHECKBOX
            )
            if item:
                item.setCheckState(new_state)

        self.table.blockSignals(False)

    def update_select_all_state(self, item: QtWidgets.QTableWidgetItem) -> None:
        # Only respond to checkbox column changes
        if item.column() != ImportFunctionTableColumns.CHECKBOX:
            return

        # Block signals to prevent recursive calls
        self.select_all_checkbox.blockSignals(True)

        # Count checked items
        checked_count = 0
        for row in range(self.table.rowCount()):
            checkbox: QtWidgets.QTableWidgetItem | None = self.table.item(
                row, ImportFunctionTableColumns.CHECKBOX
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
