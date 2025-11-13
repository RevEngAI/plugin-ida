from datetime import datetime
from typing import List, Optional

import idaapi
from revengai.models import AnalysisRecord

from reai_toolkit.app.components.dialogs.base_dialog import DialogBase
from reai_toolkit.app.core.qt_compat import QT_VER, QtCore, QtGui, QtWidgets

if QT_VER == 6:
    from reai_toolkit.app.components.forms.existing_analysis.existing_analysis_panel_ui_uic6 import (
        Ui_ExistingAnalysesPanel,
    )
else:
    from reai_toolkit.app.components.forms.existing_analysis.existing_analysis_panel_ui_uic5 import (
        Ui_ExistingAnalysesPanel,
    )


class ExistingAnalysisDialog(DialogBase):
    analyses_list: Optional[list[AnalysisRecord]]
    selected_analysis: AnalysisRecord = None

    def __init__(
        self,
        *,
        fetched_analyses: List[AnalysisRecord] = None,
        parent: QtWidgets.QWidget | None = None,
    ):
        super().__init__(parent)
        self.analyses_list = fetched_analyses

        self.setWindowTitle("RevEng.AI — Attach to existing")
        self.setModal(False)
        self.file_path = idaapi.get_input_file_path()
        self.file_name = idaapi.get_root_filename()
        self.ui = Ui_ExistingAnalysesPanel()
        self.ui.setupUi(self)
        self.setFixedSize(self.size())

        logo_path = self._find_resource(self.base_logo_path)
        px = QtGui.QPixmap(logo_path)
        self.ui.logoArea.setPixmap(px)

        self._init_table()
        self._populate_table_once()

        # Wire buttons
        self.ui.okButton.clicked.connect(self._on_ok)
        self.ui.cancelButton.clicked.connect(self.reject)

    def _populate_table_once(self) -> None:
        """Fill the analyses table once at startup."""
        view = self.ui.tableAnalyses

        try:
            QtCore.QSignalBlocker(view)
            view.setUpdatesEnabled(False)

            rows: List[AnalysisRecord] = self.analyses_list or []
            view.setRowCount(0)
            view.setRowCount(len(rows))

            def s(v):
                if v is None:
                    return ""
                if isinstance(v, datetime):
                    try:
                        return v.isoformat(sep=" ", timespec="seconds")
                    except Exception:
                        return str(v)
                return str(v)

            for r, ana in enumerate(rows):
                c0 = QtWidgets.QTableWidgetItem("")
                flags = (
                    c0.flags()
                    | QtCore.Qt.ItemIsUserCheckable
                    | QtCore.Qt.ItemIsSelectable
                    | QtCore.Qt.ItemIsEnabled
                )
                c0.setFlags(flags)
                c0.setCheckState(QtCore.Qt.Unchecked)
                key = ana.analysis_id
                c0.setData(QtCore.Qt.UserRole, ana)
                c0.setData(QtCore.Qt.UserRole + 1, key)
                view.setItem(r, 0, c0)

                view.setItem(r, 1, QtWidgets.QTableWidgetItem(s(ana.binary_name)))
                view.setItem(r, 2, QtWidgets.QTableWidgetItem(s(ana.sha_256_hash)))
                view.setItem(r, 3, QtWidgets.QTableWidgetItem(s(ana.model_name)))
                view.setItem(r, 4, QtWidgets.QTableWidgetItem(s(ana.creation)))

            self.ui.okButton.setEnabled(len(rows) > 0)

            # 🔹 Resize columns & rows to fit text after filling
            view.resizeColumnsToContents()
            view.resizeRowsToContents()

        finally:
            view.setUpdatesEnabled(True)

        view.itemChanged.connect(self._on_analysis_item_changed)

    def _on_analysis_item_changed(self, item: QtWidgets.QTableWidgetItem):
        """Make the 'Select' checkbox exclusive and store selected_analysis."""
        if item is None or item.column() != 0:
            return

        view = self.ui.tableAnalyses
        # If the user unchecked it, clear selection and disable OK
        if item.checkState() != QtCore.Qt.Checked:
            self.selected_analysis = None
            self.ui.okButton.setEnabled(False)
            return

        # The user checked this row: uncheck all others (with signal blocker to avoid recursion)
        blocker = QtCore.QSignalBlocker(view)
        try:
            for r in range(view.rowCount()):
                if view.item(r, 0) is item:
                    continue
                it = view.item(r, 0)
                if it is not None and it.checkState() == QtCore.Qt.Checked:
                    it.setCheckState(QtCore.Qt.Unchecked)
        finally:
            del blocker  # unblock

        # Save the selected analysis object & enable OK
        ana = item.data(QtCore.Qt.UserRole)
        self.selected_analysis = ana
        self.ui.okButton.setEnabled(True)

    def _init_table(self):
        view = self.ui.tableAnalyses
        labels = ["Select", "Binary\nName", "SHA 256\nHash", "Model\nName", "Creation"]
        view.setVisible(True)
        view.setColumnCount(len(labels))
        view.setHorizontalHeaderLabels(labels)

        view.setRowCount(0)

        hh = view.horizontalHeader()
        hh.setVisible(True)
        hh.setStretchLastSection(True)
        hh.setMinimumSectionSize(90)

        # Sizes: keep id columns tight, let names stretch
        hh.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)  # Select
        hh.setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)  # Binary Name
        hh.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)  # SHA
        hh.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)  # Model
        hh.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)  # Creation

        view.setWordWrap(True)
        view.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        view.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

        # Map row selection to checking the checkbox (nice UX)
        view.itemSelectionChanged.connect(lambda: self._sync_selection_to_checkbox())

    def _sync_selection_to_checkbox(self):
        """If user clicks row selection, check that row’s Select box (exclusive)."""
        view = self.ui.tableAnalyses
        sel = view.selectionModel().selectedRows()
        if not sel:
            return
        row = sel[0].row()
        it = view.item(row, 0)
        if it is None:
            return
        if it.checkState() != QtCore.Qt.Checked:
            # This will trigger _on_analysis_item_changed which will uncheck others & enable OK
            it.setCheckState(QtCore.Qt.Checked)

    def _on_ok(self):
        """Use self.selected_analysis (may be None)."""
        if not self.selected_analysis:
            # Optional: show a gentle prompt
            QtWidgets.QMessageBox.information(
                self, "Select Analysis", "Please select an analysis first."
            )
            return

        self.result_data = self.selected_analysis
        self.accept()
