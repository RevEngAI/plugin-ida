from typing import Optional

import ida_kernwin
import ida_name
from revengai import MatchedFunctionSuggestion

from reai_toolkit.app.components.dialogs.base_dialog import DialogBase
from reai_toolkit.app.core.qt_compat import QT_VER, QtCore, QtGui, QtWidgets
from reai_toolkit.app.services.auto_unstrip.auto_unstrip_service import (
    AutoUnstripResponse,
)

if QT_VER == 6:
    from reai_toolkit.app.components.forms.auto_unstrip.auto_unstrip_panel_ui_uic6 import (
        Ui_AutoUnstripPanel,
    )
else:
    from reai_toolkit.app.components.forms.auto_unstrip.auto_unstrip_panel_ui_uic5 import (
        Ui_AutoUnstripPanel,
    )


def get_safe_name(ea: int) -> Optional[str]:
    name = None

    def _do():
        nonlocal name
        name = ida_name.get_name(ea=ea)
        if name is None:
            name = "<unnamed>"

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST)
    return name


class AutoUnstripDialog(DialogBase):
    def __init__(
        self,
        auto_unstrip_response: AutoUnstripResponse,
        parent: QtWidgets.QWidget | None = None,
    ):
        super().__init__(parent)

        self.setWindowTitle("RevEng.AI — Auto Unstrip")
        self.setModal(False)

        self.ui = Ui_AutoUnstripPanel()
        self.ui.setupUi(self)
        self.setFixedSize(self.size())

        logo_path = self._find_resource(self.base_logo_path)
        px = QtGui.QPixmap(logo_path)
        self.ui.logoArea.setPixmap(px)

        self.data: AutoUnstripResponse | None = auto_unstrip_response

        if self.data:
            self._populate_table(self.data.matches)

        # Wire buttons
        self.ui.okButton.clicked.connect(self.accept)

    def _populate_table(self, matches: list[MatchedFunctionSuggestion]) -> None:
        table = self.ui.tableRenames
        # Labels
        labels = [
            "Address",
            "Old Mangled Name",
            "Suggested Mangled Name",
            "Suggested Demangled Name",
        ]

        table.setColumnCount(len(labels))
        table.setHorizontalHeaderLabels(labels)

        hdr = table.horizontalHeader()
        hdr.setStretchLastSection(False)

        table.setRowCount(len(matches))
        
        if QT_VER == 6:
            flags = QtCore.Qt.ItemFlag.ItemIsSelectable | QtCore.Qt.ItemFlag.ItemIsEnabled
        else:
            flags = QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled

        for row, m in enumerate(matches):
            # 2. address cell
            addr_item = QtWidgets.QTableWidgetItem(hex(m.function_vaddr))
            addr_item.setFlags(flags)
            addr_item.setToolTip(addr_item.text())  # show on hover
            table.setItem(row, 0, addr_item)

            # 3. current name cell
            current_name = get_safe_name(m.function_vaddr) or "<unnamed>"
            cur_item = QtWidgets.QTableWidgetItem(current_name)
            cur_item.setFlags(flags)
            cur_item.setToolTip(current_name)
            table.setItem(row, 1, cur_item)

            # 4. suggested name cell
            sug_name = m.suggested_name or ""
            sug_item = QtWidgets.QTableWidgetItem(sug_name)
            sug_item.setFlags(flags)
            sug_item.setToolTip(sug_name)  # tooltip always has full text
            table.setItem(row, 2, sug_item)

            # 5. Suggested demangled name cell
            demangled_name = m.suggested_demangled_name or sug_name
            dem_item = QtWidgets.QTableWidgetItem(demangled_name)
            dem_item.setFlags(flags)
            dem_item.setToolTip(demangled_name)  # tooltip always has full text
            table.setItem(row, 3, dem_item)

        # ---- Column sizing and text handling ----
        # don’t elide text with "..."
        table.setTextElideMode(QtCore.Qt.ElideNone)

        # OPTION A: wrapping (multi-line rows)
        # table.setWordWrap(True)
        # table.resizeColumnsToContents()
        # table.resizeRowsToContents()

        # OPTION B: horizontal scrolling (single line rows)
        table.setWordWrap(False)
        table.resizeColumnsToContents()
        table.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        table.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
