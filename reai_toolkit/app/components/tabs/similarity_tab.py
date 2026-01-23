from enum import IntEnum
from typing import Any, Optional, Callable

import idaapi
import ida_kernwin as kw
from loguru import logger

from revengai.models.matched_function import MatchedFunction

from reai_toolkit.app.core.qt_compat import QtCore, QtGui, QtWidgets


TAB_TITLE = "RevEng.AI — Function Similarity"


class SimilarityTableColumns(IntEnum):
    FUNCTION = 0
    SIMILARITY = 1
    CONFIDENCE = 2
    BINARY = 3
    DIFF = 4


class ButtonDelegate(QtWidgets.QStyledItemDelegate):
    clicked = QtCore.Signal(QtCore.QModelIndex)
    
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._pressed_index = None
    
    def paint(self, painter: QtGui.QPainter, option: QtWidgets.QStyleOptionViewItem, 
              index: QtCore.QModelIndex) -> None:
        button_option = QtWidgets.QStyleOptionButton()
        button_option.rect = option.rect.adjusted(4, 4, -4, -4)
        button_option.text = "View"
        button_option.state = QtWidgets.QStyle.State_Enabled
        
        if self._pressed_index == index:
            button_option.state |= QtWidgets.QStyle.State_Sunken
        
        QtWidgets.QApplication.style().drawControl(
            QtWidgets.QStyle.CE_PushButton, button_option, painter
        )
    
    def editorEvent(self, event: QtCore.QEvent, model: QtCore.QAbstractItemModel,
                    option: QtWidgets.QStyleOptionViewItem, 
                    index: QtCore.QModelIndex) -> bool:
        if event.type() == QtCore.QEvent.Type.MouseButtonPress:
            self._pressed_index = index
            return True
        elif event.type() == QtCore.QEvent.Type.MouseButtonRelease:
            if self._pressed_index == index:
                self.clicked.emit(index)
            self._pressed_index = None
            return True
        return False
    
    def sizeHint(self, option: QtWidgets.QStyleOptionViewItem, 
                 index: QtCore.QModelIndex) -> QtCore.QSize:
        return QtCore.QSize(60, 30)


class SimilarityTableModel(QtCore.QAbstractTableModel):
    COLUMNS: list[str] = ["Function", "Similarity", "Confidence", "Binary", ""]
    
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._data: list[MatchedFunction] = []
        self._func_id: int | None = None
    
    def rowCount(self, parent=QtCore.QModelIndex()) -> int:
        return len(self._data)
    
    def columnCount(self, parent=QtCore.QModelIndex()) -> int:
        return len(self.COLUMNS)
    
    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not (0 <= index.row() < len(self._data)):
            return None
        
        match: MatchedFunction = self._data[index.row()]
        col: int = index.column()
        
        if role == QtCore.Qt.ItemDataRole.DisplayRole:
            if col == SimilarityTableColumns.FUNCTION:
                return match.function_name
            elif col == SimilarityTableColumns.SIMILARITY:
                similarity: float = match.similarity or 0.0
                return f"{similarity:.1f}%"
            elif col == SimilarityTableColumns.CONFIDENCE:
                confidence: float = match.confidence or 0.0
                return f"{confidence:.1f}%"
            elif col == SimilarityTableColumns.BINARY:
                return match.binary_name
            elif col == SimilarityTableColumns.DIFF:
                return None  # Button column - handled by delegate
        
        elif role == QtCore.Qt.ItemDataRole.UserRole:
            return f"https://portal.reveng.ai/function/{self._func_id}/compare?id={match.function_id}"
        
        elif role == QtCore.Qt.ItemDataRole.TextAlignmentRole:
            if col == SimilarityTableColumns.SIMILARITY:
                return QtCore.Qt.AlignmentFlag.AlignCenter
            return QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter
        
        elif role == QtCore.Qt.ItemDataRole.ForegroundRole:
            if col == SimilarityTableColumns.SIMILARITY:
                similarity = match.similarity or 0
                if similarity >= 90:
                    return QtGui.QColor("#2ecc71")  # Green
                elif similarity >= 70:
                    return QtGui.QColor("#f39c12")  # Orange
                else:
                    return QtGui.QColor("#e74c3c")  # Red
            elif col == SimilarityTableColumns.CONFIDENCE:
                confidence = match.confidence or 0
                if confidence >= 90:
                    return QtGui.QColor("#2ecc71")  # Green
                elif confidence >= 70:
                    return QtGui.QColor("#f39c12")  # Orange
                else:
                    return QtGui.QColor("#e74c3c")  # Red
        
        return None
    
    def headerData(self, section: int, orientation: QtCore.Qt.Orientation, 
                   role: int = QtCore.Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == QtCore.Qt.Orientation.Horizontal and role == QtCore.Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section]
        return None
    
    def set_data(self, func_id: int, data: list[MatchedFunction]) -> None:
        self.beginResetModel()
        self._func_id = func_id
        self._data = data
        self.endResetModel()
    
    def clear(self) -> None:
        self.beginResetModel()
        self._data = []
        self.endResetModel()


class SimilarityTab(kw.PluginForm):
    """Dockable view showing similar functions for the currently selected function."""
    
    def __init__(self, on_close_callback: Callable) -> None:
        super().__init__()
        self._parent_w: Optional[QtWidgets.QWidget] = None
        self._table: Optional[QtWidgets.QTableView] = None
        self._model: Optional[SimilarityTableModel] = None
        self._status_label: Optional[QtWidgets.QLabel] = None
        self._current_func_addr: Optional[int] = None
        self._current_func_id: Optional[int] = None
        self._on_close_callback = on_close_callback

    def Create(self, title: str = "") -> Any:
        flags = getattr(kw.PluginForm, "WOPN_DP_TAB", 0) | getattr(
            kw.PluginForm, "WOPN_RESTORE", 0
        )
        success = self.Show(str(title) if title else TAB_TITLE, flags)
        if not success:
            logger.error("Failed to show Function Similarity tab")
        else:
            try:
                kw.set_dock_pos(TAB_TITLE, "Pseudocode-A", kw.DP_TAB)
            except Exception as e:
                logger.warning(f"Could not dock next to Pseudocode: {e}")

        return success

    def OnCreate(self, form) -> None:
        self._parent_w = kw.PluginForm.FormToPyQtWidget(form)  # type: ignore

        if self._parent_w is None:
            return

        # Main layout
        layout = QtWidgets.QVBoxLayout(self._parent_w)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Header with status
        header_layout = QtWidgets.QHBoxLayout()
        self._status_label = QtWidgets.QLabel("Select a function to view similarities")
        self._status_label.setStyleSheet("color: #888; font-style: italic;")
        header_layout.addWidget(self._status_label)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)

        # Table view
        self._table = QtWidgets.QTableView(self._parent_w)
        self._model = SimilarityTableModel(self._table)
        self._table.setModel(self._model)
        
        # Configure table appearance
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.setShowGrid(False)
        
        # Set column widths
        header: QtWidgets.QHeaderView = self._table.horizontalHeader()
        header.setSectionResizeMode(SimilarityTableColumns.FUNCTION, QtWidgets.QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(SimilarityTableColumns.SIMILARITY, QtWidgets.QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(SimilarityTableColumns.BINARY, QtWidgets.QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(SimilarityTableColumns.DIFF, QtWidgets.QHeaderView.ResizeMode.Fixed)
        self._table.setColumnWidth(SimilarityTableColumns.SIMILARITY, 80)
        self._table.setColumnWidth(SimilarityTableColumns.DIFF, 70)
        
        # Button delegate for the last column
        button_delegate = ButtonDelegate(self._table)
        button_delegate.clicked.connect(self._on_button_clicked)
        self._table.setItemDelegateForColumn(SimilarityTableColumns.DIFF, button_delegate)
        
        layout.addWidget(self._table)
        
    def OnClose(self, form) -> None:
        self._on_close_callback()

    def _on_button_clicked(self, index: QtCore.QModelIndex) -> None:
        """Handle click on the View button."""
        if self._model is None:
            return
        
        url = self._model.data(index, QtCore.Qt.ItemDataRole.UserRole)
        if url:
            logger.debug(f"Opening URL: {url}")
            QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))
   
    def _on_fetch_finished(self, func_id: int, func_addr: int, data: list[MatchedFunction]) -> None:
        """Handle successful API response (called on main thread)."""
        # Ignore results if user has moved to a different function
        if func_addr != self._current_func_addr:
            return
        
        if self._model:
            self._model.set_data(func_id, data)
        
        func_name = idaapi.get_func_name(func_addr) or f"sub_{func_addr:X}"
        
        if self._status_label:
            if data:
                self._status_label.setText(f"Similar to {func_name} ({len(data)} results)")
                self._status_label.setStyleSheet("color: #ccc;")
            else:
                self._status_label.setText(f"No similar functions found for {func_name}")
                self._status_label.setStyleSheet("color: #888; font-style: italic;")
        

    def update_for_function(self, func_id: int, func_addr: int, data: list[MatchedFunction], force: bool = False) -> None:
        if not force and func_addr == self._current_func_addr:
            return
        
        self._current_func_addr = func_addr
        
        # Get function name for display
        func_name: str = idaapi.get_func_name(func_addr)
        
        if self._status_label:
            self._status_label.setText(f"Loading similarities for {func_name}...")
            self._status_label.setStyleSheet("color: #888; font-style: italic;")
        
        # Clear table while loading
        if self._model:
            self._model.clear()
        
        self._on_fetch_finished(func_id, func_addr, data)
