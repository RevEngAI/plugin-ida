from enum import Enum
from typing import List, Optional

from revengai.models import (
    BinarySearchResult,
    CollectionSearchResult,
    FunctionMatch,
    MatchedFunction,
)

from reai_toolkit.app.components.dialogs import ErrorDialog
from reai_toolkit.app.components.dialogs.base_dialog import DialogBase
from reai_toolkit.app.core.qt_compat import (
    QT_VER,
    QtCore,
    QtGui,
    QtWidgets,
    Signal,
    Slot,
)
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.services.matching.matching_service import MatchingService
from reai_toolkit.app.services.matching.schema import (
    MatchEvent,
    MatchEventType,
    SummaryEvent,
    ValidFunction,
)
from reai_toolkit.app.services.data_types.data_types_service import ImportDataTypesService
from reai_toolkit.app.services.rename.rename_service import RenameService
from reai_toolkit.app.services.rename.schema import RenameInput

if QT_VER == 6:
    from reai_toolkit.app.components.forms.ann.ann_panel_ui_uic6 import (
        Ui_MatchingPanel,
    )
else:
    from reai_toolkit.app.components.forms.ann.ann_panel_ui_uic5 import (
        Ui_MatchingPanel,
    )

print("[AnnDialog] Qt version:", QT_VER)

DEBOUNCE_MS = 250


class MatchColumns(Enum):
    SELECT = 0
    VIRTUAL_ADDRESS = 1
    FUNC_NAME = 2
    MATCHED_NAME = 3
    SIMILARITY = 4
    CONFIDENCE = 5
    MATCHED_BINARY_HASH = 6
    MATCHED_BINARY_NAME = 7


class MatchingWorker(QtCore.QObject):
    event_ready = Signal(object)  # MatchingEvent (Start/BatchDone/Summary)
    finished = Signal()  # always emitted on exit
    errored = Signal(str)

    def __init__(self, match_service, data_types_service, gen_kwargs: dict):
        super().__init__()
        self._match_service = match_service
        self._data_types_service = data_types_service
        self._gen_kwargs = gen_kwargs
        self._stop = False

    @Slot()
    def run(self):
        try:
            for ev in self._match_service.perform_matching(**self._gen_kwargs):
                if self._stop:
                    break
                self.event_ready.emit(ev)
        except Exception as e:
            self.errored.emit(str(e))
        finally:
            self.finished.emit()

    def stop(self):
        self._stop = True


class MatchingDialog(DialogBase):
    matching_service: MatchingService = None
    matching_results: Optional[SummaryEvent] = None
    rename_service: RenameService = None
    single_function_id: Optional[int] = None
    _func_map: dict[str, int] = {}
    _matching_thread: Optional[QtCore.QThread] = None
    _matching_worker: Optional[MatchingWorker] = None
    _progress_bar: Optional[QtWidgets.QProgressBar] = None
    _valid_functions: list[ValidFunction] = []
    _selected_matching_items: set[int] = set()

    def __init__(
        self,
        *,
        valid_functions: list[ValidFunction],
        func_map: dict[str, int],
        matching_service: MatchingService,
        rename_service: RenameService,
        data_types_service: ImportDataTypesService,
        parent: QtWidgets.QWidget | None = None,
    ):
        super().__init__(parent=parent)
        self.setWindowTitle("RevEng.AI — Function matching")
        self.setModal(False)

        self.matching_service = matching_service
        self.rename_service = rename_service
        self.data_types_service = data_types_service
        self._func_map = func_map

        # Used for looking up which function we matched to for a given function id.
        self.current_to_matched_func: dict[int, MatchedFunction] = {}

        self.ui = Ui_MatchingPanel()
        self.setWindowTitle("RevEng.AI — Function matching")
        self.ui.setupUi(self)
        self.setFixedSize(self.size())

        # Optional logo
        try:
            logo_path = self._find_resource(self.base_logo_path)
            px = QtGui.QPixmap(logo_path)
            if hasattr(self.ui, "logoArea") and not px.isNull():
                self.ui.logoArea.setPixmap(px)
        except Exception:
            pass

        # Default to first page if present
        if hasattr(self.ui, "stack") and isinstance(self.ui.stack, QtWidgets.QStackedWidget):
            self.ui.stack.setCurrentIndex(0)

        # ----------------- Cancel Buttons -----------------
        self.ui.cancelButton.clicked.connect(self.close)
        self.ui.cancelButton1.clicked.connect(self.close)

        # ----------------- Functions table -----------------
        self._valid_functions: list[ValidFunction] = valid_functions
        if len(self._valid_functions) == 1:
            self.single_function_id = self._valid_functions[0].function_id
        self._selected_functions: set = set()  # Set of function IDs
        self._initFunctionTable()
        self._update_functions_table()

        if hasattr(self.ui, "searchFunctions"):
            self.ui.searchFunctions.textEdited.connect(self._update_functions_table)

        # ----------------- Collections state -----------------
        # Internal multi-selection: key -> (name, scope, owner, model, created)
        self._selected_collections: dict[str, CollectionSearchResult] = {}
        self._collectionsDebounce = QtCore.QTimer(self)
        self._collectionsDebounce.setSingleShot(True)
        self._collectionsDebounce.timeout.connect(self._performCollectionsSearch)

        self.ui.editCollections.installEventFilter(self)
        self.ui.editCollections.textEdited.connect(self._onCollectionsEdited)
        self.ui.editCollections.returnPressed.connect(self._acceptCheckedCollections)

        if hasattr(self.ui, "okCollectionButton"):
            self.ui.okCollectionButton.clicked.connect(self._applyCheckedCollections)

        # Treat collections popup as child sub-widget
        self.ui.collectionsPopup.setParent(self)
        self.ui.collectionsPopup.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.SubWindow)
        self.ui.collectionsPopup.setAttribute(QtCore.Qt.WA_StyledBackground, True)
        self.ui.collectionsPopup.setFocusPolicy(QtCore.Qt.NoFocus)
        self.ui.collectionsPopupView.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.ui.collectionsPopupView.itemChanged.connect(self._onCollectionItemChanged)

        self._initCollectionsHeader()

        # ----------------- Binaries state -----------------
        self._selected_binaries: dict[str, BinarySearchResult] = {}
        self._binariesDebounce = QtCore.QTimer(self)
        self._binariesDebounce.setSingleShot(True)
        self._binariesDebounce.timeout.connect(self._performBinariesSearch)

        if hasattr(self.ui, "editBinaries"):
            self.ui.editBinaries.installEventFilter(self)
            self.ui.editBinaries.textEdited.connect(self._onBinariesEdited)
            self.ui.editBinaries.returnPressed.connect(self._acceptCheckedBinaries)

        # Try a few common names for the binaries "Select" button to avoid name mismatch
        if hasattr(self.ui, "okBinariesButton"):
            self.ui.okBinariesButton.clicked.connect(self._applyCheckedBinaries)

        if hasattr(self.ui, "binariesPopup"):
            # Treat binaries popup as child sub-widget
            self.ui.binariesPopup.setParent(self)
            self.ui.binariesPopup.setWindowFlags(
                QtCore.Qt.FramelessWindowHint | QtCore.Qt.SubWindow
            )
            self.ui.binariesPopup.setAttribute(QtCore.Qt.WA_StyledBackground, True)
            self.ui.binariesPopup.setFocusPolicy(QtCore.Qt.NoFocus)

        if hasattr(self.ui, "binariesPopupView"):
            self.ui.binariesPopupView.setFocusPolicy(QtCore.Qt.StrongFocus)
            self.ui.binariesPopupView.itemChanged.connect(self._onBinaryItemChanged)
            self._initBinariesHeader()

        # Global mouse filter to close popups on outside click
        app = QtWidgets.QApplication.instance()
        if app is not None:
            app.installEventFilter(self)

        # ----------------- ANN Button -----------------

        if hasattr(self.ui, "okRunButton"):
            self.ui.okRunButton.clicked.connect(self.start_ann)

        self._progress_bar = self.ui.loadingBar if hasattr(self.ui, "loadingBar") else None
        if self._progress_bar is not None:
            print("[AnnDialog] Progress bar found")
            self._progress_bar.setMinimum(0)
            self._progress_bar.setMaximum(0)

        if hasattr(self.ui, "okRenameButton"):
            self.ui.okRenameButton.clicked.connect(self.enqueue_renames)
            self.ui.okRenameButton.clicked.connect(self.import_data_types)

        # ----------------- Util buttons -----------------
        self.ui.btnClearSelection.clicked.connect(
            lambda: self.function_update_state(check_all=False)
        )
        self.ui.btnSelectAll.clicked.connect(lambda: self.function_update_state(check_all=True))
        self.ui.btnResetFilters.clicked.connect(self.reset_all)

        # ----------------- Rename function search -----------------
        if hasattr(self.ui, "resultFunctionSearch"):
            self.ui.resultFunctionSearch.textEdited.connect(self.display_matching_results)

    # =====================================================================
    # Update functions table
    # =====================================================================
    def _initFunctionTable(self):
        """Set up the QTableWidget used for ANN function selection."""
        if not hasattr(self.ui, "tableFunctions"):
            return

        view = self.ui.tableFunctions
        labels = [
            "Select",
            "Virtual\nAddress",
            "Current\nName",
            "Current\nMangled\nName",
        ]

        view.setVisible(True)
        view.setColumnCount(len(labels))
        view.setHorizontalHeaderLabels(labels)

        # Make the header visible (UI file hides it)
        hh = view.horizontalHeader()
        hh.setVisible(True)
        hh.setStretchLastSection(True)
        hh.setMinimumSectionSize(90)
        # Keep first two tight, let names breathe
        hh.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        hh.setSectionResizeMode(3, QtWidgets.QHeaderView.Stretch)

        # Table behavior
        view.setWordWrap(True)
        view.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        view.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

        # Reconnect itemChanged for checkbox tracking (column 0)
        # try:
        #     view.itemChanged.disconnect()
        # except Exception:
        #     pass
        view.itemChanged.connect(self._onFunctionItemChanged)

    def _update_functions_table(self):
        """Populate tableFunctions from self._valid_functions with filter."""
        if not hasattr(self.ui, "tableFunctions"):
            return

        query = (
            self.ui.searchFunctions.text().strip() if hasattr(self.ui, "searchFunctions") else ""
        )
        view = self.ui.tableFunctions

        # keep current sort so we can reapply after repopulating
        hh = view.horizontalHeader()
        was_sorting = view.isSortingEnabled()
        sort_col = hh.sortIndicatorSection()
        sort_order = hh.sortIndicatorOrder()

        view.clearContents()
        view.setRowCount(0)
        view.blockSignals(True)
        view.setSortingEnabled(False)
        view.setUpdatesEnabled(False)

        # Filter rows
        filtered = []
        for func in self._valid_functions:
            # If single_function_id is set, only include that function
            if self.single_function_id is not None and func.function_id != self.single_function_id:
                continue

            # If accept_all is set, include all, or limit by query
            if (
                not query
                or query in func.demangled_name
                or query in func.mangled_name
                or query in hex(func.vaddr)
            ):
                filtered.append(func)

        # Clear rows but keep headers
        view.setRowCount(0)
        view.setRowCount(len(filtered))

        for r, func in enumerate(filtered):
            key = func.function_id

            # Column 0: checkbox
            c0 = QtWidgets.QTableWidgetItem("")
            c0.setFlags(
                c0.flags()
                | QtCore.Qt.ItemIsUserCheckable
                | QtCore.Qt.ItemIsSelectable
                | QtCore.Qt.ItemIsEnabled
            )
            c0.setCheckState(
                QtCore.Qt.Checked if key in self._selected_functions else QtCore.Qt.Unchecked
            )
            # Stash data for handler
            c0.setData(QtCore.Qt.UserRole, func)
            c0.setData(QtCore.Qt.UserRole + 1, key)
            view.setItem(r, 0, c0)

            # Column 1: vaddr
            view.setItem(r, 1, QtWidgets.QTableWidgetItem(hex(func.vaddr)))
            # Column 2: demangled
            view.setItem(r, 2, QtWidgets.QTableWidgetItem(func.demangled_name))
            # Column 3: mangled
            view.setItem(r, 3, QtWidgets.QTableWidgetItem(func.mangled_name))

        # unfreeze & reapply previous sort
        view.blockSignals(False)
        view.setUpdatesEnabled(True)
        view.setSortingEnabled(was_sorting)
        if was_sorting:
            view.sortItems(sort_col, sort_order)
        view.resizeRowsToContents()

    def _onFunctionItemChanged(self, item: QtWidgets.QTableWidgetItem):
        """Track (un)checking in column 0."""
        if item is None or item.column() != 0:
            return
        key = item.data(QtCore.Qt.UserRole + 1)
        if key is None:
            return
        if item.checkState() == QtCore.Qt.Checked:
            self._selected_functions.add(key)
        else:
            self._selected_functions.discard(key)

    # =====================================================================
    # Collections popup
    # =====================================================================
    def _showCollectionsPopup(self):
        edit = self.ui.editCollections
        below_global = edit.mapToGlobal(QtCore.QPoint(0, edit.height()))
        below_local = self.mapFromGlobal(below_global)
        popup = self.ui.collectionsPopup
        popup.move(below_local)
        if not popup.isVisible():
            popup.show()
        popup.raise_()

    def _onCollectionsEdited(self, _text: str):
        if not self.ui.collectionsPopup.isVisible():
            self._showCollectionsPopup()
        self._collectionsDebounce.start(DEBOUNCE_MS)

    def _performCollectionsSearch(self):
        query = self.ui.editCollections.text().strip()

        response: GenericApiReturn[List[CollectionSearchResult]] = (
            self.matching_service.search_collections(text_input=query)
        )

        if not response.success:
            self.error_dialog = ErrorDialog(
                error_message=response.error_message,
                parent=self,
            )
            self.error_dialog.show()
            return

        self._fillCollectionsPopup(query=query, rows=response.data)

    def _initCollectionsHeader(self):
        labels = ["Select", "Collection", "Scope", "Owner", "Model", "Created"]

        view = self.ui.collectionsPopupView
        view.setHeaderHidden(False)
        view.setColumnCount(5)
        view.setHeaderLabels(labels)
        hdr = view.header()
        hdr.setStretchLastSection(True)

        min_width = 80
        for i in range(len(labels)):
            hdr.setMinimumSectionSize(min_width)
            # still let columns resize to contents, except last which stretches
            if i < len(labels) - 1:
                hdr.setSectionResizeMode(i, QtWidgets.QHeaderView.ResizeToContents)
            else:
                hdr.setSectionResizeMode(i, QtWidgets.QHeaderView.Stretch)

    def _fillCollectionsPopup(self, query: str, rows: list[CollectionSearchResult]):
        view = self.ui.collectionsPopupView
        view.blockSignals(True)
        view.clear()

        # Ensure previously selected items are included
        for key, tup in self._selected_collections.items():
            # Prevent duplicates
            if tup not in rows:
                # If the current query is none, include it:
                if query is None or len(query) == 0:
                    rows.append(tup)
                    continue
                # If the current query matches, include it
                elif (
                    query.lower() in tup.binary_name.lower()
                    or query.lower() in tup.sha_256_hash.lower()
                ):
                    rows.append(tup)

        for tup in rows:
            key = tup.collection_id
            it = QtWidgets.QTreeWidgetItem(
                [
                    "",
                    tup.collection_name,
                    tup.scope,
                    tup.owned_by,
                    tup.model_name,
                    tup.created_at.isoformat(),
                ]
            )
            it.setFlags(
                it.flags()
                | QtCore.Qt.ItemIsUserCheckable
                | QtCore.Qt.ItemIsSelectable
                | QtCore.Qt.ItemIsEnabled
            )
            it.setCheckState(
                0,
                QtCore.Qt.Checked if key in self._selected_collections else QtCore.Qt.Unchecked,
            )
            it.setData(0, QtCore.Qt.UserRole, tup)
            it.setData(0, QtCore.Qt.UserRole + 1, key)
            view.addTopLevelItem(it)
        hdr = view.header()
        hdr.setStretchLastSection(True)
        for i in range(view.columnCount() - 1):
            hdr.setSectionResizeMode(i, QtWidgets.QHeaderView.ResizeToContents)
        view.blockSignals(False)

    def _onCollectionItemChanged(self, item: QtWidgets.QTreeWidgetItem, column: int):
        if column != 0:
            return
        key = item.data(0, QtCore.Qt.UserRole + 1)
        tup = item.data(0, QtCore.Qt.UserRole)
        if item.checkState(0) == QtCore.Qt.Checked:
            self._selected_collections[key] = tup
        else:
            self._selected_collections.pop(key, None)

    def _acceptCheckedCollections(self):
        if self.ui.collectionsPopup.isVisible():
            self._applyCheckedCollections()

    def _applyCheckedCollections(self):
        self.ui.collectionsPopup.hide()

    # =====================================================================
    # Binaries popup
    # =====================================================================
    def _showBinariesPopup(self):
        if not hasattr(self.ui, "editBinaries") or not hasattr(self.ui, "binariesPopup"):
            return
        edit = self.ui.editBinaries
        popup = self.ui.binariesPopup

        # Global rect of the line edit
        edit_top_left_g = edit.mapToGlobal(QtCore.QPoint(0, 0))
        edit_rect_g = QtCore.QRect(edit_top_left_g, edit.size())

        # Popup size we’ll try to use
        popup_size = popup.size()
        if popup_size.isEmpty():
            popup_size = popup.sizeHint()
        pw, ph = popup_size.width(), popup_size.height()

        # Desired position: right edges aligned, below the edit
        x_g = edit_rect_g.right() - pw + 1  # +1 so borders line up nicely
        y_g = edit_rect_g.bottom() + 1

        # Keep fully on the current screen
        screen = (
            self.screen()
            or QtWidgets.QApplication.screenAt(edit_top_left_g)
            or QtWidgets.QApplication.primaryScreen()
        )
        sgeom = screen.geometry() if screen else QtCore.QRect(0, 0, 1920, 1080)
        margin = 8

        # If off the right/left edge, clamp
        if x_g + pw > sgeom.right() - margin:
            x_g = sgeom.right() - margin - pw
        if x_g < sgeom.left() + margin:
            x_g = sgeom.left() + margin

        # If it would go off the bottom, flip above the edit
        if y_g + ph > sgeom.bottom() - margin:
            y_g = edit_rect_g.top() - ph - 1
            # If still off top, clamp
            if y_g < sgeom.top() + margin:
                y_g = sgeom.top() + margin

        # Our popup is a child sub-widget: convert to local coords
        pos_local = self.mapFromGlobal(QtCore.QPoint(x_g, y_g))
        popup.move(pos_local)

        if not popup.isVisible():
            popup.show()
        popup.raise_()

    def _onBinariesEdited(self, _text: str):
        if hasattr(self.ui, "binariesPopup") and not self.ui.binariesPopup.isVisible():
            self._showBinariesPopup()
        self._binariesDebounce.start(DEBOUNCE_MS)

    def _performBinariesSearch(self):
        """
        Replace with your real binaries search.
        rows = List of (binary_name, sha256, owner, model, created)
        """
        text = getattr(self.ui, "editBinaries", None)
        query = text.text().strip() if text else ""

        response: GenericApiReturn[List[BinarySearchResult]] = (
            self.matching_service.search_binaries(text_input=query)
        )

        if not response.success:
            self.error_dialog = ErrorDialog(
                error_message=response.error_message,
                parent=self,
            )
            self.error_dialog.show()
            return

        self._fillBinariesPopup(query=query, rows=response.data)

    def _initBinariesHeader(self):
        labels = ["Select", "Binary", "SHA-256", "Owner", "Model", "Created"]

        if not hasattr(self.ui, "binariesPopupView"):
            return
        view = self.ui.binariesPopupView
        view.setHeaderHidden(False)
        view.setColumnCount(6)
        view.setHeaderLabels(labels)
        view.setWordWrap(True)
        hdr = view.header()
        hdr.setStretchLastSection(True)

        min_width = 80
        for i in range(len(labels)):
            hdr.setMinimumSectionSize(min_width)
            # still let columns resize to contents, except last which stretches
            if i < len(labels) - 1:
                hdr.setSectionResizeMode(i, QtWidgets.QHeaderView.ResizeToContents)
            else:
                hdr.setSectionResizeMode(i, QtWidgets.QHeaderView.Stretch)

    def _fillBinariesPopup(self, query: str, rows: list[BinarySearchResult]):
        if not hasattr(self.ui, "binariesPopupView"):
            return
        view = self.ui.binariesPopupView
        view.blockSignals(True)
        view.clear()

        # Ensure previously selected items are included
        for key, tup in self._selected_binaries.items():
            # Prevent duplicates
            if tup not in rows:
                # If the current query is none, include it:
                if query is None or len(query) == 0:
                    rows.append(tup)
                    continue
                # If the current query matches, include it
                elif (
                    query.lower() in tup.binary_name.lower()
                    or query.lower() in tup.sha_256_hash.lower()
                ):
                    rows.append(tup)

        for tup in rows:
            key = tup.binary_id
            item = QtWidgets.QTreeWidgetItem(
                [
                    "",
                    tup.binary_name,
                    tup.sha_256_hash,
                    tup.owned_by,
                    tup.model_name,
                    tup.created_at.isoformat(),
                ]
            )
            item.setFlags(
                item.flags()
                | QtCore.Qt.ItemIsUserCheckable
                | QtCore.Qt.ItemIsSelectable
                | QtCore.Qt.ItemIsEnabled
            )
            item.setCheckState(
                0,
                QtCore.Qt.Checked if key in self._selected_binaries else QtCore.Qt.Unchecked,
            )
            item.setData(0, QtCore.Qt.UserRole, tup)
            item.setData(0, QtCore.Qt.UserRole + 1, key)
            view.addTopLevelItem(item)

        hdr = view.header()
        hdr.setStretchLastSection(True)
        for i in range(view.columnCount() - 1):
            hdr.setSectionResizeMode(i, QtWidgets.QHeaderView.ResizeToContents)
        view.blockSignals(False)

    def _onBinaryItemChanged(self, item: QtWidgets.QTreeWidgetItem, column: int):
        if column != 0:
            return
        key = item.data(0, QtCore.Qt.UserRole + 1)
        tup = item.data(0, QtCore.Qt.UserRole)
        if item.checkState(0) == QtCore.Qt.Checked:
            self._selected_binaries[key] = tup  # type: ignore[assignment]
        else:
            del self._selected_binaries[key]

    def _acceptCheckedBinaries(self):
        if hasattr(self.ui, "binariesPopup") and self.ui.binariesPopup.isVisible():
            self._applyCheckedBinaries()

    def _applyCheckedBinaries(self):
        if hasattr(self.ui, "binariesPopup"):
            self.ui.binariesPopup.hide()

    # =====================================================================
    # Ann methods
    # =====================================================================

    def start_ann(self):
        """
        Collect selected inputs and start the ANN generator in a worker thread.
        """
        function_ids = sorted(self._selected_functions) if self._selected_functions else []
        if self.single_function_id is not None and not function_ids:
            function_ids = [self.single_function_id]

        if not function_ids:
            self.error_dialog = ErrorDialog(
                error_message="Select at least one function to run ANN.",
                parent=self,
            )
            self.error_dialog.show()
            return

        """
            function_ids: list[int],
            analysis_func_count: int,
            min_similarity: int,
            binary_ids: Optional[List[int]] = None,
            collection_ids: Optional[List[int]] = None,
            user_debug_only: bool = False,
            debug_all: bool = False,
        """

        gen_kwargs = dict(
            analysis_func_count=len(self._func_map),
            function_ids=function_ids,
            min_similarity=self.ui.spinConfidence.value(),
            binary_ids=list(self._selected_binaries.keys()) or None,
            collection_ids=list(self._selected_collections.keys()) or None,
            user_debug_only=True if self.ui.chkUserDebugSymbols.isChecked() else None,
            debug_all=True if self.ui.chkDebugSymbols.isChecked() else None,
        )

        print(f"[AnnDialog] Starting ANN with args: {gen_kwargs}")

        self.stop_ann()  # ensure previous worker is cleaned up

        self._matching_thread = QtCore.QThread(self)
        self._matching_worker = MatchingWorker(self.matching_service, self.data_types_service, gen_kwargs)
        self._matching_worker.moveToThread(self._matching_thread)

        # connections
        self._matching_thread.started.connect(self._matching_worker.run)
        self._matching_worker.event_ready.connect(self.on_ann_event)
        self._matching_worker.errored.connect(self.on_ann_error)

        # tidy up thread
        self._matching_worker.finished.connect(self._matching_thread.quit)
        self._matching_worker.finished.connect(self._matching_worker.deleteLater)
        self._matching_worker.finished.connect(self._matching_thread.deleteLater)
        self._progress_bar.setVisible(True)
        # Pause UI interactions while running
        self.toggle_search_ui(pause=True)
        self._matching_thread.start()

    @Slot(str)
    def on_ann_error(self, msg: str):
        if self._progress_bar:
            self._progress_bar.setVisible(False)
        self.toggle_search_ui(pause=False)
        print(f"[AnnDialog] ANN worker error: {msg}")
        self.error_dialog = ErrorDialog(error_message=msg, parent=self)
        self.error_dialog.show()

    def toggle_search_ui(self, pause: bool):
        self.ui.stack.setEnabled(not pause)
        self.ui.loadingBar.setEnabled(pause)

    def stop_ann(self):
        """Gracefully stop an in-flight worker, if any."""
        if self._matching_worker is not None:
            try:
                self._matching_worker.stop()
            except Exception as e:
                print(f"[AnnDialog] Failed to stop ANN worker: {e}")
                pass
        if self._matching_thread is not None:
            # Let it exit naturally; Qt handles cleanup via the signals we set
            pass

    @Slot(object)
    def on_ann_event(self, ev):
        """
        ev is one of your ANNEvent Pydantic models:
          - StartEvent
          - BatchDoneEvent
          - SummaryEvent
        """
        etype = getattr(ev, "event", None)
        etype: MatchEvent

        print(
            f"[AnnDialog] ANN event: {etype}, completed: {getattr(ev, 'completed', None)}/{getattr(ev, 'total', None)}, ok: {getattr(ev, 'ok', None)}"
        )

        # Start
        if ev.event is MatchEventType.START:
            if self._progress_bar is not None:
                self._progress_bar.setRange(0, ev.total)
                self._progress_bar.setValue(0)
                self._progress_bar.setVisible(True)

        # Batch done - ignore errors till end
        elif ev.event is MatchEventType.BATCH_DONE:
            if self._progress_bar is not None and self._progress_bar.maximum() > 0:
                self._progress_bar.setValue(ev.completed)

        # Summary - end result event
        else:
            if self._progress_bar is not None:
                self._progress_bar.setRange(0, 1)
                self._progress_bar.setValue(1)

            if not ev.ok:
                self.error_dialog = ErrorDialog(
                    error_message="One or more errors occurred during ANN processing:\n"
                    + "\n".join(ev.errors),
                    parent=self,
                )
                self.error_dialog.show()
                self._progress_bar.setVisible(False)
                # Pause UI interactions while running
                self.toggle_search_ui(pause=False)
                return

            self.matching_results = ev if ev.ok else None
            self.show_results_page()
            self.display_matching_results()
            self._progress_bar.setRange(0, 0)
            self._progress_bar.setValue(0)
            self._progress_bar.setVisible(False)

            self.toggle_search_ui(pause=False)

    # =====================================================================
    # Reset methods
    # =====================================================================

    def reset_all(self):
        self.function_update_state(check_all=False)
        self.matching_results = None
        self._selected_collections = {}
        self._selected_binaries = {}
        self.ui.searchFunctions.clear()
        self.ui.editCollections.clear()
        self.ui.editBinaries.clear()
        self.ui.spinConfidence.setValue(85)
        self.ui.chkDebugSymbols.setChecked(False)
        self.ui.chkUserDebugSymbols.setChecked(False)
        self.show_select_page()

    # =====================================================================
    # Display ANN Results
    def display_matching_results(self):
        query = (
            self.ui.resultFunctionSearch.text().strip().lower()
            if hasattr(self.ui, "resultFunctionSearch")
            else ""
        )

        if (
            self.single_function_id
            and self.matching_results.total == 1
            and len(self.matching_results.results) == 1
        ):
            self.display_matching_results_single_function(query=query)
        else:
            self.display_matching_results_multiple_functions(query=query)

    def display_matching_results_single_function(self, query: str = ""):
        """Special handling for single-function ANN results. (Multiple results per function)"""
        table: QtWidgets.QTableWidget = self.ui.tableResults

        # Columns
        labels = [
            "Select",
            "Virtual Address",
            "Function Name",
            "Matched Function",
            "Similarity",
            "Confidence",
            "Matched Hash",
            "Matched Binary",
        ]

        # Build table
        table.clear()
        table.setColumnCount(len(labels))
        table.setRowCount(
            len(self.matching_results.results[0].matched_functions)
            if self.matching_results.results
            else 0
        )
        table.setHorizontalHeaderLabels(labels)
        table.setSortingEnabled(False)  # off while populating
        table.blockSignals(True)
        table.setUpdatesEnabled(False)
        table.setWordWrap(True)
        table.horizontalHeader().setVisible(True)

        filtered_functions: List[MatchedFunction] = []

        current_func_id = self.matching_results.results[0].function_id

        for row, r in enumerate(self.matching_results.results[0].matched_functions):
            if (
                not query
                or query
                in self.matching_service.function_id_to_local_name(
                    self.matching_results.results[0].function_id
                ).lower()
                or query in r.function_name.lower()
                or query in (r.mangled_name.lower() or "")
                or query in r.binary_name.lower()
            ):
                filtered_functions.append(r)

        for row, r in enumerate(filtered_functions):
            """
            Treats rows like a radio group instead, only 1 can be selected
            """
            # Column 0: checkbox (radio behavior)
            c0 = QtWidgets.QTableWidgetItem("")
            c0.setFlags(
                c0.flags()
                | QtCore.Qt.ItemIsUserCheckable
                | QtCore.Qt.ItemIsSelectable
                | QtCore.Qt.ItemIsEnabled
            )
            c0.setCheckState(
                QtCore.Qt.Checked
                if r.function_id in self._selected_matching_items
                else QtCore.Qt.Unchecked
            )
            c0.setData(QtCore.Qt.UserRole, current_func_id)
            table.setItem(row, MatchColumns.SELECT.value, c0)

            # Column 1: Virtual Address
            table.setItem(
                row,
                MatchColumns.VIRTUAL_ADDRESS.value,
                QtWidgets.QTableWidgetItem(
                    hex(self._func_map[str(self.matching_results.results[0].function_id)])
                ),
            )

            # Column 2: Function Name
            table.setItem(
                row,
                MatchColumns.FUNC_NAME.value,
                QtWidgets.QTableWidgetItem(
                    self.matching_service.function_id_to_local_name(
                        self.matching_results.results[0].function_id
                    )
                ),
            )

            # Column 3: Matched Name
            table.setItem(
                row, MatchColumns.MATCHED_NAME.value, QtWidgets.QTableWidgetItem(r.function_name)
            )

            # Column 4: Similarity
            table.setItem(
                row,
                MatchColumns.SIMILARITY.value,
                QtWidgets.QTableWidgetItem(f"{r.similarity:.2f}"),
            )

            # Column 5: Confidence
            table.setItem(
                row,
                MatchColumns.CONFIDENCE.value,
                QtWidgets.QTableWidgetItem(f"{r.confidence:.2f}"),
            )

            # Column 6: Matched Hash
            table.setItem(
                row,
                MatchColumns.MATCHED_BINARY_HASH.value,
                QtWidgets.QTableWidgetItem(r.sha_256_hash),
            )

            # Column 7: Matched Binary
            table.setItem(
                row,
                MatchColumns.MATCHED_BINARY_NAME.value,
                QtWidgets.QTableWidgetItem(r.binary_name),
            )

        # Select, Vaddr, Similarity, Confidence, SHA-256
        for col in [
            MatchColumns.SELECT.value,
            MatchColumns.VIRTUAL_ADDRESS.value,
            MatchColumns.SIMILARITY.value,
            MatchColumns.CONFIDENCE.value,
            MatchColumns.MATCHED_BINARY_HASH.value,
        ]:
            table.resizeColumnToContents(col)
        # Current Name, Matched Func Name, Matched Binary Name
        for col in [
            MatchColumns.FUNC_NAME.value,
            MatchColumns.MATCHED_NAME.value,
            MatchColumns.MATCHED_BINARY_NAME.value,
        ]:
            table.setColumnWidth(col, 250)
        # allow these to word wrap
        table.setWordWrap(True)
        table.resizeRowsToContents()

        print(
            f"Single: Displayed {len(self.matching_results.results[0].matched_functions)} ANN results"
        )

        # --- make column-0 behave like a radio group ---
        def on_item_changed(item: QtWidgets.QTableWidgetItem):
            if item.column() != 0:
                return
            if item.checkState() != QtCore.Qt.Checked:
                return

            self._selected_matching_items.clear()
            self._selected_matching_items.add(item.data(QtCore.Qt.UserRole))

            # prevent recursive signals while unchecking others
            block = table.blockSignals(True)
            try:
                r = item.row()
                for rr in range(table.rowCount()):
                    if rr == r:
                        continue
                    other = table.item(rr, 0)
                    if other and other.checkState() != QtCore.Qt.Unchecked:
                        other.setCheckState(QtCore.Qt.Unchecked)
            finally:
                table.blockSignals(block)

        table.itemChanged.connect(on_item_changed)

        table.setSortingEnabled(True)  # off while populating
        table.blockSignals(False)
        table.setUpdatesEnabled(True)

    def display_matching_results_multiple_functions(self, query: str = ""):
        """Special handling for multi-function ANN results. (One result per function)"""
        table: QtWidgets.QTableWidget = self.ui.tableResults

        # Columns
        labels = [
            "Select",
            "Virtual Address",
            "Function Name",
            "Matched Function",
            "Similarity",
            "Confidence",
            "Matched Hash",
            "Matched Binary",
        ]

        # Build table
        table.clear()
        table.setColumnCount(len(labels))
        table.setRowCount(len(self.matching_results.results))
        table.setHorizontalHeaderLabels(labels)
        table.setSortingEnabled(False)  # off while populating
        table.setWordWrap(True)
        table.horizontalHeader().setVisible(True)

        filtered_funcs: List[FunctionMatch] = []


        for r in self.matching_results.results:
            if query:
                matched_function = r.matched_functions[0] if r.matched_functions else None
                if query in self.matching_service.function_id_to_local_name(r.function_id) or (
                    matched_function
                    and (
                        query in matched_function.function_name
                        or query in (matched_function.mangled_name or "")
                        or query in matched_function.binary_name
                    )
                ):
                    filtered_funcs.append(r)
            else:
                filtered_funcs.append(r)

        for row, r in enumerate(filtered_funcs):
            # Column 0: checkbox
            c0 = QtWidgets.QTableWidgetItem("")
            c0.setFlags(
                c0.flags()
                | QtCore.Qt.ItemIsUserCheckable
                | QtCore.Qt.ItemIsSelectable
                | QtCore.Qt.ItemIsEnabled
            )
            c0.setCheckState(
                QtCore.Qt.Checked
                if r.function_id in self._selected_matching_items
                else QtCore.Qt.Unchecked
            )
            c0.setData(QtCore.Qt.UserRole, r.function_id)
            table.setItem(row, MatchColumns.SELECT.value, c0)

            # Column 1: Virtual Address
            table.setItem(
                row,
                MatchColumns.VIRTUAL_ADDRESS.value,
                QtWidgets.QTableWidgetItem(hex(self._func_map[str(r.function_id)])),
            )

            # Column 2: Function Name
            table.setItem(
                row,
                MatchColumns.FUNC_NAME.value,
                QtWidgets.QTableWidgetItem(
                    self.matching_service.function_id_to_local_name(r.function_id)
                ),
            )

            matched_function: MatchedFunction = (
                r.matched_functions[0] if r.matched_functions else None
            )

            self.current_to_matched_func[r.function_id] = matched_function

            # Column 3: Matched Name
            table.setItem(
                row,
                MatchColumns.MATCHED_NAME.value,
                QtWidgets.QTableWidgetItem(matched_function.function_name),
            )

            # Column 4: Similarity
            table.setItem(
                row,
                MatchColumns.SIMILARITY.value,
                QtWidgets.QTableWidgetItem(f"{matched_function.similarity:.2f}"),
            )
            # Column 5: Confidence
            table.setItem(
                row,
                MatchColumns.CONFIDENCE.value,
                QtWidgets.QTableWidgetItem(f"{matched_function.confidence:.2f}"),
            )

            # Column 7: Matched Hash
            table.setItem(
                row,
                MatchColumns.MATCHED_BINARY_HASH.value,
                QtWidgets.QTableWidgetItem(matched_function.sha_256_hash),
            )

            # Column 6: Matched Binary
            table.setItem(
                row,
                MatchColumns.MATCHED_BINARY_NAME.value,
                QtWidgets.QTableWidgetItem(matched_function.binary_name),
            )

        for col in [
            MatchColumns.SELECT.value,
            MatchColumns.VIRTUAL_ADDRESS.value,
            MatchColumns.SIMILARITY.value,
            MatchColumns.CONFIDENCE.value,
            MatchColumns.MATCHED_BINARY_HASH.value,
        ]:
            table.resizeColumnToContents(col)

        for col in [
            MatchColumns.FUNC_NAME.value,
            MatchColumns.MATCHED_NAME.value,
            MatchColumns.MATCHED_BINARY_NAME.value,
        ]:
            table.setColumnWidth(col, 250)

        # allow these to word wrap
        table.setWordWrap(True)
        table.resizeRowsToContents()

        def on_item_changed(item: QtWidgets.QTableWidgetItem):
            if item.column() != 0:
                return
            if item.checkState() != QtCore.Qt.Checked:
                self._selected_matching_items.discard(item.data(QtCore.Qt.UserRole))
                return
            else:
                self._selected_matching_items.add(item.data(QtCore.Qt.UserRole))

            self._selected_matching_items.pop()
            self._selected_matching_items.add(item.data(QtCore.Qt.UserRole))

        table.itemChanged.connect(on_item_changed)

        table.setSortingEnabled(True)  # off while populating
        table.blockSignals(False)
        table.setUpdatesEnabled(True)

        print(f"Multiple: Displayed {len(self.matching_results.results)} ANN results")
        pass

    def enqueue_renames(self):
        # Read checked rows from results table
        table = self.ui.tableResults

        try:
            rename_list: List[RenameInput] = []
            for r in range(table.rowCount()):
                item = table.item(r, MatchColumns.SELECT.value)
                if item is not None and item.checkState() == QtCore.Qt.Checked:
                    function_id = item.data(QtCore.Qt.UserRole)
                    matched_item = table.item(r, MatchColumns.MATCHED_NAME.value).text()
                    vaddr = self.rename_service.function_id_to_vaddr(function_id)
                    print(f"RENAME: Function ID {function_id} -> {matched_item}")
                    rename_list.append(
                        RenameInput(
                            function_id=function_id,
                            ea=vaddr,
                            new_name=matched_item,
                        )
                    )
            self.rename_service.enqueue_rename(rename_list)
            self.accept()

        except Exception as e:
            print(f"Failed to enqueue renames: {e}")
    
    def import_data_types(self):
        print("importing data types...")
        self.data_types_service.import_data_types(self.current_to_matched_func)

    # =====================================================================
    # (Optional) page-switch helpers
    # =====================================================================
    def show_results_page(self):
        if hasattr(self.ui, "stack"):
            self.ui.stack.setCurrentIndex(1)

    def show_select_page(self):
        if hasattr(self.ui, "stack"):
            self.ui.stack.setCurrentIndex(0)

    def function_update_state(self, check_all: bool):
        """Check or uncheck all functions in the table."""
        if not hasattr(self.ui, "tableFunctions"):
            return
        view = self.ui.tableFunctions
        view.blockSignals(True)
        for r in range(view.rowCount()):
            item = view.item(r, 0)
            if item is not None:
                key = item.data(QtCore.Qt.UserRole + 1)
                if key is not None:
                    if check_all:
                        item.setCheckState(QtCore.Qt.Checked)
                        self._selected_functions.add(key)
                    else:
                        item.setCheckState(QtCore.Qt.Unchecked)
                        self._selected_functions.discard(key)
        view.blockSignals(False)
