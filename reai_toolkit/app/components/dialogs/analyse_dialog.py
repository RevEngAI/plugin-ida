import os
from typing import Any, Callable

import idaapi

from reai_toolkit.app.components.dialogs.base_dialog import DialogBase
from reai_toolkit.app.core.qt_compat import QT_VER, QtGui, QtWidgets
from reai_toolkit.app.services.upload.upload_service import UploadService

if QT_VER == 6:
    from reai_toolkit.app.components.forms.analyse.analyse_panel_ui_uic6 import (
        Ui_AuthPanel,
    )
else:
    from reai_toolkit.app.components.forms.analyse.analyse_panel_ui_uic5 import (
        Ui_AuthPanel,
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

    file_path: str = None
    file_name: str = None
    debug_file_path: str = None
    upload_service: UploadService = None
    callback: Callable[..., Any] = None

    def __init__(
        self,
        *,
        upload_service: UploadService,
        callback: Callable[..., Any],
        parent: QtWidgets.QWidget | None = None,
    ):
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

    def _on_ok(self):
        """

        file_name: str,
        file_path: str,
        debug_file_path: str | None = None,
        tags: list[str] | None = None,
        public: bool = True,

        """

        self.upload_service.start_analysis(
            file_path=self.file_path,
            file_name=self.ui.apiFileName.text().strip() or self.file_name,
            debug_file_path=self.debug_file_path,
            tags=[],
            public=True if self.ui.radioButton_2.isChecked() else False,
            thread_callback=self.callback,
        )

        self.accept()
