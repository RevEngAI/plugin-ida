from reai_toolkit.app.components.dialogs.base_dialog import DialogBase
from reai_toolkit.app.core.qt_compat import QT_VER, QtGui, QtWidgets

if QT_VER == 6:
    from reai_toolkit.app.components.forms.error.error_panel_ui_uic6 import (
        Ui_AuthPanel as error_pan,
    )
else:
    from reai_toolkit.app.components.forms.error.error_panel_ui_uic5 import (
        Ui_AuthPanel as error_pan,
    )


class ErrorDialog(DialogBase):
    """
    Modal dialog using the compiled UI.
    Expects objectNames in the .ui: errorMessageEdit, okButton, cancelButton.
    """

    def __init__(self, error_message: str, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)

        self.setWindowTitle("RevEng.AI — Error")
        self.setModal(True)

        self.ui = error_pan()
        self.ui.setupUi(self)
        self.setFixedSize(self.size())

        logo_path = self._find_resource(self.base_logo_path)
        px = QtGui.QPixmap(logo_path)
        self.ui.logoArea.setPixmap(px)

        # Set the error message
        self.ui.errorMessage.setText(f"```{error_message}```")

        # Wire buttons
        self.ui.okButton.clicked.connect(self.accept)
