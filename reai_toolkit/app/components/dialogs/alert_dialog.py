from reai_toolkit.app.components.dialogs.base_dialog import DialogBase
from reai_toolkit.app.core.qt_compat import QT_VER, QtGui, QtWidgets

if QT_VER == 6:
    from reai_toolkit.app.components.forms.alert.alert_panel_ui_uic6 import (
        Ui_AlertPanel,
    )
else:
    from reai_toolkit.app.components.forms.alert.alert_panel_ui_uic5 import (
        Ui_AlertPanel,
    )


class AlertDialog(DialogBase):
    """
    Modal dialog using the compiled UI.
    """

    def __init__(self, message: str, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)

        self.setWindowTitle("RevEng.AI — Alert")
        self.setModal(True)

        self.ui = Ui_AlertPanel()
        self.ui.setupUi(self)
        self.setFixedSize(self.size())

        logo_path = self._find_resource(self.base_logo_path)
        px = QtGui.QPixmap(logo_path)
        self.ui.logoArea.setPixmap(px)

        # Set the error message
        self.ui.message.setText(f"```{message}```")

        # Wire buttons
        self.ui.okButton.clicked.connect(self.accept)
