from reai_toolkit.app.components.dialogs.base_dialog import DialogBase
from reai_toolkit.app.core.qt_compat import QT_VER, QtCore, QtGui, QtWidgets

if QT_VER == 6:
    from reai_toolkit.app.components.forms.about.about_panel_ui_uic6 import (
        Ui_AboutPanel,
    )
else:
    from reai_toolkit.app.components.forms.about.about_panel_ui_uic5 import (
        Ui_AboutPanel,
    )


class AboutDialog(DialogBase):
    def __init__(self, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)

        self.setWindowTitle("RevEng.AI — Help")
        self.setModal(True)

        self.ui = Ui_AboutPanel()
        self.ui.setupUi(self)
        self.setFixedSize(self.size())

        logo_path = self._find_resource(self.base_logo_path)
        px = QtGui.QPixmap(logo_path)
        self.ui.logoArea.setPixmap(px)

        # Buttons
        self.ui.okButton.clicked.connect(self.accept)

        self.ui.btnDiscord.clicked.connect(self._open_discord)
        self.ui.btnEmail.clicked.connect(self._open_email)

    @staticmethod
    def _open_discord():
        QtGui.QDesktopServices.openUrl(
            QtCore.QUrl("https://discord.com/invite/ZwQTvzfSbA")
        )
        return

    @staticmethod
    def _open_email():
        QtGui.QDesktopServices.openUrl(QtCore.QUrl("mailto:contact@reveng.ai"))
