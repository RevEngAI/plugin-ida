from reai_toolkit.app.components.dialogs.base_dialog import DialogBase
from reai_toolkit.app.core.config_service import ConfigService

# --- Pick a Qt binding & the right compiled UI module ---
from reai_toolkit.app.core.qt_compat import QT_VER, QtCore, QtGui, QtWidgets
from reai_toolkit.app.services.auth.auth_service import AuthService

if QT_VER == 6:
    from reai_toolkit.app.components.forms.auth.auth_panel_ui_uic6 import (
        Ui_AuthPanel,
    )
else:
    from reai_toolkit.app.components.forms.auth.auth_panel_ui_uic5 import (
        Ui_AuthPanel,
    )

import ida_kernwin


def _open_external(url: str):
    try:
        import ida_kernwin

        ida_kernwin.open_url(url)
    except Exception:
        import webbrowser

        webbrowser.open(url)


class AuthDialog(DialogBase):
    """
    Modeless dialog using the compiled UI.
    Expects objectNames in the .ui: apiUrlEdit, portalUrlEdit, apiKeyEdit,
    okButton, cancelButton, (optional) logoArea.
    """

    auth_service: AuthService = None
    config_service: ConfigService = None

    def __init__(
        self,
        *,
        cfg: ConfigService,
        auth_service: AuthService,
        parent: QtWidgets.QWidget | None = None,
    ):
        super().__init__(parent=parent)
        self.setWindowTitle("RevEng.AI — Configuration")
        self.setModal(False)
        self.auth_service = auth_service
        self.config_service = cfg
        self.ui = Ui_AuthPanel()
        self.ui.setupUi(self)
        self.setFixedSize(self.size())

        logo_path = self._find_resource(self.base_logo_path)
        px = QtGui.QPixmap(logo_path)
        self.ui.logoArea.setPixmap(px)

        if self.config_service:
            self.ui.apiUrlEdit.setText(self.config_service.api_url)
            self.ui.portalUrlEdit.setText(self.config_service.portal_url)
            self.ui.apiKeyEdit.setText(self.config_service.api_key)
            self.ui.getKeyLink.setText('<a href="get_key">Get an API key</a>')
            self.ui.getKeyLink.setTextFormat(QtCore.Qt.RichText)
            self.ui.getKeyLink.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
            self.ui.getKeyLink.setOpenExternalLinks(False)  # Disable auto-opening
            self.ui.getKeyLink.linkActivated.connect(self._on_get_key_clicked)

        # Wire buttons
        self.ui.okButton.clicked.connect(self._on_ok)
        self.ui.cancelButton.clicked.connect(self._on_cancel)

    def _on_cancel(self):
        # Reload the old config to service
        self.config_service.load()
        self.reject()

    def _on_get_key_clicked(self, _link: str):
        # Get fresh URLs from config at click time
        portal_url = getattr(self.config_service, "portal_url", "") or "#"
        if not portal_url or portal_url == "#":
            ida_kernwin.warning("No portal URL configured. Please configure it.")
            return

        full_url = f"{portal_url.rstrip('/')}/settings"
        _open_external(full_url)

    def _on_ok(self):
        # Save back into cfg if provided (fields are optional-safe)
        if self.config_service:
            self.config_service.api_url = (
                (self.ui.apiUrlEdit.text() or "").strip().rstrip("/")
            )
            self.config_service.portal_url = (
                (self.ui.portalUrlEdit.text() or "").strip().rstrip("/")
            )
            self.config_service.api_key = (self.ui.apiKeyEdit.text() or "").strip()

        # Verify the API key
        self.auth_service.build_sdk_config()
        success, error_msg = self.auth_service.verify()

        if not success:
            # Need self to keep the dialog alive - sometimes gets killed immediately otherwise
            self.open_error_dialog(error_msg)
            return

        # On success, save and reload the config values
        self.config_service.save()

        # Close dialog
        self.accept()
