# ui/dialogs/base.py
import os
from pathlib import Path

import idaapi

from reai_toolkit.app.core.qt_compat import QtWidgets


class DialogBase(QtWidgets.QDialog):
    result_data = None
    user_plugins_dir = os.path.join(idaapi.get_user_idadir(), "plugins")
    base_logo_path = "reveng_ai_logo.jpg"
    _cached_logo_path = None

    def __init__(self, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)

    def open_modal(self):
        rc = self.exec_() if hasattr(self, "exec_") else self.exec()
        return rc == QtWidgets.QDialog.Accepted, self.result_data

    def open_error_dialog(self, message: str):
        from reai_toolkit.app.components.dialogs.error_dialog import ErrorDialog

        dlg = ErrorDialog(error_message=message, parent=self)
        dlg.show()

    def _find_resource(self, name: str, ignore_cache: bool = False) -> str | None:
        if self._cached_logo_path and not ignore_cache:
            return self._cached_logo_path

        """Look for a resource next to the plugin & package; return absolute path or None."""
        here = Path(__file__).resolve()
        candidates = [
            # package-relative: .../app/components/dialogs/__file__ -> .../app/resources/name
            here.parent.parent / "resources" / name,
            # user plugins dir (if running from ~/.idapro/plugins)
            Path(getattr(self, "user_plugins_dir", ""))
            / "reai_toolkit"
            / "app"
            / "components"
            / "resources"
            / name,
            # installed-IDA plugins dir (if bundled inside the app)
            # tweak if you also ship under IDA install plugins/
            Path(idaapi.idadir(""))
            / "plugins"
            / "reai_toolkit"
            / "app"
            / "components"
            / "resources"
            / name,
        ]
        for p in candidates:
            if p and p.exists():
                self._cached_logo_path = str(p)
                return self._cached_logo_path
        return None
