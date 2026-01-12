import sys
from pathlib import Path

import ida_kernwin
import idaapi


def _add_vendor_paths():
    here = Path(__file__).resolve().parent
    pkg_root = here / "reai_toolkit"  # where your package + vendor live
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"

    # Check both root and reai_toolkit/ for vendor layouts
    roots = [here, pkg_root]
    suffixes = [
        "vendor",
        "vendor/site-packages",
        "vendor/Lib/site-packages",  # Windows
        f"vendor/lib/{pyver}/site-packages",  # Linux/mac (prefix-like)
        f"vendor/{pyver}/site-packages",  # some tools
    ]

    for root in roots:
        for suf in suffixes:
            p = root / suf
            if p.exists() and str(p) not in sys.path:
                sys.path.insert(0, str(p))


_add_vendor_paths()

# flake8: noqa: E402
from loguru import logger

from reai_toolkit.app.app import App
from reai_toolkit.app.coordinator import Coordinator
from reai_toolkit.app.factory import DialogFactory
from reai_toolkit.hooks.menu import register_menu_hooks
from reai_toolkit.hooks.popup import build_hooks
from reai_toolkit.hooks.reactive import FuncChangeHooks

# flake8: noqa: E402

# TODO: Obtain this from package metadata or ship pyproject.toml with plugin.
__PLUGIN_VERSION__ = "3.3.0"
__IDA_VERSION__ = idaapi.get_kernel_version()


class ReaiToolkitPlugin(idaapi.plugin_t):
    # flags are feature bits (NOT keep/ok/skip)
    # PLUGIN_MULTI lets it work with multiple IDBs; 0 is also fine.
    flags = idaapi.PLUGIN_MULTI

    comment = "RevEng.AI menu demo"
    help = "RevEng.AI menu demo"
    wanted_name = "RevEng.AI"
    wanted_hotkey = ""
    app: App = None
    factory: DialogFactory = None
    coordinator: Coordinator = None
    _ui_hooks: ida_kernwin.UI_Hooks = None

    def __init__(self):
        self._func_hooks = None
        self._popup_hooks = None
        self._menu_handlers = None

    def init(self):
        self.app = App(__IDA_VERSION__, __PLUGIN_VERSION__)
        self.factory = DialogFactory(self.app)
        print(Coordinator.__abstractmethods__)
        self.coordinator = Coordinator(app=self.app, factory=self.factory, log=logger)

        # Top level menu hooks
        self._menu_handlers = register_menu_hooks(self.coordinator, __PLUGIN_VERSION__)

        # Reactive function change hooks
        self._func_hooks = FuncChangeHooks(self.app)
        self._func_hooks.hook()

        # Popup menu hooks
        self._popup_hooks = build_hooks(self.coordinator)
        self._popup_hooks.hook()

        # UI hook for DB load
        self._ui_hooks = ida_kernwin.UI_Hooks()
        self._ui_hooks.database_inited = self._on_idb_loaded
        self._ui_hooks.ready_to_run = self._on_ui_ready
        self._ui_hooks.hook()

        # ida_kernwin.msg("[REAI] init() called, waiting for DB or UI ready...\n")

        # Fallback timer in case the events are missed
        idaapi.register_timer(1000, lambda: (self._show_setup_if_needed(), -1)[1])

        return idaapi.PLUGIN_KEEP

    def _on_idb_loaded(self, is_new_database, idc_script):
        ida_kernwin.msg(
            f"[REAI] _on_idb_loaded is_new={is_new_database} script={idc_script}\n"
        )
        self._show_setup_if_needed()
        return 0

    def _on_ui_ready(self):
        ida_kernwin.msg("[REAI] _on_ui_ready triggered\n")
        self._show_setup_if_needed()
        self.coordinator.safe_refresh()

    def _show_setup_if_needed(self):
        ida_kernwin.msg("[REAI] _show_setup_if_needed called\n")
        self.app.auth_service.verify()
        if self.app.auth_service.is_authenticated():
            ida_kernwin.msg("[REAI] SDK config is valid, no dialog.\n")
            ida_kernwin.refresh_idaview_anyway()
            return

        self.coordinator.authc.run_dialog()
        ida_kernwin.refresh_idaview_anyway()

    def run(self, arg):  # not used
        pass

    def term(self):
        ida_kernwin.msg("[REAI] term.\n")


def PLUGIN_ENTRY():
    # return a singleton instance (extra safety)
    if not hasattr(PLUGIN_ENTRY, "_inst"):
        PLUGIN_ENTRY._inst = ReaiToolkitPlugin()
    return PLUGIN_ENTRY._inst
