# Development

## App structure

The plugin code lives in `reai_toolkit/`, with the entry point at
`reai_toolkit_entry.py`. It follows an **app / coordinator / factory** pattern:

- **App** (`reai_toolkit/app/app.py`) — holds a single instance of each service.
- **Coordinator** (`reai_toolkit/app/coordinator.py`) — handles UI calls,
  background threads and queues, and service calls.
- **Factory** (`reai_toolkit/app/factory.py`) — constructs the dialogs.

## Hooks

- **Top-level menu** — `reai_toolkit/hooks/menu.py`. Add a
  `ida_kernwin.action_handler_t` subclass, register it in `_handlers` inside
  `register_menu_hooks` (this dict is retained so the actions don't disappear),
  create it with `ida_kernwin.register_action` using a unique `reai:` key, then
  attach it with `ida_kernwin.attach_action_to_menu`.
- **Popup / right-click** — `reai_toolkit/hooks/popup.py`. Each action has a
  `_register_*_action` helper that unregisters the action first (IDA rebuilds the
  context menu each time it opens) before re-registering it; they are wired up in
  `build_hooks`.
- **Reactive (IDA events)** — `reai_toolkit/hooks/reactive.py`. Subclass the
  relevant IDA hook base (`idaapi.IDB_Hooks`, `ida_kernwin.UI_Hooks`) and
  override the events you care about. Currently used to copy renames to the
  portal and drive the AI-decompilation view.

## UI

The UI is built with Qt5 Creator as `.ui` XML files (Qt5 format) under
`reai_toolkit/app/components/forms/`. We support both PyQt5 and PySide6 for IDA
compatibility, so each `.ui` is compiled to **two** Python modules — a
`*_uic5.py` (via `pyuic5`) and a `*_uic6.py` (via `pyside6-uic`). Qt6 is mostly
backwards compatible with the Qt5 `.ui` format.

### Regenerating the compiled UI

After editing a `.ui` file, regenerate both outputs. Example for the `about`
panel (run from the repo root inside the UV venv):

```bash
uv run pyside6-uic reai_toolkit/app/components/forms/about/about_panel_qt5.ui \
  -o reai_toolkit/app/components/forms/about/about_panel_ui_uic6.py

uv run pyuic5 reai_toolkit/app/components/forms/about/about_panel_qt5.ui \
  -o reai_toolkit/app/components/forms/about/about_panel_ui_uic5.py
```

Notes:

- You may need to (re)install the Qt tooling (`PySide6`, `pyqt5`) for these
  commands to be available.
- Run `black` over the regenerated files afterwards to match the repo style.

## Dialogs

Dialogs are the windows built on top of the compiled UI files. Inherit
`DialogBase` from `reai_toolkit/app/components/dialogs/base_dialog.py`, which
provides `open_modal()` (opens modally, returns whether it was accepted plus the
`result_data` attribute), `open_error_dialog(message)`, and
`_find_resource(name)` for locating bundled resources such as images.

Import the compiled form for whichever Qt binding is available — prefer PyQt5
(IDA 9.1) and fall back to PySide6 (IDA 9.2):

```python
try:
    from PyQt5 import QtWidgets, QtCore, QtGui  # type: ignore
    from reai_toolkit.app.components.forms.alert.alert_panel_ui_uic5 import Ui_AlertPanel
except Exception:
    from PySide6 import QtWidgets, QtCore, QtGui  # type: ignore
    from reai_toolkit.app.components.forms.alert.alert_panel_ui_uic6 import Ui_AlertPanel
```

## Local dev

Currently limited — copy changes into the IDA `plugins/` directory to test.
Vendored packages are a working copy fetched from the latest release.
