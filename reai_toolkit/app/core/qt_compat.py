# fmt: off
# isort: skip_file
# flake8: noqa

try:
    from PySide6 import QtCore, QtGui, QtWidgets

    Signal = QtCore.Signal
    Slot = QtCore.Slot
    QT_VER = 6
except Exception:
    from PyQt5 import QtCore, QtGui, QtWidgets

    Signal = QtCore.pyqtSignal
    Slot = QtCore.pyqtSlot
    QT_VER = 5


def flag_val(x):
    return x.value if hasattr(x, "value") else int(x)


def item_flags(base, *extras):
    v = flag_val(base)
    for e in extras:
        v |= flag_val(e)
    try:
        return QtCore.Qt.ItemFlags(v)  # PySide6
    except TypeError:
        return v  # PyQt5


def disconnect_safe(signal, slot=None):
    try:
        if slot is None:
            signal.disconnect()
        else:
            signal.disconnect(slot)
    except Exception:
        pass
