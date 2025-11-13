from typing import Any, Callable, Optional

import ida_kernwin as kw
from loguru import logger

# Use IDA's Qt through your compat layer
from reai_toolkit.app.core.qt_compat import QtCore, QtGui, QtWidgets


# -----------------------------
# Rich C/C++-style highlighter
# -----------------------------
class CppHighlighter(QtGui.QSyntaxHighlighter):
    def __init__(self, parent_doc: QtGui.QTextDocument):
        super().__init__(parent_doc)

        self.fmt_kw = self._fmt("#c678dd", bold=True)  # keywords
        self.fmt_type = self._fmt("#56b6c2")  # builtin types
        self.fmt_num = self._fmt("#d19a66")  # numbers
        self.fmt_str = self._fmt("#98c379")  # strings / chars
        self.fmt_com = self._fmt("#5c6370", italic=True)  # comments
        self.fmt_fn = self._fmt("#61afef")  # function idents

        keywords = """
            alignas alignof and and_eq asm auto break case catch class compl concept const consteval constexpr constinit
            continue decltype default delete do else enum explicit export extern false for friend goto if inline mutable
            namespace new noexcept not not_eq nullptr operator or or_eq private protected public reflexpr register
            reinterpret_cast requires return sizeof static static_assert static_cast struct switch template this
            thread_local throw true try typedef typeid typename union using virtual volatile while xor xor_eq
        """.split()

        types = """
            char char8_t char16_t char32_t wchar_t bool short int long signed unsigned float double void
            size_t ptrdiff_t int8_t int16_t int32_t int64_t uint8_t uint16_t uint32_t uint64_t
        """.split()

        self.rules: list[tuple[QtCore.QRegularExpression, QtGui.QTextCharFormat]] = []
        b = r"\b"
        self.rules += [
            (QtCore.QRegularExpression(b + k + b), self.fmt_kw) for k in keywords
        ]
        self.rules += [
            (QtCore.QRegularExpression(b + t + b), self.fmt_type) for t in types
        ]

        # numbers
        self.rules += [
            (QtCore.QRegularExpression(r"\b0[xX][0-9A-Fa-f]+\b"), self.fmt_num),
            (
                QtCore.QRegularExpression(r"\b\d+\.\d+(?:[eE][+-]?\d+)?[fFlL]?\b"),
                self.fmt_num,
            ),
            (QtCore.QRegularExpression(r"\b\d+[uUlL]*\b"), self.fmt_num),
        ]

        # strings & chars
        self.re_string = QtCore.QRegularExpression(r"\"([^\"\\]|\\.)*\"")
        self.re_char = QtCore.QRegularExpression(r"'([^'\\]|\\.)*'")

        # function identifier (group 1 = identifier)
        self.re_func = QtCore.QRegularExpression(r"\b([A-Za-z_]\w*)\s*(?=\()")

        # comments (// and /* ... */ with multi-line state)
        self.re_line_comment = QtCore.QRegularExpression(r"//[^\n]*")
        self.start_block = QtCore.QRegularExpression(r"/\*")
        self.end_block = QtCore.QRegularExpression(r"\*/")

    @staticmethod
    def _fmt(
        color: str, *, bold: bool = False, italic: bool = False
    ) -> QtGui.QTextCharFormat:
        f = QtGui.QTextCharFormat()
        f.setForeground(QtGui.QColor(color))
        if bold:
            f.setFontWeight(QtGui.QFont.Bold)
        if italic:
            f.setFontItalic(True)
        return f

    def highlightBlock(self, text: str):
        # base token rules
        for rx, fmt in self.rules:
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)

        # strings / chars
        for rx in (self.re_string, self.re_char):
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), self.fmt_str)

        # function identifiers
        it = self.re_func.globalMatch(text)
        while it.hasNext():
            m = it.next()
            self.setFormat(m.capturedStart(1), m.capturedLength(1), self.fmt_fn)

        # // line comments
        it = self.re_line_comment.globalMatch(text)
        while it.hasNext():
            m = it.next()
            self.setFormat(m.capturedStart(), m.capturedLength(), self.fmt_com)

        # /* ... */ multi-line comments with state
        self.setCurrentBlockState(0)
        start_idx = 0
        if self.previousBlockState() != 1:
            m = self.start_block.match(text)
            start_idx = m.capturedStart() if m.hasMatch() else -1
        else:
            start_idx = 0

        while start_idx >= 0:
            endm = self.end_block.match(text, start_idx)
            if endm.hasMatch():
                end_idx = endm.capturedEnd()
                self.setFormat(start_idx, end_idx - start_idx, self.fmt_com)
                m = self.start_block.match(text, end_idx)
                start_idx = m.capturedStart() if m.hasMatch() else -1
            else:
                self.setFormat(start_idx, len(text) - start_idx, self.fmt_com)
                self.setCurrentBlockState(1)
                break


# ----------------------------------------
# Dockable view that hosts the highlighter
# ----------------------------------------
class AIDecompView(kw.PluginForm):
    """
    Dockable tab using Qt editor + QSyntaxHighlighter.
    API kept compatible with your previous simplecustviewer_t:
      - Create(title)    -> shows the form
      - set_code(text)   -> updates text (UI-thread safe)
      - focus()          -> activates the tab
      - OnClose()        -> calls on_closed callback
    """

    TITLE = "RevEng.AI — Decompiled View"

    def __init__(self, on_closed: Optional[Callable[[], None]] = None) -> None:
        super().__init__()
        self._on_closed = on_closed
        self._parent_w: Optional[QtWidgets.QWidget] = None
        self._editor: Optional[QtWidgets.QPlainTextEdit] = None
        self._highlighter: Optional[CppHighlighter] = None

    # --- lifecycle -------------------------------------------------

    def Create(self, title: Any) -> Any:
        """Compatibility shim: show the PluginForm like your previous Create()."""
        flags = getattr(kw.PluginForm, "WOPN_DP_TAB", 0) | getattr(
            kw.PluginForm, "WOPN_RESTORE", 0
        )
        ok = self.Show(str(title) if title else self.TITLE, flags)
        if not ok:
            logger.error("Failed to show AI Decompiler tab")
        else:
            # Try docking near Hex-Rays
            try:
                kw.set_dock_pos(
                    str(title) if title else self.TITLE, "Pseudocode-A", kw.DP_RIGHT
                )
            except Exception:
                pass
        return ok

    def OnCreate(self, form) -> None:
        """Called by IDA when the form is created; build our Qt UI here."""
        self._parent_w = kw.PluginForm.FormToPyQtWidget(form)

        # Layout root
        layout = QtWidgets.QVBoxLayout(self._parent_w)
        layout.setContentsMargins(0, 0, 0, 0)

        # Editor
        self._editor = QtWidgets.QPlainTextEdit(self._parent_w)
        self._editor.setReadOnly(True)
        self._editor.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)

        # Monospace font tuned for IDA
        font = QtGui.QFont(
            "Menlo"
            if QtCore.QOperatingSystemVersion.currentType()
            == QtCore.QOperatingSystemVersion.MacOS
            else "Consolas"
        )
        font.setStyleHint(QtGui.QFont.Monospace)
        font.setFixedPitch(True)
        font.setPointSize(11)
        self._editor.setFont(font)

        layout.addWidget(self._editor)

        # Highlighter
        self._highlighter = CppHighlighter(self._editor.document())

    def OnClose(self, form) -> None:
        """Called when the user closes the tab."""
        if callable(self._on_closed):
            try:
                self._on_closed()
            except Exception as e:
                logger.warning(f"on_closed callback failed: {e}")
        self._highlighter = None
        self._editor = None
        self._parent_w = None

    # --- public API ------------------------------------------------

    def set_code(self, code: Optional[str], *, highlight: bool = True) -> None:
        """Thread-safe: marshal to UI thread if needed."""

        def _apply():
            if not self._editor:
                return
            self._editor.blockSignals(True)
            try:
                self._editor.setPlainText(code or "// No code available.")
                # Highlighter is attached to the document; nothing extra to do.
                # (If you ever want to toggle highlighting off, you can
                # reassign a NullHighlighter or call self._highlighter.setDocument(None).)
            finally:
                self._editor.blockSignals(False)

        # ensure we’re on IDA’s UI thread
        try:
            kw.execute_sync(_apply, kw.MFF_FAST)
        except Exception:
            _apply()  # best-effort fallback

    def clear(self) -> None:
        self.set_code("")

    def focus(self) -> None:
        if self._parent_w:
            try:
                kw.activate_widget(self._parent_w, True)
            except Exception:
                pass
