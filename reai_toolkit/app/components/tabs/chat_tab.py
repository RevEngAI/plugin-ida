"""Dockable Agent Chat panel + background streaming worker.

`ChatPanel` is a dumb renderer over a :class:`ChatState`; all state/business
logic lives in :class:`ChatCoordinator`. `ChatStreamWorker` runs the network
turn (create → send → stream) on a `QThread` and emits Qt signals; a QObject
relay with UI-thread affinity guarantees those signals are delivered on the UI
thread (a bound method of the non-QObject `PluginForm` would otherwise run on the
worker thread under an auto/direct connection).
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

import ida_kernwin as kw
from loguru import logger

from reai_toolkit.app.components.tabs.chat_render import (
    find_pending_confirmation,
    parse_jump_href,
    render_transcript_markdown,
    title_case,
)
from reai_toolkit.app.core.qt_compat import QtCore, QtWidgets, Signal, Slot
from reai_toolkit.app.services.chat.schema import ChatState


class ChatStreamWorker(QtCore.QObject):
    """Runs one chat turn (optional create → optional send → stream) off-thread."""

    event_ready = Signal(object)
    conversation_created = Signal(str)
    errored = Signal(str)
    finished = Signal()

    def __init__(
        self,
        chat_service,
        conversation_id: Optional[str],
        content: Optional[str],
        context,
        last_event_id: Optional[int] = None,
    ) -> None:
        super().__init__()
        self._svc = chat_service
        self._conversation_id = conversation_id
        self._content = content
        self._context = context
        self._last_event_id = last_event_id
        self._stopped = False
        self._stop_event = threading.Event()

    @Slot()
    def run(self) -> None:
        try:
            conv_id = self._conversation_id
            if conv_id is None:
                res = self._svc.create_conversation(self._context)
                if not res.success or not res.data:
                    self.errored.emit(res.error_message or "Failed to create conversation")
                    return
                conv_id = res.data
                self.conversation_created.emit(conv_id)

            if self._stopped:
                return

            if self._content is not None:
                res = self._svc.send_message(conv_id, self._content, self._context)
                if not res.success:
                    self.errored.emit(res.error_message or "Failed to send message")
                    return

            if self._stopped:
                return

            for ev in self._svc.stream(conv_id, self._stop_event, self._last_event_id):
                if self._stopped:
                    break
                self.event_ready.emit(ev)
        except Exception as e:
            self.errored.emit(str(e))
        finally:
            self.finished.emit()

    def stop(self) -> None:
        self._stopped = True
        self._stop_event.set()
        try:
            self._svc.close_active_stream()
        except Exception:
            pass


class _StreamRelay(QtCore.QObject):
    """UI-thread QObject that forwards worker signals to plain callbacks."""

    def __init__(self) -> None:
        super().__init__()
        self.on_event: Optional[Callable] = None
        self.on_conversation_created: Optional[Callable] = None
        self.on_error: Optional[Callable] = None
        self.on_finished: Optional[Callable] = None

    @Slot(object)
    def handle_event(self, ev) -> None:
        if self.on_event:
            self.on_event(ev)

    @Slot(str)
    def handle_conversation_created(self, uuid: str) -> None:
        if self.on_conversation_created:
            self.on_conversation_created(uuid)

    @Slot(str)
    def handle_error(self, msg: str) -> None:
        if self.on_error:
            self.on_error(msg)

    @Slot()
    def handle_finished(self) -> None:
        if self.on_finished:
            self.on_finished()


class _ChatInput(QtWidgets.QPlainTextEdit):
    submit = Signal()

    def keyPressEvent(self, event) -> None:
        key = event.key()
        is_enter = key in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter)
        shift = bool(event.modifiers() & QtCore.Qt.ShiftModifier)
        if is_enter and not shift:
            self.submit.emit()
            return
        super().keyPressEvent(event)


class ChatPanel(kw.PluginForm):
    TITLE = "RevEng.AI — Agent Chat"

    def __init__(self, on_closed: Optional[Callable[[], None]] = None) -> None:
        super().__init__()
        self._on_closed = on_closed

        self.on_send: Optional[Callable[[str], None]] = None
        self.on_stop: Optional[Callable[[], None]] = None
        self.on_confirm: Optional[Callable[[str, bool], None]] = None
        self.on_new_chat: Optional[Callable[[], None]] = None
        self.on_select_conversation: Optional[Callable[[str], None]] = None
        self.on_request_history: Optional[Callable[[], None]] = None
        self.on_jump: Optional[Callable[[int], None]] = None
        self.on_stream_event: Optional[Callable] = None
        self.on_stream_conversation_created: Optional[Callable[[str], None]] = None
        self.on_stream_error: Optional[Callable[[str], None]] = None
        self.on_stream_finished: Optional[Callable[[], None]] = None

        self._parent_window: Optional[QtWidgets.QWidget] = None
        self._title_label: Optional[QtWidgets.QLabel] = None
        self._context_label: Optional[QtWidgets.QLabel] = None
        self._history_list: Optional[QtWidgets.QListWidget] = None
        self._transcript: Optional[QtWidgets.QTextBrowser] = None
        self._confirm_bar: Optional[QtWidgets.QWidget] = None
        self._confirm_msg: Optional[QtWidgets.QLabel] = None
        self._input: Optional[_ChatInput] = None
        self._send_btn: Optional[QtWidgets.QPushButton] = None
        self._stop_btn: Optional[QtWidgets.QPushButton] = None

        self._relay: Optional[_StreamRelay] = None
        self._thread: Optional[QtCore.QThread] = None
        self._worker: Optional[ChatStreamWorker] = None
        self._streaming = False
        self._zombies: list = []

        self._render_timer: Optional[QtCore.QTimer] = None
        self._pending_state: Optional[ChatState] = None
        self._pending_confirm_id: Optional[str] = None
        self._last_rendered_md: Optional[str] = None

    def Create(self, title) -> bool:
        flags = getattr(kw.PluginForm, "WOPN_DP_TAB", 0) | getattr(
            kw.PluginForm, "WOPN_RESTORE", 0
        )
        name = str(title) if title else self.TITLE
        ok = self.Show(name, flags)
        if not ok:
            logger.error("Failed to show Agent Chat tab")
        else:
            try:
                kw.set_dock_pos(name, "Pseudocode-A", kw.DP_RIGHT)
            except Exception:
                pass
        return ok

    def OnCreate(self, form) -> None:
        self._parent_window = self.FormToPyQtWidget(form)
        root = QtWidgets.QVBoxLayout(self._parent_window)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        header = QtWidgets.QHBoxLayout()
        self._title_label = QtWidgets.QLabel("AI Agent")
        f = self._title_label.font()
        f.setBold(True)
        self._title_label.setFont(f)
        self._context_label = QtWidgets.QLabel("")
        self._context_label.setStyleSheet("color: gray;")
        history_btn = QtWidgets.QPushButton("History")
        new_btn = QtWidgets.QPushButton("New chat")
        header.addWidget(self._title_label)
        header.addStretch(1)
        header.addWidget(self._context_label)
        header.addWidget(history_btn)
        header.addWidget(new_btn)
        root.addLayout(header)

        self._history_list = QtWidgets.QListWidget()
        self._history_list.setVisible(False)
        self._history_list.setMaximumHeight(140)
        root.addWidget(self._history_list)

        self._transcript = QtWidgets.QTextBrowser()
        self._transcript.setOpenLinks(False)
        self._transcript.setOpenExternalLinks(False)
        self._transcript.anchorClicked.connect(self._on_anchor_clicked)
        root.addWidget(self._transcript, 1)

        self._confirm_bar = QtWidgets.QWidget()
        cbar = QtWidgets.QHBoxLayout(self._confirm_bar)
        cbar.setContentsMargins(0, 0, 0, 0)
        self._confirm_msg = QtWidgets.QLabel("")
        self._confirm_msg.setWordWrap(True)
        approve_btn = QtWidgets.QPushButton("Approve")
        reject_btn = QtWidgets.QPushButton("Reject")
        cbar.addWidget(self._confirm_msg, 1)
        cbar.addWidget(approve_btn)
        cbar.addWidget(reject_btn)
        self._confirm_bar.setVisible(False)
        root.addWidget(self._confirm_bar)

        input_row = QtWidgets.QHBoxLayout()
        self._input = _ChatInput()
        self._input.setPlaceholderText("Ask a question…  (Enter to send, Shift+Enter for newline)")
        self._input.setMaximumHeight(80)
        self._send_btn = QtWidgets.QPushButton("Send")
        self._stop_btn = QtWidgets.QPushButton("Stop")
        self._stop_btn.setEnabled(False)
        btn_col = QtWidgets.QVBoxLayout()
        btn_col.addWidget(self._send_btn)
        btn_col.addWidget(self._stop_btn)
        input_row.addWidget(self._input, 1)
        input_row.addLayout(btn_col)
        root.addLayout(input_row)

        history_btn.clicked.connect(self._on_history_clicked)
        new_btn.clicked.connect(self._on_new_chat_clicked)
        approve_btn.clicked.connect(lambda: self._on_confirm_clicked(True))
        reject_btn.clicked.connect(lambda: self._on_confirm_clicked(False))
        self._send_btn.clicked.connect(self._on_send_clicked)
        self._stop_btn.clicked.connect(self._on_stop_clicked)
        self._input.submit.connect(self._on_send_clicked)
        self._history_list.itemActivated.connect(self._on_history_item)
        self._history_list.itemClicked.connect(self._on_history_item)

        self._render_timer = QtCore.QTimer(self._parent_window)
        self._render_timer.setSingleShot(True)
        self._render_timer.setInterval(40)
        self._render_timer.timeout.connect(self._flush_render)

        self._relay = _StreamRelay()
        self._relay.on_event = self._handle_stream_event
        self._relay.on_conversation_created = self._handle_conversation_created
        self._relay.on_error = self._handle_stream_error
        self._relay.on_finished = self._handle_stream_finished

    def OnClose(self, form) -> None:
        self.stop_stream_worker()
        if self._render_timer is not None:
            try:
                self._render_timer.stop()
            except Exception:
                pass
        if callable(self._on_closed):
            try:
                self._on_closed()
            except Exception as e:
                logger.warning(f"Agent Chat on_closed failed: {e}")
        self._transcript = None
        self._input = None
        self._parent_window = None
        self._render_timer = None

    def focus(self) -> None:
        if self._parent_window:
            try:
                kw.activate_widget(self._parent_window, True)
            except Exception:
                pass

    def request_render(self, state: ChatState) -> None:
        self._pending_state = state
        if self._render_timer is None:
            self._flush_render()
        elif not self._render_timer.isActive():
            self._render_timer.start()

    def set_context_chip(self, text: str) -> None:
        if self._context_label is not None:
            self._context_label.setText(text or "")

    def set_history(self, summaries) -> None:
        if self._history_list is None:
            return
        self._history_list.clear()
        for s in summaries:
            label = s.title or "Untitled"
            item = QtWidgets.QListWidgetItem(label)
            item.setData(QtCore.Qt.UserRole, s.conversation_uuid)
            self._history_list.addItem(item)

    def clear_input(self) -> None:
        if self._input is not None:
            self._input.clear()

    def focus_input(self) -> None:
        if self._input is not None:
            self._input.setFocus()

    def _flush_render(self) -> None:
        state = self._pending_state
        if state is None or self._transcript is None:
            return

        sb = self._transcript.verticalScrollBar()
        at_bottom = sb is None or sb.value() >= sb.maximum() - 4
        md = render_transcript_markdown(state)
        if hasattr(self._transcript, "setMarkdown"):
            self._transcript.setMarkdown(md)
        else:
            self._transcript.setPlainText(md)
        if at_bottom and sb is not None:
            sb.setValue(sb.maximum())

        running = state.run_status == "running"
        if self._send_btn is not None:
            self._send_btn.setEnabled(not running)
        if self._stop_btn is not None:
            self._stop_btn.setEnabled(running)
        if self._title_label is not None:
            self._title_label.setText(state.title or "AI Agent")

        pending = find_pending_confirmation(state)
        if self._confirm_bar is not None:
            if pending is not None:
                self._pending_confirm_id = pending.id
                if self._confirm_msg is not None:
                    self._confirm_msg.setText(
                        pending.message or f"Approve tool '{title_case(pending.tool_name)}'?"
                    )
                self._confirm_bar.setVisible(True)
            else:
                self._pending_confirm_id = None
                self._confirm_bar.setVisible(False)

    def start_stream_worker(self, worker: ChatStreamWorker) -> None:
        self.stop_stream_worker()
        thread = QtCore.QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        if self._relay is not None:
            worker.event_ready.connect(self._relay.handle_event)
            worker.conversation_created.connect(self._relay.handle_conversation_created)
            worker.errored.connect(self._relay.handle_error)
            worker.finished.connect(self._relay.handle_finished)
        worker.finished.connect(thread.quit)
        self._thread = thread
        self._worker = worker
        self._streaming = True
        thread.start()

    def stop_stream_worker(self) -> None:
        self._zombies = [
            (t, w) for (t, w) in self._zombies if t is not None and not t.isFinished()
        ]

        worker, thread = self._worker, self._thread
        self._worker = None
        self._thread = None
        self._streaming = False

        if worker is not None:
            try:
                worker.stop()
            except Exception:
                pass
        if thread is None:
            return
        try:
            thread.quit()
            if not thread.wait(3000):
                self._zombies.append((thread, worker))
        except Exception:
            pass

    def is_streaming(self) -> bool:
        return self._streaming

    def _handle_stream_event(self, ev) -> None:
        if self.on_stream_event:
            self.on_stream_event(ev)

    def _handle_conversation_created(self, uuid: str) -> None:
        if self.on_stream_conversation_created:
            self.on_stream_conversation_created(uuid)

    def _handle_stream_error(self, msg: str) -> None:
        if self.on_stream_error:
            self.on_stream_error(msg)

    def _handle_stream_finished(self) -> None:
        self._streaming = False
        if self.on_stream_finished:
            self.on_stream_finished()

    def _on_send_clicked(self) -> None:
        if self._input is None:
            return
        text = self._input.toPlainText()
        if not text.strip():
            return
        self._input.clear()
        if self.on_send:
            self.on_send(text)

    def _on_stop_clicked(self) -> None:
        if self.on_stop:
            self.on_stop()

    def _on_confirm_clicked(self, approved: bool) -> None:
        if self._pending_confirm_id and self.on_confirm:
            self.on_confirm(self._pending_confirm_id, approved)

    def _on_new_chat_clicked(self) -> None:
        if self.on_new_chat:
            self.on_new_chat()

    def _on_history_clicked(self) -> None:
        if self._history_list is None:
            return
        show = not self._history_list.isVisible()
        self._history_list.setVisible(show)
        if show and self.on_request_history:
            self.on_request_history()

    def _on_history_item(self, item) -> None:
        if item is None:
            return
        uuid = item.data(QtCore.Qt.UserRole)
        if uuid and self.on_select_conversation:
            self.on_select_conversation(uuid)

    def _on_anchor_clicked(self, url) -> None:
        ea = parse_jump_href(url.toString())
        if ea is not None and self.on_jump:
            self.on_jump(ea)
