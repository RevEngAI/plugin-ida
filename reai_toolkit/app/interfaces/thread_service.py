import threading
from typing import Any, Callable

from revengai import Configuration

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.interfaces.base_service import BaseService


def stop_thread(thread: threading.Thread | None, evt: threading.Event | None) -> None:
    """Stop the background thread if running."""
    if evt is not None:
        evt.set()
    if thread is not None and thread.is_alive():
        # Don't block the UI thread
        thread.join(timeout=0.2)


class IThreadService(BaseService):
    """Service to manage a single background thread."""

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        super().__init__(netstore_service=netstore_service, sdk_config=sdk_config)
        self._worker_thread: threading.Thread | None = None
        self._stop_event: threading.Event | None = None

    def start_worker(self, target: Callable[..., Any], args: tuple = ()) -> None:
        """Start a worker thread with a stop event."""
        self.stop_worker()
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(
            target=target, args=(self._stop_event, *args), daemon=True
        )
        self._worker_thread.start()

    def stop_worker(self) -> None:
        """Stop the worker thread if running."""
        stop_thread(self._worker_thread, self._stop_event)
        self._worker_thread = None
        self._stop_event = None

    def is_worker_running(self) -> bool:
        """Check if the worker is alive."""
        return self._worker_thread is not None and self._worker_thread.is_alive()
