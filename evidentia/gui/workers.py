"""Background jobs on QThreads with progress + cancellation (JobContext bridge)."""
from __future__ import annotations

import threading
import traceback

from PySide6.QtCore import QObject, QThread, Signal

from ..core.jobs import Cancelled, JobContext


class Job(QThread):
    progressed = Signal(float, str)
    logged = Signal(str)
    succeeded = Signal(object)
    failed = Signal(str, str)      # message, traceback
    cancelled = Signal()

    def __init__(self, title: str, fn, parent=None):
        super().__init__(parent)
        self.title = title
        self.fn = fn
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    def run(self):
        ctx = JobContext(lambda f, m: self.progressed.emit(f, m), lambda m: self.logged.emit(m), self._cancel)
        try:
            result = self.fn(ctx)
        except Cancelled:
            self.cancelled.emit()
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc), traceback.format_exc())
        else:
            self.succeeded.emit(result)


class JobManager(QObject):
    """One foreground job at a time, surfaced in the main window's job bar."""
    started = Signal(object)
    ended = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current: Job | None = None

    @property
    def busy(self) -> bool:
        return self.current is not None and self.current.isRunning()

    def start(self, title: str, fn, on_done=None, on_error=None) -> Job | None:
        if self.busy:
            return None
        job = Job(title, fn, self)
        if on_done:
            job.succeeded.connect(on_done)
        if on_error:
            job.failed.connect(on_error)
        job.finished.connect(self._finished)
        self.current = job
        self.started.emit(job)
        job.start()
        return job

    def _finished(self):
        self.current = None
        self.ended.emit()
