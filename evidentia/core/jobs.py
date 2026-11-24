"""Cancellable, progress-reporting job context shared by CLI and GUI workers."""
from __future__ import annotations

import threading
from typing import Callable, Optional


class Cancelled(Exception):
    """Raised inside a job when the operator cancels it."""


ProgressFn = Callable[[float, str], None]
LogFn = Callable[[str], None]


class JobContext:
    def __init__(self, progress: Optional[ProgressFn] = None, log: Optional[LogFn] = None,
                 cancel_event: Optional[threading.Event] = None, _range=(0.0, 1.0)):
        self._progress = progress
        self._log = log
        self._cancel = cancel_event or threading.Event()
        self._lo, self._hi = _range

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def check(self) -> None:
        if self._cancel.is_set():
            raise Cancelled("operation cancelled by operator")

    def progress(self, fraction: float, message: str = "") -> None:
        if self._progress:
            f = self._lo + (self._hi - self._lo) * max(0.0, min(1.0, fraction))
            self._progress(f, message)

    def log(self, message: str) -> None:
        if self._log:
            self._log(message)

    def sub(self, start: float, end: float) -> "JobContext":
        """A child context whose 0..1 progress maps onto [start, end] of this one."""
        span = self._hi - self._lo
        return JobContext(self._progress, self._log, self._cancel,
                          (self._lo + span * start, self._lo + span * end))


NULL_CONTEXT = JobContext()
