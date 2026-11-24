"""Application state shared by all pages."""
from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from ..forensic.service import Evidentia
from .workers import JobManager


class AppState(QObject):
    case_changed = Signal(object)    # case id or None
    data_changed = Signal()          # anything in the store changed
    settings_changed = Signal()
    navigate = Signal(str)

    def __init__(self, svc: Evidentia):
        super().__init__()
        self.svc = svc
        self.jobs = JobManager(self)
        cases = svc.list_cases()
        self.case_id: str | None = cases[0]["id"] if cases else None

    def set_case(self, case_id: str | None):
        if case_id != self.case_id:
            self.case_id = case_id
            self.case_changed.emit(case_id)

    @property
    def case(self) -> dict | None:
        return self.svc.get_case(self.case_id) if self.case_id else None

    def changed(self):
        self.data_changed.emit()
