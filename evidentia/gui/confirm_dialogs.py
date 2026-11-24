"""Modal front-ends for the core two-step erase confirmation (evidentia.sanitize.confirmation).

The dialogs only collect answers; the ConfirmationSession decides, logs each step to the ledger,
and issues the authorization the sanitize engine requires."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout

from ..sanitize.confirmation import CONFIRM_WORD
from . import theme as T
from .widgets import human


def _buttons(ok_text: str, ok_slot, cancel_slot) -> tuple[QHBoxLayout, QPushButton, QPushButton]:
    row = QHBoxLayout()
    row.addStretch()
    cancel = QPushButton("Cancel")
    ok = QPushButton(ok_text)
    ok.setObjectName("danger")
    for b in (cancel, ok):
        b.setAutoDefault(False)
        b.setMinimumWidth(130)
    cancel.clicked.connect(cancel_slot)
    ok.clicked.connect(ok_slot)
    row.addWidget(cancel)
    row.addWidget(ok)
    return row, ok, cancel


class EraseConfirmDialog(QDialog):
    """Step 1: what will be destroyed, and Yes/Cancel. Cancel is the default and focused button;
    Esc and closing the window reject."""

    def __init__(self, summary: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Confirm erase (step 1 of 2)")
        self.setModal(True)
        self.setMinimumWidth(560)
        v = QVBoxLayout(self)
        v.setSpacing(12)
        head = QLabel("⚠  Permanently erase this target?")
        head.setStyleSheet(f"font-size: 17px; font-weight: 700; color: {T.BAD};")
        v.addWidget(head)
        g = QGridLayout()
        g.setHorizontalSpacing(14)
        g.setColumnStretch(1, 1)
        rows = [("Target", summary["name"]), ("Scope", summary["scope"]), ("Path", summary["path"]),
                ("Size", f"{human(summary['size_bytes'])} ({summary['size_bytes']:,} bytes)"),
                ("Device type", summary["device_type"]), ("Method", summary["method"]),
                ("NIST category", f"{summary['nist_category']} (SP 800-88 Rev. 2)")]
        for i, (k, val) in enumerate(rows):
            kl = QLabel(k)
            kl.setStyleSheet(f"color: {T.MUTED};")
            vl = QLabel(str(val))
            vl.setTextFormat(Qt.PlainText)
            vl.setWordWrap(True)
            vl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            g.addWidget(kl, i, 0, Qt.AlignTop)
            g.addWidget(vl, i, 1)
        v.addLayout(g)
        warn = QLabel(summary["warning"])
        warn.setObjectName("undoWarning")
        warn.setWordWrap(True)
        warn.setStyleSheet(f"background: rgba(239,68,68,0.12); border: 1px solid {T.BAD}; border-radius: 8px;"
                           f" padding: 10px; color: {T.TEXT}; font-weight: 600;")
        v.addWidget(warn)
        row, self.yes_btn, self.cancel_btn = _buttons("Yes, continue", self.accept, self.reject)
        self.yes_btn.setText("Yes, continue")
        self.cancel_btn.setDefault(True)
        v.addLayout(row)
        self.cancel_btn.setFocus(Qt.OtherFocusReason)

    def showEvent(self, e):
        super().showEvent(e)
        self.cancel_btn.setFocus(Qt.OtherFocusReason)


class TypedConfirmDialog(QDialog):
    """Step 2: type exactly CONFIRM. 'Start Cleaning' is enabled only on an exact match."""

    def __init__(self, summary: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Confirm erase (step 2 of 2)")
        self.setModal(True)
        self.setMinimumWidth(480)
        v = QVBoxLayout(self)
        v.setSpacing(12)
        msg = QLabel(f"To erase <b>{html.escape(summary['name'])}</b> with <b>{html.escape(summary['method'])}</b>, type "
                     f"<span style='font-family:Menlo; color:{T.BAD}'><b>{CONFIRM_WORD}</b></span> below "
                     f"(case-sensitive).")
        msg.setWordWrap(True)
        v.addWidget(msg)
        self.field = QLineEdit()
        self.field.setPlaceholderText(CONFIRM_WORD)
        self.field.textChanged.connect(self._changed)
        self.field.returnPressed.connect(self._maybe_accept)
        v.addWidget(self.field)
        row, self.start_btn, self.cancel_btn = _buttons("Start Cleaning", self._maybe_accept, self.reject)
        self.start_btn.setEnabled(False)
        v.addLayout(row)
        self.field.setFocus()

    def matches(self) -> bool:
        return self.field.text() == CONFIRM_WORD

    def _changed(self, *_):
        self.start_btn.setEnabled(self.matches())

    def _maybe_accept(self):
        if self.matches():
            self.accept()

    def typed(self) -> str:
        return self.field.text()


def run_erase_confirmation(parent, session) -> bool:
    """Drive both modal steps for ``session``. Returns True only if the session is authorized."""
    summary = session.show()
    d1 = EraseConfirmDialog(summary, parent)
    if not session.answer(d1.exec() == QDialog.Accepted):
        return False
    d2 = TypedConfirmDialog(summary, parent)
    accepted = d2.exec() == QDialog.Accepted
    return session.submit(d2.typed() if accepted else None)
