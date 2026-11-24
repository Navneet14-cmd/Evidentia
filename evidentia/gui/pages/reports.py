from __future__ import annotations

import json
import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QMessageBox, QSplitter, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from ...sanitize import certificate
from .. import theme as T
from ..widgets import Card, button, label, open_path

try:
    from PySide6.QtPdf import QPdfDocument
    from PySide6.QtPdfWidgets import QPdfView
except ImportError:  # pragma: no cover
    QPdfDocument = QPdfView = None


class ReportsPage(QWidget):
    def __init__(self, state):
        super().__init__()
        self.setObjectName("page")
        self.state = state
        v = QVBoxLayout(self)
        v.setContentsMargins(32, 14, 32, 18)
        v.setSpacing(12)
        bar = QHBoxLayout()
        bar.addWidget(button("▦  Generate case report (PDF + HTML)", "primary", self.generate))
        bar.addWidget(button("Open PDF", None, lambda: self._open("pdf")))
        bar.addWidget(button("Open HTML", None, lambda: self._open("html")))
        bar.addStretch()
        v.addLayout(bar)
        split = QSplitter()
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        c1 = Card("Case reports")
        self.reports = QTableWidget(0, 3)
        self.reports.setHorizontalHeaderLabels(["Report", "Generated", "Ledger"])
        self._table(self.reports)
        self.reports.currentCellChanged.connect(lambda r, *_: self._preview(self.reports, r))
        c1.add(self.reports)
        lv.addWidget(c1)
        c2 = Card("Sanitization certificates")
        self.certs = QTableWidget(0, 4)
        self.certs.setHorizontalHeaderLabels(["Certificate", "Method", "Result", "Signature"])
        self._table(self.certs)
        self.certs.currentCellChanged.connect(lambda r, *_: self._preview(self.certs, r))
        c2.add(self.certs)
        lv.addWidget(c2)
        split.addWidget(left)
        pv = Card("Preview")
        if QPdfView:
            self.doc = QPdfDocument(self)
            self.view = QPdfView()
            self.view.setDocument(self.doc)
            self.view.setPageMode(QPdfView.PageMode.MultiPage)
            self.view.setZoomMode(QPdfView.ZoomMode.FitToWidth)
            pv.add(self.view)
        else:
            pv.add(label("PDF preview requires QtPdf.", "muted"))
        split.addWidget(pv)
        split.setSizes([560, 760])
        v.addWidget(split, 1)
        state.case_changed.connect(lambda _: self.refresh())
        state.data_changed.connect(self.refresh)

    @staticmethod
    def _table(t):
        t.verticalHeader().hide()
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        t.horizontalHeader().setStretchLastSection(True)
        t.setAlternatingRowColors(True)

    def on_show(self):
        self.refresh()

    def refresh(self):
        svc, cid = self.state.svc, self.state.case_id
        self.reports.setRowCount(0)
        self.certs.setRowCount(0)
        if not cid:
            return
        for e in reversed([e for e in svc.ledger.entries(cid) if e["action"] == "report.generate"]):
            d = e["details"]
            r = self.reports.rowCount()
            self.reports.insertRow(r)
            for c, val in enumerate([d["report_id"], e["ts"][:19].replace("T", " "),
                                     "verified" if d.get("ledger_ok") else "TAMPERED"]):
                it = QTableWidgetItem(val)
                it.setData(Qt.UserRole, (d["pdf"], d["html"]))
                if c == 2:
                    it.setForeground(QColor(T.OK) if d.get("ledger_ok") else QColor(T.BAD))
                self.reports.setItem(r, c, it)
        for s in reversed(svc.sanitizations(cid)):
            r = self.certs.rowCount()
            self.certs.insertRow(r)
            try:
                ok, _ = certificate.verify(json.loads(open(s["certificate_json"]).read()))
            except OSError:
                ok = False
            for c, val in enumerate([s["certificate_id"], s["method"], s["result"], "valid ✓" if ok else "INVALID"]):
                it = QTableWidgetItem(val)
                it.setData(Qt.UserRole, (s["certificate_pdf"], s["certificate_json"]))
                if c in (2, 3):
                    it.setForeground(QColor(T.OK) if val in ("PASS", "valid ✓") else QColor(T.WARN) if val == "DRY-RUN" else QColor(T.BAD))
                self.certs.setItem(r, c, it)
        if self.reports.rowCount():
            self.reports.selectRow(0)
            self._preview(self.reports, 0)

    def _preview(self, table, row):
        if row < 0 or not QPdfView:
            return
        pdf = table.item(row, 0).data(Qt.UserRole)[0]
        if os.path.exists(pdf):
            self.doc.load(pdf)
        self._current = table.item(row, 0).data(Qt.UserRole)

    def _open(self, kind):
        cur = getattr(self, "_current", None)
        if cur:
            open_path(cur[0] if kind == "pdf" else cur[1])

    def generate(self):
        cid = self.state.case_id
        if not cid:
            return QMessageBox.information(self, "Report", "Select a case first.")
        self.state.jobs.start("Generating case report", lambda ctx: self.state.svc.generate_report(cid),
                              lambda r: self.refresh())
