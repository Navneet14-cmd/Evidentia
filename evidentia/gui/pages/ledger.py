from __future__ import annotations

import json
import os
import sqlite3
import tempfile

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QFileDialog, QHBoxLayout, QHeaderView, QInputDialog,
                               QMessageBox, QPlainTextEdit, QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from ...forensic.db import Store
from ...forensic.ledger import Ledger, verify_anchor_file
from ...forensic.service import summarize
from .. import theme as T
from ..widgets import Banner, Card, button, label

COLS = ["#", "Time (UTC)", "Actor", "Action", "Case", "What", "Entry hash", "Prev hash"]


class LedgerPage(QWidget):
    def __init__(self, state):
        super().__init__()
        self.setObjectName("page")
        self.state = state
        self.report = None
        self.demo_store: Store | None = None
        v = QVBoxLayout(self)
        v.setContentsMargins(32, 14, 32, 18)
        v.setSpacing(12)
        bar = QHBoxLayout()
        bar.addWidget(button("✔  Verify ledger integrity", "primary", self.verify))
        bar.addWidget(button("⚓  Export chain head", None, self.anchor,
                             "Signed JSON with head hash + Merkle root; publish it externally (OpenTimestamps, blockchain, email)"))
        bar.addWidget(button("Verify against anchor…", None, self.verify_anchor))
        bar.addWidget(button("🧪  Tamper demo (copy)", None, self.tamper_demo,
                             "Copies the ledger database, edits one entry like an attacker would, then verifies the copy"))
        self.back = button("← Back to live ledger", None, self.leave_demo)
        self.back.hide()
        bar.addWidget(self.back)
        bar.addStretch()
        self.only_case = QCheckBox("Active case only")
        self.only_case.toggled.connect(self.refresh)
        bar.addWidget(self.only_case)
        v.addLayout(bar)
        self.banner = Banner()
        v.addWidget(self.banner)
        split = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeToContents)
        h.setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.currentCellChanged.connect(self._select)
        split.addWidget(self.table)
        det = Card("Entry detail")
        self.detail = QPlainTextEdit(readOnly=True)
        self.detail.setStyleSheet(f"font-family: {T.MONO}; font-size: 11.5px; color: {T.SUBTLE};")
        det.add(self.detail)
        split.addWidget(det)
        split.setSizes([560, 220])
        v.addWidget(split, 1)
        foot = label("Each entry stores SHA-256 of the previous entry (genesis = 64 zeros) and is signed with the "
                     "installation's Ed25519 key. Append-only is enforced by SQLite triggers; tampering is detected "
                     "by recomputation; truncation is detected against an exported anchor.", "muted", wrap=True)
        v.addWidget(foot)
        state.data_changed.connect(lambda: self.refresh() if not self.demo_store else None)
        state.case_changed.connect(lambda _: self.refresh())

    def on_show(self):
        self.refresh()

    def _ledger(self) -> Ledger:
        return Ledger(self.demo_store, self.state.svc.signer) if self.demo_store else self.state.svc.ledger

    def refresh(self):
        led = self._ledger()
        rows = led.entries(self.state.case_id if self.only_case.isChecked() else None)
        bad = {i.seq: i for i in (self.report.issues if self.report else [])}
        self.table.setRowCount(0)
        self.table.setRowCount(len(rows))
        self._rows = rows
        for r, e in enumerate(rows):
            vals = [str(e["seq"]), e["ts"][:19].replace("T", " "), e["actor"], e["action"], e["case_id"] or "—",
                    summarize(e), e["entry_hash"][:16] + "…", e["prev_hash"][:16] + "…"]
            for c, val in enumerate(vals):
                it = QTableWidgetItem(val)
                if c in (6, 7):
                    it.setForeground(QColor(T.MUTED))
                if e["seq"] in bad:
                    it.setBackground(QColor(T.BAD_SOFT))
                    it.setForeground(QColor(T.BAD))
                    it.setToolTip(bad[e["seq"]].message)
                elif self.report and self.report.ok:
                    if c == 0:
                        it.setForeground(QColor(T.OK))
                self.table.setItem(r, c, it)
        if bad:
            first = next((i for i, e in enumerate(rows) if e["seq"] in bad), 0)
            self.table.scrollToItem(self.table.item(first, 0))

    def _select(self, row, *_):
        if row < 0 or row >= len(getattr(self, "_rows", [])):
            return
        e = dict(self._rows[row])
        issues = [i for i in (self.report.issues if self.report else []) if i.seq == e["seq"]]
        txt = json.dumps({k: e[k] for k in ("seq", "ts", "actor", "action", "case_id", "evidence_id", "details")},
                         indent=2, ensure_ascii=False)
        txt += f"\n\nprev_hash  {e['prev_hash']}\nentry_hash {e['entry_hash']}\nsignature  {e['signature']}"
        if issues:
            txt = "⚠ " + "\n⚠ ".join(i.message for i in issues) + "\n\n" + txt
        self.detail.setPlainText(txt)

    def _show_report(self, rep, where="live ledger"):
        self.report = rep
        if rep.ok:
            self.banner.show_msg(f"<b>{where.upper()} VERIFIED</b> — {rep.entries} entries recomputed, every hash link and "
                                 f"Ed25519 signature valid. Head #{rep.head_seq} "
                                 f"<span style='font-family:Menlo'>{rep.head_hash[:32]}…</span>"
                                 + (" · matches anchor" if rep.anchor_checked else ""), T.OK, "✔")
        else:
            self.banner.show_msg(f"<b>TAMPERING DETECTED in {where}</b> — entries "
                                 + ", ".join(f"#{s}" for s in rep.tampered_seqs) + ":<br>"
                                 + "<br>".join(f"· {i.message}" for i in rep.issues[:6]), T.BAD, "✖")
        self.refresh()

    def verify(self):
        if self.demo_store:
            return self._show_report(self._ledger().verify(), "tampered copy")
        rep = self.state.svc.verify_ledger()
        self._show_report(rep)
        self.state.changed()

    def anchor(self):
        a, p = self.state.svc.export_anchor()
        self.state.changed()
        QMessageBox.information(self, "Chain head exported",
                                f"Anchor written to:\n{p}\n\nHead #{a['head_seq']}\n{a['head_hash']}\n\nMerkle root\n"
                                f"{a['merkle_root']}\n\nPublish this hash externally (e.g. `ots stamp {os.path.basename(p)}` "
                                "for OpenTimestamps → Bitcoin) to prove the ledger's state at this time.")

    def verify_anchor(self):
        p, _ = QFileDialog.getOpenFileName(self, "Anchor file", str(self.state.svc.home / "anchors"), "JSON (*.json)")
        if not p:
            return
        a = json.loads(open(p).read())
        if not verify_anchor_file(a):
            return QMessageBox.critical(self, "Anchor", "The anchor file's own signature is invalid (forged anchor).")
        rep = self.state.svc.verify_ledger(a)
        self._show_report(rep)

    def tamper_demo(self):
        seqs = [e["seq"] for e in self.state.svc.ledger.entries()]
        if len(seqs) < 3:
            return QMessageBox.information(self, "Tamper demo", "Create some activity first.")
        seq, ok = QInputDialog.getInt(self, "Tamper demo", "Entry number to falsify on a COPY of the ledger:",
                                      seqs[len(seqs) // 2], seqs[0], seqs[-1])
        if not ok:
            return
        tmp = tempfile.mkdtemp(prefix="evidentia-tamper-")
        dst = os.path.join(tmp, "evidentia-tampered.db")
        with sqlite3.connect(dst) as out:
            self.state.svc.store.conn.backup(out)
        con = sqlite3.connect(dst)
        con.execute("DROP TRIGGER ledger_no_update")  # what an attacker with file access would do
        row = con.execute("SELECT details FROM ledger WHERE seq=?", (seq,)).fetchone()
        d = json.loads(row[0])
        d["tampered_by_demo"] = "an attacker edited this entry"
        con.execute("UPDATE ledger SET details=?, actor=? WHERE seq=?", (json.dumps(d, sort_keys=True), "mallory", seq))
        con.commit()
        con.close()
        self.demo_store = Store(dst)
        self.back.show()
        self._show_report(self._ledger().verify(), f"tampered copy ({dst})")

    def leave_demo(self):
        if self.demo_store:
            self.demo_store.close()
        self.demo_store = None
        self.report = None
        self.back.hide()
        self.banner.hide()
        self.refresh()
