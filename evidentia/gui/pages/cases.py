from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
                               QHBoxLayout, QHeaderView, QLineEdit, QListWidget, QListWidgetItem, QMessageBox,
                               QPlainTextEdit, QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from ...core.devices import list_devices
from ...sanitize.media import PROFILES
from .. import theme as T
from ..widgets import Card, Pill, button, human, label


class NewCaseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New case")
        self.setMinimumWidth(460)
        f = QFormLayout(self)
        self.title = QLineEdit()
        self.title.setPlaceholderText("e.g. Laptop seizure — suspected exfiltration")
        self.desc = QPlainTextEdit()
        self.desc.setFixedHeight(90)
        f.addRow("Title", self.title)
        f.addRow("Description", self.desc)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(lambda: self.accept() if self.title.text().strip() else None)
        bb.rejected.connect(self.reject)
        f.addRow(bb)

    def values(self):
        return self.title.text().strip(), self.desc.toPlainText().strip()


class CasesPage(QWidget):
    COLS = ["#", "Label", "Kind", "Size", "SHA-256", "MD5", "Acquired", "State"]

    def __init__(self, state):
        super().__init__()
        self.setObjectName("page")
        self.state = state
        root = QHBoxLayout(self)
        root.setContentsMargins(32, 14, 32, 18)
        split = QSplitter()
        left = Card("Cases")
        self.list = QListWidget()
        self.list.setWordWrap(True)
        self.list.currentItemChanged.connect(self._pick)
        left.add(self.list)
        left.setMinimumWidth(280)
        split.addWidget(left)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(14, 0, 0, 0)
        rv.setSpacing(14)
        head = Card()
        hh = QHBoxLayout()
        self.case_title = label("", "pageTitle")
        self.case_title.setStyleSheet("font-size: 18px;")
        self.case_pill = Pill("", T.OK)
        hh.addWidget(self.case_title, 1)
        hh.addWidget(self.case_pill)
        head.add(hh)
        self.case_meta = label("", "muted", wrap=True)
        head.add(self.case_meta)
        rv.addWidget(head)

        ev = Card("Evidence")
        bar = QHBoxLayout()
        bar.addWidget(button("+ Add disk image…", "primary", self.add_image))
        self.btn_dev = button("+ Add physical device…", None, self.add_device,
                              "Requires Advanced device access (Settings)")
        bar.addWidget(self.btn_dev)
        bar.addWidget(button("Create working copy", None, self.copy, "Hash-verified copy for destructive work"))
        bar.addWidget(button("Re-verify hash", None, self.verify))
        bar.addStretch()
        ev.add(bar)
        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        ev.add(self.table)
        rv.addWidget(ev, 3)

        notes = Card("Examiner notes")
        self.notes = QListWidget()
        self.notes.setWordWrap(True)
        notes.add(self.notes)
        nb = QHBoxLayout()
        self.note_in = QLineEdit()
        self.note_in.setPlaceholderText("Add a note (recorded in the chain of custody)…")
        self.note_in.returnPressed.connect(self.add_note)
        nb.addWidget(self.note_in, 1)
        nb.addWidget(button("Add note", None, self.add_note))
        notes.add(nb)
        rv.addWidget(notes, 2)
        split.addWidget(right)
        split.setSizes([300, 1000])
        root.addWidget(split)
        state.case_changed.connect(lambda _: self.refresh())
        state.data_changed.connect(self.refresh)
        state.settings_changed.connect(self.refresh)

    def on_show(self):
        self.refresh()

    def refresh(self):
        svc = self.state.svc
        self.list.blockSignals(True)
        self.list.clear()
        for c in svc.list_cases():
            it = QListWidgetItem(f"{c['id']}\n{c['title']}\n{c['evidence_count']} evidence · {c['created_at'][:10]}")
            it.setData(Qt.UserRole, c["id"])
            self.list.addItem(it)
            if c["id"] == self.state.case_id:
                self.list.setCurrentItem(it)
        self.list.blockSignals(False)
        self.btn_dev.setEnabled(svc.settings.advanced_device_access)
        case = self.state.case
        self.table.setRowCount(0)
        self.notes.clear()
        if not case:
            self.case_title.setText("No case selected")
            self.case_meta.setText("Create a case with “+ New case” in the top bar.")
            self.case_pill.hide()
            return
        self.case_pill.show()
        self.case_pill.set(case["status"].upper(), T.OK)
        self.case_title.setText(f"{case['id']} — {case['title']}")
        self.case_meta.setText(f"Examiner {case['examiner'] or '-'} · {case['organization'] or '-'} · opened "
                               f"{case['created_at'][:19].replace('T', ' ')} UTC<br>{case['description'] or ''}")
        for e in svc.list_evidence(case["id"]):
            r = self.table.rowCount()
            self.table.insertRow(r)
            state = "sanitized" if e["sanitized"] else ("protected original" if e["kind"] in ("original", "device")
                                                       else "working copy")
            vals = [str(e["id"]), e["label"], e["kind"], human(e["size"]), e["sha256"][:24] + "…", e["md5"][:16] + "…",
                    e["acquired_at"][:19].replace("T", " "), state]
            for c, val in enumerate(vals):
                it = QTableWidgetItem(val)
                it.setData(Qt.UserRole, e["id"])
                if c in (4, 5):
                    it.setToolTip(e["sha256"] if c == 4 else e["md5"])
                    it.setForeground(QColor(T.MUTED))
                if c == 7:
                    it.setForeground(QColor(T.OK) if state == "protected original" else QColor(T.WARN) if state == "working copy"
                                     else QColor(T.BAD))
                self.table.setItem(r, c, it)
        for n in svc.notes(case["id"]):
            self.notes.addItem(f"{n['created_at'][:19].replace('T', ' ')} · {n['author']}\n{n['body']}")

    def _pick(self, cur, _prev):
        if cur:
            self.state.set_case(cur.data(Qt.UserRole))

    def _selected_evidence(self):
        r = self.table.currentRow()
        if r < 0:
            QMessageBox.information(self, "Select evidence", "Select an evidence item first.")
            return None
        return self.table.item(r, 0).data(Qt.UserRole)

    def _need_case(self):
        if not self.state.case_id:
            QMessageBox.information(self, "No case", "Create or select a case first.")
            return False
        return True

    def add_image(self):
        if not self._need_case():
            return
        path, _ = QFileDialog.getOpenFileName(self, "Add disk image", "",
                                              "Disk images (*.dd *.img *.raw *.bin *.001 *.iso);;All files (*)")
        if not path:
            return
        prof, ok = self._profile_dialog(os.path.basename(path))
        if not ok:
            return
        cid = self.state.case_id
        self.state.jobs.start("Acquiring evidence", lambda ctx: self.state.svc.add_evidence(
            cid, path, media_profile=prof, ctx=ctx), lambda _: self.state.changed())

    def _profile_dialog(self, name):
        dlg = QDialog(self)
        dlg.setWindowTitle("Media profile")
        f = QFormLayout(dlg)
        f.addRow(label(f"What physical media was <b>{name}</b> imaged from? This drives the sanitization guidance.",
                       wrap=True))
        cb = QComboBox()
        for k, v in PROFILES.items():
            cb.addItem(v, k)
        cb.setCurrentIndex(cb.findData("image"))
        f.addRow("Media", cb)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept)
        bb.rejected.connect(dlg.reject)
        f.addRow(bb)
        ok = dlg.exec()
        return cb.currentData(), bool(ok)

    def add_device(self):
        if not self._need_case():
            return
        devs = list_devices()
        allowed = [d for d in devs if d.allowed]
        if not allowed:
            QMessageBox.warning(self, "No eligible devices",
                                "No physical disk passes the safety policy.\n\n" + "\n".join(
                                    f"{d.name}: refused — {'; '.join(d.refusal_reasons())}" for d in devs))
            return
        dlg = QDialog(self)
        dlg.setWindowTitle("Add physical device (read-only)")
        f = QFormLayout(dlg)
        cb = QComboBox()
        for d in allowed:
            cb.addItem(f"{d.name} — {d.model} — {human(d.size)} — {d.media_type}", d.path)
        f.addRow("Device", cb)
        f.addRow(label("The device is opened read-only (O_RDONLY). Reading raw devices usually needs root.", "muted",
                       wrap=True))
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept)
        bb.rejected.connect(dlg.reject)
        f.addRow(bb)
        if dlg.exec():
            path = cb.currentData()
            dev = next(d for d in allowed if d.path == path)
            cid = self.state.case_id
            self.state.jobs.start("Acquiring device", lambda ctx: self.state.svc.add_evidence(
                cid, path, media_profile=dev.media_type if dev.media_type in PROFILES else "image", ctx=ctx),
                lambda _: self.state.changed())

    def copy(self):
        eid = self._selected_evidence()
        if eid:
            self.state.jobs.start("Creating working copy", lambda ctx: self.state.svc.make_working_copy(eid, ctx=ctx),
                                  lambda r: QMessageBox.information(self, "Working copy", f"Created and hash-verified:\n{r['path']}"))

    def verify(self):
        eid = self._selected_evidence()
        if eid:
            def done(r):
                m = r["match"]
                msg = ("Hashes MATCH the acquisition record." if m else
                       "Sanitized copy — content changed as expected." if m is None else
                       "HASH MISMATCH — evidence has changed since acquisition!")
                QMessageBox.information(self, "Re-verification", f"{msg}\n\nSHA-256 {r['hashes']['sha256']}\n"
                                        f"MD5     {r['hashes']['md5']}")
            self.state.jobs.start("Re-verifying evidence hash", lambda ctx: self.state.svc.verify_evidence(eid, ctx), done)

    def add_note(self):
        text = self.note_in.text().strip()
        if text and self._need_case():
            self.state.svc.add_note(self.state.case_id, text)
            self.note_in.clear()
            self.state.changed()
