from __future__ import annotations

from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QFormLayout, QHBoxLayout, QHeaderView, QInputDialog,
                               QLineEdit, QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from ...core.devices import list_devices
from ...recovery.fs_recovery import HAVE_TSK
from .. import theme as T
from ..widgets import Card, button, human, label


class SettingsPage(QWidget):
    def __init__(self, state):
        super().__init__()
        self.setObjectName("page")
        self.state = state
        v = QVBoxLayout(self)
        v.setContentsMargins(26, 18, 26, 18)
        v.setSpacing(14)
        row = QHBoxLayout()
        row.setSpacing(14)
        ex = Card("Examiner profile (recorded in every ledger entry)")
        f = QFormLayout()
        self.name, self.org, self.eid = QLineEdit(), QLineEdit(), QLineEdit()
        f.addRow("Name", self.name)
        f.addRow("Organisation", self.org)
        f.addRow("Examiner ID", self.eid)
        ex.add(f)
        ex.add(button("Save profile", "primary", self.save))
        row.addWidget(ex, 1)
        sys_ = Card("System")
        self.sysinfo = label("", wrap=True, sel=True)
        sys_.add(self.sysinfo)
        row.addWidget(sys_, 1)
        v.addLayout(row)
        dv = Card("Physical device access")
        self.adv = QCheckBox("Enable Advanced device access (opt-in)")
        self.adv.clicked.connect(self.toggle_adv)
        dv.add(self.adv)
        dv.add(label("Even in advanced mode Evidentia refuses the system/boot disk and any disk with a mounted volume, "
                     "opens evidence read-only, requires the device name to be typed before any destructive operation, "
                     "and defaults to dry-run.", "muted", wrap=True))
        hb = QHBoxLayout()
        hb.addWidget(label("Detected disks", "h2"))
        hb.addStretch()
        hb.addWidget(button("Refresh", None, self.load_devices))
        dv.add(hb)
        self.devs = QTableWidget(0, 6)
        self.devs.setHorizontalHeaderLabels(["Device", "Model", "Size", "Media", "Mounted", "Policy"])
        self.devs.verticalHeader().hide()
        self.devs.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.devs.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.devs.horizontalHeader().setStretchLastSection(True)
        dv.add(self.devs)
        v.addWidget(dv, 1)

    def on_show(self):
        s = self.state.svc.settings
        self.name.setText(s.examiner_name)
        self.org.setText(s.examiner_org)
        self.eid.setText(s.examiner_id)
        self.adv.setChecked(s.advanced_device_access)
        svc = self.state.svc
        self.sysinfo.setText(
            f"<b>Workspace</b><br>{svc.home}<br><br><b>Ed25519 signing key</b><br>"
            f"<span style='font-family:Menlo'>{svc.signer.fingerprint}</span><br>{svc.home / 'keys'}<br><br>"
            f"<b>The Sleuth Kit (pytsk3)</b>: {'available' if HAVE_TSK else 'NOT installed — carving only'}")
        self.load_devices()

    def save(self):
        s = self.state.svc.settings
        s.examiner_name, s.examiner_org, s.examiner_id = self.name.text().strip(), self.org.text().strip(), self.eid.text().strip()
        self.state.svc.save_settings()
        self.state.settings_changed.emit()
        QMessageBox.information(self, "Saved", "Examiner profile saved.")

    def toggle_adv(self, on):
        s = self.state.svc.settings
        if on:
            text, ok = QInputDialog.getText(self, "Enable physical device access",
                                            "Physical devices can be read (and, with confirmation, erased).\n"
                                            "Type I UNDERSTAND to enable:")
            if not ok or text.strip() != "I UNDERSTAND":
                self.adv.setChecked(False)
                return
        s.advanced_device_access = bool(on)
        self.state.svc.save_settings()
        self.state.svc.log("settings.device_access", None, advanced_device_access=bool(on))
        self.state.settings_changed.emit()
        self.state.changed()

    def load_devices(self):
        self.devs.setRowCount(0)
        for d in list_devices():
            r = self.devs.rowCount()
            self.devs.insertRow(r)
            pol = "allowed" if d.allowed else "REFUSED — " + "; ".join(d.refusal_reasons())
            for c, val in enumerate([d.path, d.model, human(d.size), d.media_type, ", ".join(d.mountpoints[:3]) or "—", pol]):
                it = QTableWidgetItem(val)
                if c == 5:
                    from PySide6.QtGui import QColor
                    it.setForeground(QColor(T.OK if d.allowed else T.BAD))
                self.devs.setItem(r, c, it)
