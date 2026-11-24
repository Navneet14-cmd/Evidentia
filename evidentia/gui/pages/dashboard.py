from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QListWidget, QListWidgetItem, QVBoxLayout, QWidget

from ...forensic.service import summarize
from .. import theme as T
from ..widgets import Banner, Card, StatCard, button, label


class DashboardPage(QWidget):
    def __init__(self, state):
        super().__init__()
        self.setObjectName("page")
        self.state = state
        v = QVBoxLayout(self)
        v.setContentsMargins(26, 22, 26, 22)
        v.setSpacing(16)
        self.hello = label("", "h2")
        self.hello.setStyleSheet("font-size: 17px;")
        v.addWidget(self.hello)
        self.banner = Banner()
        v.addWidget(self.banner)
        grid = QGridLayout()
        grid.setSpacing(14)
        self.c_cases = StatCard("Cases", T.ACCENT)
        self.c_ev = StatCard("Evidence items", T.ACCENT2)
        self.c_rec = StatCard("Recovered files", T.OK)
        self.c_san = StatCard("Sanitizations", T.WARN)
        self.c_led = StatCard("Ledger integrity", T.OK)
        for i, c in enumerate((self.c_cases, self.c_ev, self.c_rec, self.c_san, self.c_led)):
            grid.addWidget(c, 0, i)
        v.addLayout(grid)
        row = QHBoxLayout()
        row.setSpacing(14)
        qa = Card("Quick actions")
        for text, kind, page in (("Open case workspace", "primary", "cases"), ("Recover deleted files", None, "recovery"),
                                 ("Sanitize media", None, "sanitize"), ("Verify audit ledger", None, "ledger"),
                                 ("Generate report", None, "reports")):
            qa.add(button(text, kind, lambda _=False, p=page: state.navigate.emit(p)))
        qa.lay.addStretch()
        flow = label(
            f"<b>Workflow</b><br><span style='color:{T.MUTED}'>1 · Create a case and acquire an image (hashed, read-only)<br>"
            "2 · Recover: file system → carving → reconstruction → scoring<br>"
            "3 · Report: evidence, files, custody timeline<br>"
            "4 · Sanitize a working copy → verify → signed certificate<br>"
            "5 · Verify the hash-chained ledger and anchor its head</span>", wrap=True)
        qa.add(flow)
        qa.setFixedWidth(340)
        row.addWidget(qa)
        act = Card("Recent custody activity")
        self.activity = QListWidget()
        act.add(self.activity)
        row.addWidget(act, 1)
        v.addLayout(row, 1)
        state.data_changed.connect(self.refresh)
        state.settings_changed.connect(self.refresh)

    def on_show(self):
        self.refresh()

    def refresh(self):
        svc = self.state.svc
        st = svc.stats()
        self.hello.setText(f"Welcome back, {svc.settings.examiner_label}")
        self.c_cases.set(st["cases"], "open investigations")
        self.c_ev.set(st["evidence"], "images, copies & devices")
        self.c_rec.set(st["recovered"], f"{st['intact']} structurally intact")
        self.c_san.set(st["sanitizations"], "with signed certificates")
        rep = svc.ledger.verify()
        self.c_led.set("VERIFIED" if rep.ok else "TAMPERED", f"{rep.entries} hash-chained entries",
                       T.OK if rep.ok else T.BAD)
        if svc.settings.advanced_device_access:
            self.banner.show_msg("Advanced mode: physical device access is enabled. System/boot and mounted disks are "
                                 "always refused; destructive operations need typed confirmation.", T.WARN, "⚠")
        else:
            self.banner.show_msg("Safe mode: Evidentia works on disk image files only (.dd / .img / .raw). Evidence is "
                                 "opened read-only and hashed before and after every operation.", T.OK, "✔")
        self.activity.clear()
        for e in reversed(svc.ledger.entries()[-40:]):
            it = QListWidgetItem(f"#{e['seq']:<4}  {e['ts'][11:19]}   {e['action']:<18}  {summarize(e)}")
            it.setToolTip(f"{e['actor']} · {e['case_id'] or '-'}\nentry {e['entry_hash']}\nprev  {e['prev_hash']}")
            self.activity.addItem(it)
