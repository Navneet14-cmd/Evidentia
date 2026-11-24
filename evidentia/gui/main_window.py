"""Main window: sidebar navigation, top bar with case selector, stacked pages, job bar."""
from __future__ import annotations

from PySide6.QtWidgets import (QButtonGroup, QComboBox, QFrame, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
                               QProgressBar, QStackedWidget, QVBoxLayout, QWidget)

from .. import __version__
from . import theme as T
from .pages.cases import CasesPage, NewCaseDialog
from .pages.dashboard import DashboardPage
from .pages.ledger import LedgerPage
from .pages.recovery import RecoveryPage
from .pages.reports import ReportsPage
from .pages.sanitize import SanitizePage
from .pages.settings import SettingsPage
from .state import AppState
from .widgets import Pill, button, label

NAV = [("dashboard", "◉  Dashboard", "Overview of casework, integrity and recent activity"),
       ("cases", "▤  Cases", "Cases, evidence items, hashes and examiner notes"),
       ("recovery", "⟲  Recovery", "File-system recovery, signature carving and fragment reconstruction"),
       ("sanitize", "⌫  Sanitization", "NIST SP 800-88 Rev. 2 Clear / Purge with verification and certificates"),
       ("ledger", "⛓  Audit Ledger", "Tamper-evident, hash-chained chain-of-custody ledger"),
       ("reports", "▦  Reports", "Case reports and sanitization certificates"),
       ("settings", "⚙  Settings", "Examiner profile, device safety and signing key")]


class MainWindow(QMainWindow):
    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self.setWindowTitle(f"Evidentia {__version__} — Digital Forensics Platform")
        self.resize(1440, 900)
        self.setMinimumSize(1100, 700)
        root = QWidget()
        root.setObjectName("root")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._topnav())
        h = QHBoxLayout()
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        h.addWidget(self._sidebar())
        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)
        right.addWidget(self._pagehead())
        self.stack = QStackedWidget()
        self.pages = {
            "dashboard": DashboardPage(state), "cases": CasesPage(state), "recovery": RecoveryPage(state),
            "sanitize": SanitizePage(state), "ledger": LedgerPage(state), "reports": ReportsPage(state),
            "settings": SettingsPage(state)}
        for p in self.pages.values():
            self.stack.addWidget(p)
        right.addWidget(self.stack, 1)
        h.addLayout(right, 1)
        outer.addLayout(h, 1)
        outer.addWidget(self._footer())
        self.setCentralWidget(root)
        state.navigate.connect(self.go)
        state.case_changed.connect(lambda _: self._refresh_cases())
        state.data_changed.connect(self._refresh_cases)
        state.data_changed.connect(self._refresh_footer)
        state.settings_changed.connect(self._refresh_footer)
        state.jobs.started.connect(self._job_started)
        state.jobs.ended.connect(self._job_ended)
        self._refresh_cases()
        self._refresh_footer()
        self.go("dashboard")

    # ------------------------------------------------------------------ chrome
    def _topnav(self):
        bar = QFrame()
        bar.setObjectName("topnav")
        bar.setFixedHeight(64)
        h = QHBoxLayout(bar)
        h.setContentsMargins(32, 0, 32, 0)
        h.setSpacing(24)
        h.addWidget(label("Evidentia", "brand"))
        h.addSpacing(16)
        self.toplink = label("", "topLink")
        h.addWidget(self.toplink)
        h.addStretch(1)
        self.topuser = label("", "topUser")
        h.addWidget(self.topuser)
        self.casebox = QComboBox()
        self.casebox.setMinimumWidth(330)
        self.casebox.setToolTip("Active case")
        self.casebox.currentIndexChanged.connect(self._case_picked)
        h.addWidget(self.casebox)
        h.addWidget(button("+ New case", "primary", self.new_case))
        return bar

    def _sidebar(self):
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(240)
        v = QVBoxLayout(side)
        v.setContentsMargins(16, 20, 16, 16)
        v.setSpacing(4)
        head = QHBoxLayout()
        head.setSpacing(10)
        mark = QLabel("◆")
        mark.setStyleSheet("font-size: 20px;")
        head.addWidget(mark)
        col = QVBoxLayout()
        col.setSpacing(0)
        col.addWidget(label("Forensic Examiner", "sideRole"))
        self.session = label("", "sideSession")
        col.addWidget(self.session)
        head.addLayout(col)
        head.addStretch()
        v.addLayout(head)
        v.addSpacing(28)
        self.navgroup = QButtonGroup(self)
        self.navbtn = {}
        for key, text, tip in NAV:
            b = button(text, "nav", tip=tip)
            b.setCheckable(True)
            b.clicked.connect(lambda _=False, k=key: self.go(k))
            self.navgroup.addButton(b)
            self.navbtn[key] = b
            v.addWidget(b)
        v.addStretch()
        self.who = label("", "sideFoot", wrap=True)
        self.keyfp = label("", "sideFoot", wrap=True)
        self.keyfp.setStyleSheet("font-size: 10.5px;")
        for w in (self.who, self.keyfp):
            v.addWidget(w)
        return side

    def _pagehead(self):
        head = QFrame()
        head.setObjectName("pagehead")
        v = QVBoxLayout(head)
        v.setContentsMargins(32, 26, 32, 6)
        v.setSpacing(4)
        row = QHBoxLayout()
        row.setSpacing(12)
        self.title = label("", "pageTitle")
        row.addWidget(self.title)
        row.addStretch(1)
        self.case_pill = Pill("", T.ACCENT)
        self.mode_pill = Pill("", T.OK)
        row.addWidget(self.case_pill)
        row.addWidget(self.mode_pill)
        v.addLayout(row)
        self.sub = label("", "pageSub")
        v.addWidget(self.sub)
        return head

    def _footer(self):
        bar = QFrame()
        bar.setObjectName("footer")
        h = QHBoxLayout(bar)
        h.setContentsMargins(32, 10, 32, 10)
        h.setSpacing(14)
        self.footnote = label(f"Evidentia {__version__} · Digital Forensics Platform", "footNote")
        h.addWidget(self.footnote)
        # job progress (only visible while a job runs)
        self.jobbar = QWidget()
        jb = QHBoxLayout(self.jobbar)
        jb.setContentsMargins(0, 0, 0, 0)
        jb.setSpacing(12)
        self.jobtitle = label("", "h2")
        self.jobmsg = label("", "muted")
        self.jobprog = QProgressBar()
        self.jobprog.setRange(0, 1000)
        self.jobprog.setFixedWidth(320)
        self.jobprog.setFixedHeight(10)
        self.jobprog.setTextVisible(False)
        self.jobpct = label("")
        self.jobcancel = button("Cancel", None, self._cancel_job)
        jb.addWidget(self.jobtitle)
        jb.addWidget(self.jobmsg, 1)
        jb.addWidget(self.jobprog)
        jb.addWidget(self.jobpct)
        jb.addWidget(self.jobcancel)
        self.jobbar.hide()
        h.addWidget(self.jobbar, 1)
        self.foothint = label("Every action is signed into the hash-chained audit ledger.", "footHint")
        h.addStretch(0)
        h.addWidget(self.foothint)
        self.footcta = button("⛓  VERIFY LEDGER", "cta", lambda: self.go("ledger"),
                              tip="Open the audit ledger to verify its integrity")
        h.addWidget(self.footcta)
        return bar

    # ------------------------------------------------------------------ behaviour
    def go(self, key: str):
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        self.navbtn[key].setChecked(True)
        text = next(t for k, t, _ in NAV if k == key).split("  ", 1)[1]
        self.title.setText(text)
        self.toplink.setText(text)
        self.sub.setText(next(tip for k, _, tip in NAV if k == key))
        if hasattr(page, "on_show"):
            page.on_show()

    def _refresh_cases(self):
        self.casebox.blockSignals(True)
        self.casebox.clear()
        cases = self.state.svc.list_cases()
        for c in cases:
            self.casebox.addItem(f"{c['id']} — {c['title']}", c["id"])
        if not cases:
            self.casebox.addItem("No cases yet — create one", None)
        idx = self.casebox.findData(self.state.case_id)
        self.casebox.setCurrentIndex(max(0, idx))
        self.casebox.blockSignals(False)
        cid = self.casebox.currentData()
        self.case_pill.set(cid or "NO CASE", T.ACCENT, filled=bool(cid))

    def _case_picked(self, idx):
        self.state.set_case(self.casebox.itemData(idx))

    def _refresh_footer(self):
        s = self.state.svc.settings
        if s.advanced_device_access:
            self.mode_pill.set("● ADVANCED · PHYSICAL DEVICES", T.WARN)
            self.mode_pill.setToolTip("Physical devices enabled (system and mounted disks are still refused)")
            self.session.setText("Advanced device access")
        else:
            self.mode_pill.set("● SAFE MODE · IMAGES ONLY", T.OK)
            self.mode_pill.setToolTip("Evidentia works on disk image files only")
            self.session.setText("Safe mode session")
        self.topuser.setText(f"◉  Examiner: {s.examiner_label}")
        self.who.setText(f"<b>{s.examiner_label}</b>" + (f"<br>{s.examiner_org}" if s.examiner_org else ""))
        self.keyfp.setText(f"Ed25519 key {self.state.svc.signer.fingerprint[:19]}…")

    def new_case(self):
        dlg = NewCaseDialog(self)
        if dlg.exec():
            title, desc = dlg.values()
            c = self.state.svc.create_case(title, desc)
            self.state.case_id = None
            self.state.set_case(c["id"])
            self.state.changed()
            self.go("cases")

    def _job_started(self, job):
        self.jobtitle.setText(job.title)
        self.jobmsg.setText("starting…")
        self.jobprog.setValue(0)
        self.jobpct.setText("0%")
        self.jobcancel.setEnabled(True)
        job.progressed.connect(self._job_progress)
        job.failed.connect(lambda m, tb: QMessageBox.critical(self, job.title + " failed", m))
        job.cancelled.connect(lambda: self.jobmsg.setText("cancelled by operator"))
        self.foothint.hide()
        self.jobbar.show()

    def _job_progress(self, f, msg):
        self.jobprog.setValue(int(f * 1000))
        self.jobpct.setText(f"{f * 100:.0f}%")
        if msg:
            self.jobmsg.setText(msg)

    def _job_ended(self):
        self.jobbar.hide()
        self.foothint.show()
        self.state.changed()

    def _cancel_job(self):
        if self.state.jobs.current:
            self.state.jobs.current.cancel()
            self.jobcancel.setEnabled(False)
            self.jobmsg.setText("cancelling…")

    def closeEvent(self, ev):
        if self.state.jobs.busy:
            if QMessageBox.question(self, "Job running", "A job is still running. Cancel it and quit?") != QMessageBox.Yes:
                ev.ignore()
                return
            self.state.jobs.current.cancel()
            self.state.jobs.current.wait(5000)
        ev.accept()
