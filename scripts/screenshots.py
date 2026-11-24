#!/usr/bin/env python3
"""Render documentation screenshots of every GUI page (offscreen) from a demo workspace.

    python -m evidentia.cli --home demo_workspace demo --fresh
    QT_QPA_PLATFORM=offscreen python scripts/screenshots.py demo_workspace docs/screenshots
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QInputDialog, QMessageBox  # noqa: E402

from evidentia.forensic.service import Evidentia  # noqa: E402
from evidentia.gui.main_window import MainWindow  # noqa: E402
from evidentia.gui.state import AppState  # noqa: E402
from evidentia.gui import theme  # noqa: E402


def pump(app, secs=0.3):
    t = time.time()
    while time.time() - t < secs:
        app.processEvents()
        time.sleep(0.01)


def main(home, out):
    os.makedirs(out, exist_ok=True)
    app = QApplication([])
    theme.apply(app)
    QMessageBox.information = staticmethod(lambda *a, **k: QMessageBox.Ok)
    QMessageBox.warning = staticmethod(lambda *a, **k: QMessageBox.Yes)
    st = AppState(Evidentia(home))
    w = MainWindow(st)
    w.resize(1440, 900)
    w.show()
    pump(app)

    def shot(name):
        pump(app, 0.6)
        w.grab().save(os.path.join(out, f"{name}.png"))

    w.go("dashboard"); shot("01_dashboard")
    w.go("cases"); shot("02_cases")
    w.go("recovery")
    rec = w.pages["recovery"]
    for i in range(rec.proxy.rowCount()):
        if rec.proxy.index(i, 1).data().startswith("thesis"):
            rec.view.selectRow(i)
    shot("03_recovery")
    w.go("sanitize")
    san = w.pages["sanitize"]
    san.tbtn["image"].setChecked(True)
    ev = [e for e in st.svc.list_evidence(st.case_id) if e["kind"] == "working-copy"]
    if ev:
        san.imgpath.setText(ev[0]["path"])
        san.mbtn["purge-crypto-erase"].setChecked(True)
        san.vmode.setCurrentIndex(1)
        san.dry.setChecked(False)
        from PySide6.QtWidgets import QDialog

        from evidentia.gui import confirm_dialogs as cd
        from evidentia.sanitize.confirmation import build_summary
        t = san._target()
        from evidentia.sanitize.engine import Request
        summ = build_summary(Request(t, "purge-crypto-erase"), os.path.getsize(t.path))
        d1 = cd.EraseConfirmDialog(summ, w)
        d1.resize(600, d1.sizeHint().height())
        d1.show(); pump(app, 0.4); d1.grab().save(os.path.join(out, "09_confirm_step1.png")); d1.close()
        d2 = cd.TypedConfirmDialog(summ, w)
        d2.show(); d2.field.setText("CONFIRM"); pump(app, 0.4)
        d2.grab().save(os.path.join(out, "10_confirm_step2.png")); d2.close()
        # drive the real flow (dialogs answered programmatically for the screenshot run)
        cd.EraseConfirmDialog.exec = lambda self: QDialog.Accepted
        cd.TypedConfirmDialog.exec = lambda self: self.field.setText("CONFIRM") or QDialog.Accepted
        san.run()
        while st.jobs.busy:
            pump(app, 0.1)
    shot("04_sanitize")
    w.go("ledger")
    led = w.pages["ledger"]
    QInputDialog.getInt = staticmethod(lambda *a, **k: (5, True))
    led.tamper_demo()
    shot("05_ledger_tamper_demo")
    led.leave_demo()
    led.verify()
    shot("06_ledger_verified")
    w.go("reports"); pump(app, 1.5); shot("07_reports")
    w.go("settings"); shot("08_settings")
    print("screenshots written to", out)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo_workspace", sys.argv[2] if len(sys.argv) > 2 else "docs/screenshots")
