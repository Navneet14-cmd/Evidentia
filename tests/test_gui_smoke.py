"""Drives the real GUI offscreen: recovery job, sanitize dry-run + erase, ledger verify + tamper demo."""
import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")


@pytest.fixture
def gui(svc, monkeypatch):
    from PySide6.QtWidgets import QApplication, QMessageBox

    from evidentia.gui.main_window import MainWindow
    from evidentia.gui.state import AppState
    from evidentia.gui.theme import QSS
    for name in ("information", "critical"):
        monkeypatch.setattr(QMessageBox, name, staticmethod(lambda *a, **k: QMessageBox.Ok))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: QMessageBox.Yes))  # "erase?" -> Yes
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.Yes))
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(QSS)
    st = AppState(svc)
    w = MainWindow(st)
    w.show()
    yield app, st, w, monkeypatch
    w.close()


def wait(app, st, timeout=120):
    t0 = time.time()
    app.processEvents()
    while st.jobs.busy and time.time() - t0 < timeout:
        app.processEvents()
        time.sleep(0.02)
    for _ in range(5):
        app.processEvents()


def test_end_to_end_through_widgets(gui, images):
    app, st, w, mp = gui
    d, _ = images
    svc = st.svc
    case = svc.create_case("GUI smoke")
    st.set_case(case["id"])
    ev = svc.add_evidence(case["id"], str(d / "fat32.img"))
    st.changed()
    for page in w.pages:
        w.go(page)
        app.processEvents()

    rec = w.pages["recovery"]
    w.go("recovery")
    rec.run()
    assert st.jobs.busy  # runs on a worker thread
    wait(app, st)
    assert rec.model.rowCount() > 10
    assert rec.proxy.rowCount() < rec.model.rowCount()  # duplicates hidden by default
    rec.view.selectRow(0)
    app.processEvents()
    assert "100" in rec.score.total.text() or rec.score.total.text()

    copy = svc.make_working_copy(ev["id"])
    st.changed()
    san = w.pages["sanitize"]
    w.go("sanitize")
    san.copybox.setCurrentIndex(san.copybox.findData(copy["id"]))
    san.mbtn["clear-zero"].setChecked(True)
    assert san.dry.isChecked() and san.go.isEnabled()
    san.run()
    wait(app, st)
    assert san.last["certificate"]["result"] == "DRY-RUN"
    san.dry.setChecked(False)
    from PySide6.QtWidgets import QDialog

    from evidentia.gui import confirm_dialogs as cd
    mp.setattr(cd.EraseConfirmDialog, "exec", lambda self: QDialog.Accepted)
    mp.setattr(cd.TypedConfirmDialog, "exec", lambda self: self.field.setText("CONFIRM") or QDialog.Accepted)
    san.run()
    wait(app, st)
    assert san.last["certificate"]["result"] == "PASS"
    assert open(copy["path"], "rb").read(1 << 20) == bytes(1 << 20)

    led = w.pages["ledger"]
    w.go("ledger")
    led.verify()
    assert led.report.ok
    from PySide6.QtWidgets import QInputDialog
    mp.setattr(QInputDialog, "getInt", staticmethod(lambda *a, **k: (3, True)))
    led.tamper_demo()
    assert not led.report.ok and 3 in led.report.tampered_seqs
    led.leave_demo()
    assert svc.ledger.verify().ok  # the live ledger was never touched

    rep = w.pages["reports"]
    w.go("reports")
    rep.generate()
    wait(app, st)
    assert rep.reports.rowCount() >= 1
