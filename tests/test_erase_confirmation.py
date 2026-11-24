"""Two-step erase confirmation: core state machine, engine/service gate, ledger audit, CLI and GUI front-ends."""
import os

import pytest

from evidentia.sanitize.confirmation import (CONFIRM_WORD, ConfirmationAborted, ConfirmationRequired,
                                             ErasureAuthorization)
from evidentia.sanitize.engine import Request, SanitizeEngine, Target
from evidentia.sanitize.testing import authorize_for_tests

WRONG_TEXT = ["confirm", "CONFIRM ", " CONFIRM", "Confirm", "CONFIRMED", "CONF IRM", "", "yes"]


@pytest.fixture
def victim(tmp_path):
    p = tmp_path / "victim.img"
    p.write_bytes(os.urandom(2 << 20))
    return p


def erase_req(path, method="clear-zero"):
    return Request(Target("image", str(path)), method, verify_mode="full", dry_run=False)


def actions_since(svc, seq):
    return [e for e in svc.ledger.entries() if e["seq"] > seq]


def head(svc):
    return svc.ledger.head()[0]


# --------------------------------------------------------------------------- step 1
@pytest.mark.parametrize("answer", [False, None, "yes", 1])
def test_cancel_at_step1_aborts_and_writes_nothing(svc, victim, answer):
    before, h = victim.read_bytes(), head(svc)
    req = erase_req(victim)
    s = svc.begin_sanitize_confirmation(req)
    summary = s.show()
    assert summary["nist_category"] == "Clear" and summary["size_bytes"] == 2 << 20
    assert "cannot be undone" in summary["warning"]
    assert s.answer(answer) is False  # only the literal True means "Yes, continue"
    assert s.state == "aborted"
    with pytest.raises(ConfirmationRequired):
        s.authorization
    with pytest.raises(ConfirmationAborted):  # cannot resume an aborted session
        s.submit(CONFIRM_WORD)
    with pytest.raises(ConfirmationRequired):
        svc.sanitize(req, authorization=None)
    assert victim.read_bytes() == before
    log = actions_since(svc, h)
    assert [e["action"] for e in log] == ["sanitize.confirm.shown", "sanitize.confirm.step1", "sanitize.aborted",
                                          "sanitize.aborted"]  # last one: the service refusing the token-less call
    assert log[1]["details"]["answer"] == "cancel" and log[2]["details"]["stage"] == 1
    assert "sanitize.start" not in [e["action"] for e in svc.ledger.entries()]
    assert svc.verify_ledger().ok


# --------------------------------------------------------------------------- step 2
@pytest.mark.parametrize("typed", WRONG_TEXT)
def test_wrong_text_at_step2_aborts(svc, victim, typed):
    before, h = victim.read_bytes(), head(svc)
    s = svc.begin_sanitize_confirmation(erase_req(victim))
    s.show()
    assert s.answer(True)
    assert s.submit(typed) is False
    assert s.state == "aborted" and not s.authorized
    with pytest.raises(ConfirmationRequired):
        s.authorization
    assert victim.read_bytes() == before
    log = actions_since(svc, h)
    assert [e["action"] for e in log] == ["sanitize.confirm.shown", "sanitize.confirm.step1",
                                          "sanitize.confirm.step2", "sanitize.aborted"]
    assert log[2]["details"]["passed"] is False and log[3]["details"]["stage"] == 2


def test_cancel_at_step2_aborts(svc, victim):
    h = head(svc)
    s = svc.begin_sanitize_confirmation(erase_req(victim))
    s.show()
    s.answer(True)
    assert s.submit(None) is False
    log = actions_since(svc, h)
    assert log[2]["details"]["result"] == "cancelled" and log[-1]["action"] == "sanitize.aborted"


def test_exact_confirm_starts_the_job(svc, victim):
    h = head(svc)
    req = erase_req(victim)
    s = svc.begin_sanitize_confirmation(req)
    s.show()
    assert s.answer(True) and s.submit("CONFIRM") and s.authorized
    out = svc.sanitize(req, authorization=s.authorization)
    assert out["certificate"]["result"] == "PASS"
    assert victim.read_bytes() == bytes(2 << 20)
    log = actions_since(svc, h)
    acts = [e["action"] for e in log]
    assert acts[:5] == ["sanitize.confirm.shown", "sanitize.confirm.step1", "sanitize.confirm.step2",
                        "sanitize.start", "sanitize.complete"]
    assert log[3]["details"]["confirmation_id"] == s.session_id
    for e in log[:4]:  # every step carries operator and timestamp, and belongs to the same session
        assert e["ts"] and e["actor"].startswith("Test Examiner")
    assert all(e["details"]["confirmation_id"] == s.session_id for e in log[:4])
    assert svc.verify_ledger().ok


def test_steps_cannot_be_skipped_or_reordered(svc, victim):
    s = svc.begin_sanitize_confirmation(erase_req(victim))
    with pytest.raises(ConfirmationAborted):
        s.answer(True)          # dialog was never shown
    s.show()
    with pytest.raises(ConfirmationAborted):
        s.submit(CONFIRM_WORD)  # step 2 before step 1
    with pytest.raises(ConfirmationAborted):
        s.show()                # cannot re-show


# --------------------------------------------------------------------------- engine/service gate
def test_engine_without_token_raises(victim):
    before = victim.read_bytes()
    with pytest.raises(ConfirmationRequired):
        SanitizeEngine().run(erase_req(victim))
    with pytest.raises(ConfirmationRequired):
        SanitizeEngine().run(erase_req(victim), authorization="CONFIRM")  # strings are not tokens
    assert victim.read_bytes() == before


def test_service_without_token_raises_and_is_logged(svc, victim):
    before, h = victim.read_bytes(), head(svc)
    with pytest.raises(ConfirmationRequired):
        svc.sanitize(erase_req(victim))
    assert victim.read_bytes() == before
    log = actions_since(svc, h)
    assert [e["action"] for e in log] == ["sanitize.aborted"] and log[0]["details"]["stage"] == "engine"


def test_dry_run_needs_no_token(victim):
    before = victim.read_bytes()
    r = SanitizeEngine().run(Request(Target("image", str(victim)), "clear-zero", dry_run=True))
    assert r.dry_run and victim.read_bytes() == before


def test_token_cannot_be_forged():
    with pytest.raises(ConfirmationRequired):
        ErasureAuthorization(object(), "id", "f" * 64, "me")


def test_token_is_single_use(victim):
    req = erase_req(victim)
    auth = authorize_for_tests(req)
    SanitizeEngine().run(req, authorization=auth)
    with pytest.raises(ConfirmationRequired, match="already been used"):
        SanitizeEngine().run(req, authorization=auth)


def test_token_is_bound_to_target_and_method(tmp_path, victim):
    other = tmp_path / "other.img"
    other.write_bytes(os.urandom(1 << 20))
    auth = authorize_for_tests(erase_req(victim))
    with pytest.raises(ConfirmationRequired, match="different target"):
        SanitizeEngine().run(erase_req(other), authorization=auth)
    with pytest.raises(ConfirmationRequired, match="different target"):
        SanitizeEngine().run(erase_req(victim, "clear-random"), authorization=auth)
    assert not auth.used  # a rejected use does not burn the token


def test_token_expires(victim, monkeypatch):
    import evidentia.sanitize.confirmation as c
    auth = authorize_for_tests(erase_req(victim))
    monkeypatch.setattr(c, "TOKEN_TTL_S", -1)
    with pytest.raises(ConfirmationRequired, match="expired"):
        SanitizeEngine().run(erase_req(victim), authorization=auth)


def test_test_helper_refuses_outside_pytest(victim, monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    with pytest.raises(ConfirmationRequired):
        authorize_for_tests(erase_req(victim))


# --------------------------------------------------------------------------- CLI
def _inputs(*answers):
    it = iter(answers)

    def fake(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None
    return fake


@pytest.mark.parametrize("answers,ok", [
    (("",), False),                    # default is N
    (("n",), False),
    (("maybe",), False),
    ((), False),                       # EOF at step 1
    (("y", "confirm"), False),
    (("y", "CONFIRM "), False),
    (("y",), False),                   # EOF at step 2
    (("y", "CONFIRM"), True),
    (("YES", "CONFIRM"), True),
])
def test_cli_prompts(svc, victim, answers, ok):
    from evidentia.cli import confirm_interactively
    s = svc.begin_sanitize_confirmation(erase_req(victim))
    lines = []
    assert confirm_interactively(s, _inputs(*answers), lines.append) is ok
    assert s.authorized is ok
    text = "\n".join(lines)
    assert "cannot be undone" in text and "victim.img" in text and "Clear" in text


def test_cli_sanitize_execute_end_to_end(svc, victim, monkeypatch, capsys):
    from evidentia import cli
    home = str(svc.home)
    svc.close()
    before = victim.read_bytes()
    base = ["--home", home, "sanitize", "--path", str(victim), "--method", "clear-zero", "--execute"]
    prompts = []
    monkeypatch.setattr("builtins.input", lambda p="": prompts.append(p) or "")
    assert cli.main(base) == 1 and victim.read_bytes() == before
    assert prompts == ["Proceed with this erase? [y/N]: "]
    monkeypatch.setattr("builtins.input", _inputs("y", "confirm"))
    assert cli.main(base) == 1 and victim.read_bytes() == before
    monkeypatch.setattr("builtins.input", _inputs("y", "CONFIRM"))
    assert cli.main(base) == 0 and victim.read_bytes() == bytes(2 << 20)
    assert "result: PASS" in capsys.readouterr().out
    # a dry run never prompts and never writes
    monkeypatch.setattr("builtins.input", lambda p="": pytest.fail("dry run must not prompt"))
    assert cli.main(base[:-1]) == 0


# --------------------------------------------------------------------------- GUI dialogs
@pytest.fixture
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


SUMMARY = {"name": "x.img", "scope": "Whole image file", "path": "/tmp/x.img", "size_bytes": 1024,
           "device_type": "image", "method": "Single-pass zero overwrite", "nist_category": "Clear",
           "warning": "This cannot be undone."}


def test_step1_dialog_defaults_to_cancel(qapp):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QDialog

    from evidentia.gui.confirm_dialogs import EraseConfirmDialog
    d = EraseConfirmDialog(SUMMARY)
    d.show()
    qapp.processEvents()
    assert d.cancel_btn.isDefault() and not d.yes_btn.isDefault()
    assert d.focusWidget() is d.cancel_btn
    assert d.yes_btn.text() == "Yes, continue" and d.cancel_btn.text() == "Cancel"
    QTest.keyClick(d, Qt.Key_Return)          # Enter hits the default button: Cancel
    assert d.result() == QDialog.Rejected
    d2 = EraseConfirmDialog(SUMMARY)
    d2.show()
    QTest.keyClick(d2, Qt.Key_Escape)         # Esc = Cancel
    assert d2.result() == QDialog.Rejected
    d3 = EraseConfirmDialog(SUMMARY)
    d3.show()
    d3.close()                                # closing the window = Cancel
    assert d3.result() == QDialog.Rejected


def test_step2_button_enabled_only_on_exact_confirm(qapp):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QDialog

    from evidentia.gui.confirm_dialogs import TypedConfirmDialog
    d = TypedConfirmDialog(SUMMARY)
    d.show()
    assert d.start_btn.text() == "Start Cleaning" and not d.start_btn.isEnabled()
    for wrong in WRONG_TEXT:
        d.field.setText(wrong)
        assert not d.start_btn.isEnabled(), wrong
    QTest.keyClick(d.field, Qt.Key_Return)    # Enter with wrong text does nothing
    assert d.isVisible()
    d.field.setText("CONFIRM")
    assert d.start_btn.isEnabled()
    d.start_btn.click()
    assert d.result() == QDialog.Accepted


@pytest.mark.parametrize("step1,typed,expect_job", [
    (False, None, False),
    (True, None, False),
    (True, "confirm", False),
    (True, "CONFIRM ", False),
    (True, "CONFIRM", True),
])
def test_gui_flow_only_starts_job_after_both_steps(qapp, svc, tmp_path, monkeypatch, step1, typed, expect_job):
    import time

    from PySide6.QtWidgets import QDialog

    from evidentia.gui import confirm_dialogs as cd
    from evidentia.gui.main_window import MainWindow
    from evidentia.gui.state import AppState
    img = tmp_path / "target.img"
    img.write_bytes(os.urandom(1 << 20))
    before = img.read_bytes()
    seen = []
    monkeypatch.setattr(cd.EraseConfirmDialog, "exec",
                        lambda self: seen.append(1) or (QDialog.Accepted if step1 else QDialog.Rejected))

    def step2(self):
        seen.append(2)
        if typed is None:
            return QDialog.Rejected
        self.field.setText(typed)
        return QDialog.Accepted if self.start_btn.isEnabled() else QDialog.Rejected
    monkeypatch.setattr(cd.TypedConfirmDialog, "exec", step2)
    st = AppState(svc)
    w = MainWindow(st)
    san = w.pages["sanitize"]
    san.tbtn["image"].setChecked(True)
    san.imgpath.setText(str(img))
    san.mbtn["clear-zero"].setChecked(True)
    san.dry.setChecked(False)
    assert san.go.isEnabled()  # no image-name typing any more: the dialogs do the confirming
    started = []
    real_start = st.jobs.start
    monkeypatch.setattr(st.jobs, "start", lambda *a, **k: started.append(a[0]) or real_start(*a, **k))
    san.run()
    t0 = time.time()
    while st.jobs.busy and time.time() - t0 < 60:
        qapp.processEvents()
        time.sleep(0.02)
    qapp.processEvents()
    assert seen == ([1, 2] if step1 else [1])
    assert started == (["Sanitizing"] if expect_job else [])
    assert (img.read_bytes() == bytes(1 << 20)) is expect_job
    if not expect_job:
        assert img.read_bytes() == before and "CANCELLED" in san.verdict.text()
    acts = [e["action"] for e in svc.ledger.entries()]
    assert ("sanitize.start" in acts) is expect_job and ("sanitize.aborted" in acts) is (not expect_job)
    w.close()
