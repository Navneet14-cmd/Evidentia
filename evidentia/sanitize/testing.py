"""TEST-ONLY helper: drive a ConfirmationSession through both steps without a human.

It refuses to run outside pytest (``PYTEST_CURRENT_TEST`` must be set), and every step it
takes is still reported to the audit callback, exactly like an interactive confirmation.
Production code (GUI, CLI, service, background jobs) must never import this module.
"""
from __future__ import annotations

import os

from .confirmation import CONFIRM_WORD, ConfirmationRequired, ConfirmationSession, ErasureAuthorization, build_summary


def _assert_under_pytest() -> None:
    if "PYTEST_CURRENT_TEST" not in os.environ:
        raise ConfirmationRequired("evidentia.sanitize.testing may only be used from the test suite")


def authorize_for_tests(req, *, svc=None, evidence_id=None, case_id=None, audit=None) -> ErasureAuthorization:
    """Return an authorization for ``req`` by answering Yes and typing CONFIRM.

    With ``svc`` the session comes from ``svc.begin_sanitize_confirmation`` so the steps land in the
    ledger; otherwise a bare session is used (optionally with an ``audit`` callback)."""
    _assert_under_pytest()
    if svc is not None:
        s = svc.begin_sanitize_confirmation(req, evidence_id=evidence_id, case_id=case_id)
    else:
        s = ConfirmationSession(req, build_summary(req), audit=audit, operator="test-harness")
    s.show()
    s.answer(True)
    s.submit(CONFIRM_WORD)
    return s.authorization
