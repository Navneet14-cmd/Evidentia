"""Two-step erase confirmation, enforced in the core.

Every destructive sanitization (``dry_run=False``) needs an :class:`ErasureAuthorization`.
The only public way to obtain one is a :class:`ConfirmationSession` that has passed both steps:

1. **Yes/No** - the operator is shown the target, method and NIST category with a
   "This cannot be undone" warning and answers *Yes, continue* (anything else cancels).
2. **Typed confirmation** - the operator types exactly ``CONFIRM`` (case-sensitive, no
   surrounding whitespace accepted).

The authorization is bound to the request it was issued for (target, method, media profile),
is single-use, and expires after :data:`TOKEN_TTL_S` seconds. Every step is reported to an
``audit`` callback; the forensic service wires that callback to the hash-chained ledger.

GUI dialogs and CLI prompts are only front-ends for this state machine: they collect the
answers, but the session decides whether the answers are acceptable.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable

from ..core.devices import SafetyError
from .media import METHODS

CONFIRM_WORD = "CONFIRM"
TOKEN_TTL_S = 10 * 60
IRREVERSIBLE_WARNING = ("This cannot be undone. All data in the target will be permanently destroyed "
                        "and cannot be recovered by Evidentia or any other tool.")

_MINT = object()  # private capability: only this module can create authorizations

Audit = Callable[..., object]


class ConfirmationRequired(SafetyError):
    """A destructive run was attempted without a valid two-step authorization."""


class ConfirmationAborted(SafetyError):
    """The operator cancelled, or failed, one of the confirmation steps."""


def request_fingerprint(req) -> str:
    """Stable digest of what is about to be destroyed and how."""
    t = req.target
    doc = {"kind": t.kind, "path": os.path.realpath(t.path), "offset": t.offset, "length": t.length,
           "paths": sorted(os.path.realpath(p) for p in (t.paths or [])),
           "method": req.method, "media_profile": req.media_profile}
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


class ErasureAuthorization:
    """Opaque, single-use proof that both confirmation steps were passed for one request."""

    __slots__ = ("session_id", "fingerprint", "operator", "_issued", "_used")

    def __init__(self, _key, session_id: str, fingerprint: str, operator: str):
        if _key is not _MINT:
            raise ConfirmationRequired("ErasureAuthorization can only be issued by a completed ConfirmationSession")
        self.session_id = session_id
        self.fingerprint = fingerprint
        self.operator = operator
        self._issued = time.monotonic()
        self._used = False

    def check(self, req) -> None:
        """Raise ConfirmationRequired unless this authorization is valid for ``req``."""
        if self._used:
            raise ConfirmationRequired("This confirmation has already been used; confirm again for a new erase")
        if time.monotonic() - self._issued > TOKEN_TTL_S:
            raise ConfirmationRequired("Confirmation expired; confirm again")
        if request_fingerprint(req) != self.fingerprint:
            raise ConfirmationRequired("Confirmation was given for a different target or method; confirm again")

    def consume(self, req) -> None:
        self.check(req)
        self._used = True

    @property
    def used(self) -> bool:
        return self._used

    def __repr__(self) -> str:
        return f"<ErasureAuthorization session={self.session_id[:8]} used={self._used}>"


def require_authorization(req, authorization) -> None:
    """Gate used by the engine: destructive runs must carry a valid, unused authorization."""
    if req.dry_run:
        return
    if not isinstance(authorization, ErasureAuthorization):
        raise ConfirmationRequired("Erase refused: two-step confirmation (Yes, then typed CONFIRM) is required "
                                   "before any data is destroyed")
    authorization.consume(req)


@dataclass
class ConfirmationSession:
    """State machine for one confirmation attempt: new -> shown -> confirmed_yes -> authorized | aborted."""

    request: object
    summary: dict
    audit: Audit | None = None
    operator: str = ""
    session_id: str = field(default_factory=lambda: secrets.token_hex(8))
    state: str = "new"
    abort_reason: str = ""
    _auth: ErasureAuthorization | None = field(default=None, repr=False)

    def _log(self, action: str, **details) -> None:
        if self.audit:
            self.audit(action, confirmation_id=self.session_id, operator=self.operator,
                       target=self.summary.get("name"), method=self.summary.get("method"), **details)

    def _abort(self, stage: int, reason: str) -> None:
        self.state, self.abort_reason = "aborted", reason
        self._log("sanitize.aborted", stage=stage, reason=reason, summary=f"erase aborted at step {stage}: {reason}")

    def _expect(self, state: str) -> None:
        if self.state != state:
            raise ConfirmationAborted(f"confirmation is '{self.state}', expected '{state}'")

    # step 1 -------------------------------------------------------------------------------
    def show(self) -> dict:
        """Record that the Yes/No confirmation was presented; returns what must be shown."""
        self._expect("new")
        self.state = "shown"
        self._log("sanitize.confirm.shown", step=1, details=self.summary,
                  summary=f"erase confirmation shown for {self.summary.get('name')}")
        return self.summary

    def answer(self, yes: bool) -> bool:
        """Step 1 answer. Anything but an explicit Yes (Cancel, Esc, closing the dialog) aborts."""
        self._expect("shown")
        yes = yes is True
        self._log("sanitize.confirm.step1", step=1, answer="yes" if yes else "cancel",
                  summary="operator chose 'Yes, continue'" if yes else "operator cancelled")
        if not yes:
            self._abort(1, "operator cancelled the Yes/No confirmation")
            return False
        self.state = "confirmed_yes"
        return True

    # step 2 -------------------------------------------------------------------------------
    def submit(self, typed: str | None) -> bool:
        """Step 2: ``typed`` must be exactly CONFIRM. ``None`` means the operator cancelled."""
        self._expect("confirmed_yes")
        if typed is None:
            self._log("sanitize.confirm.step2", step=2, passed=False, result="cancelled",
                      summary="operator cancelled the typed confirmation")
            self._abort(2, "operator cancelled the typed confirmation")
            return False
        ok = typed == CONFIRM_WORD
        self._log("sanitize.confirm.step2", step=2, passed=ok, result="passed" if ok else "failed",
                  typed_length=len(typed), summary="typed confirmation passed" if ok else
                  "typed confirmation FAILED (text did not exactly match CONFIRM)")
        if not ok:
            self._abort(2, "typed text did not exactly match CONFIRM")
            return False
        self.state = "authorized"
        self._auth = ErasureAuthorization(_MINT, self.session_id, request_fingerprint(self.request), self.operator)
        return True

    @property
    def authorized(self) -> bool:
        return self.state == "authorized"

    @property
    def authorization(self) -> ErasureAuthorization:
        if not self._auth:
            raise ConfirmationRequired(f"confirmation not completed (state: {self.state})")
        return self._auth


def build_summary(req, length: int | None = None, device: dict | None = None) -> dict:
    """What the step-1 dialog / prompt shows."""
    t = req.target
    m = METHODS[req.method]
    if t.kind == "files":
        name = ", ".join(os.path.basename(p.rstrip("/")) for p in (t.paths or [t.path]))
        size = 0
        for p in t.paths or [t.path]:
            if os.path.isdir(p):
                for root, _, files in os.walk(p):
                    size += sum(os.path.getsize(os.path.join(root, f)) for f in files
                                if not os.path.islink(os.path.join(root, f)))
            elif os.path.isfile(p):
                size += os.path.getsize(p)
    else:
        name = t.label or os.path.basename(t.path)
        size = length or 0
    dev_type = req.media_profile
    if device:
        dev_type = f"{device.get('media_type') or req.media_profile} - {device.get('model') or device.get('name')}"
    scope = {"image": "Whole image file", "device": "Whole physical device", "files": "Files / folders",
             "partition": f"Partition at offset {t.offset:,}"}.get(t.kind, t.kind)
    return {"name": name, "path": os.path.abspath(t.path) if t.kind != "files" else
            "; ".join(os.path.abspath(p) for p in (t.paths or [t.path])),
            "scope": scope, "size_bytes": size, "device_type": dev_type,
            "method": m.label, "method_id": req.method, "nist_category": m.category,
            "warning": IRREVERSIBLE_WARNING}


def summary_text(s: dict) -> str:
    return (f"  Target:      {s['name']}\n  Scope:       {s['scope']}\n  Path:        {s['path']}\n"
            f"  Size:        {s['size_bytes']:,} bytes\n  Device type: {s['device_type']}\n"
            f"  Method:      {s['method']}\n  NIST:        {s['nist_category']} (SP 800-88 Rev. 2)")
