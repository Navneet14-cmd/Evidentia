"""Tamper-evident, append-only audit ledger (hash chain, blockchain-style).

Every entry stores ``prev_hash`` (the previous entry's ``entry_hash``) and
``entry_hash = SHA-256(canonical JSON of seq, ts, actor, action, case_id, evidence_id, details,
prev_hash)``. Each entry hash is additionally signed with the installation's Ed25519 key, so an
attacker who edits the database cannot simply recompute the chain.

Protections, layered:
  1. SQLite triggers reject UPDATE/DELETE (stops accidents, not attackers).
  2. Hash chain: any edit, deletion, insertion or reordering breaks recomputation or linkage.
  3. Ed25519 signature per entry: rewriting + re-chaining is detectable without the private key.
  4. Anchors: the chain head (and a Merkle root) can be exported, signed, and published externally
     (e.g. OpenTimestamps / a public blockchain / email to a third party). That detects truncation
     of the newest entries, which a chain alone cannot.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .db import Store, utcnow
from .keys import Signer, verify_signature

GENESIS = "0" * 64


def canonical(entry: dict) -> bytes:
    body = {k: entry[k] for k in ("seq", "ts", "actor", "action", "case_id", "evidence_id", "prev_hash")}
    details = entry["details"]
    body["details"] = json.loads(details) if isinstance(details, str) else details
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def entry_hash(entry: dict) -> str:
    return hashlib.sha256(canonical(entry)).hexdigest()


def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return GENESIS
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


@dataclass
class Issue:
    seq: int
    kind: str      # content_modified | chain_broken | sequence_gap | bad_signature | anchor_mismatch
    message: str


@dataclass
class VerifyReport:
    ok: bool
    entries: int
    head_hash: str
    head_seq: int
    issues: list[Issue] = field(default_factory=list)
    checked_at: str = ""
    anchor_checked: bool = False

    @property
    def tampered_seqs(self) -> list[int]:
        return sorted({i.seq for i in self.issues})

    def to_dict(self) -> dict:
        return {"ok": self.ok, "entries": self.entries, "head_hash": self.head_hash, "head_seq": self.head_seq,
                "checked_at": self.checked_at, "anchor_checked": self.anchor_checked,
                "issues": [i.__dict__ for i in self.issues], "tampered_seqs": self.tampered_seqs}


class Ledger:
    def __init__(self, store: Store, signer: Signer):
        self.store = store
        self.signer = signer

    def append(self, actor: str, action: str, *, case_id: str | None = None, evidence_id: int | None = None,
               details: dict | None = None) -> dict:
        with self.store.tx() as c:
            last = c.execute("SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
            seq = (last["seq"] + 1) if last else 1
            prev = last["entry_hash"] if last else GENESIS
            entry = {"seq": seq, "ts": utcnow(), "actor": actor, "action": action, "case_id": case_id,
                     "evidence_id": evidence_id, "details": details or {}, "prev_hash": prev}
            h = entry_hash(entry)
            sig = self.signer.sign(bytes.fromhex(h))
            c.execute("INSERT INTO ledger (seq, ts, actor, action, case_id, evidence_id, details, prev_hash, "
                      "entry_hash, signature) VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (seq, entry["ts"], actor, action, case_id, evidence_id,
                       json.dumps(entry["details"], sort_keys=True), prev, h, sig))
        entry.update(entry_hash=h, signature=sig)
        return entry

    def entries(self, case_id: str | None = None, limit: int | None = None) -> list[dict]:
        sql = "SELECT * FROM ledger" + (" WHERE case_id=?" if case_id else "") + " ORDER BY seq"
        if limit:
            sql += f" LIMIT {int(limit)}"
        rows = self.store.query(sql, (case_id,) if case_id else ())
        for r in rows:
            try:
                r["details"] = json.loads(r["details"])
            except ValueError:
                pass
        return rows

    def head(self) -> tuple[int, str]:
        r = self.store.one("SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1")
        return (r["seq"], r["entry_hash"]) if r else (0, GENESIS)

    def verify(self, anchor: dict | None = None, public_b64: str | None = None) -> VerifyReport:
        """Recompute the whole chain. Pinpoints each tampered entry."""
        pub = public_b64 or self.signer.public_b64
        rows = self.store.query("SELECT * FROM ledger ORDER BY seq")
        issues: list[Issue] = []
        prev_stored = GENESIS
        expected_seq = 1
        by_seq = {}
        for r in rows:
            seq = r["seq"]
            by_seq[seq] = r
            if seq != expected_seq:
                issues.append(Issue(seq, "sequence_gap",
                                    f"expected entry #{expected_seq} but found #{seq}: entries were deleted"))
            try:
                recomputed = entry_hash(r)
            except (ValueError, TypeError):
                recomputed = None
            if recomputed != r["entry_hash"]:
                issues.append(Issue(seq, "content_modified",
                                    f"entry #{seq} content does not match its stored hash (fields were edited)"))
            elif not r["signature"] or not verify_signature(pub, r["signature"], bytes.fromhex(r["entry_hash"])):
                issues.append(Issue(seq, "bad_signature",
                                    f"entry #{seq} hash was rewritten: Ed25519 signature does not verify"))
            if r["prev_hash"] != prev_stored:
                culprit = seq - 1 if seq - 1 in by_seq else seq
                issues.append(Issue(culprit, "chain_broken",
                                    f"link from #{seq} to its predecessor is broken (entry #{seq - 1} was "
                                    "rewritten, removed or reordered)"))
            prev_stored = r["entry_hash"]
            expected_seq = seq + 1
        head_seq, head_hash = (rows[-1]["seq"], rows[-1]["entry_hash"]) if rows else (0, GENESIS)
        anchor_checked = False
        if anchor:
            anchor_checked = True
            a_seq, a_hash = int(anchor["head_seq"]), anchor["head_hash"]
            if a_seq not in by_seq:
                issues.append(Issue(a_seq, "anchor_mismatch",
                                    f"anchored entry #{a_seq} is missing: ledger was truncated"))
            elif by_seq[a_seq]["entry_hash"] != a_hash:
                issues.append(Issue(a_seq, "anchor_mismatch",
                                    f"entry #{a_seq} differs from the externally anchored hash"))
        return VerifyReport(not issues, len(rows), head_hash, head_seq, issues, utcnow(), anchor_checked)

    def build_anchor(self) -> dict:
        rows = self.store.query("SELECT seq, entry_hash FROM ledger ORDER BY seq")
        seq, h = (rows[-1]["seq"], rows[-1]["entry_hash"]) if rows else (0, GENESIS)
        payload = {"type": "evidentia-ledger-anchor", "version": 1, "head_seq": seq, "head_hash": h,
                   "merkle_root": merkle_root([r["entry_hash"] for r in rows]), "entries": len(rows),
                   "exported_at": utcnow(), "public_key": self.signer.public_b64,
                   "key_fingerprint": self.signer.fingerprint}
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        payload["signature"] = self.signer.sign(body)
        payload["anchoring_hint"] = ("Publish head_hash externally to fix this state in time, e.g. "
                                     "`ots stamp anchor.json` (OpenTimestamps → Bitcoin), a transaction "
                                     "OP_RETURN, or a signed email to the case supervisor.")
        return payload


def verify_anchor_file(anchor: dict) -> bool:
    body = {k: v for k, v in anchor.items() if k not in ("signature", "anchoring_hint")}
    data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return verify_signature(anchor["public_key"], anchor["signature"], data)
