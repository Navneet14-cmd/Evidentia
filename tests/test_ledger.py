"""Hash-chained ledger: integrity, tamper detection and pinpointing, anchoring."""
import json
import sqlite3

import pytest

from evidentia.forensic.ledger import entry_hash, verify_anchor_file


def _fill(svc, n=6):
    c = svc.create_case("Ledger test")
    for i in range(n):
        svc.add_note(c["id"], f"note {i}")
    return c


def _raw(svc):
    """Simulate an attacker with direct database access: drop the append-only triggers."""
    con = sqlite3.connect(svc.store.path)
    con.execute("DROP TRIGGER ledger_no_update")
    con.execute("DROP TRIGGER ledger_no_delete")
    return con


def test_clean_ledger_verifies(svc):
    _fill(svc)
    rep = svc.ledger.verify()
    assert rep.ok and rep.entries == 7 and not rep.issues


def test_triggers_block_update_and_delete(svc):
    _fill(svc)
    with pytest.raises(sqlite3.IntegrityError):
        svc.store.conn.execute("UPDATE ledger SET actor='mallory' WHERE seq=2")
    with pytest.raises(sqlite3.IntegrityError):
        svc.store.conn.execute("DELETE FROM ledger WHERE seq=2")


def test_edit_of_details_is_pinpointed(svc):
    _fill(svc)
    con = _raw(svc)
    con.execute("UPDATE ledger SET details=? WHERE seq=4", (json.dumps({"excerpt": "forged"}),))
    con.commit()
    rep = svc.ledger.verify()
    assert not rep.ok and rep.tampered_seqs == [4]
    assert rep.issues[0].kind == "content_modified"


def test_rewritten_hash_caught_by_signature_and_link(svc):
    _fill(svc)
    con = _raw(svc)
    row = dict(zip([d[0] for d in con.execute("SELECT * FROM ledger WHERE seq=3").description],
                   con.execute("SELECT * FROM ledger WHERE seq=3").fetchone()))
    row["actor"] = "mallory"
    con.execute("UPDATE ledger SET actor=?, entry_hash=? WHERE seq=3", ("mallory", entry_hash(row)))
    con.commit()
    rep = svc.ledger.verify()
    kinds = {(i.seq, i.kind) for i in rep.issues}
    assert (3, "bad_signature") in kinds and (3, "chain_broken") in kinds
    assert rep.tampered_seqs == [3]


def test_deleted_entry_detected(svc):
    _fill(svc)
    con = _raw(svc)
    con.execute("DELETE FROM ledger WHERE seq=5")
    con.commit()
    rep = svc.ledger.verify()
    assert {i.kind for i in rep.issues} >= {"sequence_gap", "chain_broken"}


def test_anchor_detects_truncation(svc):
    _fill(svc)
    anchor = svc.ledger.build_anchor()
    assert verify_anchor_file(anchor)
    assert svc.ledger.verify(anchor).ok
    con = _raw(svc)
    con.execute("DELETE FROM ledger WHERE seq=7")
    con.commit()
    plain = svc.ledger.verify()
    assert plain.ok  # a chain alone cannot see tail truncation...
    rep = svc.ledger.verify(anchor)
    assert not rep.ok and rep.issues[0].kind == "anchor_mismatch"  # ...the external anchor can


def test_forged_anchor_rejected(svc):
    _fill(svc)
    a = svc.ledger.build_anchor()
    a["head_hash"] = "0" * 64
    assert not verify_anchor_file(a)


def test_service_actions_are_logged(svc, images):
    d, _ = images
    c = svc.create_case("custody")
    ev = svc.add_evidence(c["id"], str(d / "ext4.img") if (d / "ext4.img").exists() else str(d / "fat32.img"))
    actions = [e["action"] for e in svc.ledger.entries(c["id"])]
    assert actions == ["case.create", "evidence.acquire"]
    acq = svc.ledger.entries(c["id"])[-1]
    assert acq["details"]["sha256"] == ev["sha256"] and acq["actor"].startswith("Test Examiner")
