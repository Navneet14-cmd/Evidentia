"""Certificates and the full service flow (create case -> recover -> report -> sanitize -> verify)."""
import json
import os

import pytest

from evidentia.core.devices import SafetyError
from evidentia.recovery.engine import RecoveryOptions
from evidentia.sanitize import certificate
from evidentia.sanitize.engine import Request, Target
from evidentia.sanitize.testing import authorize_for_tests


def test_full_flow(svc, images):
    d, meta = images
    case = svc.create_case("Flow test", "pytest")
    ev = svc.add_evidence(case["id"], str(d / "fat32.img"))
    run = svc.run_recovery(ev["id"], RecoveryOptions())
    assert run["source_unchanged"] == 1 and run["pre_sha256"] == ev["sha256"]
    files = svc.recovered_files(run["id"])
    assert files and all(f["sha256"] and os.path.exists(f["output_path"]) for f in files)

    exported = svc.export_files([files[0]["id"]], str(svc.home / "export"))
    assert exported[0]["verified"]

    rep = svc.generate_report(case["id"])
    assert os.path.getsize(rep["pdf"]) > 10_000 and "Chain of custody" in open(rep["html"]).read()

    # originals can never be sanitized; working copies can
    with pytest.raises(SafetyError, match="ORIGINAL"):  # refused before any confirmation dialog is shown
        svc.begin_sanitize_confirmation(Request(Target("image", ev["path"]), "clear-zero", dry_run=False),
                                        evidence_id=ev["id"])
    copy = svc.make_working_copy(ev["id"])
    assert copy["sha256"] == ev["sha256"]
    req = Request(Target("image", copy["path"]), "clear-zero", verify_mode="full", dry_run=False)
    out = svc.sanitize(req, evidence_id=copy["id"],
                       authorization=authorize_for_tests(req, svc=svc, evidence_id=copy["id"]))
    cert = out["certificate"]
    assert cert["result"] == "PASS" and cert["nist_category"] == "Clear"
    assert certificate.verify(cert)[0]
    assert os.path.exists(out["certificate_pdf"])
    # original is still bit-identical
    from evidentia.core.hashing import hash_file
    assert hash_file(ev["path"])["sha256"] == ev["sha256"]

    actions = [e["action"] for e in svc.ledger.entries(case["id"])]
    for a in ("case.create", "evidence.acquire", "recovery.start", "recovery.complete", "file.export",
              "report.generate", "evidence.copy", "sanitize.start", "sanitize.complete", "sanitize.verify",
              "certificate.issue"):
        assert a in actions, a
    assert svc.verify_ledger().ok


def test_certificate_tamper_detected(svc, tmp_path):
    p = tmp_path / "x.img"
    p.write_bytes(os.urandom(3 << 20))
    req = Request(Target("image", str(p)), "clear-random", dry_run=False)
    out = svc.sanitize(req, authorization=authorize_for_tests(req, svc=svc))
    cert = json.loads(open(out["certificate_json"]).read())
    assert certificate.verify(cert)[0]
    cert["verification"]["passed"] = True
    cert["result"] = "PASS"
    cert["operator"]["name"] = "Someone Else"
    ok, why = certificate.verify(cert)
    assert not ok and "modified" in why
