"""Signed Certificate of Sanitization (JSON + PDF), modelled on NIST SP 800-88's sample certificate."""
from __future__ import annotations

import hashlib
import json
import platform
import uuid
from pathlib import Path

from .. import __version__
from ..forensic.db import utcnow
from ..forensic.keys import Signer, verify_signature
from .media import PROFILES


def _canonical(doc: dict) -> bytes:
    body = {k: v for k, v in doc.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def build(result: dict, *, media: dict, operator: dict, case: dict | None, ledger_seq: int | None,
          signer: Signer, destination: str = "Reuse within organisation") -> dict:
    m = result["method"]
    v = result["verification"]
    doc = {
        "type": "evidentia-sanitization-certificate", "version": 1,
        "certificate_id": f"EVD-SAN-{uuid.uuid4().hex[:12].upper()}",
        "issued_at": utcnow(),
        "standard": "NIST SP 800-88 Rev. 2 (Guidelines for Media Sanitization)",
        "nist_category": result["nist_category"],
        "tool": {"name": "Evidentia", "version": __version__, "host": platform.node(),
                 "platform": f"{platform.system()} {platform.release()} {platform.machine()}"},
        "operator": operator,
        "case": {"case_id": case["id"], "title": case["title"]} if case else None,
        "media": {**media, "media_type": PROFILES.get(media.get("media_profile"), media.get("media_profile"))},
        "sanitization": {
            "job_id": result["job_id"], "method_id": m["id"], "method": m["label"], "technique": m["technique"],
            "description": m["description"], "simulated": result["simulated"], "dry_run": result["dry_run"],
            "passes": result["passes"], "bytes_target": result["bytes_target"],
            "bytes_written": result["bytes_written"], "started": result["started"], "finished": result["finished"],
            "duration_s": result["duration_s"], "firmware_commands": [" ".join(c) for c in result["commands"]],
            "warnings": result["warnings"]},
        "verification": {**v, "pre_sha256": result.get("pre_sha256"), "post_sha256": result.get("post_sha256")},
        "files": result.get("files")[:200] if result.get("files") else None,
        "result": "PASS" if result["success"] and not result["dry_run"] else ("DRY-RUN" if result["dry_run"] else "FAIL"),
        "post_sanitization_destination": destination,
        "ledger_seq": ledger_seq,
    }
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    doc["signature"] = {"algorithm": "Ed25519", "public_key": signer.public_b64,
                        "key_fingerprint": signer.fingerprint, "payload_sha256": digest,
                        "value": signer.sign(_canonical(doc))}
    return doc


def verify(doc: dict) -> tuple[bool, str]:
    sig = doc.get("signature") or {}
    data = _canonical(doc)
    if hashlib.sha256(data).hexdigest() != sig.get("payload_sha256"):
        return False, "payload hash mismatch: certificate content was modified"
    if not verify_signature(sig.get("public_key", ""), sig.get("value", ""), data):
        return False, "Ed25519 signature invalid"
    return True, f"valid Ed25519 signature by key {sig.get('key_fingerprint')}"


def write(doc: dict, out_dir: str | Path) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    jp = out / f"{doc['certificate_id']}.json"
    jp.write_text(json.dumps(doc, indent=2, ensure_ascii=False))
    pp = out / f"{doc['certificate_id']}.pdf"
    render_pdf(doc, pp)
    return jp, pp


def render_pdf(doc: dict, path: Path) -> None:
    from reportlab.graphics.barcode.qr import QrCodeWidget
    from reportlab.graphics.shapes import Drawing
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Spacer, Table, TableStyle

    from ..forensic.pdfstyle import BAD, BODY, H2, MONO, OK, SMALL, WARN, P, header_band, kv_table

    s, v, md, op = doc["sanitization"], doc["verification"], doc["media"], doc["operator"]
    res = doc["result"]
    colour = OK if res == "PASS" else WARN if res == "DRY-RUN" else BAD
    story = []
    badge = Table([[P(f"<font color='white' size='15'><b>{res}</b></font>", BODY),
                    P(f"<font size='9'><b>{doc['nist_category'].upper()}</b> &nbsp; per {doc['standard']}</font><br/>"
                      f"<font size='8' color='#475569'>Certificate {doc['certificate_id']} &middot; issued "
                      f"{doc['issued_at']}</font>", BODY)]], colWidths=(90, 410), rowHeights=(40,))
    badge.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), colour), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("ALIGN", (0, 0), (0, 0), "CENTER"), ("BOX", (0, 0), (-1, -1), 0.6, colour),
                               ("LEFTPADDING", (1, 0), (1, 0), 12)]))
    story += [badge, Spacer(1, 8)]
    story += [P("Media information", H2), kv_table([
        ("Media type", md.get("media_type") or "-"), ("Identifier / path", md.get("path", "-")),
        ("Label", md.get("label") or "-")] + ([("Model / serial", f"{md.get('model') or '-'} / {md.get('serial') or '-'}")]
                                              if md.get("model") or md.get("serial") else []) + [
        ("Capacity sanitized", f"{s['bytes_target']:,} bytes"),
        ("Target scope", md.get("scope", "-")),
        ("Case", f"{doc['case']['case_id']} — {doc['case']['title']}" if doc.get("case") else "-")])]
    story += [P("Sanitization", H2), kv_table([
        ("Method", f"{s['method']} ({s['method_id']})"), ("NIST category", doc["nist_category"]),
        ("Technique", s["technique"] + (" — SIMULATED on image (equivalent end state)" if s["simulated"] else "")),
        ("Passes", "; ".join(f"#{p['pass']}: {p['pattern']}" + (" ✓" if p.get("verified") else "")
                             for p in s["passes"]) or "-"),
        ("Started / finished", f"{s['started']}  →  {s['finished']}  ({s['duration_s']} s)"),
        ("Firmware commands", "<br/>".join(s["firmware_commands"]) or "n/a (host overwrite)"),
        ("Warnings", "<br/>".join(s["warnings"]) or "none"),
        ("Post-sanitization", doc["post_sanitization_destination"])])]
    vrows = [("Verification mode", f"{v.get('mode')} — {v.get('sample_percent', 100)}% of blocks"
              if v.get("mode") == "sample" else str(v.get("mode"))),
             ("Blocks checked", f"{v.get('blocks_checked', v.get('files_verified', '-'))} of "
                                f"{v.get('blocks_total', v.get('files_total', '-'))}"),
             ("Mismatches", str(v.get("mismatched_blocks", 0))),
             ("Criterion", v.get("criterion") or f"read-back equals expected pattern ({v.get('expected_pattern', '-')})"),
             ("Residual file signatures", "n/a (random pattern)" if v.get("residual_signatures") is None
              else f"{v['residual_signatures']} found in checked blocks"),
             ("SHA-256 before", P(v.get("pre_sha256") or "-", MONO)),
             ("SHA-256 after", P(v.get("post_sha256") or "-", MONO)),
             ("Verification result", f"<b>{'PASSED' if v.get('passed') else 'FAILED' if v.get('passed') is False else 'n/a'}</b>")]
    story += [P("Verification", H2), kv_table(vrows)]
    if doc.get("files"):
        story.append(P(f"Files erased: {len(doc['files'])} (listed in the JSON certificate)", SMALL))
    story += [P("Performed by", H2), kv_table([
        ("Name", op.get("name") or "-"), ("Organisation", op.get("organization") or "-"),
        ("Examiner ID", op.get("id") or "-"), ("Tool", f"Evidentia {doc['tool']['version']} on {doc['tool']['platform']}"),
        ("Audit ledger entry", f"#{doc['ledger_seq']}" if doc.get("ledger_seq") else "-")])]
    sig = doc["signature"]
    qr_payload = json.dumps({"id": doc["certificate_id"], "sha256": sig["payload_sha256"], "key": sig["key_fingerprint"],
                             "result": res}, separators=(",", ":"))
    qr = QrCodeWidget(qr_payload)
    b = qr.getBounds()
    d = Drawing(86, 86, transform=[86 / (b[2] - b[0]), 0, 0, 86 / (b[3] - b[1]), 0, 0])
    d.add(qr)
    sigtbl = Table([[kv_table([("Algorithm", "Ed25519"), ("Key fingerprint", P(sig["key_fingerprint"], MONO)),
                               ("Payload SHA-256", P(sig["payload_sha256"], MONO)),
                               ("Signature", P(sig["value"], MONO))], widths=(90, 300)), d]], colWidths=(400, 100))
    sigtbl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [P("Digital signature", H2), sigtbl,
              P("Verify with: <font face='Courier'>python -m evidentia.cli verify-cert "
                f"{doc['certificate_id']}.json</font>. The signature covers every field of the JSON certificate.", SMALL)]
    pdf = SimpleDocTemplate(str(path), pagesize=A4, topMargin=74, bottomMargin=34, leftMargin=36, rightMargin=36,
                            title=f"Certificate of Sanitization {doc['certificate_id']}", author="Evidentia")
    sub = f"NIST SP 800-88 Rev. 2 · {doc['nist_category']} · {doc['certificate_id']}"
    pdf.build(story, onFirstPage=lambda c, d_: header_band(c, d_, "Certificate of Sanitization", sub),
              onLaterPages=lambda c, d_: header_band(c, d_, "Certificate of Sanitization", sub))
