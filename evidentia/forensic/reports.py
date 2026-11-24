"""Automated case reports (PDF + self-contained HTML)."""
from __future__ import annotations

import base64
import html
import os
import uuid
from pathlib import Path

from .. import __version__
from .db import utcnow


def _collect(svc, case_id: str) -> dict:
    case = svc.get_case(case_id)
    if not case:
        raise KeyError(case_id)
    files = [f for f in svc.recovered_files(case_id=case_id) if f["superseded_by"] is None]
    ver = svc.ledger.verify()
    return {
        "report_id": f"EVD-RPT-{uuid.uuid4().hex[:10].upper()}", "generated": utcnow(), "case": case,
        "evidence": svc.list_evidence(case_id), "runs": svc.list_runs(case_id), "files": files,
        "superseded": len([f for f in svc.recovered_files(case_id=case_id) if f["superseded_by"] is not None]),
        "sanitizations": svc.sanitizations(case_id), "notes": svc.notes(case_id),
        "timeline": svc.ledger.entries(case_id), "verify": ver, "fingerprint": svc.signer.fingerprint,
        "examiner": svc.actor,
    }


def build_report(svc, case_id: str, out_dir: Path) -> dict:
    from .service import summarize
    d = _collect(svc, case_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf = out_dir / f"{d['report_id']}.pdf"
    htm = out_dir / f"{d['report_id']}.html"
    _pdf(d, pdf, summarize)
    _html(d, htm, summarize)
    return {"report_id": d["report_id"], "pdf": str(pdf), "html": str(htm), "ledger_ok": d["verify"].ok}


def _short(h, n=16):
    return (h or "-")[:n] + ("…" if h and len(h) > n else "")


# ------------------------------------------------------------------------------------- PDF
def _pdf(d: dict, path: Path, summarize) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import Image as RLImage
    from reportlab.platypus import PageBreak, SimpleDocTemplate, Spacer, Table, TableStyle

    from .pdfstyle import BAD, BODY, CELL, H1, H2, MONO, OK, SMALL, P, grid_table, header_band, kv_table

    c, v = d["case"], d["verify"]
    story = [P(f"{c['id']} — {c['title']}", H1)]
    story.append(kv_table([("Examiner", c["examiner"] or "-"), ("Organisation", c["organization"] or "-"),
                           ("Case opened", c["created_at"]), ("Report generated", f"{d['generated']} by {d['examiner']}"),
                           ("Report ID", d["report_id"]), ("Description", c["description"] or "-")]))
    colour = OK if v.ok else BAD
    status = (f"<font color='white'><b>LEDGER {'VERIFIED' if v.ok else 'TAMPERED'}</b></font>")
    detail = (f"{v.entries} entries recomputed; head #{v.head_seq} {v.head_hash[:24]}…; every hash link and "
              f"Ed25519 signature checked." if v.ok else
              "Tampered entries: " + ", ".join(f"#{s}" for s in v.tampered_seqs) + " — " +
              "; ".join(i.message for i in v.issues[:3]))
    box = Table([[P(status, BODY), P(detail, CELL)]], colWidths=(130, 393))
    box.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), colour), ("BOX", (0, 0), (-1, -1), 0.6, colour),
                             ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (1, 0), (1, 0), 10)]))
    story += [Spacer(1, 8), box]

    story.append(P("Evidence summary", H2))
    rows = [[str(e["id"]), e["label"], e["kind"], f"{e['size']:,}", P(e["sha256"], MONO), P(e["md5"], MONO),
             e["acquired_at"][:19].replace("T", " ")] for e in d["evidence"]]
    story.append(grid_table(["#", "Label", "Kind", "Bytes", "SHA-256", "MD5", "Acquired (UTC)"], rows,
                            (18, 95, 52, 50, 140, 90, 78)))

    if d["runs"]:
        story.append(P("Recovery runs and source integrity", H2))
        rows = []
        for r in d["runs"]:
            s = r.get("stats") or {}
            same = r.get("source_unchanged")
            rows.append([str(r["id"]), str(r["evidence_id"]), (r.get("finished_at") or "")[:19].replace("T", " "),
                         f"{s.get('total', 0)} total / {s.get('intact', 0)} intact / {s.get('reconstructed', 0)} rebuilt",
                         P(f"pre&nbsp; {_short(r.get('pre_sha256'), 24)}<br/>post {_short(r.get('post_sha256'), 24)}", MONO),
                         P(f"<font color='{'#16a34a' if same else '#dc2626'}'><b>{'UNCHANGED' if same else 'CHANGED'}</b></font>", CELL)])
        story.append(grid_table(["Run", "Ev.", "Finished", "Results", "Source SHA-256", "Integrity"], rows,
                                (30, 26, 76, 140, 170, 81)))

    story.append(P(f"Recovered files ({len(d['files'])}; {d['superseded']} duplicates/superseded omitted)", H2))
    rows = []
    for f in d["files"]:
        thumb = ""
        if f.get("thumbnail_path") and os.path.exists(f["thumbnail_path"]):
            try:
                thumb = RLImage(f["thumbnail_path"], width=30, height=22, kind="proportional")
            except Exception:  # noqa: BLE001
                thumb = ""
        conf = f["confidence"] or 0
        cc = "#16a34a" if conf >= 80 else "#d97706" if conf >= 50 else "#dc2626"
        mm = " <font color='#dc2626'><b>ext≠</b></font>" if f["ext_mismatch"] else ""
        rows.append([thumb, P(f"{f['name']}<br/><font color='#64748b' size='6.5'>{f['source']} · {f['path']}</font>", CELL),
                     P(f"{f['detected_type']}{mm}", CELL), f["validation_status"],
                     P(f"<font color='{cc}'><b>{conf}</b></font>", CELL), f"{f['size']:,}",
                     P(f"{f['sha256']}<br/>md5 {f['md5']}", MONO)])
    story.append(grid_table(["", "File", "Type", "Validation", "Conf.", "Bytes", "SHA-256 / MD5"], rows,
                            (34, 120, 50, 50, 30, 45, 194)))
    story.append(P("Confidence (0-100) = metadata (20) + structural validation (40) + fragmentation (20) + "
                   "entropy (20). 'ext≠' marks a file whose content type contradicts its extension.", SMALL))

    if d["sanitizations"]:
        story.append(P("Sanitization", H2))
        rows = [[s["certificate_id"], s["method"], s["nist_category"], f"{s['target'].get('kind')}: "
                 f"{os.path.basename(s['target'].get('path') or '')}", s["result"],
                 (s.get("finished_at") or "")[:19].replace("T", " ")] for s in d["sanitizations"]]
        story.append(grid_table(["Certificate", "Method", "NIST", "Target", "Result", "Finished"], rows,
                                (110, 110, 45, 120, 50, 88)))
    if d["notes"]:
        story.append(P("Examiner notes", H2))
        for n in d["notes"]:
            story.append(P(f"<b>{html.escape(n['created_at'][:19])} — {html.escape(n['author'])}</b>: "
                           f"{html.escape(n['body'])}", CELL))
    story += [PageBreak(), P("Chain of custody timeline", H2)]
    tampered = set(v.tampered_seqs)
    rows = []
    for e in d["timeline"]:
        flag = "<font color='#dc2626'><b>TAMPERED</b></font>" if e["seq"] in tampered else "<font color='#16a34a'>✓</font>"
        rows.append([str(e["seq"]), e["ts"][:19].replace("T", " "), e["actor"], e["action"],
                     P(html.escape(summarize(e)), CELL), P(e["entry_hash"][:16] + "…", MONO), P(flag, CELL)])
    story.append(grid_table(["#", "UTC", "Actor", "Action", "What", "Entry hash", ""], rows,
                            (22, 72, 70, 70, 175, 82, 32)))
    story.append(P(f"Signing key fingerprint (Ed25519): {d['fingerprint']}. Ledger head #{v.head_seq}: {v.head_hash}.", SMALL))
    doc = SimpleDocTemplate(str(path), pagesize=A4, topMargin=80, bottomMargin=40, leftMargin=36, rightMargin=36,
                            title=f"Case report {d['case']['id']}", author="Evidentia")
    sub = f"{d['case']['id']} · {d['report_id']} · generated {d['generated'][:19]} UTC · Evidentia {__version__}"
    doc.build(story, onFirstPage=lambda cv, dc: header_band(cv, dc, "Forensic Case Report", sub),
              onLaterPages=lambda cv, dc: header_band(cv, dc, "Forensic Case Report", sub))


# ------------------------------------------------------------------------------------ HTML
_CSS = """
:root{--bg:#f8fafc;--fg:#0f172a;--muted:#64748b;--line:#e2e8f0;--card:#fff;--ok:#16a34a;--bad:#dc2626;--warn:#d97706;--acc:#0ea5e9}
@media (prefers-color-scheme:dark){:root{--bg:#0b1120;--fg:#e2e8f0;--muted:#94a3b8;--line:#1e293b;--card:#111827}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Inter,sans-serif}
header{background:#0f172a;color:#fff;padding:22px 32px;border-bottom:3px solid var(--acc)}
header h1{margin:0;font-size:22px}header p{margin:4px 0 0;color:#94a3b8;font-size:12px}
main{max-width:1200px;margin:0 auto;padding:24px 16px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 20px;margin-bottom:18px}
h2{font-size:16px;margin:0 0 12px}table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--muted);font-weight:600}code{font:11px ui-monospace,Menlo,monospace;word-break:break-all}
.pill{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700;color:#fff}
.ok{background:var(--ok)}.bad{background:var(--bad)}.warn{background:var(--warn)}
.banner{display:flex;gap:16px;align-items:center;padding:14px 18px;border-radius:10px;color:#fff;margin-bottom:18px}
.kv td:first-child{width:180px;color:var(--muted)}img.t{width:56px;height:42px;object-fit:cover;border-radius:4px}
.tamper td{background:rgba(220,38,38,.12)}.wrap{overflow-x:auto}
"""


def _img64(p):
    try:
        return "data:image/png;base64," + base64.b64encode(Path(p).read_bytes()).decode()
    except OSError:
        return ""


def _html(d: dict, path: Path, summarize) -> None:
    e = html.escape
    c, v = d["case"], d["verify"]
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>Case report {e(c['id'])}</title><style>{_CSS}</style></head><body>"
           f"<header><h1>Forensic Case Report — {e(c['id'])}</h1><p>{e(d['report_id'])} · generated {e(d['generated'][:19])} UTC "
           f"by {e(d['examiner'])} · Evidentia {__version__}</p></header><main>"]
    out.append(f"<div class='banner' style='background:{'var(--ok)' if v.ok else 'var(--bad)'}'><b>LEDGER "
               f"{'VERIFIED' if v.ok else 'TAMPERED'}</b><span>{v.entries} entries · head #{v.head_seq} "
               f"<code style='color:#fff'>{v.head_hash[:32]}…</code>"
               + ("" if v.ok else " · tampered: " + ", ".join(f"#{s}" for s in v.tampered_seqs)) + "</span></div>")
    out.append("<section><h2>Case</h2><table class='kv'>" + "".join(
        f"<tr><td>{k}</td><td>{e(str(val or '-'))}</td></tr>" for k, val in
        [("Title", c["title"]), ("Examiner", c["examiner"]), ("Organisation", c["organization"]),
         ("Opened", c["created_at"]), ("Description", c["description"])]) + "</table></section>")
    out.append("<section><h2>Evidence</h2><div class='wrap'><table><tr><th>#</th><th>Label</th><th>Kind</th><th>Bytes</th>"
               "<th>SHA-256</th><th>MD5</th><th>Acquired</th></tr>" + "".join(
                   f"<tr><td>{x['id']}</td><td>{e(x['label'])}</td><td>{x['kind']}</td><td>{x['size']:,}</td>"
                   f"<td><code>{x['sha256']}</code></td><td><code>{x['md5']}</code></td><td>{x['acquired_at'][:19]}</td></tr>"
                   for x in d["evidence"]) + "</table></div></section>")
    if d["runs"]:
        out.append("<section><h2>Recovery runs</h2><table><tr><th>Run</th><th>Evidence</th><th>Results</th>"
                   "<th>Source SHA-256 (pre / post)</th><th>Integrity</th></tr>" + "".join(
                       f"<tr><td>{r['id']}</td><td>#{r['evidence_id']}</td><td>{(r.get('stats') or {}).get('total', 0)} total, "
                       f"{(r.get('stats') or {}).get('intact', 0)} intact, {(r.get('stats') or {}).get('reconstructed', 0)} reconstructed</td>"
                       f"<td><code>{r.get('pre_sha256')}</code><br><code>{r.get('post_sha256')}</code></td><td>"
                       f"<span class='pill {'ok' if r.get('source_unchanged') else 'bad'}'>{'UNCHANGED' if r.get('source_unchanged') else 'CHANGED'}</span></td></tr>"
                       for r in d["runs"]) + "</table></section>")
    rows = []
    for f in d["files"]:
        conf = f["confidence"] or 0
        cls = "ok" if conf >= 80 else "warn" if conf >= 50 else "bad"
        thumb = f"<img class='t' src='{_img64(f['thumbnail_path'])}' alt=''>" if f.get("thumbnail_path") else ""
        comps = "; ".join(f"{x['label']} {x['points']}/{x['max']}" for x in (f["detail"].get("score") or {}).get("components", []))
        rows.append(f"<tr><td>{thumb}</td><td>{e(f['name'])}<br><small style='color:var(--muted)'>{e(f['source'])} · {e(f['path'])}</small></td>"
                    f"<td>{e(f['detected_type'])}{' <span class=\"pill bad\">ext mismatch</span>' if f['ext_mismatch'] else ''}</td>"
                    f"<td>{e(f['validation_status'])}</td><td><span class='pill {cls}' title='{e(comps)}'>{conf}</span></td>"
                    f"<td>{f['size']:,}</td><td><code>{f['sha256']}</code><br><code>md5 {f['md5']}</code></td></tr>")
    out.append(f"<section><h2>Recovered files ({len(d['files'])}; {d['superseded']} duplicates omitted)</h2><div class='wrap'><table>"
               "<tr><th></th><th>File</th><th>Type</th><th>Validation</th><th>Confidence</th><th>Bytes</th><th>Hashes</th></tr>"
               + "".join(rows) + "</table></div></section>")
    if d["sanitizations"]:
        out.append("<section><h2>Sanitization</h2><table><tr><th>Certificate</th><th>Method</th><th>NIST</th><th>Target</th>"
                   "<th>Result</th></tr>" + "".join(
                       f"<tr><td>{e(s['certificate_id'])}</td><td>{e(s['method'])}</td><td>{s['nist_category']}</td>"
                       f"<td>{e(s['target'].get('kind', ''))}: {e(os.path.basename(s['target'].get('path') or ''))}</td>"
                       f"<td><span class='pill {'ok' if s['result'] == 'PASS' else 'warn' if s['result'] == 'DRY-RUN' else 'bad'}'>{s['result']}</span></td></tr>"
                       for s in d["sanitizations"]) + "</table></section>")
    if d["notes"]:
        out.append("<section><h2>Notes</h2>" + "".join(f"<p><b>{e(n['created_at'][:19])} {e(n['author'])}</b>: {e(n['body'])}</p>"
                                                         for n in d["notes"]) + "</section>")
    tampered = set(v.tampered_seqs)
    out.append("<section><h2>Chain of custody</h2><div class='wrap'><table><tr><th>#</th><th>UTC</th><th>Actor</th><th>Action</th>"
               "<th>What</th><th>Entry hash</th></tr>" + "".join(
                   f"<tr class='{'tamper' if x['seq'] in tampered else ''}'><td>{x['seq']}</td><td>{x['ts'][:19]}</td><td>{e(x['actor'])}</td>"
                   f"<td>{e(x['action'])}</td><td>{e(summarize(x))}</td><td><code>{x['entry_hash'][:20]}…</code></td></tr>"
                   for x in d["timeline"]) + f"</table></div><p style='color:var(--muted);font-size:12px'>Ed25519 key {d['fingerprint']}</p></section>")
    out.append("</main></body></html>")
    path.write_text("".join(out), encoding="utf-8")
