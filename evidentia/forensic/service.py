"""The shared forensic core used by both GUI and CLI.

Every state-changing action goes through this facade, which records it in the chain of custody
(the hash-chained ledger) with who, when, what and the relevant hashes.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime
from pathlib import Path

from ..core.config import Settings, data_dir
from ..core.devices import SafetyError, is_device_path
from ..core.hashing import hash_file, hash_reader
from ..core.jobs import JobContext, NULL_CONTEXT
from ..core.source import EvidenceSource
from ..recovery.engine import RecoveryEngine, RecoveryOptions
from ..sanitize import certificate
from ..sanitize.confirmation import ConfirmationRequired, ConfirmationSession, ErasureAuthorization, build_summary
from ..sanitize.engine import Request, SanitizeEngine
from .db import Store, utcnow
from .keys import Signer
from .ledger import Ledger, merkle_root


def summarize(entry: dict) -> str:
    d = entry.get("details") or {}
    a = entry["action"]
    if a == "case.create":
        return f"Case opened: {d.get('title')}"
    if a == "evidence.acquire":
        return f"Acquired {d.get('label')} ({d.get('size', 0):,} B) sha256 {str(d.get('sha256'))[:16]}…"
    if a == "evidence.copy":
        return f"Working copy #{d.get('copy_id')} of #{d.get('source_id')} — hashes {'match' if d.get('hash_match') else 'DIFFER'}"
    if a == "recovery.start":
        return f"Recovery started; source sha256 {str(d.get('pre_sha256'))[:16]}…"
    if a == "recovery.complete":
        s = d.get("stats", {})
        return (f"Recovered {s.get('total', 0)} items ({s.get('intact', 0)} intact); source "
                f"{'unchanged' if d.get('source_unchanged') else 'CHANGED'}")
    if a == "file.export":
        return f"Exported {d.get('count')} file(s) to {d.get('destination')}"
    if a.startswith("sanitize."):
        return f"{d.get('method', '')} on {d.get('target', '')}: {d.get('summary', '')}"
    if a == "certificate.issue":
        return f"Certificate {d.get('certificate_id')} ({d.get('result')})"
    if a == "report.generate":
        return f"Case report generated ({d.get('report_id')})"
    if a == "ledger.verify":
        return f"Ledger verified: {'OK' if d.get('ok') else 'TAMPERING DETECTED'} ({d.get('entries')} entries)"
    if a == "ledger.anchor":
        return f"Chain head exported for anchoring: {str(d.get('head_hash'))[:16]}…"
    if a == "evidence.verify":
        m = d.get("match")
        return "Re-hash: " + ("matches acquisition" if m else "sanitized copy (expected change)" if m is None else "MISMATCH")
    if a == "note.add":
        return f"Note: {str(d.get('excerpt'))[:60]}"
    return json.dumps(d)[:80]


class Evidentia:
    def __init__(self, home: str | os.PathLike | None = None):
        self.home = Path(home) if home else data_dir()
        self.home.mkdir(parents=True, exist_ok=True)
        self.settings = Settings.load(self.home)
        self.store = Store(self.home / "evidentia.db")
        self.signer = Signer(self.home / "keys")
        self.ledger = Ledger(self.store, self.signer)

    # ------------------------------------------------------------------ identity
    @property
    def actor(self) -> str:
        s = self.settings
        return s.examiner_label + (f" ({s.examiner_id})" if s.examiner_id else "")

    @property
    def operator(self) -> dict:
        s = self.settings
        return {"name": s.examiner_label, "organization": s.examiner_org, "id": s.examiner_id}

    def save_settings(self) -> None:
        self.settings.save(self.home)

    def log(self, action: str, case_id=None, evidence_id=None, **details) -> dict:
        return self.ledger.append(self.actor, action, case_id=case_id, evidence_id=evidence_id, details=details)

    # ------------------------------------------------------------------ cases
    def create_case(self, title: str, description: str = "", examiner: str | None = None,
                    organization: str | None = None) -> dict:
        year = datetime.now().year
        n = (self.store.one("SELECT COUNT(*) AS n FROM cases WHERE id LIKE ?", (f"CASE-{year}-%",)) or {"n": 0})["n"] + 1
        cid = f"CASE-{year}-{n:04d}"
        while self.store.one("SELECT id FROM cases WHERE id=?", (cid,)):
            n += 1
            cid = f"CASE-{year}-{n:04d}"
        row = {"id": cid, "title": title, "description": description,
               "examiner": examiner or self.settings.examiner_label,
               "organization": organization if organization is not None else self.settings.examiner_org,
               "status": "open", "created_at": utcnow()}
        self.store.insert("cases", row)
        (self.case_dir(cid)).mkdir(parents=True, exist_ok=True)
        self.log("case.create", cid, title=title, examiner=row["examiner"], organization=row["organization"])
        return row

    def case_dir(self, case_id: str) -> Path:
        return self.home / "cases" / case_id

    def list_cases(self) -> list[dict]:
        return self.store.query("SELECT c.*, (SELECT COUNT(*) FROM evidence e WHERE e.case_id=c.id) AS evidence_count "
                                "FROM cases c ORDER BY created_at DESC")

    def get_case(self, case_id: str) -> dict | None:
        return self.store.one("SELECT * FROM cases WHERE id=?", (case_id,))

    def add_note(self, case_id: str, body: str) -> dict:
        row = {"case_id": case_id, "author": self.actor, "body": body, "created_at": utcnow()}
        row["id"] = self.store.insert("notes", row)
        self.log("note.add", case_id, note_id=row["id"], excerpt=body[:120],
                 sha256=hashlib.sha256(body.encode()).hexdigest())
        return row

    def notes(self, case_id: str) -> list[dict]:
        return self.store.query("SELECT * FROM notes WHERE case_id=? ORDER BY created_at", (case_id,))

    # ------------------------------------------------------------------ evidence
    def add_evidence(self, case_id: str, path: str, label: str | None = None, *, media_profile: str = "image",
                     notes: str = "", ctx: JobContext = NULL_CONTEXT) -> dict:
        path = os.path.abspath(path)
        with EvidenceSource(path, advanced=self.settings.advanced_device_access) as src:
            hashes = hash_reader(src.read, src.size, ("sha256", "md5"), ctx, label="Acquisition hash")
            size = src.size
            kind = "device" if src.is_device else "original"
        row = {"case_id": case_id, "label": label or os.path.basename(path), "path": path, "kind": kind,
               "size": size, "sha256": hashes["sha256"], "md5": hashes["md5"], "media_profile": media_profile,
               "acquired_at": utcnow(), "acquired_by": self.actor, "notes": notes}
        row["id"] = self.store.insert("evidence", row)
        self.log("evidence.acquire", case_id, row["id"], label=row["label"], path=path, kind=kind, size=size,
                 sha256=hashes["sha256"], md5=hashes["md5"], access="read-only (O_RDONLY)")
        return row

    def make_working_copy(self, evidence_id: int, dest_dir: str | None = None,
                          ctx: JobContext = NULL_CONTEXT) -> dict:
        ev = self.get_evidence(evidence_id)
        if ev["kind"] == "device":
            raise SafetyError("Image the device first (working copies are made from image files)")
        dest_dir = Path(dest_dir or self.case_dir(ev["case_id"]) / "working")
        dest_dir.mkdir(parents=True, exist_ok=True)
        stem, ext = os.path.splitext(os.path.basename(ev["path"]))
        n = len(list(dest_dir.glob(f"{stem}_copy*"))) + 1
        dest = dest_dir / f"{stem}_copy{n}{ext or '.img'}"
        h = {a: hashlib.new(a) for a in ("sha256", "md5")}
        with EvidenceSource(ev["path"]) as src, open(dest, "xb") as out:
            done = 0
            while done < src.size:
                ctx.check()
                b = src.read(done, 4 << 20)
                out.write(b)
                for x in h.values():
                    x.update(b)
                done += len(b)
                ctx.progress(done / src.size, f"Copying {done >> 20}/{src.size >> 20} MiB")
            out.flush()
            os.fsync(out.fileno())
        copy_hash = hash_file(dest, ("sha256",))["sha256"]
        src_hash = h["sha256"].hexdigest()
        match = copy_hash == src_hash == ev["sha256"]
        row = {"case_id": ev["case_id"], "label": f"{ev['label']} (working copy {n})", "path": str(dest),
               "kind": "working-copy", "parent_id": evidence_id, "size": os.path.getsize(dest), "sha256": copy_hash,
               "md5": h["md5"].hexdigest(), "media_profile": ev["media_profile"], "acquired_at": utcnow(),
               "acquired_by": self.actor, "notes": ""}
        row["id"] = self.store.insert("evidence", row)
        self.log("evidence.copy", ev["case_id"], row["id"], source_id=evidence_id, copy_id=row["id"], path=str(dest),
                 source_sha256=ev["sha256"], copy_sha256=copy_hash, hash_match=match)
        if not match:
            raise RuntimeError("working copy hash does not match the original — copy rejected")
        return row

    def verify_evidence(self, evidence_id: int, ctx: JobContext = NULL_CONTEXT) -> dict:
        """Re-hash an evidence item and compare with the acquisition hash."""
        ev = self.get_evidence(evidence_id)
        with EvidenceSource(ev["path"], advanced=self.settings.advanced_device_access) as src:
            h = hash_reader(src.read, src.size, ("sha256", "md5"), ctx, label="Verifying")
        match = h["sha256"] == ev["sha256"] and h["md5"] == ev["md5"]
        if ev.get("sanitized"):
            match = None  # sanitized copies are expected to differ
        self.log("evidence.verify", ev["case_id"], evidence_id, sha256=h["sha256"], md5=h["md5"],
                 acquisition_sha256=ev["sha256"], match=match)
        return {"evidence": ev, "hashes": h, "match": match}

    def get_evidence(self, evidence_id: int) -> dict:
        ev = self.store.one("SELECT * FROM evidence WHERE id=?", (evidence_id,))
        if not ev:
            raise KeyError(f"evidence #{evidence_id} not found")
        return ev

    def list_evidence(self, case_id: str) -> list[dict]:
        return self.store.query("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,))

    def original_paths(self) -> list[str]:
        return [r["path"] for r in self.store.query("SELECT path FROM evidence WHERE kind IN ('original','device')")]

    # ------------------------------------------------------------------ recovery
    def run_recovery(self, evidence_id: int, options: RecoveryOptions | None = None,
                     ctx: JobContext = NULL_CONTEXT) -> dict:
        ev = self.get_evidence(evidence_id)
        opts = options or RecoveryOptions()
        run_id = self.store.insert("recovery_runs", {"case_id": ev["case_id"], "evidence_id": evidence_id,
                                                     "started_at": utcnow(), "options": opts.to_dict(),
                                                     "status": "running"})
        out_dir = self.case_dir(ev["case_id"]) / "recovery" / f"run-{run_id:03d}"
        try:
            with EvidenceSource(ev["path"], advanced=self.settings.advanced_device_access) as src:
                pre = hash_reader(src.read, src.size, ("sha256", "md5"), ctx.sub(0, 0.08), label="Pre-recovery hash")
                self.log("recovery.start", ev["case_id"], evidence_id, run_id=run_id, pre_sha256=pre["sha256"],
                         pre_md5=pre["md5"], options=opts.to_dict(), access="read-only")
                result = RecoveryEngine(opts).run(src, out_dir, ctx.sub(0.08, 0.92))
                post = hash_reader(src.read, src.size, ("sha256", "md5"), ctx.sub(0.92, 1.0), label="Post-recovery hash")
        except Exception as exc:
            self.store.update("recovery_runs", "id", run_id, {"status": f"failed: {exc}", "finished_at": utcnow()})
            self.log("recovery.failed", ev["case_id"], evidence_id, run_id=run_id, error=str(exc))
            raise
        unchanged = pre == post
        for it in result.items:
            r = it.to_row()
            self.store.insert("recovered_files", {
                "run_id": run_id, "case_id": ev["case_id"], "evidence_id": evidence_id, "item_id": r["item_id"],
                "source": r["source"], "name": r["name"], "path": r["path"], "offset": r["offset"], "size": r["size"],
                "deleted": int(r["deleted"]), "detected_type": r["detected_type"], "mime": r["mime"],
                "claimed_ext": r["claimed_ext"], "ext_mismatch": int(r["ext_mismatch"]),
                "validation_status": r["validation_status"], "confidence": r["confidence"],
                "fragmentation": r["fragmentation"], "sha256": r["sha256"], "md5": r["md5"],
                "output_path": r["output_path"], "thumbnail_path": r["thumbnail_path"],
                "superseded_by": r["superseded_by"], "detail": r})
        manifest = [{"item": i.item_id, "name": i.name, "sha256": i.hashes["sha256"]} for i in result.items]
        (out_dir / "manifest.json").write_text(json.dumps({"run_id": run_id, "evidence": ev["path"],
                                                           "pre": pre, "post": post, "files": manifest}, indent=2))
        stats = {**result.stats, "warnings": result.warnings}
        self.store.update("recovery_runs", "id", run_id, {
            "finished_at": utcnow(), "stats": stats, "partitions": result.partitions, "out_dir": str(out_dir),
            "pre_sha256": pre["sha256"], "post_sha256": post["sha256"], "source_unchanged": int(unchanged),
            "status": "complete"})
        self.log("recovery.complete", ev["case_id"], evidence_id, run_id=run_id, stats=result.stats,
                 pre_sha256=pre["sha256"], post_sha256=post["sha256"], source_unchanged=unchanged,
                 files_merkle_root=merkle_root([m["sha256"] for m in manifest]), files=manifest[:500])
        return self.get_run(run_id)

    def get_run(self, run_id: int) -> dict:
        r = self.store.one("SELECT * FROM recovery_runs WHERE id=?", (run_id,))
        for k in ("options", "stats", "partitions"):
            if r and r.get(k):
                r[k] = json.loads(r[k])
        return r

    def list_runs(self, case_id: str) -> list[dict]:
        return [self.get_run(r["id"]) for r in
                self.store.query("SELECT id FROM recovery_runs WHERE case_id=? ORDER BY id", (case_id,))]

    def recovered_files(self, run_id: int | None = None, case_id: str | None = None) -> list[dict]:
        if run_id is not None:
            rows = self.store.query("SELECT * FROM recovered_files WHERE run_id=? ORDER BY item_id", (run_id,))
        else:
            rows = self.store.query("SELECT * FROM recovered_files WHERE case_id=? ORDER BY run_id, item_id", (case_id,))
        for r in rows:
            r["detail"] = json.loads(r["detail"]) if r.get("detail") else {}
        return rows

    def export_files(self, file_ids: list[int], dest: str, ctx: JobContext = NULL_CONTEXT) -> list[dict]:
        dest_p = Path(dest)
        dest_p.mkdir(parents=True, exist_ok=True)
        out, case_id = [], None
        for i, fid in enumerate(file_ids):
            r = self.store.one("SELECT * FROM recovered_files WHERE id=?", (fid,))
            case_id = r["case_id"]
            target = dest_p / os.path.basename(r["output_path"])
            shutil.copy2(r["output_path"], target)
            h = hash_file(target)
            out.append({"file_id": fid, "name": r["name"], "path": str(target), "sha256": h["sha256"], "md5": h["md5"],
                        "verified": h["sha256"] == r["sha256"]})
            ctx.progress((i + 1) / len(file_ids), f"Exported {r['name']}")
        self.log("file.export", case_id, count=len(out), destination=str(dest_p), files=out)
        return out

    # ------------------------------------------------------------------ sanitization
    def _prepare_sanitize(self, req: Request, evidence_id, case_id):
        req.protected_paths = self.original_paths()
        req.advanced = self.settings.advanced_device_access
        req.operator = self.operator
        ev = self.get_evidence(evidence_id) if evidence_id else None
        return ev, case_id or (ev["case_id"] if ev else None)

    def begin_sanitize_confirmation(self, req: Request, *, evidence_id: int | None = None,
                                    case_id: str | None = None) -> ConfirmationSession:
        """Start the mandatory two-step confirmation for a destructive sanitization.

        Safety gates run first, so a refused target (original evidence, system disk, ...) never
        reaches the confirmation dialog. Every step of the session is written to the ledger."""
        _, case_id = self._prepare_sanitize(req, evidence_id, case_id)
        _, _, length, device = SanitizeEngine().resolve(req)
        return ConfirmationSession(
            req, build_summary(req, length, device), operator=self.actor,
            audit=lambda action, **d: self.log(action, case_id, evidence_id, **d))

    def sanitize(self, req: Request, *, evidence_id: int | None = None, case_id: str | None = None,
                 ctx: JobContext = NULL_CONTEXT, authorization: ErasureAuthorization | None = None) -> dict:
        ev, case_id = self._prepare_sanitize(req, evidence_id, case_id)
        t = req.target
        tdesc = t.label or (f"{t.kind}:{os.path.basename(t.path)}" + (f"@{t.offset}" if t.kind == "partition" else ""))
        engine = SanitizeEngine()
        if not req.dry_run:
            try:
                if not isinstance(authorization, ErasureAuthorization):
                    raise ConfirmationRequired("Erase refused: two-step confirmation (Yes, then typed CONFIRM) "
                                               "is required before any data is destroyed")
                authorization.check(req)
            except ConfirmationRequired as e:
                self.log("sanitize.aborted", case_id, evidence_id, stage="engine", target=tdesc, method=req.method,
                         reason=str(e), summary=f"erase refused: {e}")
                raise
        engine.resolve(req)  # safety gates before anything is logged as started
        if not req.dry_run:
            self.log("sanitize.start", case_id, evidence_id, method=req.method, target=tdesc, path=t.path,
                     offset=t.offset, length=t.length, verify_mode=req.verify_mode, media_profile=req.media_profile,
                     confirmation_id=authorization.session_id, summary="job started after two-step confirmation")
        res = engine.run(req, ctx, authorization=authorization)
        rd = res.to_dict()
        summary = ("dry run — no data written" if res.dry_run else
                   f"{res.bytes_written:,} bytes written; verification {'PASSED' if res.success else 'FAILED'}")
        action = "sanitize.dry_run" if res.dry_run else "sanitize.complete"
        self.log(action, case_id, evidence_id, method=req.method, target=tdesc, nist_category=res.nist_category,
                 simulated=res.simulated, bytes_written=res.bytes_written, pre_sha256=res.pre_sha256,
                 post_sha256=res.post_sha256, summary=summary, plan=res.plan)
        ver_entry = None
        if not res.dry_run:
            ver_entry = self.log("sanitize.verify", case_id, evidence_id, method=req.method, target=tdesc,
                                 summary=f"verification {'PASSED' if res.success else 'FAILED'}",
                                 verification=res.verification)
        media = {"path": os.path.abspath(t.path), "label": ev["label"] if ev else os.path.basename(t.path),
                 "media_profile": req.media_profile, "scope": t.kind + (f" (partition at offset {t.offset}, "
                                                                        f"{t.length:,} bytes)" if t.kind == "partition" else ""),
                 "model": (res.device or {}).get("model", ""), "serial": (res.device or {}).get("serial", ""),
                 "evidence_id": evidence_id}
        case = self.get_case(case_id) if case_id else None
        cert = certificate.build(rd, media=media, operator=self.operator, case=case,
                                 ledger_seq=ver_entry["seq"] if ver_entry else None, signer=self.signer)
        cdir = (self.case_dir(case_id) if case_id else self.home) / "certificates"
        jp, pp = certificate.write(cert, cdir)
        self.log("certificate.issue", case_id, evidence_id, certificate_id=cert["certificate_id"], result=cert["result"],
                 json_path=str(jp), pdf_path=str(pp), json_sha256=hash_file(jp, ("sha256",))["sha256"],
                 pdf_sha256=hash_file(pp, ("sha256",))["sha256"], payload_sha256=cert["signature"]["payload_sha256"])
        self.store.insert("sanitizations", {
            "case_id": case_id, "evidence_id": evidence_id, "target": {"kind": t.kind, "path": t.path, "offset": t.offset,
                                                                       "length": t.length, "paths": t.paths},
            "method": req.method, "nist_category": res.nist_category, "started_at": res.started,
            "finished_at": res.finished, "result": cert["result"], "verification": res.verification,
            "certificate_id": cert["certificate_id"], "certificate_json": str(jp), "certificate_pdf": str(pp),
            "operator": self.actor, "dry_run": int(res.dry_run)})
        if ev and not res.dry_run and res.success and t.kind == "image":
            self.store.update("evidence", "id", evidence_id, {"sanitized": 1})
        return {"result": rd, "certificate": cert, "certificate_json": str(jp), "certificate_pdf": str(pp)}

    def sanitizations(self, case_id: str | None = None) -> list[dict]:
        rows = self.store.query("SELECT * FROM sanitizations" + (" WHERE case_id=?" if case_id else "") +
                                " ORDER BY id", (case_id,) if case_id else ())
        for r in rows:
            for k in ("target", "verification"):
                r[k] = json.loads(r[k]) if r.get(k) else {}
        return rows

    # ------------------------------------------------------------------ ledger
    def verify_ledger(self, anchor: dict | None = None, record: bool = True):
        rep = self.ledger.verify(anchor)
        if record:
            self.log("ledger.verify", None, ok=rep.ok, entries=rep.entries, head_hash=rep.head_hash,
                     tampered=rep.tampered_seqs, issues=[i.__dict__ for i in rep.issues][:50])
        return rep

    def export_anchor(self, path: str | None = None) -> tuple[dict, str]:
        anchor = self.ledger.build_anchor()
        p = Path(path) if path else self.home / "anchors" / f"anchor-{anchor['head_seq']:06d}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(anchor, indent=2))
        self.store.insert("anchors", {"seq": anchor["head_seq"], "head_hash": anchor["head_hash"],
                                      "merkle_root": anchor["merkle_root"], "exported_at": anchor["exported_at"],
                                      "path": str(p)})
        self.log("ledger.anchor", None, head_seq=anchor["head_seq"], head_hash=anchor["head_hash"],
                 merkle_root=anchor["merkle_root"], path=str(p))
        return anchor, str(p)

    # ------------------------------------------------------------------ reports & stats
    def generate_report(self, case_id: str, out_dir: str | None = None) -> dict:
        from .reports import build_report
        out = Path(out_dir) if out_dir else self.case_dir(case_id) / "reports"
        rep = build_report(self, case_id, out)
        self.log("report.generate", case_id, report_id=rep["report_id"], pdf=rep["pdf"], html=rep["html"],
                 pdf_sha256=hash_file(rep["pdf"], ("sha256",))["sha256"],
                 html_sha256=hash_file(rep["html"], ("sha256",))["sha256"], ledger_ok=rep["ledger_ok"])
        return rep

    def stats(self) -> dict:
        q = lambda sql: (self.store.one(sql) or {"n": 0})["n"]  # noqa: E731
        return {"cases": q("SELECT COUNT(*) n FROM cases"), "evidence": q("SELECT COUNT(*) n FROM evidence"),
                "recovered": q("SELECT COUNT(*) n FROM recovered_files WHERE superseded_by IS NULL"),
                "intact": q("SELECT COUNT(*) n FROM recovered_files WHERE superseded_by IS NULL AND validation_status='intact'"),
                "sanitizations": q("SELECT COUNT(*) n FROM sanitizations WHERE dry_run=0"),
                "ledger_entries": q("SELECT COUNT(*) n FROM ledger")}

    def close(self):
        self.store.close()


def is_device(path: str) -> bool:
    return is_device_path(path)
