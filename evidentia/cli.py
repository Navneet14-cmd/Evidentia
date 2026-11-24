"""Evidentia command-line interface (headless counterpart of the GUI)."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

from .core.jobs import JobContext


def _ctx(quiet=False) -> JobContext:
    last = [0.0]

    def prog(f, msg):
        if quiet or time.time() - last[0] < 0.1 and f < 1:
            return
        last[0] = time.time()
        bar = "█" * int(f * 30)
        sys.stderr.write(f"\r  [{bar:<30}] {f * 100:5.1f}% {msg[:60]:<60}")
        if f >= 1:
            sys.stderr.write("\n")
        sys.stderr.flush()
    return JobContext(prog, lambda m: None)


def _svc(args):
    from .forensic.service import Evidentia
    svc = Evidentia(args.home)
    if args.advanced:
        svc.settings.advanced_device_access = True
    if args.examiner:
        svc.settings.examiner_name = args.examiner
    return svc


def cmd_devices(args):
    from .core.devices import list_devices
    devs = list_devices()
    if not devs:
        print("No devices found (or device enumeration unsupported on this platform).")
    for d in devs:
        status = "ALLOWED" if d.allowed else "REFUSED: " + "; ".join(d.refusal_reasons())
        print(f"{d.name:10s} {d.media_type:5s} {d.size / 1e9:8.1f} GB  {d.model[:28]:28s} {status}")


def cmd_case(args):
    svc = _svc(args)
    if args.action == "new":
        c = svc.create_case(args.title, args.description or "")
        print(c["id"])
    else:
        for c in svc.list_cases():
            print(f"{c['id']}  {c['title']}  ({c['evidence_count']} evidence)  {c['created_at'][:19]}")


def cmd_evidence(args):
    svc = _svc(args)
    if args.action == "add":
        ev = svc.add_evidence(args.case, args.path, args.label, ctx=_ctx())
        print(f"evidence #{ev['id']} sha256={ev['sha256']}")
    elif args.action == "copy":
        ev = svc.make_working_copy(int(args.case), ctx=_ctx())
        print(f"working copy #{ev['id']} {ev['path']} sha256={ev['sha256']}")
    else:
        for e in svc.list_evidence(args.case):
            print(f"#{e['id']} {e['kind']:12s} {e['label']}  {e['sha256']}")


def cmd_recover(args):
    from .recovery.engine import RecoveryOptions
    if args.signatures:
        from .recovery.signatures import load_json
        print("loaded signatures:", ", ".join(s.name for s in load_json(args.signatures)))
    svc = _svc(args)
    run = svc.run_recovery(args.evidence, RecoveryOptions(filesystem=not args.no_fs, carving=not args.no_carve,
                                                          reconstruct=not args.no_reconstruct,
                                                          unallocated_only=not args.all_space,
                                                          include_allocated=args.include_allocated), _ctx())
    _print_run(svc, run)


def _print_run(svc, run):
    print(f"run #{run['id']}: {run['stats']}  source unchanged: {bool(run['source_unchanged'])}")
    for f in svc.recovered_files(run["id"]):
        if f["superseded_by"]:
            continue
        mm = " EXT-MISMATCH" if f["ext_mismatch"] else ""
        print(f"  {f['confidence']:3d}  {f['validation_status']:8s} {f['detected_type']:5s} {f['source']:13s} "
              f"{f['name'][:30]:30s} {f['sha256'][:16]}{mm}")


def cmd_report(args):
    svc = _svc(args)
    r = svc.generate_report(args.case)
    print(f"PDF:  {r['pdf']}\nHTML: {r['html']}\nledger ok: {r['ledger_ok']}")


def confirm_interactively(session, input_fn=None, out=print) -> bool:
    """CLI front-end for the two-step confirmation: y/N (default N), then type CONFIRM.

    EOF / Ctrl-C at either prompt count as Cancel. The session (core) decides what passes."""
    from .sanitize.confirmation import summary_text
    input_fn = input_fn or input
    s = session.show()
    out("\n" + "=" * 64 + "\n  ERASE CONFIRMATION (step 1 of 2)\n" + "=" * 64)
    out(summary_text(s))
    out(f"\n  !! {s['warning']}\n")
    try:
        ans = input_fn("Proceed with this erase? [y/N]: ")
    except (EOFError, KeyboardInterrupt):
        ans = None
    if not session.answer(ans is not None and ans.strip().lower() in ("y", "yes")):
        out("Cancelled. Nothing was erased.")
        return False
    out("\n  Step 2 of 2: typed confirmation (case-sensitive).")
    try:
        typed = input_fn("Type CONFIRM to proceed: ")
    except (EOFError, KeyboardInterrupt):
        typed = None
    if not session.submit(typed):
        out("Confirmation " + ("cancelled" if typed is None else "text did not match") + ". Nothing was erased.")
        return False
    return True


def cmd_sanitize(args):
    from .sanitize.engine import Request, Target, image_partitions
    svc = _svc(args)
    off, length = 0, None
    if args.target == "partition":
        parts = image_partitions(args.path)
        p = parts[args.partition]
        off, length = p["offset"], p["length"]
    t = Target(args.target, args.path, off, length, paths=args.paths or [])
    req = Request(t, args.method, media_profile=args.profile, verify_mode=args.verify,
                  sample_percent=args.sample, dry_run=not args.execute, confirm=args.confirm or "")
    auth = None
    if args.execute:
        session = svc.begin_sanitize_confirmation(req, evidence_id=args.evidence, case_id=args.case)
        if not confirm_interactively(session):
            return 1
        auth = session.authorization
    out = svc.sanitize(req, evidence_id=args.evidence, case_id=args.case, ctx=_ctx(), authorization=auth)
    r = out["result"]
    for line in r["plan"]:
        print("  " + line)
    for w in r["warnings"]:
        print("  ! " + w)
    print(f"result: {out['certificate']['result']}  verification: {r['verification'].get('passed')}")
    print(f"certificate: {out['certificate_pdf']}\n             {out['certificate_json']}")


def cmd_verify_ledger(args):
    svc = _svc(args)
    anchor = json.loads(Path(args.anchor).read_text()) if args.anchor else None
    rep = svc.verify_ledger(anchor)
    print(f"ledger {'OK' if rep.ok else 'TAMPERED'}: {rep.entries} entries, head #{rep.head_seq} {rep.head_hash}")
    for i in rep.issues:
        print(f"  #{i.seq} {i.kind}: {i.message}")
    return 0 if rep.ok else 2


def cmd_anchor(args):
    svc = _svc(args)
    a, p = svc.export_anchor(args.out)
    print(f"anchor written to {p}\n  head #{a['head_seq']} {a['head_hash']}\n  merkle root {a['merkle_root']}")


def cmd_verify_cert(args):
    from .sanitize.certificate import verify
    ok, why = verify(json.loads(Path(args.file).read_text()))
    print(("VALID: " if ok else "INVALID: ") + why)
    return 0 if ok else 2


def cmd_make_images(args):
    from .testdata.generator import generate
    meta = generate(args.out)
    for k, v in meta["images"].items():
        print(f"  {k:9s} {v}")
    for n in meta["notes"]:
        print("  note:", n)


def cmd_demo(args):
    """Full judge flow: case -> recovery -> report -> sanitize copy -> verify -> certificate -> ledger."""
    from .recovery.engine import RecoveryOptions
    from .sanitize.engine import Request, Target
    from .testdata.generator import generate
    home = Path(args.home or "demo_workspace")
    if args.fresh and home.exists():
        shutil.rmtree(home)
    images = Path(args.images or "test_images")
    if not (images / "fat32.img").exists():
        print(f"[1/9] generating test images in {images}")
        generate(images)
    args.home = str(home)
    svc = _svc(args)
    if not svc.settings.examiner_name:
        svc.settings.examiner_name, svc.settings.examiner_org, svc.settings.examiner_id = \
            "Demo Examiner", "SIH 26149 Forensics Lab", "EX-001"
        svc.save_settings()
    step = lambda n, s: print(f"\n[{n}/9] {s}")  # noqa: E731
    step(1, "Create case")
    case = svc.create_case("Laptop seizure — suspected data exfiltration",
                           "Demo case for SIH 26149: recover deleted files, then sanitize a working copy.")
    print("  ", case["id"])
    step(2, "Acquire evidence (read-only, SHA-256 + MD5)")
    ev = svc.add_evidence(case["id"], str(images / "fat32.img"), "Seized USB stick (FAT32 image)", ctx=_ctx())
    print(f"   evidence #{ev['id']} sha256 {ev['sha256']}")
    svc.add_note(case["id"], "Image received sealed; bag #A-1137. Hash verified against acquisition log.")
    step(3, "Recover deleted files (file-system + carving + reconstruction)")
    run = svc.run_recovery(ev["id"], RecoveryOptions(), _ctx())
    _print_run(svc, run)
    files = [f for f in svc.recovered_files(run["id"]) if not f["superseded_by"]]
    exp = svc.export_files([f["id"] for f in files if f["confidence"] >= 80][:5], str(svc.case_dir(case["id"]) / "export"))
    print(f"   exported {len(exp)} high-confidence files (hash-verified: {all(e['verified'] for e in exp)})")
    step(4, "Generate case report (PDF + HTML)")
    rep = svc.generate_report(case["id"])
    print(f"   {rep['pdf']}\n   {rep['html']}")
    step(5, "Make a hash-verified working copy for sanitization")
    copy = svc.make_working_copy(ev["id"], ctx=_ctx())
    print(f"   {copy['path']}")
    step(6, "Dry run, then sanitize the copy (Clear: random pass, full verification)")
    t = Target("image", copy["path"])
    dry = svc.sanitize(Request(t, "clear-random", verify_mode="full", dry_run=True), evidence_id=copy["id"])
    for line in dry["result"]["plan"]:
        print("   " + line)
    req = Request(t, "clear-random", verify_mode="full", dry_run=False)
    session = svc.begin_sanitize_confirmation(req, evidence_id=copy["id"])
    if not confirm_interactively(session):
        print("   demo stopped at the erase confirmation (the working copy was left intact)")
        return 1
    out = svc.sanitize(req, evidence_id=copy["id"], ctx=_ctx(), authorization=session.authorization)
    v = out["result"]["verification"]
    step(7, "Verify erasure")
    print(f"   {v['blocks_checked']}/{v['blocks_total']} blocks read back, {v['mismatched_blocks']} mismatches -> "
          f"{'PASS' if v['passed'] else 'FAIL'}")
    from .core.source import EvidenceSource
    from .recovery.engine import RecoveryEngine
    with EvidenceSource(copy["path"]) as src:
        leftover = RecoveryEngine(RecoveryOptions()).run(src, svc.home / "tmp-residual")
    shutil.rmtree(svc.home / "tmp-residual", ignore_errors=True)
    print(f"   residual recovery attempt on the erased copy: {leftover.stats['total']} files recoverable")
    step(8, "Signed certificate (PDF + JSON, Ed25519)")
    from .sanitize.certificate import verify
    print(f"   {out['certificate_pdf']}\n   signature: {verify(out['certificate'])[1]}")
    step(9, "Verify the audit ledger + export chain head for anchoring")
    rep2 = svc.verify_ledger()
    print(f"   ledger {'OK' if rep2.ok else 'TAMPERED'} — {rep2.entries} entries, head {rep2.head_hash[:24]}…")
    a, p = svc.export_anchor()
    print(f"   anchor: {p}")
    rep3 = svc.generate_report(case["id"])
    print(f"\nFinal report: {rep3['pdf']}\nWorkspace: {svc.home.resolve()}")
    print("Open it in the GUI with:  EVIDENTIA_HOME=" + str(svc.home.resolve()) + " python -m evidentia")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="evidentia", description="Evidentia forensic recovery & sanitization (CLI)")
    ap.add_argument("--home", default=os.environ.get("EVIDENTIA_HOME"), help="workspace directory (default ~/.evidentia)")
    ap.add_argument("--advanced", action="store_true", help="allow physical device access (still refuses system/mounted disks)")
    ap.add_argument("--examiner", help="examiner name recorded in the ledger")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("devices", help="list physical disks and their safety status").set_defaults(fn=cmd_devices)
    p = sub.add_parser("case")
    p.add_argument("action", choices=["new", "list"])
    p.add_argument("--title", default="Untitled case")
    p.add_argument("--description")
    p.set_defaults(fn=cmd_case)
    p = sub.add_parser("evidence", help="evidence add CASE PATH | evidence copy EVIDENCE_ID | evidence list CASE")
    p.add_argument("action", choices=["add", "copy", "list"])
    p.add_argument("case")
    p.add_argument("path", nargs="?")
    p.add_argument("--label")
    p.set_defaults(fn=cmd_evidence)
    p = sub.add_parser("recover")
    p.add_argument("evidence", type=int)
    for f in ("--no-fs", "--no-carve", "--no-reconstruct", "--all-space", "--include-allocated"):
        p.add_argument(f, action="store_true")
    p.add_argument("--signatures", help="JSON file with extra carving signatures (see docs/custom_signatures.example.json)")
    p.set_defaults(fn=cmd_recover)
    p = sub.add_parser("report")
    p.add_argument("case")
    p.set_defaults(fn=cmd_report)
    p = sub.add_parser("sanitize", help="dry run unless --execute is given")
    p.add_argument("--target", choices=["image", "partition", "files", "device"], default="image")
    p.add_argument("--path", required=True)
    p.add_argument("--paths", nargs="*", help="files/folders for --target files")
    p.add_argument("--partition", type=int, default=0)
    from .sanitize.media import METHODS, PROFILES
    p.add_argument("--method", choices=list(METHODS), default="clear-zero")
    p.add_argument("--profile", choices=list(PROFILES), default="image")
    p.add_argument("--verify", choices=["sample", "full"], default="sample")
    p.add_argument("--sample", type=float, default=10.0)
    p.add_argument("--execute", action="store_true", help="actually write (default is a dry run)")
    p.add_argument("--confirm", help="physical devices only: the device name (e.g. disk4). The interactive y/N + CONFIRM prompts are always required")
    p.add_argument("--evidence", type=int)
    p.add_argument("--case")
    p.set_defaults(fn=cmd_sanitize)
    p = sub.add_parser("verify-ledger")
    p.add_argument("--anchor")
    p.set_defaults(fn=cmd_verify_ledger)
    p = sub.add_parser("anchor")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_anchor)
    p = sub.add_parser("verify-cert")
    p.add_argument("file")
    p.set_defaults(fn=cmd_verify_cert)
    p = sub.add_parser("make-images")
    p.add_argument("out", nargs="?", default="test_images")
    p.set_defaults(fn=cmd_make_images)
    p = sub.add_parser("demo", help="run the full end-to-end demo flow")
    p.add_argument("--images")
    p.add_argument("--fresh", action="store_true", help="delete the demo workspace first")
    p.set_defaults(fn=cmd_demo)
    args = ap.parse_args(argv)
    try:
        return args.fn(args) or 0
    except Exception as exc:  # noqa: BLE001
        from .core.devices import SafetyError
        if isinstance(exc, SafetyError):
            print(f"SAFETY: {exc}", file=sys.stderr)
            return 3
        raise


if __name__ == "__main__":
    sys.exit(main())
