"""Sanitization engine: target resolution, safety gates, overwrite / (simulated) purge,
read-back verification and a result record used for the certificate and the ledger."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..core.devices import (SafetyError, assert_device_allowed, assert_safe_host_path, confirm_device_name,
                            is_device_path)
from ..core.entropy import shannon_entropy
from ..core.hashing import hash_reader
from ..core.jobs import JobContext, NULL_CONTEXT
from ..recovery.signatures import SIGS
from . import purge
from .confirmation import ErasureAuthorization, require_authorization
from .media import METHODS, method_warning
from .patterns import ConstPattern, CryptoEraseSim, Pattern, RandomPattern

BLOCK = 1 << 20
_HEADERS = re.compile(b"|".join(s.header for s in SIGS.values()), re.DOTALL)


@dataclass
class Target:
    kind: str                       # image | partition | files | device
    path: str                       # image/device path, or a file/folder
    offset: int = 0
    length: int | None = None       # None = to end of image/device
    label: str = ""
    partition: dict | None = None
    paths: list[str] = field(default_factory=list)   # for kind=files (files and/or folders)

    @property
    def device_name(self) -> str:
        """Physical devices additionally require the operator to type the device name (e.g. disk4)."""
        from ..core.devices import whole_disk_name
        return whole_disk_name(self.path)


@dataclass
class Request:
    target: Target
    method: str
    media_profile: str = "image"
    verify_mode: str = "sample"     # sample | full
    sample_percent: float = 10.0
    dry_run: bool = True
    confirm: str = ""               # physical devices only: the typed device name (e.g. disk4)
    advanced: bool = False
    operator: dict = field(default_factory=dict)
    protected_paths: list[str] = field(default_factory=list)  # e.g. original evidence


@dataclass
class Result:
    job_id: str
    request: dict
    method: dict
    nist_category: str
    simulated: bool
    dry_run: bool
    started: str
    finished: str = ""
    duration_s: float = 0.0
    bytes_target: int = 0
    bytes_written: int = 0
    passes: list[dict] = field(default_factory=list)
    verification: dict = field(default_factory=dict)
    pre_sha256: str | None = None
    post_sha256: str | None = None
    files: list[dict] = field(default_factory=list)
    commands: list[list[str]] = field(default_factory=list)
    command_results: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)
    device: dict | None = None
    success: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _now() -> str:
    from ..forensic.db import utcnow
    return utcnow()


def _pattern(name: str) -> Pattern:
    return {"zero": lambda: ConstPattern(0), "ones": lambda: ConstPattern(0xFF), "random": RandomPattern}[name]()


def _open_rw(path: str) -> int:
    fd = os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0))
    return fd


def _nocache(fd: int) -> None:
    """Make verification reads come from the medium, not the page cache (best effort)."""
    try:
        if sys.platform == "darwin":
            import fcntl
            fcntl.fcntl(fd, 48, 1)  # F_NOCACHE
        elif hasattr(os, "posix_fadvise"):
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    except OSError:
        pass


def _pread(fd, n, off):
    if hasattr(os, "pread"):
        return os.pread(fd, n, off)
    os.lseek(fd, off, 0)
    return os.read(fd, n)


def _pwrite(fd, data, off):
    if hasattr(os, "pwrite"):
        return os.pwrite(fd, data, off)
    os.lseek(fd, off, 0)
    return os.write(fd, data)


def _region_size(path: str) -> int:
    if is_device_path(path):
        from ..core.source import EvidenceSource
        fd = os.open(path, os.O_RDONLY)
        try:
            src = EvidenceSource.__new__(EvidenceSource)
            src.is_device, src._fd, src.path = True, fd, path
            return src._detect_size(os.fstat(fd))
        finally:
            os.close(fd)
    return os.path.getsize(path)


class SanitizeEngine:
    def resolve(self, req: Request) -> tuple[str, int, int, dict | None]:
        """Validate the target against the safety policy. Returns (path, offset, length, device)."""
        t = req.target
        if req.method not in METHODS:
            raise ValueError(f"unknown method {req.method}")
        real = os.path.realpath(t.path)
        for p in req.protected_paths:
            if p and os.path.exists(p) and os.path.realpath(p) == real:
                raise SafetyError("Refusing to sanitize ORIGINAL evidence. Create a working copy, or "
                                  "sanitize media that is not registered as an original.")
        device = None
        if t.kind == "device" or is_device_path(t.path):
            dev = assert_device_allowed(t.path, advanced=req.advanced, purpose="sanitize")
            device = dev.to_dict()
            if not req.dry_run:
                confirm_device_name(dev, req.confirm)
        elif t.kind == "files":
            for p in t.paths or [t.path]:
                assert_safe_host_path(p)
                if not os.path.exists(p):
                    raise SafetyError(f"{p} does not exist")
            return t.path, 0, 0, None
        else:
            if not os.path.isfile(t.path):
                raise SafetyError(f"{t.path} is not an image file")
        size = _region_size(t.path)
        length = t.length if t.length is not None else size - t.offset
        if t.offset < 0 or length <= 0 or t.offset + length > size:
            raise SafetyError("target region lies outside the medium")
        return t.path, t.offset, length, device

    # ------------------------------------------------------------------ main entry
    def run(self, req: Request, ctx: JobContext = NULL_CONTEXT, *,
            authorization: ErasureAuthorization | None = None) -> Result:
        """Execute a sanitization. Destructive runs (``dry_run=False``) require an authorization
        from a completed two-step :class:`~evidentia.sanitize.confirmation.ConfirmationSession`;
        it is checked before any safety resolution or I/O and consumed (single use)."""
        m = METHODS[req.method]
        if not req.dry_run:
            if not isinstance(authorization, ErasureAuthorization):
                require_authorization(req, authorization)  # raises ConfirmationRequired
            authorization.check(req)
        path, off, length, device = self.resolve(req)
        if not req.dry_run:
            require_authorization(req, authorization)  # consume only after the target passed safety checks
        simulated = m.technique != "overwrite" and not (device and not req.dry_run)
        cat = m.category
        res = Result(uuid.uuid4().hex, {**asdict(req), "confirm": "***"}, asdict(m), cat, simulated, req.dry_run,
                     _now(), bytes_target=length, device=device)
        w = method_warning(req.method, req.media_profile)
        if w:
            res.warnings.append(w)
            if m.technique == "overwrite" and req.media_profile in ("SSD", "NVMe", "USB"):
                res.nist_category = "Clear"
        if m.technique != "overwrite":
            res.commands = purge.commands(m.technique, device["path"] if device else "/dev/<device>")
        t0 = time.time()
        if req.target.kind == "files":
            return self._files(req, res, ctx, t0)
        res.plan = self._plan(req, m, path, off, length)
        if req.dry_run:
            res.finished, res.duration_s, res.success = _now(), round(time.time() - t0, 3), True
            res.verification = {"mode": "none", "passed": None, "note": "dry run: no data was written"}
            return res

        fd = _open_rw(path)
        try:
            pre_samples = self._sample_hashes(fd, off, length, req)
            if req.target.kind in ("image", "partition") and length <= (8 << 30):
                res.pre_sha256 = hash_reader(lambda o, n: _pread(fd, n, o), length, ("sha256",),
                                             ctx.sub(0, 0.1), offset=off, label="Pre-hash")["sha256"]
            body = ctx.sub(0.1, 0.8)
            if m.technique == "overwrite":
                patterns = [_pattern(p) for p in m.passes]
                for i, pat in enumerate(patterns):
                    pctx = body.sub(i / len(patterns), (i + 1) / len(patterns))
                    self._overwrite(fd, off, length, pat, pctx.sub(0, 0.75), f"Pass {i + 1}/{len(patterns)}")
                    v = self._verify(fd, off, length, pat, req, pctx.sub(0.75, 1.0))
                    res.passes.append({"pass": i + 1, "pattern": pat.describe(), "verified": v["passed"],
                                       "blocks_checked": v["blocks_checked"]})
                    res.bytes_written += length
                    if not v["passed"]:
                        break
                res.verification = v
            elif device and not req.dry_run:
                problems = purge.preflight(m.technique, device["path"])
                if problems:
                    raise SafetyError("Purge preflight failed: " + "; ".join(problems))
                res.command_results = purge.execute(m.technique, device["path"], ctx.log)
                res.verification = self._verify_purge(fd, off, length, m.technique, req, pre_samples, body)
            else:
                self._simulate_purge(fd, off, length, m.technique, body, res)
                res.verification = self._verify_purge(fd, off, length, m.technique, req, pre_samples,
                                                      ctx.sub(0.8, 0.9))
            if req.target.kind in ("image", "partition") and length <= (8 << 30):
                res.post_sha256 = hash_reader(lambda o, n: _pread(fd, n, o), length, ("sha256",),
                                              ctx.sub(0.9, 1.0), offset=off, label="Post-hash")["sha256"]
        finally:
            os.close(fd)
        res.finished = _now()
        res.duration_s = round(time.time() - t0, 3)
        res.success = bool(res.verification.get("passed"))
        ctx.progress(1.0, "Sanitization complete" if res.success else "Verification FAILED")
        return res

    # ------------------------------------------------------------------ helpers
    def _plan(self, req, m, path, off, length) -> list[str]:
        plan = [f"Target: {req.target.kind} {path} [offset {off}, {length:,} bytes]",
                f"Method: {m.label} — NIST SP 800-88 Rev. 2 category {m.category}"]
        if m.technique == "overwrite":
            plan += [f"Pass {i + 1}: write {p} over {length:,} bytes, then verify ({req.verify_mode})"
                     for i, p in enumerate(m.passes)]
        else:
            plan.append("Image target: firmware command simulated with an equivalent end state"
                        if req.target.kind != "device" else "Firmware commands: " +
                        " && ".join(" ".join(c) for c in purge.commands(m.technique, path)))
        plan.append(f"Verification: {req.verify_mode} read-back"
                    + (f" of {req.sample_percent:g}% of 1 MiB blocks" if req.verify_mode == "sample" else ""))
        return plan

    def _overwrite(self, fd, off, length, pat: Pattern, ctx: JobContext, label: str) -> None:
        done = 0
        while done < length:
            ctx.check()
            n = min(BLOCK, length - done)
            _pwrite(fd, pat.block(done, n), off + done)
            done += n
            if done % (16 * BLOCK) == 0 or done == length:
                ctx.progress(done / length, f"{label}: {pat.describe()} {done >> 20}/{length >> 20} MiB")
        os.fsync(fd)

    def _blocks(self, length: int, req: Request) -> list[int]:
        nblocks = -(-length // BLOCK)
        if req.verify_mode == "full":
            return list(range(nblocks))
        k = max(min(nblocks, 16), int(nblocks * req.sample_percent / 100))
        rng = secrets.SystemRandom()
        chosen = {0, nblocks - 1} | set(rng.sample(range(nblocks), min(k, nblocks)))
        return sorted(chosen)

    def _verify(self, fd, off, length, pat: Pattern, req: Request, ctx: JobContext) -> dict:
        _nocache(fd)
        blocks = self._blocks(length, req)
        bad, residual = [], 0
        for i, b in enumerate(blocks):
            ctx.check()
            o = b * BLOCK
            n = min(BLOCK, length - o)
            got = _pread(fd, n, off + o)
            if got != pat.block(o, n):
                bad.append(off + o)
            residual += len(_HEADERS.findall(got))
            if i % 32 == 0:
                ctx.progress(i / len(blocks), f"Verifying {i}/{len(blocks)} blocks")
        return {"mode": req.verify_mode, "sample_percent": req.sample_percent if req.verify_mode == "sample" else 100,
                "blocks_total": -(-length // BLOCK), "blocks_checked": len(blocks),
                "bytes_checked": sum(min(BLOCK, length - b * BLOCK) for b in blocks),
                "mismatched_blocks": len(bad), "first_mismatches": bad[:10], "expected_pattern": pat.describe(),
                "residual_signatures": residual if not isinstance(pat, RandomPattern) else None,
                "passed": not bad}

    def _sample_hashes(self, fd, off, length, req) -> dict[int, str]:
        blocks = self._blocks(length, Request(req.target, req.method, verify_mode="sample", sample_percent=2))
        return {b: hashlib.sha256(_pread(fd, min(BLOCK, length - b * BLOCK), off + b * BLOCK)).hexdigest()
                for b in blocks}

    def _simulate_purge(self, fd, off, length, technique: str, ctx: JobContext, res: Result) -> None:
        if technique in ("ata-secure-erase", "nvme-sanitize-block"):
            self._overwrite(fd, off, length, ConstPattern(0), ctx, "Simulated firmware erase")
            res.passes.append({"pass": 1, "pattern": "firmware erase (simulated as 0x00)", "verified": None})
        else:
            sim = CryptoEraseSim()
            done = 0
            while done < length:
                ctx.check()
                n = min(BLOCK, length - done)
                _pwrite(fd, sim.transform(done, _pread(fd, n, off + done)), off + done)
                done += n
                if done % (16 * BLOCK) == 0 or done == length:
                    ctx.progress(done / length, f"Simulated crypto-erase {done >> 20}/{length >> 20} MiB")
            os.fsync(fd)
            sim.destroy_key()
            res.passes.append({"pass": 1, "pattern": sim.name, "verified": None, "key_destroyed": True})
        res.bytes_written += length

    def _verify_purge(self, fd, off, length, technique, req, pre_samples, ctx) -> dict:
        _nocache(fd)
        blocks = self._blocks(length, req)
        bad, residual = [], 0
        for i, b in enumerate(blocks):
            ctx.check()
            n = min(BLOCK, length - b * BLOCK)
            got = _pread(fd, n, off + b * BLOCK)
            if technique in ("ata-secure-erase", "nvme-sanitize-block"):
                ok = got.count(0) == n or got.count(0xFF) == n
            else:
                prev = pre_samples.get(b)
                ok = shannon_entropy(got) > 7.5 and (prev is None or hashlib.sha256(got).hexdigest() != prev)
            if not ok:
                bad.append(off + b * BLOCK)
            residual += len(_HEADERS.findall(got)) if technique != "crypto-erase" else 0
            if i % 32 == 0:
                ctx.progress(i / len(blocks), f"Verifying {i}/{len(blocks)} blocks")
        crit = ("every sampled block is uniformly 0x00 or 0xFF" if technique in ("ata-secure-erase", "nvme-sanitize-block")
                else "every sampled block is high-entropy ciphertext differing from its pre-erase hash")
        return {"mode": req.verify_mode, "sample_percent": req.sample_percent if req.verify_mode == "sample" else 100,
                "blocks_total": -(-length // BLOCK), "blocks_checked": len(blocks), "mismatched_blocks": len(bad),
                "first_mismatches": bad[:10], "criterion": crit, "residual_signatures": residual, "passed": not bad}

    # ------------------------------------------------------------------ files & folders
    def _files(self, req: Request, res: Result, ctx: JobContext, t0: float) -> Result:
        m = METHODS[req.method]
        if m.technique != "overwrite":
            raise SafetyError("Purge methods apply to whole devices/images, not individual files")
        targets: list[Path] = []
        dirs: list[Path] = []
        for p in map(Path, req.target.paths or [req.target.path]):
            if p.is_symlink():
                continue
            if p.is_dir():
                for root, dnames, fnames in os.walk(p, followlinks=False):
                    targets += [Path(root) / f for f in fnames if not (Path(root) / f).is_symlink()]
                    dirs += [Path(root) / d for d in dnames]
                dirs.append(p)
            elif p.is_file():
                targets.append(p)
        res.bytes_target = sum(f.stat().st_size for f in targets)
        res.warnings.append("File-level overwrite is best-effort on journaling / copy-on-write file systems "
                            "(APFS, btrfs, ZFS, NTFS with shadow copies) and on SSDs: older copies of the data "
                            "may persist in snapshots or remapped blocks.")
        res.plan = [f"{len(targets)} file(s), {res.bytes_target:,} bytes, then remove {len(dirs)} folder(s)",
                    f"Each file: {' -> '.join(m.passes)} overwrite, full read-back, rename to random name, unlink"]
        if req.dry_run:
            res.files = [{"path": str(f), "size": f.stat().st_size} for f in targets]
            res.finished, res.success = _now(), True
            res.verification = {"mode": "none", "passed": None, "note": "dry run: no data was written"}
            return res
        all_ok = True
        for i, f in enumerate(targets):
            ctx.check()
            size = f.stat().st_size
            sha_before = hashlib.sha256(f.read_bytes()).hexdigest() if size <= (256 << 20) else None
            fd = _open_rw(str(f))
            ok = True
            try:
                for name in m.passes:
                    pat = _pattern(name)
                    if size:
                        self._overwrite(fd, 0, size, pat, NULL_CONTEXT, "file")
                        v = self._verify(fd, 0, size, pat, Request(req.target, req.method, verify_mode="full"),
                                         NULL_CONTEXT)
                        ok &= v["passed"]
            finally:
                os.close(fd)
            tmp = f.with_name(secrets.token_hex(8))
            os.replace(f, tmp)
            tmp.unlink()
            res.bytes_written += size * len(m.passes)
            res.files.append({"path": str(f), "size": size, "sha256_before": sha_before, "verified": ok, "removed": True})
            all_ok &= ok
            ctx.progress((i + 1) / max(1, len(targets)), f"Erased {f.name}")
        for d in sorted(set(dirs), key=lambda p: len(p.parts), reverse=True):
            try:
                d.rmdir()
            except OSError:
                pass
        res.verification = {"mode": "full", "files_verified": sum(x["verified"] for x in res.files),
                            "files_total": len(res.files), "passed": all_ok}
        res.finished, res.duration_s, res.success = _now(), round(time.time() - t0, 3), all_ok
        return res


def image_partitions(path: str) -> list[dict]:
    """Partitions inside an image (for partition-level sanitization)."""
    from ..core.source import EvidenceSource
    from ..recovery import fs_recovery
    with EvidenceSource(path) as src:
        scan = fs_recovery.scan(src, read_content=False) if fs_recovery.HAVE_TSK else None
    if not scan:
        return []
    return [{"index": p.index, "offset": p.offset, "length": p.length, "description": p.description,
             "fs_type": p.fs_type} for p in scan.partitions]
