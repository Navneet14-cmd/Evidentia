"""Generate forensic test images with known deleted, fragmented and corrupted files.

Outputs (in ``out_dir``):
  fat32.img      FAT32 volume built byte-by-byte (deleted, bifragmented, corrupted, orphaned files)
  ext4.img       ext4 volume via mke2fs -d + debugfs rm (if e2fsprogs is available)
  disk_mbr.img   MBR-partitioned disk containing both volumes (partition / volume-system demo)
  ntfs.img       NTFS volume (only if mkntfs + ntfscp from ntfs-3g are installed; live files only)
  manifest.json  ground truth: every planted file, its SHA-256, state and expected outcome
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from . import samples as S
from .fat32 import Fat32Image

E2FS_DIRS = ["/opt/homebrew/opt/e2fsprogs/sbin", "/usr/local/opt/e2fsprogs/sbin", "/usr/sbin", "/sbin"]


def _which(tool: str) -> str | None:
    found = shutil.which(tool)
    if found:
        return found
    for d in E2FS_DIRS:
        p = os.path.join(d, tool)
        if os.path.exists(p):
            return p
    return None


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _rec(manifest, image, path, data, state, ftype, offset=None, **extra):
    manifest.append({"image": image, "path": path, "type": ftype, "size": len(data), "sha256": _sha(data),
                     "md5": hashlib.md5(data).hexdigest(), "state": state, "offset": offset, **extra})


# ----------------------------------------------------------------------------- FAT32
def build_fat32(out: Path, manifest: list) -> Path:
    img = Fat32Image(72 * 1024 * 1024, sectors_per_cluster=2)
    cs = img.cluster_size
    rnd = random.Random(26149)
    dcim = img.mkdir(None, "DCIM")
    docs = img.mkdir(None, "Documents")
    vids = img.mkdir(None, "Videos")
    name = "fat32.img"

    def add(parent, pname, fname, data, state, ftype, deleted, **kw):
        node = img.add_file(parent, fname, data, deleted=deleted, **kw)
        _rec(manifest, name, f"{pname}/{fname}", data, state, ftype, img.offset(node.clusters[0]))
        return node

    # live (allocated) files
    add(dcim, "/DCIM", "IMG_0001.jpg", S.jpeg(1, "IMG_0001 - live"), "allocated", "jpeg", False)
    add(docs, "/Documents", "report.pdf", S.pdf("Quarterly Report", [S.text(3, 6).decode()]), "allocated", "pdf", False)
    add(docs, "/Documents", "budget.xlsx", S.xlsx(4, [["Item", "Cost"], ["Laptop", 1200], ["Drive", 90]]),
        "allocated", "xlsx", False)
    add(None, "", "readme.txt", S.text(5, 10), "allocated", "text", False)

    # deleted, contiguous, intact
    add(dcim, "/DCIM", "IMG_0002.jpg", S.jpeg(2, "IMG_0002 - deleted"), "deleted", "jpeg", True)
    add(docs, "/Documents", "contract.docx",
        S.docx(6, "Sale contract", ["Party A agrees to sell the asset.", "Signed 2026-10-30."]),
        "deleted", "docx", True)
    add(None, "", "photo_scan.png", S.png(7, "photo_scan.png"), "deleted", "png", True)
    add(None, "", "animation.gif", S.gif(8, "GIF"), "deleted", "gif", True)
    add(vids, "/Videos", "clip.mp4", S.mp4(9), "deleted", "mp4", True)
    add(docs, "/Documents", "minutes.pdf",
        S.pdf("Board Minutes", ["Decision: wipe old laptops per NIST SP 800-88.", S.text(10, 4).decode()]),
        "deleted", "pdf", True)
    add(docs, "/Documents", "todo.txt", S.text(11, 15), "deleted", "text", True)
    # extension mismatches (content-based classification must catch these)
    add(docs, "/Documents", "invoice.pdf", S.jpeg(12, "invoice.pdf is really a JPEG"), "deleted-mismatch", "jpeg", True)
    add(None, "", "notes.txt", S.pdf("Hidden notes", ["This PDF was renamed to .txt"]), "deleted-mismatch", "pdf", True)

    # deleted + bifragmented JPEG: head | live random filler | tail
    jpg = S.jpeg(13, "IMG_0003 - fragmented")
    n = img.clusters_for(len(jpg))
    head = img.alloc(n // 3)
    filler = rnd.randbytes(12 * cs)
    add(docs, "/Documents", "cache.bin", filler, "allocated", "data", False)
    tail = img.alloc(n - len(head))
    node = img.add_file(dcim, "IMG_0003.jpg", jpg, clusters=head + tail, deleted=True)
    _rec(manifest, name, "/DCIM/IMG_0003.jpg", jpg, "deleted-fragmented", "jpeg", img.offset(node.clusters[0]),
         fragments=[[img.offset(head[0]), len(head) * cs], [img.offset(tail[0]), len(jpg) - len(head) * cs]])

    # deleted + bifragmented DOCX (gap of zeroed, never-written clusters)
    dx = S.docx(14, "Thesis draft", ["Chapter 1: Evidence handling.", S.text(15, 8).decode()])
    n = img.clusters_for(len(dx))
    head = img.alloc(n // 2)
    img.skip(9)
    tail = img.alloc(n - len(head))
    node = img.add_file(docs, "thesis.docx", dx, clusters=head + tail, deleted=True)
    _rec(manifest, name, "/Documents/thesis.docx", dx, "deleted-fragmented", "docx", img.offset(node.clusters[0]),
         fragments=[[img.offset(head[0]), len(head) * cs], [img.offset(tail[0]), len(dx) - len(head) * cs]])

    # deleted + corrupted in place (3 clusters overwritten with random data)
    bad = S.jpeg(16, "IMG_0004 - corrupted")
    node = img.add_file(dcim, "IMG_0004.jpg", bad, deleted=True)
    mid = node.clusters[len(node.clusters) // 2: len(node.clusters) // 2 + 3]
    img.write_raw(mid, rnd.randbytes(3 * cs))
    _rec(manifest, name, "/DCIM/IMG_0004.jpg", bad, "deleted-corrupted", "jpeg", img.offset(node.clusters[0]))

    # deleted + second half wiped with zeros (truncated)
    pn = S.png(17, "scan.png - wiped")
    node = img.add_file(docs, "scan.png", pn, deleted=True)
    half = node.clusters[len(node.clusters) // 2:]
    img.write_raw(half, bytes(len(half) * cs))
    _rec(manifest, name, "/Documents/scan.png", pn, "deleted-truncated", "png", img.offset(node.clusters[0]))

    # orphaned JPEG: data in free space, no directory entry at all (carving only)
    orphan = S.jpeg(18, "orphan - no metadata")
    oc = img.alloc(img.clusters_for(len(orphan)))
    img.write_raw(oc, orphan)
    _rec(manifest, name, "(unallocated)", orphan, "orphaned", "jpeg", img.offset(oc[0]))

    path = out / name
    path.write_bytes(img.build())
    return path


# ----------------------------------------------------------------------------- ext4
def build_ext4(out: Path, manifest: list) -> Path | None:
    mke2fs, debugfs = _which("mke2fs"), _which("debugfs")
    if not (mke2fs and debugfs):
        return None
    name = "ext4.img"
    plan = [
        ("photos/beach.jpg", S.jpeg(31, "beach.jpg (ext4 live)"), "allocated", "jpeg", False),
        ("docs/memo.pdf", S.pdf("Memo", ["Live file on ext4."]), "allocated", "pdf", False),
        ("docs/plan.docx", S.docx(32, "Plan", ["Live DOCX on ext4"]), "allocated", "docx", False),
        ("photos/sunset.jpg", S.jpeg(33, "sunset.jpg (ext4 deleted)"), "deleted", "jpeg", True),
        ("docs/secret.pdf", S.pdf("Secret", ["Deleted PDF on ext4.", S.text(34, 5).decode()]), "deleted", "pdf", True),
        ("docs/ledger.xlsx", S.xlsx(35, [["Account", "Balance"], ["A-1", 500]]), "deleted", "xlsx", True),
        ("docs/payroll.txt", S.jpeg(36, "payroll.txt is a JPEG"), "deleted-mismatch", "jpeg", True),
        ("clip.gif", S.gif(37, "ext4"), "deleted", "gif", True),
    ]
    path = out / name
    with tempfile.TemporaryDirectory() as stage:
        for rel, data, *_ in plan:
            p = Path(stage) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        env = dict(os.environ, E2FSPROGS_FAKE_TIME="1793520000")
        if path.exists():
            path.unlink()
        subprocess.run([mke2fs, "-q", "-F", "-t", "ext4", "-b", "4096", "-L", "EVIDENTIA",
                        "-U", "6e0b1b4c-2614-4926-9a1e-0e5f0c0de001", "-E", "root_owner=0:0",
                        "-d", stage, str(path), "32M"], check=True, env=env, capture_output=True)
        for rel, data, state, ftype, deleted in plan:
            if deleted:
                subprocess.run([debugfs, "-w", "-R", f"rm /{rel}", str(path)], check=True, env=env,
                               capture_output=True)
    for rel, data, state, ftype, deleted in plan:
        _rec(manifest, name, "/" + rel, data, state, ftype)
    return path


# ----------------------------------------------------------------------------- NTFS (optional)
def build_ntfs(out: Path, manifest: list) -> Path | None:
    mkntfs, ntfscp = _which("mkntfs"), _which("ntfscp")
    if not (mkntfs and ntfscp):
        return None
    name = "ntfs.img"
    path = out / name
    with open(path, "wb") as fh:
        fh.truncate(48 * 1024 * 1024)
    subprocess.run([mkntfs, "-F", "-Q", "-q", "-L", "EVIDENTIA", str(path)], check=True, capture_output=True)
    files = [("photo.jpg", S.jpeg(41, "NTFS live")), ("report.pdf", S.pdf("NTFS report", ["Live file."]))]
    with tempfile.TemporaryDirectory() as stage:
        for fname, data in files:
            src = Path(stage) / fname
            src.write_bytes(data)
            subprocess.run([ntfscp, "-f", str(path), str(src), fname], check=True, capture_output=True)
            _rec(manifest, name, "/" + fname, data, "allocated", fname.rsplit(".", 1)[1].replace("jpg", "jpeg"))
    return path


# ----------------------------------------------------------------------------- MBR disk
def build_mbr(out: Path, volumes: list[tuple[Path, int]]) -> Path:
    path = out / "disk_mbr.img"
    lba = 2048
    entries = b""
    with open(path, "wb") as fh:
        fh.write(bytes(lba * 512))
        for vol, ptype in volumes:
            sectors = vol.stat().st_size // 512
            entries += struct.pack("<B3sB3sII", 0, b"\xfe\xff\xff", ptype, b"\xfe\xff\xff", lba, sectors)
            with open(vol, "rb") as src:
                shutil.copyfileobj(src, fh, 4 << 20)
            lba += sectors
            pad = (-lba) % 2048
            fh.write(bytes(pad * 512))
            lba += pad
        fh.seek(446)
        fh.write(entries.ljust(64, b"\0") + b"\x55\xaa")
    return path


def generate(out_dir: str | os.PathLike, *, with_ext4: bool = True, with_mbr: bool = True,
             with_ntfs: bool = True) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    manifest: list = []
    images = {"fat32": str(build_fat32(out, manifest))}
    notes = []
    if with_ext4:
        p = build_ext4(out, manifest)
        if p:
            images["ext4"] = str(p)
        else:
            notes.append("ext4 skipped: e2fsprogs (mke2fs, debugfs) not found — `brew install e2fsprogs` "
                         "or `apt install e2fsprogs`")
    if with_ntfs:
        p = build_ntfs(out, manifest)
        if p:
            images["ntfs"] = str(p)
        else:
            notes.append("NTFS skipped: mkntfs/ntfscp (ntfs-3g) not found — install ntfs-3g on Linux to enable")
    if with_mbr:
        vols = [(Path(images["fat32"]), 0x0C)] + ([(Path(images["ext4"]), 0x83)] if "ext4" in images else [])
        images["disk_mbr"] = str(build_mbr(out, vols))
    meta = {"generated": datetime.now().isoformat(timespec="seconds"), "images": images, "notes": notes,
            "fat32_cluster_size": 1024, "files": manifest}
    (out / "manifest.json").write_text(json.dumps(meta, indent=2))
    return meta
