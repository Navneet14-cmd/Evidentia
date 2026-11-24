"""Recovery orchestrator: FS-aware recovery + carving + reconstruction + correlation + scoring."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..core.entropy import sampled_entropy, zero_block_ratio
from ..core.hashing import hash_bytes
from ..core.jobs import JobContext, NULL_CONTEXT
from . import fs_recovery
from . import validators as V
from .carver import IntervalSet, carve
from .classifier import Classification, classify, expected_entropy
from .scoring import ScoreResult, compute_score
from .signatures import enabled

IMAGE_TYPES = {"jpeg", "png", "gif"}


@dataclass
class RecoveryOptions:
    filesystem: bool = True
    carving: bool = True
    reconstruct: bool = True
    unallocated_only: bool = True     # carve only space not owned by live files
    include_allocated: bool = False   # also extract live files via the file system
    types: list[str] | None = None    # carving signature names; None = all
    alignment: int = 512

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class RecoveredItem:
    item_id: int
    source: str                       # filesystem | carved | reconstructed
    name: str
    path: str
    offset: int | None
    size: int
    deleted: bool
    classification: Classification
    validation: V.ValidationResult
    entropy: float
    zero_ratio: float
    fragmentation: str
    fragments: list = field(default_factory=list)
    fs_type: str | None = None
    partition: int | None = None
    inode: int | None = None
    times: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    score: ScoreResult | None = None
    hashes: dict = field(default_factory=dict)
    output_path: str | None = None
    thumbnail_path: str | None = None
    superseded_by: int | None = None
    data: bytes | None = field(default=None, repr=False)

    def to_row(self) -> dict:
        return {
            "item_id": self.item_id, "source": self.source, "name": self.name, "path": self.path,
            "offset": self.offset, "size": self.size, "deleted": self.deleted,
            "detected_type": self.classification.type, "mime": self.classification.mime,
            "claimed_ext": self.classification.claimed_extension, "ext_mismatch": self.classification.mismatch,
            "validation_status": self.validation.status, "validation": self.validation.to_dict(),
            "entropy": round(self.entropy, 3), "zero_ratio": round(self.zero_ratio, 4),
            "fragmentation": self.fragmentation, "fragments": self.fragments, "fs_type": self.fs_type,
            "partition": self.partition, "inode": self.inode, "times": self.times, "notes": self.notes,
            "confidence": self.score.total if self.score else None,
            "score": self.score.to_dict() if self.score else None,
            "sha256": self.hashes.get("sha256"), "md5": self.hashes.get("md5"),
            "output_path": self.output_path, "thumbnail_path": self.thumbnail_path,
            "superseded_by": self.superseded_by,
        }


@dataclass
class RecoveryResult:
    items: list[RecoveredItem]
    partitions: list[dict]
    stats: dict
    warnings: list[str]


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80] or "file"


def _validate_for(cls: Classification, data: bytes) -> V.ValidationResult:
    return V.validate(cls.type, data)


def _thumbnail(data: bytes, dest: Path) -> str | None:
    try:
        import io
        from PIL import Image, ImageFile
        ImageFile.LOAD_TRUNCATED_IMAGES = True  # thumbnails of damaged files are still useful
        try:
            with Image.open(io.BytesIO(data)) as im:
                im.thumbnail((192, 192))
                im.convert("RGB").save(dest, "PNG")
        finally:
            ImageFile.LOAD_TRUNCATED_IMAGES = False
        return str(dest)
    except Exception:  # noqa: BLE001
        return None


class RecoveryEngine:
    def __init__(self, options: RecoveryOptions | None = None):
        self.opt = options or RecoveryOptions()

    def run(self, source, out_dir: str | os.PathLike, ctx: JobContext = NULL_CONTEXT) -> RecoveryResult:
        out = Path(out_dir)
        (out / "files").mkdir(parents=True, exist_ok=True)
        (out / "thumbs").mkdir(parents=True, exist_ok=True)
        items: list[RecoveredItem] = []
        warnings: list[str] = []
        scan = fs_recovery.FsScan()
        nid = 1

        # 1. file-system-aware recovery ---------------------------------------------------
        if self.opt.filesystem:
            ctx.log("Walking file systems with The Sleuth Kit")
            scan = fs_recovery.scan(source, include_allocated=self.opt.include_allocated, ctx=ctx.sub(0.0, 0.25))
            warnings += scan.warnings
            for e in scan.entries:
                data = e.data or b""
                cls = classify(data, e.name)
                if e.read_error or not data:
                    v = V.ValidationResult(V.CORRUPT, 0, [f"content unreadable: {e.read_error or 'no data'}"])
                else:
                    v = _validate_for(cls, data)
                runs_contig = len(e.runs) <= 1 or all(a[0] + a[1] == b[0] for a, b in zip(e.runs, e.runs[1:]))
                if v.status == V.INTACT:
                    frag = "contiguous" if runs_contig else "fs-chain"
                elif v.status == V.CORRUPT:
                    frag = "broken"
                else:
                    frag = "unknown"
                notes = []
                if e.deleted and e.fs_type and e.fs_type.startswith("FAT"):
                    notes.append("FAT deleted entry: allocation chain freed, content read assuming contiguity")
                items.append(RecoveredItem(
                    nid, "filesystem", e.name, e.path, e.start_offset, len(data), e.deleted, cls, v,
                    sampled_entropy(data), zero_block_ratio(data), frag,
                    [list(r) for r in e.runs[:16]], e.fs_type, e.partition, e.inode, e.times, notes, data=data))
                nid += 1

        # 2. signature carving -----------------------------------------------------------
        if self.opt.carving:
            ctx.log("Carving by file signatures")
            exclude = IntervalSet(scan.allocated_ranges) if self.opt.unallocated_only and scan.allocated_ranges else None
            parts = [(p.offset, p.offset + p.length, p.cluster_size) for p in scan.partitions if p.cluster_size]

            def cluster(off, parts=parts):
                return next((c for s, e, c in parts if s <= off < e), 512)
            for cf in carve(source.read, source.size, signatures=enabled(self.opt.types), ctx=ctx.sub(0.25, 0.85),
                            alignment=self.opt.alignment, cluster=cluster, exclude=exclude,
                            reconstruct_fragments=self.opt.reconstruct):
                cls = classify(cf.data)
                v = cf.validation
                if cls.type != cf.signature.name and cls.type in ("docx", "xlsx", "pptx"):
                    v = _validate_for(cls, cf.data)
                frag = ("reconstructed" if cf.reconstructed else
                        "contiguous" if v.status == V.INTACT else "broken" if v.status == V.CORRUPT else "unknown")
                notes = [f"end located by {cf.end_method}"]
                if cf.reconstructed:
                    notes += cf.reconstruction.notes + [f"{cf.reconstruction.candidates_tested} candidate(s) tested"]
                items.append(RecoveredItem(
                    nid, "reconstructed" if cf.reconstructed else "carved", f"carved_{cf.offset:010x}.{cls.extension}",
                    f"@0x{cf.offset:x}", cf.offset, len(cf.data), True, cls, v, sampled_entropy(cf.data),
                    zero_block_ratio(cf.data), frag, [list(f) for f in cf.fragments], notes=notes, data=cf.data))
                nid += 1

        # 3. correlate FS entries with carved results -------------------------------------
        ctx.progress(0.87, "Correlating file-system and carved results")
        self._correlate(items)

        # 4. score, hash, export ---------------------------------------------------------
        live = items
        for n, it in enumerate(live):
            ctx.check()
            data = it.data or b""
            it.hashes = hash_bytes(data)
            has_fs = it.inode is not None
            it.score = compute_score(
                has_name=has_fs, has_times=has_fs and any(it.times.values()), has_inode=has_fs,
                size_consistent=has_fs and (it.validation.length in (None, it.size) or it.validation.status == V.UNKNOWN),
                validation_status=it.validation.status, fragmentation=it.fragmentation, entropy=it.entropy,
                expected_entropy=expected_entropy(it.classification.type), zero_ratio=it.zero_ratio)
            stem = os.path.splitext(_safe(it.name))[0]
            ext = it.classification.extension
            fname = f"{it.item_id:04d}_{stem}.{ext}"
            dest = out / "files" / fname
            dest.write_bytes(data)
            it.output_path = str(dest)
            if it.classification.type in IMAGE_TYPES and data:
                it.thumbnail_path = _thumbnail(data, out / "thumbs" / f"{it.item_id:04d}.png")
            it.data = None
            ctx.progress(0.88 + 0.12 * (n + 1) / max(1, len(live)), f"Hashing & exporting {fname}")

        stats = {
            "total": len(items),
            "filesystem": sum(i.source == "filesystem" for i in items),
            "carved": sum(i.source == "carved" for i in items),
            "reconstructed": sum(i.source == "reconstructed" for i in items),
            "intact": sum(i.validation.status == V.INTACT for i in items),
            "partial": sum(i.validation.status == V.PARTIAL for i in items),
            "corrupt": sum(i.validation.status == V.CORRUPT for i in items),
            "ext_mismatch": sum(i.classification.mismatch for i in items),
            "superseded": sum(i.superseded_by is not None for i in items),
        }
        parts = [p.__dict__ for p in scan.partitions]
        return RecoveryResult(items, parts, stats, warnings)

    @staticmethod
    def _correlate(items: list[RecoveredItem]) -> None:
        fs_by_off = {i.offset: i for i in items if i.source == "filesystem" and i.offset is not None and i.deleted}
        fs_hashes = {hash_bytes(i.data or b"", ("sha256",))["sha256"]: i for i in items if i.source == "filesystem"}
        for c in [i for i in items if i.source != "filesystem"]:
            h = hash_bytes(c.data or b"", ("sha256",))["sha256"]
            twin = fs_hashes.get(h)
            if twin is not None:
                twin.notes.append(f"content confirmed independently by signature carving (item {c.item_id})")
                c.superseded_by = twin.item_id
                c.notes.append(f"duplicate of file-system item {twin.item_id}")
                continue
            fs = fs_by_off.get(c.offset)
            if fs is None:
                continue
            if c.validation.status == V.INTACT and fs.validation.status != V.INTACT:
                # carved/reconstructed content is right; adopt the file-system metadata
                c.name, c.path, c.inode, c.times = fs.name, fs.path, fs.inode, fs.times
                c.fs_type, c.partition = fs.fs_type, fs.partition
                c.classification = classify(c.data or b"", fs.name)
                c.notes.append(f"metadata adopted from file-system entry {fs.path} (item {fs.item_id})")
                fs.superseded_by = c.item_id
                fs.notes.append(f"superseded by {c.source} item {c.item_id} (validated content)")
