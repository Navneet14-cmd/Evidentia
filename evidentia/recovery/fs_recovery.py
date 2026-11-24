"""File-system-aware recovery of deleted entries via The Sleuth Kit (pytsk3).

Supports every file system TSK understands (FAT12/16/32, exFAT, NTFS, ext2/3/4, HFS+, ...),
inside an optional DOS/GPT partition table. All reads go through the read-only EvidenceSource.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..core.jobs import JobContext, NULL_CONTEXT

try:
    import pytsk3
    HAVE_TSK = True
except ImportError:  # pragma: no cover
    pytsk3 = None
    HAVE_TSK = False

MAX_FILE = 256 * 1024 * 1024


def _fs_type_names() -> dict[int, str]:
    if not HAVE_TSK:
        return {}
    out = {}
    for n in dir(pytsk3):
        if n.startswith("TSK_FS_TYPE_") and not n.endswith(("DETECT", "ENUM")):
            out[int(getattr(pytsk3, n))] = n[len("TSK_FS_TYPE_"):]
    return out


FS_NAMES = _fs_type_names()


@dataclass
class Partition:
    index: int
    offset: int
    length: int
    description: str
    fs_type: str | None = None
    block_size: int | None = None
    cluster_size: int | None = None     # allocation unit (FAT cluster may differ from TSK block)


@dataclass
class FsEntry:
    partition: int
    fs_type: str
    block_size: int
    inode: int
    path: str
    name: str
    size: int
    deleted: bool
    times: dict
    runs: list[tuple[int, int]]          # absolute byte ranges in the image
    data: bytes | None = None
    read_error: str | None = None

    @property
    def start_offset(self) -> int | None:
        return self.runs[0][0] if self.runs else None


@dataclass
class FsScan:
    partitions: list[Partition] = field(default_factory=list)
    entries: list[FsEntry] = field(default_factory=list)
    allocated_ranges: list[tuple[int, int]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def block_size(self) -> int | None:
        sizes = {p.cluster_size for p in self.partitions if p.cluster_size}
        return sizes.pop() if len(sizes) == 1 else None


if HAVE_TSK:
    class SourceImg(pytsk3.Img_Info):
        """Bridges TSK onto our read-only EvidenceSource."""

        def __init__(self, source):
            self._src = source
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset, size):  # noqa: D401
            return self._src.read(offset, size)

        def get_size(self):
            return self._src.size

        def close(self):
            pass


def _ts(v) -> str | None:
    if not v:
        return None
    try:
        return datetime.fromtimestamp(int(v), tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


_DATA_ATTRS = set()
if HAVE_TSK:
    for _n in ("TSK_FS_ATTR_TYPE_DEFAULT", "TSK_FS_ATTR_TYPE_NTFS_DATA", "TSK_FS_ATTR_TYPE_HFS_DATA",
               "TSK_FS_ATTR_TYPE_HFS_DEFAULT", "TSK_FS_ATTR_TYPE_APFS_DATA", "TSK_FS_ATTR_TYPE_UNIX_EXTENT"):
        if hasattr(pytsk3.TSK_FS_ATTR_TYPE_ENUM, _n):
            _DATA_ATTRS.add(int(getattr(pytsk3.TSK_FS_ATTR_TYPE_ENUM, _n)))


def _runs(f, part_off: int, bs: int) -> list[tuple[int, int]]:
    out = []
    try:
        for attr in f:
            if int(attr.info.type) not in _DATA_ATTRS:
                continue
            for run in attr:
                if run.len <= 0 or int(run.flags) & (int(pytsk3.TSK_FS_ATTR_RUN_FLAG_FILLER) |
                                                      int(pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE)):
                    continue
                out.append((part_off + run.addr * bs, run.len * bs))
            break
    except (IOError, OSError, RuntimeError):
        pass
    return out


def _read_all(f, size: int) -> bytes:
    chunks, off = [], 0
    while off < size:
        n = min(4 << 20, size - off)
        b = f.read_random(off, n)
        if not b:
            break
        chunks.append(b)
        off += len(b)
    return b"".join(chunks)


def scan(source, *, include_allocated: bool = False, read_content: bool = True,
         ctx: JobContext = NULL_CONTEXT) -> FsScan:
    res = FsScan()
    if not HAVE_TSK:
        res.warnings.append("pytsk3 not installed: file-system recovery disabled (carving still works)")
        return res
    img = SourceImg(source)
    parts: list[Partition] = []
    try:
        vol = pytsk3.Volume_Info(img)
        bs = vol.info.block_size
        for p in vol:
            if int(p.flags) & int(pytsk3.TSK_VS_PART_FLAG_ALLOC) and p.len > 0:
                parts.append(Partition(len(parts), p.start * bs, p.len * bs,
                                       p.desc.decode("utf-8", "replace") if isinstance(p.desc, bytes) else str(p.desc)))
    except (IOError, OSError, RuntimeError):
        parts = [Partition(0, 0, source.size, "whole image (no partition table)")]
    res.partitions = parts
    for pi, part in enumerate(parts):
        ctx.check()
        try:
            fs = pytsk3.FS_Info(img, offset=part.offset)
        except (IOError, OSError, RuntimeError):
            res.warnings.append(f"partition {part.index} ({part.description}): no recognised file system")
            continue
        part.fs_type = FS_NAMES.get(int(fs.info.ftype), str(fs.info.ftype))
        part.block_size = fs.info.block_size
        part.cluster_size = fs.info.block_size
        if part.fs_type and part.fs_type.startswith("FAT"):
            boot = source.read(part.offset, 512)
            bps, spc = int.from_bytes(boot[11:13], "little"), boot[13]
            if bps and spc:
                part.cluster_size = bps * spc
        _walk(fs, part, res, include_allocated, read_content, ctx.sub(pi / len(parts), (pi + 1) / len(parts)))
    return res


def _walk(fs, part: Partition, res: FsScan, include_allocated: bool, read_content: bool, ctx: JobContext):
    bs = fs.info.block_size
    seen_dirs: set[int] = set()
    seen_files: set[int] = set()
    stack = [("/", fs.open_dir(path="/"))]
    reg = int(pytsk3.TSK_FS_META_TYPE_REG)
    dtype = int(pytsk3.TSK_FS_META_TYPE_DIR)
    unalloc = int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
    count = 0
    while stack:
        ctx.check()
        path, d = stack.pop()
        try:
            entries = list(d)
        except (IOError, OSError, RuntimeError):
            continue
        for f in entries:
            name_b = f.info.name.name
            name = name_b.decode("utf-8", "replace") if isinstance(name_b, bytes) else str(name_b)
            if name in (".", "..") or (path == "/" and name.startswith("$") and name != "$OrphanFiles"):
                continue
            meta = f.info.meta
            if meta is None:
                continue
            deleted = bool(int(f.info.name.flags) & unalloc)
            mtype = int(meta.type)
            full = path.rstrip("/") + "/" + name
            if mtype == dtype:
                if meta.addr not in seen_dirs and not deleted:
                    seen_dirs.add(meta.addr)
                    try:
                        stack.append((full, f.as_directory()))
                    except (IOError, OSError, RuntimeError):
                        pass
                continue
            if mtype != reg:
                continue
            runs = _runs(f, part.offset, bs)
            if not deleted:
                res.allocated_ranges.extend((s, s + ln) for s, ln in runs)
            if not deleted and not include_allocated:
                continue
            key = (meta.addr << 1) | deleted
            if key in seen_files:
                continue
            seen_files.add(key)
            entry = FsEntry(part.index, part.fs_type, bs, int(meta.addr), full, name, int(meta.size), deleted,
                            {"modified": _ts(meta.mtime), "accessed": _ts(meta.atime),
                             "changed": _ts(meta.ctime), "created": _ts(meta.crtime)}, runs)
            if read_content and 0 < entry.size <= MAX_FILE:
                try:
                    entry.data = _read_all(f, entry.size)
                except (IOError, OSError, RuntimeError) as exc:
                    entry.read_error = str(exc)
            elif entry.size > MAX_FILE:
                entry.read_error = "file too large for in-memory recovery"
            res.entries.append(entry)
            count += 1
            ctx.progress(min(0.95, count / 200), f"File system: {count} entries ({name})")
    ctx.progress(1.0, f"File system walk complete: {count} entries")
