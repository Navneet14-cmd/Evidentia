"""Signature-based carving over raw evidence bytes."""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Iterator

from ..core.jobs import JobContext, NULL_CONTEXT
from . import validators as V
from .fragments import Reconstruction, reconstruct
from .signatures import Signature, enabled

CHUNK = 16 * 1024 * 1024
OVERLAP = 64
PARTIAL_CAP = 4 * 1024 * 1024


class IntervalSet:
    """Sorted, non-overlapping [start, end) intervals with O(log n) membership."""

    def __init__(self, ranges=()):
        merged: list[list[int]] = []
        for s, e in sorted(r for r in ranges if r[1] > r[0]):
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        self._starts = [m[0] for m in merged]
        self._ends = [m[1] for m in merged]

    def __contains__(self, x: int) -> bool:
        i = bisect.bisect_right(self._starts, x) - 1
        return i >= 0 and x < self._ends[i]

    def __len__(self):
        return len(self._starts)


@dataclass
class CarvedFile:
    offset: int
    length: int
    signature: Signature
    data: bytes
    validation: V.ValidationResult
    fragments: list[tuple[int, int]] = field(default_factory=list)
    reconstruction: Reconstruction | None = None
    end_method: str = "structure"

    @property
    def reconstructed(self) -> bool:
        return self.reconstruction is not None


def _trim_partial(data: bytes) -> bytes:
    """For files whose end could not be found: stop at the first all-zero 4 KiB block."""
    z = bytes(4096)
    for i in range(4096, len(data), 4096):
        if data[i:i + 4096] == z:
            return data[:i]
    return data


def carve(read, size: int, *, signatures: list[Signature] | None = None, ctx: JobContext = NULL_CONTEXT,
          alignment: int = 512, cluster=512, exclude: IntervalSet | None = None,
          reconstruct_fragments: bool = True, start: int = 0, end: int | None = None) -> Iterator[CarvedFile]:
    sigs = signatures or enabled()
    end = size if end is None else min(end, size)
    pattern = re.compile(b"|".join(b"(?P<s%d>%s)" % (i, s.header) for i, s in enumerate(sigs)), re.DOTALL)
    pos, skip_until = start, 0
    while pos < end:
        ctx.check()
        buf = read(pos, min(CHUNK + OVERLAP, end - pos))
        if not buf:
            break
        for m in pattern.finditer(buf):
            if m.start() >= CHUNK:
                break  # belongs to the next chunk
            sig = sigs[int(m.lastgroup[1:])]
            off = pos + m.start() - sig.header_offset
            if off < skip_until or off < 0 or (alignment > 1 and off % alignment):
                continue
            if exclude is not None and off in exclude:
                continue
            cl = cluster(off) if callable(cluster) else cluster
            cf = carve_at(read, size, off, sig, cl, reconstruct_fragments)
            if cf is None:
                continue
            yield cf
            if cf.validation.status in (V.INTACT, V.PARTIAL):
                skip_until = off + (cf.fragments[0][1] if cf.reconstructed else cf.length)
        pos += CHUNK
        ctx.progress((pos - start) / max(1, end - start), f"Carving {min(pos, end) >> 20}/{end >> 20} MiB")


def carve_at(read, size: int, off: int, sig: Signature, cluster: int = 512,
             reconstruct_fragments: bool = True) -> CarvedFile | None:
    length = sig.measure(read, off, size) if sig.measure else None
    method = "structure"
    if length is None and sig.footer:
        window = read(off, min(sig.max_size, size - off))
        i = window.find(sig.footer, 1)
        if i >= 0:
            length, method = i + len(sig.footer), "footer"
    if length is None:
        if sig.name == "mp4":
            return None  # 'ftyp' without a plausible box chain: false positive
        data = _trim_partial(read(off, min(PARTIAL_CAP, sig.max_size, size - off)))
        method = "truncated"
    else:
        data = read(off, length)
    if len(data) < 16:
        return None
    v = V.validate(sig.name, data)
    rec = None
    if v.status != V.INTACT and reconstruct_fragments and sig.reconstructable:
        rec = reconstruct(sig.name, read, off, size, cluster)
        if rec:
            data = rec.data
            v = V.validate(sig.name, data)
            method = rec.method
    if v.status == V.CORRUPT and not v.info and len(data) < 64:
        return None
    frags = rec.fragments if rec else [(off, len(data))]
    return CarvedFile(off, len(data), sig, data, v, frags, rec, method)
