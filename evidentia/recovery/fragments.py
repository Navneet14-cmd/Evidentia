"""Validation-guided bifragment reconstruction (after Garfinkel's "bifragment gap carving").

Model: a file was written as two cluster-aligned runs — a head [start, start+split) and a tail
that begins somewhere after a gap of foreign clusters. We search for the split point and the gap
and accept the first candidate that passes the *full* structural validator.

* ZIP/OOXML: the central directory (in the tail) records the logical file length, so the gap size
  is known exactly; only the split point is searched (O(n) candidates, each checked by per-entry
  CRC-32).
* JPEG: the split point is found by testing each cluster for "looks like entropy-coded data"
  (valid 0xFF byte-stuffing, high entropy, no zero runs); the tail start is then searched cluster
  by cluster. A candidate must parse structurally, decode with Pillow, and not end prematurely
  (libjpeg fills missing data with a flat band, which we detect), so skipping an *overwritten*
  region is not mistaken for a reconstruction. Every candidate must also survive an exact baseline
  Huffman decode (validators.jpeg_entropy_check), and clusters that belong to another intact JPEG
  starting inside the gap are never used as a tail (same-camera images otherwise splice
  "successfully" because Huffman decoding self-synchronises).

Limits (documented in README): exactly two fragments, in order, cluster-aligned; the break must lie
inside the JPEG scan data (not in the headers); gap search is bounded (``max_gap_clusters``);
progressive JPEGs and ZIP64 are not specially handled.
"""
from __future__ import annotations

import io
import struct
from dataclasses import dataclass, field

from ..core.entropy import shannon_entropy
from . import validators as V

try:
    from PIL import Image, ImageStat
except ImportError:  # pragma: no cover
    Image = None


@dataclass
class Reconstruction:
    data: bytes
    fragments: list[tuple[int, int]]          # (absolute offset, length)
    candidates_tested: int
    method: str
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- JPEG helpers
def looks_like_scan(block: bytes) -> bool:
    """Could this cluster be JPEG entropy-coded data?"""
    if len(block) < 64 or b"\x00" * 64 in block:
        return False
    if shannon_entropy(block) < 4.5:
        return False
    i = block.find(b"\xff")
    while 0 <= i < len(block) - 1:
        n = block[i + 1]
        if n == 0xD9:
            return True  # EOI; the rest of the cluster is slack space
        if not (n == 0x00 or 0xD0 <= n <= 0xD7 or n == 0xFF):
            return False
        i = block.find(b"\xff", i + 1 if n == 0xFF else i + 2)
    return True


def jpeg_decodes_fully(data: bytes) -> bool:
    """Reject decodes that ran out of data (libjpeg pads with a flat band of identical blocks)."""
    if Image is None:
        return True
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            w, h = im.size
            band = im.crop((0, max(0, h - 8), w, h)).convert("RGB")
            return max(ImageStat.Stat(band).stddev) > 0.5
    except Exception:  # noqa: BLE001
        return False


def reconstruct_jpeg(read, start: int, limit: int, cluster: int, max_size: int = 8 << 20,
                     max_gap_clusters: int = 4096) -> Reconstruction | None:
    data = read(start, min(max_size, limit - start))
    st = V.jpeg_structure(data)
    if st.status == V.INTACT or "scan_start" not in st.info:
        return None
    scan_start = st.info["scan_start"]
    nclust = len(data) // cluster
    k0 = -(-scan_start // cluster)
    k = k0
    while k < nclust and looks_like_scan(data[k * cluster:(k + 1) * cluster]):
        k += 1
    first_bad = k
    if "corrupt_at" in st.info:
        first_bad = min(first_bad, st.info["corrupt_at"] // cluster)
    if first_bad >= nclust:
        return None  # simply truncated, nothing to bridge
    # Clusters already owned by another intact JPEG that starts inside the gap cannot be our tail.
    owned: list[tuple[int, int]] = []
    hp = data.find(b"\xff\xd8\xff", first_bad * cluster)
    while hp >= 0:
        if hp % cluster == 0:
            other = V.jpeg_structure(data[hp:])
            if other.status == V.INTACT:
                owned.append((hp, hp + other.length))
        hp = data.find(b"\xff\xd8\xff", hp + 3)
    tested = 0
    for split_k in (first_bad, first_bad - 1, first_bad - 2, first_bad - 3):
        if split_k < max(k0, 1):
            continue
        head = data[: split_k * cluster]
        for g in range(split_k + 1, min(nclust, split_k + 1 + max_gap_clusters)):
            off = g * cluster
            if any(a <= off < b for a, b in owned) or not looks_like_scan(data[off:off + cluster]):
                continue
            tested += 1
            cand = head + data[off:]
            s2 = V.jpeg_structure(cand)
            if s2.status != V.INTACT:
                continue
            cand = cand[: s2.length]
            v = V.validate_jpeg(cand)
            if v.intact and jpeg_decodes_fully(cand):
                tail_len = len(cand) - len(head)
                return Reconstruction(
                    cand, [(start, len(head)), (start + off, tail_len)], tested, "jpeg-bifragment",
                    [f"split after {len(head)} bytes, gap of {off - len(head)} bytes "
                     f"({(off - len(head)) // cluster} clusters)"])
    return None


# ---------------------------------------------------------------- ZIP
def reconstruct_zip(read, start: int, limit: int, cluster: int, max_size: int = 64 << 20) -> Reconstruction | None:
    data = read(start, min(max_size, limit - start))
    length, consistent = V.zip_end(data)
    if length is None or consistent:
        return None
    e = data.rfind(b"PK\x05\x06", 0, length)
    eo = V.parse_eocd(data, e)
    if not eo:
        return None
    expected = eo["cd_offset"] + eo["cd_size"] + 22 + eo["comment_len"]
    gap = length - expected
    if gap <= 0:
        return None
    span = data[:length]
    # local-header offsets listed in the central directory (located in the tail)
    cd = span[e - eo["cd_size"]: e]
    offsets, p = [], 0
    while cd[p:p + 4] == b"PK\x01\x02":
        nlen, elen, clen = struct.unpack_from("<HHH", cd, p + 28)
        offsets.append(struct.unpack_from("<I", cd, p + 42)[0])
        p += 46 + nlen + elen + clen
    if not offsets:
        return None
    tested = 0
    for step in sorted({cluster, 512}, reverse=True):
        if gap % step:
            continue
        for split in range(step, expected, step):
            def at(x):
                return span[x: x + 4] if x < split else span[x + gap: x + gap + 4]
            if any(at(o) != b"PK\x03\x04" for o in offsets):
                continue
            tested += 1
            cand = span[:split] + span[split + gap:]
            if V.validate_zip(cand).intact:
                return Reconstruction(
                    cand, [(start, split), (start + split + gap, len(cand) - split)], tested, "zip-bifragment",
                    [f"central directory implies {expected} bytes; bridged a {gap}-byte gap after {split} bytes"])
    return None


def reconstruct(sig_name: str, read, start: int, limit: int, cluster: int) -> Reconstruction | None:
    if sig_name == "jpeg":
        return reconstruct_jpeg(read, start, limit, cluster)
    if sig_name == "zip":
        return reconstruct_zip(read, start, limit, cluster)
    return None
