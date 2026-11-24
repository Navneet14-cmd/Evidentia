"""Structure-based validators.

Each validator parses the candidate bytes the way a reader of that format would and returns a
:class:`ValidationResult`:

* ``intact``  – structure complete and internally consistent (CRCs / offsets / decode all OK)
* ``partial`` – structurally valid prefix but truncated (end marker missing)
* ``corrupt`` – structural violation (bad CRC, invalid marker, broken offsets, zero-filled holes)
* ``unknown`` – no validator for the type

``length`` is the structural end of the file when it could be determined; the carver uses it to
find where a file ends inside a larger window of raw bytes.
"""
from __future__ import annotations

import base64
import io
import re
import struct
import zlib
from dataclasses import dataclass, field

try:  # Pillow gives us a real decode as a second opinion for image formats
    from PIL import Image, ImageFile
    ImageFile.LOAD_TRUNCATED_IMAGES = False
    Image.MAX_IMAGE_PIXELS = 100_000_000
except ImportError:  # pragma: no cover
    Image = None

INTACT, PARTIAL, CORRUPT, UNKNOWN = "intact", "partial", "corrupt", "unknown"
ZERO_RUN = bytes(512)


@dataclass
class ValidationResult:
    status: str
    length: int | None = None
    issues: list[str] = field(default_factory=list)
    info: dict = field(default_factory=dict)

    @property
    def intact(self) -> bool:
        return self.status == INTACT

    def summary(self) -> str:
        return self.status if not self.issues else f"{self.status}: {self.issues[0]}"

    def to_dict(self) -> dict:
        return {"status": self.status, "length": self.length, "issues": self.issues, "info": self.info}


def _pillow_check(data: bytes, issues: list[str], all_frames: bool = False) -> bool:
    if Image is None:
        return True
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            if all_frames:
                for i in range(1, getattr(im, "n_frames", 1)):
                    im.seek(i)
                    im.load()
        return True
    except Exception as exc:  # noqa: BLE001 - any decoder failure means "not decodable"
        issues.append(f"decoder error: {exc}")
        return False


# ============================================================================ JPEG
_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
_ALLOWED_AFTER_SCAN = {0xD9, 0xC4, 0xDA, 0xDB, 0xDD, 0xDC, 0xFE} | set(range(0xE0, 0xF0))


def jpeg_scan(data: bytes, pos: int, info: dict, issues: list[str]) -> int | None:
    """Walk entropy-coded data from ``pos``; return the index of the next real marker (0xFF xx),
    or None if the data ends first. Records the first structural violation in ``info``."""
    n = len(data)
    expected_rst = 0
    while True:
        i = data.find(b"\xff", pos)
        if i < 0 or i + 1 >= n:
            return None
        nxt = data[i + 1]
        if nxt == 0x00:
            pos = i + 2
        elif 0xD0 <= nxt <= 0xD7:
            if nxt - 0xD0 != expected_rst and "rst_error_at" not in info:
                info["rst_error_at"] = i
                issues.append(f"restart marker out of sequence at offset {i}")
            expected_rst = (nxt - 0xD0 + 1) % 8
            pos = i + 2
        elif nxt == 0xFF:
            pos = i + 1
        else:
            if nxt not in _ALLOWED_AFTER_SCAN:
                info.setdefault("corrupt_at", i)
                issues.append(f"invalid marker 0xFF{nxt:02X} inside entropy-coded data at offset {i}")
            return i


def jpeg_structure(data: bytes) -> ValidationResult:
    issues: list[str] = []
    info: dict = {"scans": 0}
    n = len(data)
    if not data.startswith(b"\xff\xd8\xff"):
        return ValidationResult(CORRUPT, None, ["missing SOI marker"], info)
    pos, end, truncated = 2, None, False
    while pos < n:
        if data[pos] != 0xFF:
            info.setdefault("corrupt_at", pos)
            issues.append(f"expected marker at offset {pos}")
            break
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            truncated = True
            break
        m = data[pos]
        pos += 1
        if m == 0xD9:
            end = pos
            break
        if m == 0x01 or 0xD0 <= m <= 0xD7:
            continue
        if pos + 2 > n:
            truncated = True
            break
        seglen = struct.unpack_from(">H", data, pos)[0]
        if seglen < 2:
            info.setdefault("corrupt_at", pos)
            issues.append(f"invalid segment length at offset {pos}")
            break
        if pos + seglen > n:
            truncated = True
            break
        if m in _SOF and seglen >= 8:
            _, h, w, nc = struct.unpack_from(">BHHB", data, pos + 2)
            info.update(width=w, height=h, components=nc, progressive=m in (0xC2, 0xC6, 0xCA, 0xCE))
        elif m == 0xDD and seglen >= 4:
            info["restart_interval"] = struct.unpack_from(">H", data, pos + 2)[0]
        pos += seglen
        if m == 0xDA:
            info["scans"] += 1
            info.setdefault("scan_start", pos)
            nxt = jpeg_scan(data, pos, info, issues)
            if nxt is None:
                truncated = True
                break
            z = data.find(ZERO_RUN, pos, nxt)
            if z >= 0:
                info.setdefault("corrupt_at", z)
                issues.append(f"zero-filled run inside entropy-coded data at offset {z} (missing sectors?)")
            if "corrupt_at" in info:
                break
            pos = nxt
    if "width" not in info:
        issues.append("no SOF (frame header) found")
    if info["scans"] == 0:
        issues.append("no SOS (scan) found")
    if "corrupt_at" in info or "width" not in info:
        return ValidationResult(CORRUPT, end, issues, info)
    if truncated or end is None:
        issues.append("truncated: EOI marker not found")
        return ValidationResult(PARTIAL, None, issues, info)
    return ValidationResult(INTACT, end, issues, info)


_BITS = [format(b, "08b") for b in range(256)]
DEEP_DECODE_LIMIT = 6 * 1024 * 1024


class _Huff:
    __slots__ = ("maxcode", "valptr", "mincode", "vals")

    def __init__(self, counts, vals):
        self.vals = vals
        self.maxcode = [-1] * 17
        self.valptr = [0] * 17
        self.mincode = [0] * 17
        code = k = 0
        for ln in range(1, 17):
            n = counts[ln - 1]
            if n:
                self.valptr[ln] = k
                self.mincode[ln] = code
                code += n
                k += n
                self.maxcode[ln] = code - 1
            code <<= 1


def jpeg_entropy_check(data: bytes) -> tuple[bool | None, str]:
    """Decode every Huffman symbol of a baseline JPEG and check that the scan ends after exactly
    the expected number of MCUs with only 1-bit padding left over. Returns (ok, reason), with
    ok=None when the check does not apply (progressive/arithmetic/multi-scan/too large).

    This is what makes bifragment reconstruction trustworthy: a stream spliced at the wrong point,
    or one with an overwritten region skipped, desynchronises the Huffman decoder."""
    pos, n = 2, len(data)
    comps, tables, interval, frame, scan = {}, {}, 0, None, None
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            return None, "unparsed"
        m = data[pos + 1]
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
            pos += 2
            continue
        ln = struct.unpack_from(">H", data, pos + 2)[0]
        seg = data[pos + 4: pos + 2 + ln]
        if m in (0xC0, 0xC1):
            _, h, w, nc = struct.unpack_from(">BHHB", seg)
            frame = (w, h, nc)
            for i in range(nc):
                cid, hv, _tq = seg[6 + 3 * i: 9 + 3 * i]
                comps[cid] = (hv >> 4, hv & 15)
        elif m in _SOF:
            return None, "not baseline Huffman"
        elif m == 0xC4:
            p = 0
            while p < len(seg):
                tc_th = seg[p]
                counts = seg[p + 1: p + 17]
                total = sum(counts)
                tables[(tc_th >> 4, tc_th & 15)] = _Huff(counts, seg[p + 17: p + 17 + total])
                p += 17 + total
        elif m == 0xDD:
            interval = struct.unpack_from(">H", seg)[0]
        elif m == 0xDA:
            ns = seg[0]
            scan = [(seg[1 + 2 * i], seg[2 + 2 * i] >> 4, seg[2 + 2 * i] & 15) for i in range(ns)]
            pos += 2 + ln
            break
        pos += 2 + ln
    if not frame or not scan:
        return None, "no baseline frame/scan"
    end = data.rfind(b"\xff\xd9")
    if end < pos:
        return False, "no EOI after scan"
    entropy = data[pos:end]
    if re.search(rb"\xff[\xc0-\xcf\xda-\xfe]", entropy):
        return None, "multiple scans"
    if len(entropy) > DEEP_DECODE_LIMIT:
        return None, "too large for deep check"
    w, h, _ = frame
    hmax = max(c[0] for c in comps.values())
    vmax = max(c[1] for c in comps.values())
    if len(scan) == 1:
        ch, cv = comps[scan[0][0]]
        bx = -(-(-(-w * ch // hmax)) // 8)
        by = -(-(-(-h * cv // vmax)) // 8)
        total, layout = bx * by, [(scan[0], 1)]
    else:
        total = -(-w // (8 * hmax)) * -(-h // (8 * vmax))
        layout = [(sc, comps[sc[0]][0] * comps[sc[0]][1]) for sc in scan]
    try:
        plan = [(tables[(0, td)], tables[(1, ta)], nb) for (_cid, td, ta), nb in layout]
    except KeyError:
        return False, "scan references a missing Huffman table"
    segments = re.split(rb"\xff[\xd0-\xd7]", entropy)
    per_seg = interval or total
    if interval and len(segments) != -(-total // interval):
        return False, f"{len(segments)} restart segments, expected {-(-total // interval)}"
    done = 0
    for si, segm in enumerate(segments):
        bits = "".join(_BITS[b] for b in segm.replace(b"\xff\x00", b"\xff"))
        nbits, bp = len(bits), 0
        want = min(per_seg, total - done)
        for _ in range(want):
            for dc, ac, nb in plan:
                for _b in range(nb):
                    for k, tbl in ((0, dc), (1, ac)):
                        coef = 1
                        while True:
                            if bp >= nbits:
                                return False, f"entropy data exhausted after {done} of {total} MCUs"
                            peek = int(bits[bp:bp + 16].ljust(16, "1"), 2)
                            mx, ln = tbl.maxcode, 1
                            while ln <= 16 and (peek >> (16 - ln)) > mx[ln]:
                                ln += 1
                            if ln > 16:
                                return False, f"invalid Huffman code after {done} MCUs"
                            sym = tbl.vals[tbl.valptr[ln] + (peek >> (16 - ln)) - tbl.mincode[ln]]
                            bp += ln
                            if k == 0:
                                if sym > 11:
                                    return False, "invalid DC magnitude"
                                bp += sym
                                break
                            r, sz = sym >> 4, sym & 15
                            if sz == 0:
                                if r != 15:
                                    break
                                coef += 16
                            else:
                                coef += r
                                bp += sz
                                coef += 1
                            if coef > 64:
                                return False, f"AC coefficient overflow after {done} MCUs"
                            if coef == 64:
                                break
            done += 1
        rest = nbits - bp
        if rest < 0 or rest > 7 or bits[bp:].strip("1"):
            return False, f"{rest} unexpected trailing bits in segment {si} after {done} MCUs"
    if done != total:
        return False, f"decoded {done} of {total} MCUs"
    return True, f"{total} MCUs decoded exactly"


def validate_jpeg(data: bytes, deep: bool = True) -> ValidationResult:
    r = jpeg_structure(data)
    if r.status == INTACT:
        body = data[: r.length]
        if deep:
            ok, why = jpeg_entropy_check(body)
            r.info["entropy_check"] = why
            if ok is False:
                r.status = CORRUPT
                r.issues.append(f"entropy-coded data does not decode: {why}")
                return r
        if not _pillow_check(body, r.issues):
            r.status = CORRUPT
    return r


# ============================================================================ PNG
_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PNG_CH = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def validate_png(data: bytes) -> ValidationResult:
    issues: list[str] = []
    info: dict = {"chunks": 0}
    if not data.startswith(_PNG_SIG):
        return ValidationResult(CORRUPT, None, ["missing PNG signature"], info)
    pos, n, idat, end = 8, len(data), [], None
    while pos + 8 <= n:
        ln, typ = struct.unpack_from(">I4s", data, pos)
        if not re.fullmatch(rb"[A-Za-z]{4}", typ) or ln > 0x7FFFFFFF:
            issues.append(f"invalid chunk header at offset {pos}")
            info["corrupt_at"] = pos
            return ValidationResult(CORRUPT, None, issues, info)
        if pos + 12 + ln > n:
            issues.append(f"truncated inside chunk {typ.decode()} at offset {pos}")
            return ValidationResult(PARTIAL, None, issues, info)
        body = data[pos + 8: pos + 8 + ln]
        crc = struct.unpack_from(">I", data, pos + 8 + ln)[0]
        info["chunks"] += 1
        if info["chunks"] == 1 and typ != b"IHDR":
            issues.append("first chunk is not IHDR")
        if zlib.crc32(typ + body) & 0xFFFFFFFF != crc:
            issues.append(f"CRC mismatch in {typ.decode()} chunk at offset {pos}")
            info.setdefault("corrupt_at", pos)
        if typ == b"IHDR" and ln >= 13:
            w, h, depth, ctype, _, _, inter = struct.unpack_from(">IIBBBBB", body)
            info.update(width=w, height=h, bit_depth=depth, color_type=ctype, interlaced=bool(inter))
        elif typ == b"IDAT":
            idat.append(body)
        pos += 12 + ln
        if typ == b"IEND":
            end = pos
            break
    if end is None:
        issues.append("truncated: IEND chunk not found")
        return ValidationResult(PARTIAL if "corrupt_at" not in info else CORRUPT, None, issues, info)
    if "corrupt_at" in info:
        return ValidationResult(CORRUPT, end, issues, info)
    try:
        raw = zlib.decompress(b"".join(idat))
        if "width" in info and not info.get("interlaced") and info["color_type"] in _PNG_CH:
            row = (info["width"] * _PNG_CH[info["color_type"]] * info["bit_depth"] + 7) // 8 + 1
            if len(raw) != row * info["height"]:
                issues.append("decompressed image data has unexpected size")
                return ValidationResult(CORRUPT, end, issues, info)
    except zlib.error as exc:
        issues.append(f"IDAT stream does not inflate: {exc}")
        return ValidationResult(CORRUPT, end, issues, info)
    return ValidationResult(INTACT, end, issues, info)


# ============================================================================ GIF
def validate_gif(data: bytes) -> ValidationResult:
    issues: list[str] = []
    info: dict = {"frames": 0}
    n = len(data)
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")) or n < 13:
        return ValidationResult(CORRUPT, None, ["missing GIF header"], info)
    w, h, flags = struct.unpack_from("<HHB", data, 6)
    info.update(width=w, height=h)
    pos = 13 + (3 * (1 << ((flags & 7) + 1)) if flags & 0x80 else 0)

    def skip_subblocks(p: int) -> int | None:
        while p < n:
            size = data[p]
            p += 1
            if size == 0:
                return p
            p += size
        return None

    end = None
    while pos < n:
        b = data[pos]
        if b == 0x3B:
            end = pos + 1
            break
        if b == 0x21:
            nxt = skip_subblocks(pos + 2)
        elif b == 0x2C:
            if pos + 10 > n:
                nxt = None
            else:
                lflags = data[pos + 9]
                p = pos + 10 + (3 * (1 << ((lflags & 7) + 1)) if lflags & 0x80 else 0)
                nxt = skip_subblocks(p + 1) if p < n else None
                info["frames"] += 1
        else:
            issues.append(f"unknown block 0x{b:02X} at offset {pos}")
            info["corrupt_at"] = pos
            return ValidationResult(CORRUPT, None, issues, info)
        if nxt is None:
            issues.append("truncated inside data sub-blocks")
            return ValidationResult(PARTIAL, None, issues, info)
        pos = nxt
    if end is None:
        issues.append("truncated: trailer (0x3B) not found")
        return ValidationResult(PARTIAL, None, issues, info)
    if info["frames"] == 0:
        issues.append("no image frames")
        return ValidationResult(CORRUPT, end, issues, info)
    if not _pillow_check(data[:end], issues, all_frames=True):
        return ValidationResult(CORRUPT, end, issues, info)
    return ValidationResult(INTACT, end, issues, info)


# ============================================================================ PDF
_OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")
_STREAM_RE = re.compile(rb"(?<!end)stream\r?\n")


def pdf_end(data: bytes) -> int | None:
    """End of a PDF inside a window: the first %%EOF, extended over incremental updates."""
    nxt_hdr = data.find(b"%PDF-", 5)
    limit = nxt_hdr if nxt_hdr > 0 else len(data)
    e = data.find(b"%%EOF", 0, limit)
    if e < 0:
        return None
    end = e + 5
    while True:
        e2 = data.find(b"%%EOF", end, limit)
        if e2 < 0 or b"startxref" not in data[end:e2]:
            break
        end = e2 + 5
    while end < len(data) and data[end:end + 1] in (b"\r", b"\n") and end - e < 7:
        end += 1
    return end


def validate_pdf(data: bytes) -> ValidationResult:
    issues: list[str] = []
    info: dict = {}
    m = re.match(rb"%PDF-(\d\.\d)", data)
    if not m:
        return ValidationResult(CORRUPT, None, ["missing %PDF header"], info)
    info["version"] = m.group(1).decode()
    end = pdf_end(data)
    body = data[:end] if end else data
    objs = {int(o.group(1)): o.start() for o in _OBJ_RE.finditer(body)}
    info["objects"] = len(objs)
    if end is None:
        issues.append("truncated: %%EOF not found")
        return ValidationResult(PARTIAL, None, issues, info)
    sx = body.rfind(b"startxref")
    xref_ok = False
    if sx >= 0:
        mm = re.match(rb"startxref\s+(\d+)", body[sx:sx + 40])
        if mm:
            off = int(mm.group(1))
            if body[off:off + 4] == b"xref":
                xref_ok = _check_xref_table(body, off, issues, info)
            elif _OBJ_RE.match(body, off):
                xref_ok = True
                info["xref"] = "stream"
            else:
                issues.append(f"startxref points to invalid offset {off}")
    else:
        issues.append("startxref not found")
    bad_streams = 0
    for s in _STREAM_RE.finditer(body):
        hdr = body[max(0, s.start() - 400): s.start()]
        hdr = hdr[hdr.rfind(b"obj"):]
        if b"/FlateDecode" not in hdr:
            continue
        stop = body.find(b"endstream", s.end())
        if stop < 0:
            bad_streams += 1
            continue
        raw = body[s.end():stop]
        try:
            if b"/ASCII85Decode" in hdr:
                raw = raw.strip()
                if b"~>" in raw:
                    raw = base64.a85decode(raw[:raw.rfind(b"~>") + 2], adobe=True)
                else:
                    raw = base64.a85decode(raw)
            zlib.decompressobj().decompress(raw)
        except (zlib.error, ValueError):
            bad_streams += 1
    if bad_streams:
        issues.append(f"{bad_streams} compressed stream(s) fail to inflate")
    info["streams_bad"] = bad_streams
    if not objs:
        issues.append("no PDF objects found")
    if not xref_ok or bad_streams or not objs:
        return ValidationResult(CORRUPT, end, issues, info)
    return ValidationResult(INTACT, end, issues, info)


def _check_xref_table(body: bytes, off: int, issues: list[str], info: dict) -> bool:
    pos = off + 4
    checked = bad = 0
    sub = re.compile(rb"\s*(\d+)\s+(\d+)\s*\r?\n")
    while True:
        m = sub.match(body, pos)
        if not m:
            break
        start, count = int(m.group(1)), int(m.group(2))
        pos = m.end()
        for i in range(count):
            line = body[pos:pos + 20]
            pos += 20
            em = re.match(rb"(\d{10}) (\d{5}) ([nf])", line)
            if not em:
                issues.append("malformed xref entry")
                return False
            if em.group(3) == b"n":
                checked += 1
                o = int(em.group(1))
                om = _OBJ_RE.match(body, o)
                if not om or int(om.group(1)) != start + i:
                    bad += 1
    info["xref"] = "table"
    info["xref_entries"] = checked
    if bad:
        issues.append(f"{bad} xref entries point to wrong offsets")
        return False
    return checked > 0


# ============================================================================ ZIP / OOXML
def _ooxml_kind(names: list[str]) -> str | None:
    s = set(names)
    if "[Content_Types].xml" in s:
        if any(n.startswith("word/") for n in names):
            return "docx"
        if any(n.startswith("xl/") for n in names):
            return "xlsx"
        if any(n.startswith("ppt/") for n in names):
            return "pptx"
    if "mimetype" in s and any(n == "content.xml" for n in names):
        return "odf"
    if "META-INF/MANIFEST.MF" in s:
        return "jar"
    return None


def parse_eocd(data: bytes, pos: int) -> dict | None:
    if data[pos:pos + 4] != b"PK\x05\x06" or pos + 22 > len(data):
        return None
    _, _, _, n_disk, n_total, cd_size, cd_off, clen = struct.unpack_from("<4sHHHHIIH", data, pos)
    return {"entries": n_total, "cd_size": cd_size, "cd_offset": cd_off, "comment_len": clen,
            "end": pos + 22 + clen}


def zip_end(data: bytes) -> tuple[int | None, bool]:
    """Find the end of a ZIP in a window. Returns (length, consistent).

    The first EOCD after the header normally belongs to the file. If it disagrees with its own
    central-directory offset we look for a later, consistent EOCD (nested stored archives) and
    otherwise return the first one with ``consistent=False`` — a strong fragmentation hint."""
    first = None
    pos = 0
    while True:
        e = data.find(b"PK\x05\x06", pos)
        if e < 0:
            break
        eo = parse_eocd(data, e)
        if eo:
            if eo["cd_offset"] + eo["cd_size"] == e:
                return eo["end"], True
            if first is None:
                first = eo["end"]
        pos = e + 4
    return first, False


def validate_zip(data: bytes) -> ValidationResult:
    issues: list[str] = []
    info: dict = {}
    if not data.startswith(b"PK\x03\x04"):
        return ValidationResult(CORRUPT, None, ["missing local file header"], info)
    e = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    eo = parse_eocd(data, e) if e >= 0 else None
    if eo is None:
        # truncated: count readable local entries
        pos, good = 0, 0
        while data[pos:pos + 4] == b"PK\x03\x04" and pos + 30 <= len(data):
            csize, _, nlen, elen = struct.unpack_from("<IIHH", data, pos + 18)
            pos += 30 + nlen + elen + csize
            if pos <= len(data):
                good += 1
        info["entries_readable"] = good
        issues.append("truncated: end-of-central-directory record not found")
        return ValidationResult(PARTIAL, None, issues, info)
    info["entries"] = eo["entries"]
    if eo["cd_offset"] + eo["cd_size"] != e:
        info["cd_gap"] = e - (eo["cd_offset"] + eo["cd_size"])
        issues.append(f"central directory offset mismatch by {info['cd_gap']} bytes (fragmented?)")
        return ValidationResult(CORRUPT, eo["end"], issues, info)
    pos, names, bad = eo["cd_offset"], [], 0
    for _ in range(eo["entries"]):
        if data[pos:pos + 4] != b"PK\x01\x02":
            issues.append(f"bad central directory entry at offset {pos}")
            return ValidationResult(CORRUPT, eo["end"], issues, info)
        (method, _, _, crc, csize, usize, nlen, elen, clen) = struct.unpack_from("<HHHIIIHHH", data, pos + 10)
        loff = struct.unpack_from("<I", data, pos + 42)[0]
        name = data[pos + 46: pos + 46 + nlen].decode("utf-8", "replace")
        names.append(name)
        pos += 46 + nlen + elen + clen
        if data[loff:loff + 4] != b"PK\x03\x04":
            bad += 1
            issues.append(f"entry '{name}': local header missing at offset {loff}")
            continue
        lnlen, lelen = struct.unpack_from("<HH", data, loff + 26)
        start = loff + 30 + lnlen + lelen
        comp = data[start:start + csize]
        try:
            if method == 0:
                raw = comp
            elif method == 8:
                raw = zlib.decompressobj(-15).decompress(comp)
            else:
                continue
            if len(raw) != usize or zlib.crc32(raw) & 0xFFFFFFFF != crc:
                bad += 1
                issues.append(f"entry '{name}': CRC/size mismatch")
        except zlib.error as exc:
            bad += 1
            issues.append(f"entry '{name}': inflate error ({exc})")
    info["names"] = names[:50]
    kind = _ooxml_kind(names)
    if kind:
        info["container"] = kind
    if bad:
        info["bad_entries"] = bad
        return ValidationResult(CORRUPT, eo["end"], issues, info)
    return ValidationResult(INTACT, eo["end"], issues, info)


# ============================================================================ MP4 / ISO-BMFF
MP4_TOP_BOXES = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"moof", b"mfra",
                 b"meta", b"pdin", b"sidx", b"styp", b"emsg", b"prft", b"ssix", b"pnot"}


def mp4_walk(read, start: int, limit: int) -> tuple[int | None, list[tuple[bytes, int, int]], list[str]]:
    """Walk top-level boxes using ``read(offset, n)``. Returns (length, boxes, issues)."""
    pos, boxes, issues = start, [], []
    while pos + 8 <= limit:
        hdr = read(pos, 16)
        if len(hdr) < 8:
            break
        size, typ = struct.unpack_from(">I4s", hdr)
        if typ not in MP4_TOP_BOXES:
            break
        if size == 1:
            if len(hdr) < 16:
                break
            size = struct.unpack_from(">Q", hdr, 8)[0]
        elif size == 0:
            size = limit - pos
        if size < 8:
            issues.append(f"invalid box size at offset {pos - start}")
            break
        boxes.append((typ, pos - start, size))
        pos += size
    if not boxes:
        return None, boxes, issues
    return pos - start, boxes, issues


def validate_mp4(data: bytes) -> ValidationResult:
    def read(off, n):
        return data[off:off + n]
    length, boxes, issues = mp4_walk(read, 0, len(data))
    info = {"boxes": [b[0].decode() for b in boxes]}
    if not boxes or boxes[0][0] != b"ftyp":
        issues.append("first box is not ftyp")
        return ValidationResult(CORRUPT, length, issues, info)
    info["brand"] = data[8:12].decode("latin-1")
    if length is not None and length > len(data):
        issues.append("truncated: last box extends beyond available data")
        return ValidationResult(PARTIAL, None, issues, info)
    types = {b[0] for b in boxes}
    if b"moov" not in types or (b"mdat" not in types and b"moof" not in types):
        issues.append("missing moov or mdat box")
        return ValidationResult(PARTIAL if b"moov" not in types else CORRUPT, length, issues, info)
    _, off, size = next(b for b in boxes if b[0] == b"moov")
    moov = data[off + 8: off + size]
    if b"mvhd" not in moov[:64]:
        issues.append("moov box has no mvhd header")
        return ValidationResult(CORRUPT, length, issues, info)
    return ValidationResult(INTACT, length, issues, info)


VALIDATORS = {
    "jpeg": validate_jpeg, "png": validate_png, "gif": validate_gif, "pdf": validate_pdf,
    "zip": validate_zip, "docx": validate_zip, "xlsx": validate_zip, "pptx": validate_zip,
    "mp4": validate_mp4,
}


def validate(type_name: str, data: bytes) -> ValidationResult:
    fn = VALIDATORS.get(type_name)
    if fn is None:
        return ValidationResult(UNKNOWN, len(data), ["no structural validator for this type"], {})
    try:
        return fn(data)
    except Exception as exc:  # noqa: BLE001 - malformed input must never crash recovery
        return ValidationResult(CORRUPT, None, [f"validator error: {exc}"], {})
