"""Pluggable carving signature table.

A :class:`Signature` describes how to find a file's start (header regex), how to find its end
(a structural ``measure`` function or a plain footer + max size), and which validator checks it.
Extra signatures can be registered at runtime with :func:`register` or loaded from a JSON file
(:func:`load_json`), e.g.::

    [{"name": "bmp", "extensions": ["bmp"], "mime": "image/bmp", "header_hex": "424d",
      "footer_hex": null, "max_size": 20000000}]
"""
from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import validators as V

MiB = 1024 * 1024
# measure(read, start, limit) -> length or None
MeasureFn = Callable[[Callable[[int, int], bytes], int, int], Optional[int]]


@dataclass
class Signature:
    name: str
    extensions: tuple[str, ...]
    mime: str
    header: bytes                  # regex (bytes) matched against raw data
    max_size: int
    footer: bytes | None = None    # literal footer for the generic strategy
    header_offset: int = 0         # file starts this many bytes BEFORE the regex match
    measure: MeasureFn | None = None
    family: str = "other"
    expected_entropy: tuple[float, float] = (0.0, 8.0)
    reconstructable: bool = False  # bifragment reconstruction supported
    description: str = ""
    _re: re.Pattern = field(init=False, repr=False)

    def __post_init__(self):
        self._re = re.compile(self.header, re.DOTALL)

    def find_end(self, read, start: int, limit: int) -> int | None:
        if self.measure:
            return self.measure(read, start, limit)
        if self.footer:
            window = read(start, min(self.max_size, limit - start))
            i = window.find(self.footer, 1)
            return i + len(self.footer) if i >= 0 else None
        return None


def _window(read, start, limit, cap):
    return read(start, min(cap, limit - start))


def _m_jpeg(read, start, limit):
    return V.jpeg_structure(_window(read, start, limit, SIGS["jpeg"].max_size)).length


def _m_png(read, start, limit):
    return V.validate_png(_window(read, start, limit, SIGS["png"].max_size)).length


def _m_gif(read, start, limit):
    data = _window(read, start, limit, SIGS["gif"].max_size)
    r = V.validate_gif(data)
    if r.length:
        return r.length
    i = data.find(b"\x00\x3b")  # fallback: block terminator + trailer
    return i + 2 if i > 0 else None


def _m_pdf(read, start, limit):
    return V.pdf_end(_window(read, start, limit, SIGS["pdf"].max_size))


def _m_zip(read, start, limit):
    return V.zip_end(_window(read, start, limit, SIGS["zip"].max_size))[0]


def _m_mp4(read, start, limit):
    hdr = read(start, 8)
    if len(hdr) < 8 or not 8 <= struct.unpack(">I", hdr[:4])[0] <= 1024:
        return None
    length, boxes, _ = V.mp4_walk(read, start, min(limit, start + SIGS["mp4"].max_size))
    return length if boxes and len(boxes) >= 2 else None


SIGS: dict[str, Signature] = {}


def register(sig: Signature) -> Signature:
    SIGS[sig.name] = sig
    return sig


register(Signature("jpeg", ("jpg", "jpeg", "jpe", "jfif"), "image/jpeg", rb"\xff\xd8\xff[\xc0-\xfe]",
                   32 * MiB, footer=b"\xff\xd9", measure=_m_jpeg, family="image",
                   expected_entropy=(7.0, 8.0), reconstructable=True, description="JPEG/JFIF/EXIF image"))
register(Signature("png", ("png",), "image/png", rb"\x89PNG\r\n\x1a\n", 32 * MiB,
                   footer=b"IEND\xaeB`\x82", measure=_m_png, family="image",
                   expected_entropy=(6.0, 8.0), description="Portable Network Graphics"))
register(Signature("gif", ("gif",), "image/gif", rb"GIF8[79]a", 16 * MiB, footer=b"\x00\x3b",
                   measure=_m_gif, family="image", expected_entropy=(5.0, 8.0),
                   description="GIF image / animation"))
register(Signature("pdf", ("pdf",), "application/pdf", rb"%PDF-[12]\.\d", 64 * MiB, footer=b"%%EOF",
                   measure=_m_pdf, family="document", expected_entropy=(4.0, 8.0),
                   description="Portable Document Format"))
register(Signature("zip", ("zip", "docx", "xlsx", "pptx", "jar", "odt", "ods", "apk", "epub"),
                   "application/zip", rb"PK\x03\x04[\x0a-\x3f]\x00", 128 * MiB, footer=b"PK\x05\x06",
                   measure=_m_zip, family="archive", expected_entropy=(6.5, 8.0), reconstructable=True,
                   description="ZIP archive / OOXML (DOCX, XLSX, PPTX)"))
register(Signature("mp4", ("mp4", "m4v", "m4a", "mov", "3gp"), "video/mp4",
                   rb"ftyp(?:isom|iso[2-6]|mp41|mp42|avc1|M4V |M4A |qt  |dash|3gp[4-6]|MSNV)", 512 * MiB,
                   header_offset=4, measure=_m_mp4, family="video", expected_entropy=(6.5, 8.0),
                   description="MPEG-4 / ISO base media file"))

# Types the classifier can name that are refinements of a carving signature.
DERIVED = {
    "docx": ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "document"),
    "xlsx": ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "document"),
    "pptx": ("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "document"),
}


def load_json(path: str) -> list[Signature]:
    """Load additional generic (header/footer/max-size) signatures from a JSON file."""
    out = []
    for item in json.loads(open(path, encoding="utf-8").read()):
        sig = Signature(
            name=item["name"], extensions=tuple(item.get("extensions", [item["name"]])),
            mime=item.get("mime", "application/octet-stream"),
            header=re.escape(bytes.fromhex(item["header_hex"])),
            footer=bytes.fromhex(item["footer_hex"]) if item.get("footer_hex") else None,
            max_size=int(item.get("max_size", 10 * MiB)), family=item.get("family", "other"),
            description=item.get("description", "user-defined signature"))
        out.append(register(sig))
    return out


def enabled(names: list[str] | None = None) -> list[Signature]:
    return [s for n, s in SIGS.items() if names is None or n in names]
