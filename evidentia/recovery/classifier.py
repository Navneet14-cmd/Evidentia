"""Content-based file type classification (never trusts the extension)."""
from __future__ import annotations

import os
from dataclasses import dataclass

from .signatures import DERIVED, SIGS
from .validators import _ooxml_kind

try:
    import filetype as _filetype
except ImportError:  # pragma: no cover
    _filetype = None

TEXT_EXTS = {"txt", "log", "csv", "md", "json", "xml", "html", "htm", "ini", "cfg", "yaml", "yml", "py"}
# extension groups that are legitimately interchangeable
COMPATIBLE = [{"jpg", "jpeg", "jpe", "jfif"}, {"mp4", "m4v", "m4a", "mov", "3gp"}, {"tif", "tiff"}]


@dataclass
class Classification:
    type: str            # canonical type id (jpeg, png, docx, text, data, ...)
    extension: str       # preferred extension for that type
    mime: str
    family: str
    method: str          # how it was decided: signature | container | filetype | heuristic
    claimed_extension: str = ""
    mismatch: bool = False

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _zip_kind(data: bytes) -> str | None:
    # look at central-directory file names (cheap: no decompression)
    names, pos = [], 0
    while True:
        i = data.find(b"PK\x01\x02", pos)
        if i < 0 or len(names) > 200:
            break
        nlen = int.from_bytes(data[i + 28:i + 30], "little")
        names.append(data[i + 46:i + 46 + nlen].decode("utf-8", "replace"))
        pos = i + 46
    if not names:  # no central directory (truncated) -> use local headers
        pos = 0
        while (i := data.find(b"PK\x03\x04", pos)) >= 0 and len(names) < 50:
            nlen = int.from_bytes(data[i + 26:i + 28], "little")
            names.append(data[i + 30:i + 30 + nlen].decode("utf-8", "replace"))
            pos = i + 30
    return _ooxml_kind(names)


def _looks_text(data: bytes) -> bool:
    sample = data[:8192]
    if not sample or b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start < len(sample) - 4:
            return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample) > 0.9


def classify(data: bytes, name: str | None = None) -> Classification:
    claimed = os.path.splitext(name or "")[1].lower().lstrip(".")
    cls = None
    for sig in SIGS.values():
        m = sig._re.match(data, sig.header_offset) if len(data) > sig.header_offset else None
        if m:
            cls = Classification(sig.name, sig.extensions[0], sig.mime, sig.family, "signature")
            break
    if cls and cls.type == "zip":
        kind = _zip_kind(data)
        if kind in DERIVED:
            ext, mime, fam = DERIVED[kind]
            cls = Classification(kind, ext, mime, fam, "container")
    if cls is None and _filetype is not None:
        g = _filetype.guess(data[:8192])
        if g:
            cls = Classification(g.extension, g.extension, g.mime, g.mime.split("/")[0], "filetype")
    if cls is None:
        if _looks_text(data):
            cls = Classification("text", "txt", "text/plain", "text", "heuristic")
        else:
            cls = Classification("data", "bin", "application/octet-stream", "other", "heuristic")
    cls.claimed_extension = claimed
    cls.mismatch = bool(claimed) and not _ext_ok(cls, claimed)
    return cls


def _ext_ok(cls: Classification, claimed: str) -> bool:
    if cls.type == "data":
        return True  # unknown content: nothing to compare against
    if cls.type == "text":
        return claimed in TEXT_EXTS
    valid = set(SIGS[cls.type].extensions) if cls.type in SIGS else {cls.extension}
    if cls.type in DERIVED:
        valid = {cls.extension}
    if claimed in valid:
        return True
    return any(claimed in g and cls.extension in g for g in COMPATIBLE)


def expected_entropy(type_name: str) -> tuple[float, float]:
    if type_name in SIGS:
        return SIGS[type_name].expected_entropy
    if type_name in DERIVED:
        return SIGS["zip"].expected_entropy
    if type_name == "text":
        return (2.5, 6.0)
    return (0.0, 8.0)
