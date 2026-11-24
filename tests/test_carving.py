"""Signature carving against generated images (no file-system help)."""
import json
import random

from evidentia.core.source import EvidenceSource
from evidentia.recovery import signatures
from evidentia.recovery import validators as V
from evidentia.recovery.carver import IntervalSet, carve
from evidentia.testdata import samples as S


def _carve_hashes(path, **kw):
    import hashlib
    with EvidenceSource(path) as src:
        out = list(carve(src.read, src.size, **kw))
    return out, {hashlib.sha256(c.data).hexdigest(): c for c in out}


def test_carving_finds_every_contiguous_planted_file(images, truth):
    d, meta = images
    _, hashes = _carve_hashes(d / "fat32.img", cluster=1024)
    expected = [f for f in meta["files"] if f["image"] == "fat32.img" and f["type"] != "text" and f["type"] != "data"
                and f["state"] in ("allocated", "deleted", "deleted-mismatch", "orphaned")]
    missing = [f["path"] for f in expected if f["sha256"] not in hashes]
    assert not missing, f"not carved: {missing}"
    for f in expected:
        assert hashes[f["sha256"]].validation.status == V.INTACT


def test_carving_reconstructs_bifragmented_files(images):
    d, meta = images
    _, hashes = _carve_hashes(d / "fat32.img", cluster=1024)
    for f in meta["files"]:
        if f["state"] == "deleted-fragmented":
            c = hashes.get(f["sha256"])
            assert c is not None, f"{f['path']} not reconstructed"
            assert c.reconstructed and len(c.fragments) == 2
            assert [list(x) for x in c.fragments] == f["fragments"]


def test_corrupted_file_is_not_falsely_reconstructed(images):
    d, meta = images
    out, hashes = _carve_hashes(d / "fat32.img", cluster=1024)
    bad = next(f for f in meta["files"] if f["state"] == "deleted-corrupted")
    at = [c for c in out if c.offset == bad["offset"]]
    assert at and at[0].validation.status == V.CORRUPT and not at[0].reconstructed


def test_carving_inside_ext4(images, truth):
    d, meta = images
    _, hashes = _carve_hashes(d / "ext4.img", cluster=4096)
    for f in meta["files"]:
        if f["image"] == "ext4.img" and f["type"] in ("jpeg", "gif", "xlsx", "pdf", "docx"):
            assert f["sha256"] in hashes, f["path"]


def test_exclusion_of_allocated_ranges():
    blob = bytearray(1 << 20)
    jpg = S.jpeg(5, "x")
    blob[4096:4096 + len(jpg)] = jpg
    read = lambda o, n: bytes(blob[o:o + n])  # noqa: E731
    assert len(list(carve(read, len(blob)))) == 1
    assert list(carve(read, len(blob), exclude=IntervalSet([(4096, 8192)]))) == []


def test_pluggable_signature_table(tmp_path):
    spec = [{"name": "testfmt", "extensions": ["tst"], "header_hex": "deadbeef4556", "footer_hex": "cafef00d",
             "max_size": 100000}]
    p = tmp_path / "sigs.json"
    p.write_text(json.dumps(spec))
    try:
        sigs = signatures.load_json(str(p))
        blob = bytearray(64 * 1024)
        payload = bytes.fromhex("deadbeef4556") + random.Random(1).randbytes(3000) + bytes.fromhex("cafef00d")
        blob[8192:8192 + len(payload)] = payload
        out = list(carve(lambda o, n: bytes(blob[o:o + n]), len(blob), signatures=sigs))
        assert len(out) == 1 and out[0].data == payload and out[0].validation.status == V.UNKNOWN
    finally:
        signatures.SIGS.pop("testfmt", None)
