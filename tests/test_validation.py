"""Structure-based validation: intact vs truncated vs corrupted, per format."""
import random

import pytest

from evidentia.recovery import validators as V
from evidentia.testdata import samples as S

SAMPLES = {
    "jpeg": lambda: S.jpeg(101, "validation"),
    "png": lambda: S.png(102, "validation"),
    "gif": lambda: S.gif(103, "validation"),
    "pdf": lambda: S.pdf("Validation", [S.text(104, 8).decode()]),
    "zip": lambda: S.docx(105, "Validation", ["body text"]),
    "mp4": lambda: S.mp4(106),
}


@pytest.mark.parametrize("kind", SAMPLES)
def test_intact(kind):
    data = SAMPLES[kind]()
    r = V.validate(kind, data)
    assert r.status == V.INTACT, r.issues
    assert r.length == len(data)


@pytest.mark.parametrize("kind", SAMPLES)
def test_truncated_is_not_intact(kind):
    data = SAMPLES[kind]()
    r = V.validate(kind, data[: len(data) * 6 // 10])
    assert r.status in (V.PARTIAL, V.CORRUPT)
    assert r.status != V.INTACT


@pytest.mark.parametrize("kind", ["jpeg", "png", "gif", "pdf", "zip"])
def test_random_overwrite_is_corrupt(kind):
    data = bytearray(SAMPLES[kind]())
    n = min(2048, len(data) // 8)        # damage the body, not the trailer
    mid = len(data) // 3
    data[mid:mid + n] = random.Random(7).randbytes(n)
    assert V.validate(kind, bytes(data)).status == V.CORRUPT


def test_jpeg_zero_filled_hole_is_corrupt():
    data = bytearray(SAMPLES["jpeg"]())
    data[30000:32048] = bytes(2048)
    r = V.validate("jpeg", bytes(data))
    assert r.status == V.CORRUPT
    assert any("zero-filled" in i or "decode" in i for i in r.issues)


def test_jpeg_entropy_check_counts_mcus():
    ok, why = V.jpeg_entropy_check(SAMPLES["jpeg"]())
    assert ok is True and "MCUs decoded exactly" in why


def test_jpeg_spliced_stream_fails_deep_check():
    a, b = S.jpeg(1, "a"), S.jpeg(2, "b")
    spliced = a[:40000] + b[45000:]
    assert V.validate_jpeg(spliced).status != V.INTACT


def test_png_crc_flip_detected():
    data = bytearray(SAMPLES["png"]())
    data[200] ^= 0xFF                    # inside the IDAT payload
    r = V.validate_png(bytes(data))
    assert r.status == V.CORRUPT and any("CRC" in i for i in r.issues)


def test_zip_reports_ooxml_container():
    r = V.validate_zip(SAMPLES["zip"]())
    assert r.info["container"] == "docx"


def test_zip_central_directory_gap_reported():
    data = SAMPLES["zip"]()
    gapped = data[:4096] + bytes(2048) + data[4096:]
    r = V.validate_zip(gapped)
    assert r.status == V.CORRUPT and r.info["cd_gap"] == 2048


def test_unknown_type():
    assert V.validate("text", b"hello").status == V.UNKNOWN
