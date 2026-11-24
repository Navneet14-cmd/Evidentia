"""Bifragment reconstruction on synthetic layouts."""
import random

from evidentia.recovery.fragments import reconstruct_jpeg, reconstruct_zip
from evidentia.testdata import samples as S

CL = 4096


def _layout(data, head_clusters, gap):
    head = data[: head_clusters * CL]
    tail = data[head_clusters * CL:]
    pad = (-len(tail)) % CL
    blob = bytes(CL) + head + gap + tail + bytes(pad) + bytes(4 * CL)
    return blob, CL


def test_jpeg_bifragment_random_gap():
    jpg = S.jpeg(21, "frag", 640, 480)
    blob, start = _layout(jpg, 6, random.Random(3).randbytes(5 * CL))
    rec = reconstruct_jpeg(lambda o, n: blob[o:o + n], start, len(blob), CL)
    assert rec is not None and rec.data == jpg
    assert rec.fragments == [(start, 6 * CL), (start + 11 * CL, len(jpg) - 6 * CL)]


def test_jpeg_bifragment_zero_gap():
    jpg = S.jpeg(22, "frag", 640, 480)
    blob, start = _layout(jpg, 4, bytes(3 * CL))
    rec = reconstruct_jpeg(lambda o, n: blob[o:o + n], start, len(blob), CL)
    assert rec is not None and rec.data == jpg


def test_zip_bifragment():
    dx = S.docx(23, "Fragmented docx", ["x" * 500])
    blob, start = _layout(dx, len(dx) // CL // 2 or 1, random.Random(4).randbytes(7 * CL))
    rec = reconstruct_zip(lambda o, n: blob[o:o + n], start, len(blob), CL)
    assert rec is not None and rec.data == dx


def test_contiguous_file_needs_no_reconstruction():
    jpg = S.jpeg(24, "ok")
    blob = bytes(CL) + jpg + bytes(CL)
    assert reconstruct_jpeg(lambda o, n: blob[o:o + n], CL, len(blob), CL) is None


def test_in_place_overwrite_is_not_reconstructed():
    jpg = bytearray(S.jpeg(25, "overwritten", 640, 480))
    jpg[5 * CL:7 * CL] = random.Random(9).randbytes(2 * CL)
    blob = bytes(CL) + bytes(jpg) + bytes(CL)
    assert reconstruct_jpeg(lambda o, n: blob[o:o + n], CL, len(blob), CL) is None
