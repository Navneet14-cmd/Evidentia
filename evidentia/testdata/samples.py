"""Deterministic sample file content (JPEG, PNG, GIF, PDF, DOCX, XLSX, MP4, text)."""
from __future__ import annotations

import io
import random
import struct
import zipfile

from PIL import Image, ImageDraw, ImageFont


def _font(size: int):
    try:
        return ImageFont.load_default(size=size)
    except TypeError:  # older Pillow
        return ImageFont.load_default()


def _picture(seed: int, w: int, h: int, label: str, noise: int = 40) -> Image.Image:
    rnd = random.Random(seed)
    base = [rnd.randint(30, 200) for _ in range(3)]
    im = Image.new("RGB", (w, h))
    px = im.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = (
                (base[0] + x * 160 // w + rnd.randint(-noise, noise)) % 256,
                (base[1] + y * 160 // h + rnd.randint(-noise, noise)) % 256,
                (base[2] + (x + y) * 80 // (w + h) + rnd.randint(-noise, noise)) % 256,
            )
    d = ImageDraw.Draw(im)
    for _ in range(6):
        x0, y0 = rnd.randint(0, w - 40), rnd.randint(0, h - 40)
        d.ellipse((x0, y0, x0 + rnd.randint(20, w // 3), y0 + rnd.randint(20, h // 3)),
                  outline=tuple(rnd.randint(0, 255) for _ in range(3)), width=4)
    d.rectangle((0, h - 44, w, h), fill=(10, 14, 24))
    d.text((12, h - 38), label, fill=(240, 240, 240), font=_font(26))
    return im


def jpeg(seed: int, label: str, w: int = 480, h: int = 360, quality: int = 90) -> bytes:
    buf = io.BytesIO()
    _picture(seed, w, h, label).save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def png(seed: int, label: str, w: int = 240, h: int = 180) -> bytes:
    buf = io.BytesIO()
    _picture(seed, w, h, label, noise=25).save(buf, "PNG")
    return buf.getvalue()


def gif(seed: int, label: str, w: int = 200, h: int = 150, frames: int = 4) -> bytes:
    imgs = []
    for i in range(frames):
        im = _picture(seed + i, w, h, f"{label} {i + 1}/{frames}", noise=10).convert("P", palette=Image.ADAPTIVE)
        imgs.append(im)
    buf = io.BytesIO()
    imgs[0].save(buf, "GIF", save_all=True, append_images=imgs[1:], duration=300, loop=0)
    return buf.getvalue()


def pdf(title: str, paragraphs: list[str]) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4, pageCompression=1, invariant=1)
    c.setTitle(title)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(60, 780, title)
    c.setFont("Helvetica", 11)
    y = 750
    for p in paragraphs:
        for line in [p[i:i + 90] for i in range(0, len(p), 90)]:
            c.drawString(60, y, line)
            y -= 16
            if y < 60:
                c.showPage()
                c.setFont("Helvetica", 11)
                y = 780
        y -= 8
    c.showPage()
    c.save()
    return buf.getvalue()


_CT_DOCX = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="png" ContentType="image/png"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""
_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{target}"/>
</Relationships>"""


def _zip(entries: list[tuple[str, bytes]], seed: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            zi = zipfile.ZipInfo(name, date_time=(2026, 11, 1, 10, seed % 60, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data)
    return buf.getvalue()


def docx(seed: int, title: str, paragraphs: list[str], with_image: bool = True) -> bytes:
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in [title] + paragraphs)
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           f"<w:body>{body}</w:body></w:document>")
    entries = [("[Content_Types].xml", _CT_DOCX.encode()),
               ("_rels/.rels", _RELS.format(target="word/document.xml").encode()),
               ("word/document.xml", doc.encode())]
    if with_image:
        entries.append(("word/media/image1.png", png(seed, title[:20], 200, 150)))
    return _zip(entries, seed)


def xlsx(seed: int, rows: list[list]) -> bytes:
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
          '</Types>')
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
          '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>')
    wbrels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
              '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
              '</Relationships>')
    cells = []
    for r, row in enumerate(rows, 1):
        cs = []
        for c, v in enumerate(row):
            ref = f"{chr(65 + c)}{r}"
            if isinstance(v, (int, float)):
                cs.append(f'<c r="{ref}"><v>{v}</v></c>')
            else:
                cs.append(f'<c r="{ref}" t="inlineStr"><is><t>{v}</t></is></c>')
        cells.append(f'<row r="{r}">{"".join(cs)}</row>')
    sheet = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
             f'<sheetData>{"".join(cells)}</sheetData></worksheet>')
    return _zip([("[Content_Types].xml", ct.encode()), ("_rels/.rels", _RELS.format(target="xl/workbook.xml").encode()),
                 ("xl/workbook.xml", wb.encode()), ("xl/_rels/workbook.xml.rels", wbrels.encode()),
                 ("xl/worksheets/sheet1.xml", sheet.encode())], seed)


def mp4(seed: int, payload: int = 120_000) -> bytes:
    """Structurally valid ISO-BMFF container (ftyp + moov/mvhd + mdat). Not a playable video."""
    rnd = random.Random(seed)

    def box(t: bytes, body: bytes) -> bytes:
        return struct.pack(">I", 8 + len(body)) + t + body
    ftyp = box(b"ftyp", b"isom" + struct.pack(">I", 512) + b"isomiso2avc1mp41")
    mvhd = box(b"mvhd", struct.pack(">I", 0) + struct.pack(">IIII", 0, 0, 1000, 10_000) + b"\x00" * 80)
    trak = box(b"trak", box(b"tkhd", b"\x00" * 84))
    moov = box(b"moov", mvhd + trak)
    mdat = box(b"mdat", rnd.randbytes(payload))
    return ftyp + moov + mdat


def text(seed: int, lines: int = 40) -> bytes:
    rnd = random.Random(seed)
    words = ("evidence custody hash ledger sector cluster report witness suspect device image "
             "timeline examiner warrant seizure analysis recovered deleted").split()
    return "\n".join(" ".join(rnd.choice(words) for _ in range(12)) for _ in range(lines)).encode() + b"\n"
