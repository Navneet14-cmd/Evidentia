from evidentia.recovery.classifier import classify
from evidentia.testdata import samples as S


def test_content_beats_extension():
    c = classify(S.jpeg(1, "x"), "invoice.pdf")
    assert c.type == "jpeg" and c.mismatch


def test_ooxml_detection():
    assert classify(S.docx(1, "t", ["p"]), "a.docx").type == "docx"
    assert classify(S.xlsx(1, [["a", 1]]), "a.xlsx").type == "xlsx"
    assert not classify(S.xlsx(1, [["a", 1]]), "a.xlsx").mismatch


def test_compatible_extensions_are_not_mismatches():
    assert not classify(S.jpeg(1, "x"), "photo.JPEG").mismatch
    assert not classify(S.text(1), "notes.log").mismatch


def test_pdf_named_txt_is_mismatch():
    c = classify(S.pdf("t", ["x"]), "notes.txt")
    assert c.type == "pdf" and c.mismatch


def test_mp4_and_text():
    assert classify(S.mp4(1)).type == "mp4"
    assert classify(S.text(3)).type == "text"
    assert classify(bytes(range(256)) * 8).type == "data"
