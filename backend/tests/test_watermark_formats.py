"""
Tests for the multi-format watermark handlers and the dispatcher.
"""
import io
import json
import os
import re
import tempfile
import zipfile

import numpy as np
import pymupdf
import pytest
from PIL import Image
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from backend.app.watermark import formats
from backend.app.watermark.dct_watermark import generate_watermark_id
from backend.app.watermark.handlers import common, container, image, text

ZW_RE = re.compile("[\u200b\u200c\u2060]")
IMAGE_SIZE = (640, 480)


def _wm(tag: str) -> str:
    return generate_watermark_id("doc-hash", f"USER-{tag}", "SES-1", f"nonce-{tag}")


def _pdf_bytes(lines: int = 2) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(72, 720, "Confidential forensic report")
    for index in range(lines):
        c.drawString(72, 700 - index * 18, f"Recipient copy line {index + 1}")
    c.showPage()
    c.save()
    return buf.getvalue()


def _image_bytes(fmt: str, mode: str = "RGB", size: tuple[int, int] = IMAGE_SIZE) -> bytes:
    width, height = size
    rng = np.random.default_rng(1234)
    array = rng.integers(60, 200, size=(height, width, 3), dtype=np.uint8)
    array[:, :, 0] = np.linspace(0, 255, width, dtype=np.uint8)[None, :]
    img = Image.fromarray(array, "RGB")
    if mode == "RGBA":
        alpha = np.tile(np.linspace(0, 255, width, dtype=np.uint8), (height, 1))
        img = img.convert("RGBA")
        img.putalpha(Image.fromarray(alpha, "L"))
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def _minimal_docx() -> bytes:
    content_types = (
        '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
    )
    rels = (
        '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>'
    )
    document = (
        '<?xml version="1.0"?><w:document '
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
        '<w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document)
    return buf.getvalue()


def _minimal_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("data.txt", b"not ooxml")
    return buf.getvalue()


def _strip_zw(data: bytes) -> bytes:
    return ZW_RE.sub("", data.decode("utf-8")).encode("utf-8")


def test_extension_sets():
    expected = {
        ".pdf", ".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff",
        ".txt", ".csv", ".tsv", ".md", ".log", ".json", ".xml", ".yaml", ".yml",
        ".docx", ".xlsx", ".pptx",
    }
    assert expected <= formats.SUPPORTED_EXTENSIONS
    assert formats.IMAGE_EXTENSIONS == {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}
    assert formats.OOXML_EXTENSIONS == {".docx", ".xlsx", ".pptx"}


@pytest.mark.parametrize("fmt,extension", [
    ("PNG", ".png"), ("JPEG", ".jpg"), ("BMP", ".bmp"), ("TIFF", ".tiff"), ("WEBP", ".webp"),
])
def test_image_roundtrip(fmt, extension):
    wm = _wm(fmt)
    data = _image_bytes(fmt)
    out = formats.embed_watermark(data, wm, "photo" + extension)
    assert formats.handler_kind("photo" + extension) == "image"
    assert formats.extract_watermark(out, "photo" + extension) == wm
    with Image.open(io.BytesIO(out)) as img:
        assert img.size == IMAGE_SIZE


def test_image_psnr_above_30db():
    data = _image_bytes("PNG")
    wm = _wm("PSNR")
    out = formats.embed_watermark(data, wm, "photo.png")
    original = np.array(Image.open(io.BytesIO(data)).convert("RGB")).astype(np.float64)
    marked = np.array(Image.open(io.BytesIO(out)).convert("RGB")).astype(np.float64)
    mse = float(np.mean((original - marked) ** 2))
    psnr = 20 * np.log10(255.0 / np.sqrt(mse))
    print(f"\nimage channel PSNR: {psnr:.2f} dB")
    assert psnr > 30.0


def test_image_rgba_keeps_alpha():
    data = _image_bytes("PNG", mode="RGBA")
    wm = _wm("RGBA")
    out = formats.embed_watermark(data, wm, "alpha.png")
    with Image.open(io.BytesIO(data)) as source, Image.open(io.BytesIO(out)) as marked:
        assert marked.mode == "RGBA"
        assert np.array_equal(np.array(source.getchannel("A")), np.array(marked.getchannel("A")))
    assert formats.extract_watermark(out, "alpha.png") == wm


def test_small_image_falls_back_to_container():
    data = _image_bytes("PNG", size=(64, 64))
    wm = _wm("SMALL")
    out = formats.embed_watermark(data, wm, "tiny.png")
    assert zipfile.is_zipfile(io.BytesIO(out))
    assert formats.extract_watermark(out, "tiny.png") == wm


def test_handlers_direct_api():
    wm = _wm("DIRECT")
    assert image.extract_image(image.embed_image(_image_bytes("PNG"), wm)) == wm
    assert text.extract_text(text.embed_text(b"hello\n", wm, "a.txt")) == wm
    assert container.extract_container(container.embed_container(b"blob", wm, "a.bin")) == wm


def test_text_txt_roundtrip_and_visible_content():
    original = b"alpha\nbeta\ngamma\n"
    wm = _wm("TXT")
    out = formats.embed_watermark(original, wm, "notes.txt")
    assert formats.extract_watermark(out, "notes.txt") == wm
    assert _strip_zw(out) == original


def test_text_csv_roundtrip_and_visible_content():
    original = b"name,score\nalice,1\nbob,2\n"
    wm = _wm("CSV")
    out = formats.embed_watermark(original, wm, "table.csv")
    assert formats.extract_watermark(out, "table.csv") == wm
    assert _strip_zw(out) == original
    assert out.count(b"\n") == original.count(b"\n")


def test_text_json_roundtrip_and_validity():
    original = b'{"user": "alice", "roles": ["admin", "auditor"]}'
    wm = _wm("JSON")
    out = formats.embed_watermark(original, wm, "payload.json")
    assert formats.extract_watermark(out, "payload.json") == wm
    assert _strip_zw(out) == original
    assert isinstance(json.loads(out.decode("utf-8")), dict)


def test_text_yaml_roundtrip():
    original = b"name: alice\nrole: admin\n"
    wm = _wm("YAML")
    out = formats.embed_watermark(original, wm, "config.yaml")
    assert formats.extract_watermark(out, "config.yaml") == wm
    assert text.extract_text(out) == wm


def test_text_extract_returns_none_for_unwatermarked():
    assert text.extract_text(b"plain content") is None
    assert formats.extract_watermark(b"plain content", "plain.txt") is None


def test_json_without_string_literal_falls_back_to_container():
    wm = _wm("JSONNUM")
    out = formats.embed_watermark(b"12345", wm, "number.json")
    assert zipfile.is_zipfile(io.BytesIO(out))
    assert formats.extract_watermark(out, "number.json") == wm


@pytest.mark.parametrize("name,data", [
    ("page.html", b"<html><body>hello</body></html>"),
    ("data.xml", b"<root><item>1</item></root>"),
    ("notes.md", b"# Heading\n\nbody\n"),
    ("app.log", b"2026-01-01 boot\n"),
    ("settings.ini", b"[main]\nkey=value\n"),
    ("settings.cfg", b"key=value\n"),
    ("table.tsv", b"a\tb\n1\t2\n"),
])
def test_more_text_roundtrips(name, data):
    wm = _wm(name)
    out = formats.embed_watermark(data, wm, name)
    assert formats.extract_watermark(out, name) == wm


def test_container_bin_roundtrip_and_size():
    data = os.urandom(1024)
    wm = _wm("BIN")
    out = formats.embed_watermark(data, wm, "blob.bin")
    assert zipfile.is_zipfile(io.BytesIO(out))
    assert formats.extract_watermark(out, "blob.bin") == wm
    assert len(out) < 3 * len(data)
    with zipfile.ZipFile(io.BytesIO(out)) as archive:
        assert archive.testzip() is None
        assert archive.read("blob.bin") == data


def test_container_zip_input_keeps_members():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", b"alpha")
        archive.writestr("b.bin", b"beta")
    original = buf.getvalue()
    wm = _wm("ZIP")
    out = formats.embed_watermark(original, wm, "bundle.zip")
    assert zipfile.is_zipfile(io.BytesIO(out))
    assert formats.extract_watermark(out, "bundle.zip") == wm
    with zipfile.ZipFile(io.BytesIO(out)) as archive:
        assert archive.testzip() is None
        assert archive.namelist() == ["a.txt", "b.bin"]
        assert archive.read("a.txt") == b"alpha"
        assert archive.read("b.bin") == b"beta"
    assert len(out) < len(original) + 256

    wm2 = _wm("ZIP2")
    out2 = formats.embed_watermark(out, wm2, "bundle.zip")
    assert formats.extract_watermark(out2, "bundle.zip") == wm2
    assert len(out2) <= len(out) + 8


def test_container_extract_without_comment_returns_none():
    assert container.extract_container(_minimal_zip()) is None


def test_unknown_binary_extension_uses_container():
    payload = bytes(range(256)) * 4
    wm = _wm("XYZ")
    out = formats.embed_watermark(payload, wm, "data.xyz")
    assert zipfile.is_zipfile(io.BytesIO(out))
    assert formats.extract_watermark(out, "data.xyz") == wm
    assert formats.extract_watermark(out) == wm
    assert formats.output_filename("data.xyz") == "data.xyz.zip"
    with zipfile.ZipFile(io.BytesIO(out)) as archive:
        assert archive.read("data.xyz") == payload


def test_unknown_text_extension_uses_text_channel():
    original = b"mystery bytes\n"
    wm = _wm("XYZTEXT")
    out = formats.embed_watermark(original, wm, "data.xyz")
    assert not zipfile.is_zipfile(io.BytesIO(out))
    assert formats.extract_watermark(out, "data.xyz") == wm
    assert _strip_zw(out) == original


def test_container_tempfile_roundtrip():
    wm = _wm("TMP")
    with tempfile.TemporaryDirectory() as tmp:
        source = os.path.join(tmp, "blob.bin")
        with open(source, "wb") as handle:
            handle.write(bytes(range(256)) * 8)
        with open(source, "rb") as handle:
            out = formats.embed_watermark(handle.read(), wm, "blob.bin")
        target = os.path.join(tmp, "blob.bin.zip")
        with open(target, "wb") as handle:
            handle.write(out)
        with open(target, "rb") as handle:
            assert formats.extract_watermark(handle.read(), "blob.bin") == wm


def test_pdf_preserve_roundtrip_and_text():
    pdf = _pdf_bytes()
    wm = _wm("PDF")
    out = formats.embed_watermark(pdf, wm, "report.pdf")
    assert formats.handler_kind("report.pdf") == "pdf"
    doc = pymupdf.open(stream=out, filetype="pdf")
    page_text = doc[0].get_text()
    doc.close()
    assert "Confidential forensic report" in page_text
    assert formats.extract_watermark(out, "report.pdf") == wm


def test_pdf_rasterize_mode_through_dispatcher():
    wm = _wm("RAST")
    out = formats.embed_watermark(_pdf_bytes(), wm, "report.pdf", mode="rasterize")
    assert formats.extract_watermark(out) == wm


def test_filename_none_uses_pdf_magic():
    wm = _wm("NOPDF")
    out = formats.embed_watermark(_pdf_bytes(), wm)
    assert formats.extract_watermark(out) == wm


def test_filename_none_never_assumes_pdf():
    wm = _wm("NOPDF2")
    out = formats.embed_watermark(_image_bytes("PNG"), wm)
    assert zipfile.is_zipfile(io.BytesIO(out))
    assert formats.extract_watermark(out) == wm


def test_handler_kind_by_extension_and_sniffing():
    assert formats.handler_kind("a.pdf") == "pdf"
    for extension in sorted(formats.IMAGE_EXTENSIONS):
        assert formats.handler_kind("a" + extension) == "image"
    for extension in sorted(formats.TEXT_EXTENSIONS):
        assert formats.handler_kind("a" + extension) == "text"
    for extension in sorted(formats.OOXML_EXTENSIONS):
        assert formats.handler_kind("a" + extension) == "ooxml"
    assert formats.handler_kind("a.bin") == "container"
    assert formats.handler_kind(None, _pdf_bytes()) == "pdf"
    assert formats.handler_kind(None, _image_bytes("PNG")) == "image"
    assert formats.handler_kind(None, _minimal_docx()) == "ooxml"
    assert formats.handler_kind(None, _minimal_zip()) == "container"
    assert formats.handler_kind(None, b"hello world") == "text"
    assert formats.handler_kind(None, b"\x00\xff\x00\x01") == "container"


def test_different_recipients_and_sessions():
    wm1 = generate_watermark_id("doc", "ALICE", "SES-A", "nonce")
    wm2 = generate_watermark_id("doc", "BOB", "SES-A", "nonce")
    wm3 = generate_watermark_id("doc", "ALICE", "SES-B", "nonce")
    assert len({wm1, wm2, wm3}) == 3
    samples = {
        "doc.pdf": _pdf_bytes(),
        "img.png": _image_bytes("PNG"),
        "file.txt": b"hello\n",
        "blob.bin": os.urandom(64),
    }
    for name, data in samples.items():
        assert formats.extract_watermark(formats.embed_watermark(data, wm1, name), name) == wm1
        assert formats.extract_watermark(formats.embed_watermark(data, wm2, name), name) == wm2
        assert formats.extract_watermark(formats.embed_watermark(data, wm3, name), name) == wm3


def test_invalid_watermark_id_raises():
    for invalid in ("", "WM-", "WM-ABC", "not-a-watermark", "WM-!!!!!!!!!!!!!!!!!!!!!!!!!!"):
        with pytest.raises(ValueError):
            formats.embed_watermark(b"payload", invalid, "file.txt")


@pytest.mark.parametrize("payload", [b"", b"\x00\x01\x02\x03", b"%PDF-1.7 broken", bytes(range(256))])
def test_extract_never_raises_on_garbage(payload):
    assert formats.extract_watermark(payload) is None


def test_is_supported():
    assert formats.is_supported("report.pdf")
    assert formats.is_supported("photo.png")
    assert formats.is_supported("data.xyz")
    assert not formats.is_supported("")
    assert not formats.is_supported(None)


def test_output_helpers():
    assert formats.output_filename("report.pdf") == "report.pdf"
    assert formats.output_filename("photo.png") == "photo.png"
    assert formats.output_filename("blob.bin") == "blob.bin.zip"
    assert formats.output_filename("bundle.zip") == "bundle.zip"
    assert formats.output_media_type("report.pdf") == "application/pdf"
    assert formats.output_media_type("blob.bin") in ("application/zip", "application/x-zip-compressed")
    assert formats.output_media_type("notes.txt").startswith("text/")


def test_zero_width_primitives():
    wm = _wm("ZW")
    marker = common.zw_marker(wm)
    assert marker.startswith("\u2060") and marker.endswith("\u2060")
    assert set(marker[1:-1]) <= {"\u200b", "\u200c"}
    assert common.zw_find("pre" + marker + "post") == [wm]
    assert common.zw_find("no markers here") == []
    assert common.zw_find(marker[:10]) == []


def test_every_supported_extension_handles_a_sample():
    wm = _wm("SWEEP")
    samples = {
        ".pdf": _pdf_bytes(),
        ".txt": b"alpha\n",
        ".csv": b"a,b\n1,2\n",
        ".tsv": b"a\tb\n1\t2\n",
        ".md": b"# t\n",
        ".markdown": b"# t\n",
        ".log": b"boot\n",
        ".json": b'{"k": "v"}',
        ".xml": b"<r><i>1</i></r>",
        ".yaml": b"k: v\n",
        ".yml": b"k: v\n",
        ".html": b"<html><body>hi</body></html>",
        ".htm": b"<html><body>hi</body></html>",
        ".ini": b"[s]\nk=v\n",
        ".cfg": b"k=v\n",
    }
    for extension in formats.IMAGE_EXTENSIONS:
        samples[extension] = _image_bytes("PNG", size=(96, 96))
    for extension in formats.OOXML_EXTENSIONS:
        samples[extension] = _minimal_zip()
    missing = formats.SUPPORTED_EXTENSIONS - set(samples)
    assert not missing, missing
    for extension in sorted(formats.SUPPORTED_EXTENSIONS):
        out = formats.embed_watermark(samples[extension], wm, "sample" + extension)
        assert formats.extract_watermark(out, "sample" + extension) == wm, extension


def test_ooxml_docx_dispatcher_smoke():
    pytest.importorskip("backend.app.watermark.handlers.ooxml")
    docx = _minimal_docx()
    wm = _wm("DOCX")
    out = formats.embed_watermark(docx, wm, "sample.docx")
    assert formats.handler_kind("sample.docx") == "ooxml"
    assert formats.extract_watermark(out, "sample.docx") == wm
    with zipfile.ZipFile(io.BytesIO(docx)) as source, zipfile.ZipFile(io.BytesIO(out)) as archive:
        assert archive.testzip() is None
        assert archive.namelist() == source.namelist()
        assert archive.read("[Content_Types].xml") == source.read("[Content_Types].xml")
        assert archive.read("_rels/.rels") == source.read("_rels/.rels")
        assert b"Hello" in archive.read("word/document.xml")
