"""
Tests for the v2 DCT + invisible-text watermarking pipeline.
"""
import io
import os
import re
import tempfile
import time

import numpy as np
import pymupdf
from PIL import Image
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

from backend.app.watermark.dct_watermark import (
    WATERMARK_BITS,
    _decode_image_bytes,
    calculate_psnr,
    embed_watermark,
    extract_watermark,
    generate_watermark_id,
)

ID_RE = re.compile(r"^WM-[A-Z2-7]{26}$")
ID_SCAN_RE = re.compile(r"WM-[A-Z2-7]{26}")
DPI = 150


def _make_text_pdf(pages: int = 1) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    for index in range(pages):
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, 730, f"Confidential forensic report - page {index + 1}")
        c.setFont("Helvetica", 10)
        for line in range(30):
            c.drawString(72, 700 - line * 20, f"Recipient copy line {line + 1}: watermark roundtrip content.")
        c.showPage()
    c.save()
    return buf.getvalue()


def _make_image_pdf(width: int = 1200, height: int = 800, seed: int = 7) -> bytes:
    rng = np.random.default_rng(seed)
    pixels = rng.integers(70, 190, size=(height, width, 3), dtype=np.uint8)
    for row in range(0, height, 37):
        pixels[row:row + 3, :] = 20
    buf = io.BytesIO()
    Image.fromarray(pixels).save(buf, format="PNG")

    out = io.BytesIO()
    c = canvas.Canvas(out, pagesize=letter)
    c.drawString(72, 740, "Document with an embedded raster image")
    c.drawImage(ImageReader(io.BytesIO(buf.getvalue())), 72, 260, width=468, height=312)
    c.showPage()
    c.save()
    return out.getvalue()


def _make_masked_image_pdf(width: int = 1200, height: int = 800, seed: int = 11) -> bytes:
    rng = np.random.default_rng(seed)
    pixels = rng.integers(70, 190, size=(height, width, 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(pixels).save(buf, format="PNG")
    image = buf.getvalue()
    gradient = np.tile(np.linspace(0, 255, width, dtype=np.uint8), (height, 1))
    buf = io.BytesIO()
    Image.fromarray(gradient, "L").save(buf, format="PNG")

    doc = pymupdf.open()
    page = doc.new_page(width=letter[0], height=letter[1])
    page.insert_image(pymupdf.Rect(72, 300, 540, 612), stream=image, mask=buf.getvalue())
    data = doc.tobytes()
    doc.close()
    return data


def _rebuild_as_jpeg_pdf(pdf_bytes: bytes, quality: int = 85) -> bytes:
    src = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    out = pymupdf.open()
    zoom = DPI / 72.0
    matrix = pymupdf.Matrix(zoom, zoom)
    try:
        for page in src:
            rect = page.rect
            pix = page.get_pixmap(matrix=matrix, alpha=False)
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=quality)
            new_page = out.new_page(width=rect.width, height=rect.height)
            new_page.insert_image(rect, stream=buf.getvalue(), keep_proportion=False, overlay=True)
        return out.tobytes()
    finally:
        src.close()
        out.close()


def test_watermark_id_format_and_determinism():
    wm = generate_watermark_id("abc", "alice", "SES-123", "nonceXYZ")
    assert ID_RE.match(wm)
    assert len(wm) == 29
    assert wm.isupper()
    assert WATERMARK_BITS == (29 + 4) * 8
    assert wm == generate_watermark_id("abc", "ALICE", "SES-123", "nonceXYZ")
    assert wm == generate_watermark_id("abc", "alice", "SES-123", "nonceXYZ")


def test_watermark_id_uniqueness_across_recipients_and_sessions():
    wm = generate_watermark_id("hash", "ALICE", "SES-AAA", "nonce1")
    assert generate_watermark_id("hash", "BOB", "SES-AAA", "nonce1") != wm
    assert generate_watermark_id("hash", "ALICE", "SES-BBB", "nonce1") != wm
    assert generate_watermark_id("other", "ALICE", "SES-AAA", "nonce1") != wm
    assert generate_watermark_id("hash", "ALICE", "SES-AAA", "nonce2") != wm


def test_roundtrip_multipage_text_pdf():
    pdf = _make_text_pdf(pages=3)
    wm = generate_watermark_id("hash", "ALICE", "SES-1", "n1")
    started = time.perf_counter()
    watermarked = embed_watermark(pdf, wm, mode="preserve")
    elapsed = time.perf_counter() - started
    print(f"\n3-page preserve embed: {elapsed:.2f}s, original={len(pdf)} bytes, "
          f"watermarked={len(watermarked)} bytes")
    doc = pymupdf.open(stream=watermarked, filetype="pdf")
    texts = [page.get_text() for page in doc]
    doc.close()
    assert all(wm in text for text in texts)
    assert extract_watermark(watermarked) == wm


def test_exact_roundtrip_both_modes():
    pdf = _make_text_pdf(pages=2)
    wm = generate_watermark_id("hash", "MODE", "SES-M", "n-mode")
    for mode in ("preserve", "rasterize"):
        marked = embed_watermark(pdf, wm, mode=mode)
        assert extract_watermark(marked) == wm, f"mode={mode}"


def test_preserve_mode_keeps_text_selectable():
    pdf = _make_text_pdf(pages=2)
    wm = generate_watermark_id("hash", "TEXT", "SES-T", "n-text")
    marked = embed_watermark(pdf, wm, mode="preserve")
    doc = pymupdf.open(stream=marked, filetype="pdf")
    texts = [page.get_text() for page in doc]
    image_counts = [len(page.get_images()) for page in doc]
    doc.close()
    assert all("Confidential forensic report" in text for text in texts)
    assert all("Recipient copy line 1" in text for text in texts)
    assert image_counts == [0, 0]
    assert extract_watermark(marked) == wm


def test_preserve_size_below_1_5x():
    pdf = _make_text_pdf(pages=1)
    wm = generate_watermark_id("hash", "SIZE", "SES-S", "n-size")
    marked = embed_watermark(pdf, wm, mode="preserve")
    print(f"\n1-page preserve size: original={len(pdf)} bytes, watermarked={len(marked)} bytes")
    assert len(marked) < 1.5 * len(pdf)


def test_preserve_mode_watermarks_embedded_image():
    pdf = _make_image_pdf()
    wm = generate_watermark_id("hash", "IMAGE", "SES-I", "n-image")
    with tempfile.TemporaryDirectory() as tmp:
        source_path = os.path.join(tmp, "source.pdf")
        with open(source_path, "wb") as handle:
            handle.write(pdf)
        with open(source_path, "rb") as handle:
            marked = embed_watermark(handle.read(), wm, mode="preserve")

    src = pymupdf.open(stream=pdf, filetype="pdf")
    original = src.extract_image(src[0].get_images(full=True)[0][0])["image"]
    src.close()

    doc = pymupdf.open(stream=marked, filetype="pdf")
    images = doc[0].get_images(full=True)
    assert images
    replaced = doc.extract_image(images[0][0])["image"]
    doc.close()
    assert replaced != original
    assert _decode_image_bytes(replaced) == wm

    stripped = pymupdf.open()
    page = stripped.new_page(width=612, height=400)
    page.insert_image(pymupdf.Rect(0, 0, 612, 400), stream=replaced)
    clean = stripped.tobytes()
    stripped.close()
    doc = pymupdf.open(stream=clean, filetype="pdf")
    assert not ID_SCAN_RE.search(doc[0].get_text())
    doc.close()
    assert extract_watermark(clean) == wm


def test_preserve_mode_keeps_image_alpha():
    pdf = _make_masked_image_pdf()
    wm = generate_watermark_id("hash", "ALPHA", "SES-A", "n-alpha")
    marked = embed_watermark(pdf, wm, mode="preserve")
    doc = pymupdf.open(stream=marked, filetype="pdf")
    images = doc[0].get_images(full=True)
    assert images
    base = images[0]
    assert base[1] != 0
    assert _decode_image_bytes(doc.extract_image(base[0])["image"]) == wm
    pix = doc[0].get_pixmap(matrix=pymupdf.Matrix(1, 1), alpha=False)
    doc.close()
    samples = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
    left = float(samples[320, 80].mean())
    right = float(samples[320, 520].mean())
    assert left > 230
    assert right < 220


def test_dct_fallback_after_jpeg_rerender():
    with tempfile.TemporaryDirectory() as tmp:
        pdf = _make_text_pdf(pages=2)
        wm = generate_watermark_id("hash", "BOB", "SES-2", "n2")
        watermarked = embed_watermark(pdf, wm, mode="rasterize")
        assert extract_watermark(watermarked) == wm

        wm_path = os.path.join(tmp, "watermarked.pdf")
        with open(wm_path, "wb") as handle:
            handle.write(watermarked)
        with open(wm_path, "rb") as handle:
            rebuilt = _rebuild_as_jpeg_pdf(handle.read())

        rebuilt_path = os.path.join(tmp, "rerendered.pdf")
        with open(rebuilt_path, "wb") as handle:
            handle.write(rebuilt)

        doc = pymupdf.open(stream=rebuilt, filetype="pdf")
        joined = "".join(page.get_text() for page in doc)
        doc.close()
        assert not ID_SCAN_RE.search(joined)

        with open(rebuilt_path, "rb") as handle:
            leaked = handle.read()
        assert extract_watermark(leaked) == wm


def test_size_below_600kb():
    pdf = _make_text_pdf(pages=1)
    wm = generate_watermark_id("hash", "CAROL", "SES-3", "n3")
    watermarked = embed_watermark(pdf, wm, mode="rasterize")
    print(f"\n1-page rasterize size: original={len(pdf)} bytes, watermarked={len(watermarked)} bytes")
    assert len(watermarked) < 600 * 1024


def test_psnr_above_30db():
    pdf = _make_text_pdf(pages=1)
    wm = generate_watermark_id("hash", "DAVE", "SES-4", "n4")
    preserved = embed_watermark(pdf, wm, mode="preserve")
    rasterized = embed_watermark(pdf, wm, mode="rasterize")
    psnr_preserve = calculate_psnr(pdf, preserved)
    psnr_rasterize = calculate_psnr(pdf, rasterized)
    print(f"\nPSNR preserve={psnr_preserve:.2f} dB, rasterize={psnr_rasterize:.2f} dB")
    assert psnr_preserve > 30.0
    assert psnr_rasterize > 30.0


def test_different_recipients_extract_different_ids():
    pdf = _make_text_pdf(pages=1)
    wm_alice = generate_watermark_id("hash", "ALICE", "SES-5", "n5")
    wm_bob = generate_watermark_id("hash", "BOB", "SES-5", "n5")
    for mode in ("preserve", "rasterize"):
        ext_alice = extract_watermark(embed_watermark(pdf, wm_alice, mode=mode))
        ext_bob = extract_watermark(embed_watermark(pdf, wm_bob, mode=mode))
        assert ext_alice == wm_alice, f"mode={mode}"
        assert ext_bob == wm_bob, f"mode={mode}"
        assert ext_alice != ext_bob
