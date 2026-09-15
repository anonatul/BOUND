"""
DCT-based invisible watermarking (frequency-domain).

- Watermark ids are "WM-" + 26 base32 chars derived from a 128-bit SHA-256 prefix.
- Preserve mode (default) keeps the original PDF content: selectable text,
  original quality and size. It adds an invisible text layer on every page and
  watermarks each embedded raster image in place via QIM on an 8x8 DCT
  coefficient of the image's Y channel.
- Rasterize mode replaces every page with a watermarked 150 DPI JPEG page and is
  robust against full re-rendering/flattening.
- Extraction order: invisible text, per-image DCT, then rendered-page DCT; the
  DCT payload is repetition-coded and protected by CRC32.
- Blind extraction (no original needed); prototype-level robustness.
"""
import base64
import binascii
import hashlib
import io
import re

import numpy as np
import pymupdf
from PIL import Image
from scipy.fftpack import dct

ID_RE = re.compile(r"^WM-[A-Z2-7]{26}$")
ID_SCAN_RE = re.compile(r"WM-[A-Z2-7]{26}")
WATERMARK_CHARS = 26
WATERMARK_ID_LEN = 3 + WATERMARK_CHARS
PAYLOAD_BYTES = WATERMARK_ID_LEN + 4  # id ASCII bytes + CRC32
WATERMARK_BITS = PAYLOAD_BYTES * 8  # 264
REPETITION = 5
EXTENDED_BITS = WATERMARK_BITS * REPETITION
Q = 16  # quantization step: invisibility vs robustness
COEFF_POS = (3, 2)  # mid-frequency position in 8x8 DCT block
DPI = 150
JPEG_QUALITY = 85
MAX_TEXT_CHUNK = 8
MODES = ("preserve", "rasterize")
MIN_IMAGE_SIDE = 64
MIN_IMAGE_BLOCKS = EXTENDED_BITS * 2


def generate_watermark_id(document_hash: str, recipient_id: str, session_id: str, nonce: str) -> str:
    """
    Derive an opaque 128-bit id: "WM-" + 26 base32 chars of SHA-256 over inputs.
    """
    material = f"{document_hash}|{recipient_id.upper()}|{session_id}|{nonce}".encode()
    digest = hashlib.sha256(material).digest()[:16]
    return "WM-" + base64.b32encode(digest).decode("ascii").rstrip("=")


def _payload_bits(watermark_id: str) -> np.ndarray:
    """ID bytes + big-endian CRC32, expanded with a repetition R=5 code."""
    data = watermark_id.encode("ascii")
    crc = binascii.crc32(data) & 0xFFFFFFFF
    payload = data + crc.to_bytes(4, "big")
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    return np.repeat(bits, REPETITION)


def _dct2(blocks: np.ndarray) -> np.ndarray:
    return dct(dct(blocks, axis=-1, norm="ortho"), axis=-2, norm="ortho")


def _block_view(Y: np.ndarray) -> tuple[np.ndarray, int, int]:
    """Split Y into an (rows, cols, 8, 8) view, zero-padding to multiples of 8."""
    H, W = Y.shape
    H_pad = (H + 7) // 8 * 8
    W_pad = (W + 7) // 8 * 8
    padded = np.zeros((H_pad, W_pad), dtype=np.float32)
    padded[:H, :W] = Y
    blocks = padded.reshape(H_pad // 8, 8, W_pad // 8, 8).transpose(0, 2, 1, 3)
    return blocks, H_pad, W_pad


def _basis(row: int, col: int) -> np.ndarray:
    """Orthonormal DCT-II basis block for one coefficient position."""
    idx = np.arange(8, dtype=np.float64)

    def axis(k: int) -> np.ndarray:
        if k == 0:
            return np.full(8, 1.0 / np.sqrt(8.0))
        return np.sqrt(2.0 / 8.0) * np.cos(np.pi * k * (2.0 * idx + 1.0) / 16.0)

    return np.outer(axis(row), axis(col)).astype(np.float32)


def _rgb_to_ycbcr(rgb: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """rgb HxWx3 uint8 -> Y, Cb, Cr float arrays."""
    R = rgb[:, :, 0].astype(np.float32)
    G = rgb[:, :, 1].astype(np.float32)
    B = rgb[:, :, 2].astype(np.float32)
    Y = 0.299 * R + 0.587 * G + 0.114 * B
    Cb = 128 - 0.168736 * R - 0.331264 * G + 0.5 * B
    Cr = 128 + 0.5 * R - 0.418688 * G - 0.081312 * B
    return Y, Cb, Cr


def _ycbcr_to_rgb(Y: np.ndarray, Cb: np.ndarray, Cr: np.ndarray) -> np.ndarray:
    """Y, Cb, Cr float arrays -> rgb HxWx3 uint8."""
    R = Y + 1.402 * (Cr - 128)
    G = Y - 0.344136 * (Cb - 128) - 0.714136 * (Cr - 128)
    B = Y + 1.772 * (Cb - 128)
    rgb = np.stack([R, G, B], axis=2)
    return np.clip(np.round(rgb), 0, 255).astype(np.uint8)


def _apply_coeff(blocks: np.ndarray, coeff: np.ndarray, target: np.ndarray,
                 basis: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Set COEFF_POS to target, return the rounded/clipped pixels and actual coeff."""
    trial = np.rint(blocks + (target - coeff)[:, :, None, None] * basis).clip(0, 255)
    actual = np.sum(trial * basis, axis=(2, 3))
    return trial, actual


def _embed_bits_in_y(Y: np.ndarray, bits: np.ndarray) -> np.ndarray:
    """
    Embed bits cyclically across 8x8 blocks via QIM parity on COEFF_POS.

    Pixel clipping can pull the realised coefficient away from the QIM target,
    so the target is refined until the actual coefficient is centered on the
    nearest same-parity multiple of Q (which keeps parity stable under JPEG).
    """
    blocks, H_pad, W_pad = _block_view(Y)
    coeff = _dct2(blocks)[:, :, COEFF_POS[0], COEFF_POS[1]]
    basis = _basis(COEFF_POS[0], COEFF_POS[1])
    wanted = bits[np.arange(coeff.size) % bits.size].reshape(coeff.shape)
    quant = np.rint(coeff / Q).astype(np.int64)
    shift = np.where(coeff / Q >= quant, 1, -1)
    quant = quant + np.where((quant & 1) != wanted, shift, 0)
    desired = quant.astype(np.float32) * Q
    target = desired.copy()
    pixels, actual = _apply_coeff(blocks, coeff, target, basis)
    for _ in range(3):
        off = desired - actual
        need = np.abs(off) > 0.15 * Q
        if not need.any():
            break
        _, probe = _apply_coeff(blocks, coeff, target + np.where(need, Q, 0.0), basis)
        slope = np.clip(np.where(need, (probe - actual) / Q, 1.0), 0.2, 1.0)
        target = np.clip(target + np.where(need, off / slope, 0.0), -4096.0, 4096.0)
        pixels, actual = _apply_coeff(blocks, coeff, target, basis)
    wm = pixels.transpose(0, 2, 1, 3).reshape(H_pad, W_pad)
    return wm[: Y.shape[0], : Y.shape[1]]


def _accumulate_votes(Y: np.ndarray, ones: np.ndarray, totals: np.ndarray) -> None:
    """Add per-bit-position QIM votes from one page's Y channel."""
    blocks, _, _ = _block_view(Y)
    coeffs = _dct2(blocks)
    coeff = coeffs[:, :, COEFF_POS[0], COEFF_POS[1]].ravel()
    quant = np.rint(coeff / Q).astype(np.int64)
    bits = (quant & 1).astype(bool)
    idx = np.arange(bits.size) % EXTENDED_BITS
    ones += np.bincount(idx[bits], minlength=EXTENDED_BITS)
    totals += np.bincount(idx, minlength=EXTENDED_BITS)


def _decode_votes(ones: np.ndarray, totals: np.ndarray) -> str | None:
    """Majority-vote extended bits, undo repetition, then verify CRC32."""
    extended = ones * 2 > totals
    groups = extended.reshape(WATERMARK_BITS, REPETITION)
    raw = np.packbits((groups.sum(axis=1) * 2 > REPETITION).astype(np.uint8)).tobytes()
    id_bytes = raw[:WATERMARK_ID_LEN]
    crc = raw[WATERMARK_ID_LEN:PAYLOAD_BYTES]
    if (binascii.crc32(id_bytes) & 0xFFFFFFFF).to_bytes(4, "big") != crc:
        return None
    try:
        watermark_id = id_bytes.decode("ascii")
    except UnicodeDecodeError:
        return None
    return watermark_id if ID_RE.match(watermark_id) else None


def _insert_invisible_text(page: pymupdf.Page, watermark_id: str) -> None:
    """Insert the id at four page corners as invisible text (render mode 3)."""
    fontsize = 6
    margin = 12
    text_width = pymupdf.get_text_length(watermark_id, fontname="helv", fontsize=fontsize)
    anchors = [
        (margin, margin + fontsize),
        (page.rect.width - margin, margin + fontsize),
        (margin, page.rect.height - margin),
        (page.rect.width - margin, page.rect.height - margin),
    ]
    fits = text_width <= page.rect.width - 2 * margin
    chunks = [watermark_id[i:i + MAX_TEXT_CHUNK] for i in range(0, len(watermark_id), MAX_TEXT_CHUNK)]
    for ax, ay in anchors:
        if fits:
            x = margin if ax <= page.rect.width / 2 else max(margin, ax - text_width)
            page.insert_text((x, ay), watermark_id, fontsize=fontsize, fontname="helv",
                             render_mode=3, overlay=True)
        else:
            for i, chunk in enumerate(chunks):
                page.insert_text((margin, ay + i * (fontsize + 1)), chunk, fontsize=fontsize,
                                 fontname="helv", render_mode=3, overlay=True)


def _watermarked_page_jpeg(page: pymupdf.Page, bits: np.ndarray) -> bytes:
    """Render one page at DPI, embed bits in the Y channel, return JPEG bytes."""
    zoom = DPI / 72.0
    pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom), alpha=False)
    rgb = np.array(Image.frombytes("RGB", [pix.width, pix.height], pix.samples))
    Y, Cb, Cr = _rgb_to_ycbcr(rgb)
    rgb_wm = _ycbcr_to_rgb(_embed_bits_in_y(Y, bits), Cb, Cr)
    buf = io.BytesIO()
    Image.fromarray(rgb_wm).save(buf, format="JPEG", quality=JPEG_QUALITY)
    return buf.getvalue()


def _embed_rasterized(doc: pymupdf.Document, watermark_id: str, bits: np.ndarray) -> bytes:
    """Replace every page with a watermarked 150 DPI JPEG page."""
    out = pymupdf.open()
    try:
        for page in doc:
            rect = page.rect
            jpeg = _watermarked_page_jpeg(page, bits)
            new_page = out.new_page(width=rect.width, height=rect.height)
            new_page.insert_image(rect, stream=jpeg, keep_proportion=False, overlay=True)
            _insert_invisible_text(new_page, watermark_id)
        buf = io.BytesIO()
        out.save(buf, garbage=3, deflate=True)
        return buf.getvalue()
    finally:
        out.close()


def _collect_page_images(doc: pymupdf.Document) -> list[tuple[pymupdf.Page, int, int, int, int]]:
    """Collect (page, xref, smask, width, height) before any replacement."""
    collected = []
    for page in doc:
        for info in page.get_images(full=True):
            xref, smask, width, height = info[0], info[1], info[2], info[3]
            if xref > 0:
                collected.append((page, xref, smask, width, height))
    return collected


def _watermark_image(info: dict, bits: np.ndarray, mask_info: dict | None = None) -> bytes | None:
    """Watermark one extracted image; return a re-encoded stream or None."""
    width, height = info["width"], info["height"]
    if width < MIN_IMAGE_SIDE or height < MIN_IMAGE_SIDE:
        return None
    if (width // 8) * (height // 8) < MIN_IMAGE_BLOCKS:
        return None
    try:
        img = Image.open(io.BytesIO(info["image"]))
        fmt = (img.format or "").upper()
        alpha = None
        if mask_info is not None:
            alpha = Image.open(io.BytesIO(mask_info["image"])).convert("L")
        elif img.mode in ("RGBA", "LA"):
            alpha = img.getchannel("A")
        elif img.mode == "P" and "transparency" in img.info:
            alpha = img.convert("RGBA").getchannel("A")
        rgb = img.convert("RGB")
        if alpha is not None and alpha.size != rgb.size:
            alpha = alpha.resize(rgb.size, Image.LANCZOS)
    except Exception:
        return None
    Y, Cb, Cr = _rgb_to_ycbcr(np.array(rgb))
    out = Image.fromarray(_ycbcr_to_rgb(_embed_bits_in_y(Y, bits), Cb, Cr))
    buf = io.BytesIO()
    if alpha is not None:
        out = out.convert("RGBA")
        out.putalpha(alpha)
        out.save(buf, format="PNG")
    elif fmt == "PNG" or img.mode == "P":
        out.save(buf, format="PNG")
    else:
        out.save(buf, format="JPEG", quality=JPEG_QUALITY)
    return buf.getvalue()


def _embed_preserved(doc: pymupdf.Document, watermark_id: str, bits: np.ndarray) -> bytes:
    """Add invisible text to every page and watermark raster images in place."""
    entries = _collect_page_images(doc)
    mask_xrefs = {smask for _, _, smask, _, _ in entries if smask}
    for page in doc:
        _insert_invisible_text(page, watermark_id)
    streams: dict[int, bytes | None] = {}
    for page, xref, smask, _, _ in entries:
        if xref in mask_xrefs:
            continue
        if xref not in streams:
            try:
                mask_info = doc.extract_image(smask) if smask else None
                streams[xref] = _watermark_image(doc.extract_image(xref), bits, mask_info)
            except Exception:
                streams[xref] = None
        stream = streams[xref]
        if stream is None:
            continue
        try:
            page.replace_image(xref, stream=stream)
        except Exception:
            continue
    buf = io.BytesIO()
    doc.save(buf, garbage=4, deflate=True, clean=True)
    return buf.getvalue()


def embed_watermark(pdf_bytes: bytes, watermark_id: str, mode: str = "preserve") -> bytes:
    """
    Embed watermark_id invisibly and return the new PDF bytes.

    mode="preserve" (default) keeps original pages and selectable text, adding
    an invisible text layer plus a DCT watermark inside embedded raster images.
    mode="rasterize" replaces every page with a watermarked JPEG page.
    """
    watermark_id = watermark_id.upper()
    if not ID_RE.match(watermark_id):
        raise ValueError(f"invalid watermark id: {watermark_id!r}")
    if mode not in MODES:
        raise ValueError(f"unknown watermark mode: {mode!r}")
    bits = _payload_bits(watermark_id)
    src = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    try:
        if mode == "rasterize":
            return _embed_rasterized(src, watermark_id, bits)
        return _embed_preserved(src, watermark_id, bits)
    finally:
        src.close()


def _decode_image_bytes(image_bytes: bytes) -> str | None:
    """Decode the CRC-checked DCT payload from one stored image stream."""
    try:
        rgb = np.array(Image.open(io.BytesIO(image_bytes)).convert("RGB"))
    except Exception:
        return None
    Y, _, _ = _rgb_to_ycbcr(rgb)
    ones = np.zeros(EXTENDED_BITS, dtype=np.int64)
    totals = np.zeros(EXTENDED_BITS, dtype=np.int64)
    _accumulate_votes(Y, ones, totals)
    return _decode_votes(ones, totals)


def _extract_from_images(doc: pymupdf.Document) -> str | None:
    """Decode each unique embedded image independently via its DCT payload."""
    seen = set()
    for page in doc:
        for info in page.get_images(full=True):
            xref = info[0]
            if xref <= 0 or xref in seen:
                continue
            seen.add(xref)
            try:
                result = _decode_image_bytes(doc.extract_image(xref)["image"])
            except Exception:
                result = None
            if result:
                return result
    return None


def _extract_from_rendered_pages(doc: pymupdf.Document) -> str | None:
    """Collect QIM votes from every rendered page and decode the payload."""
    ones = np.zeros(EXTENDED_BITS, dtype=np.int64)
    totals = np.zeros(EXTENDED_BITS, dtype=np.int64)
    zoom = DPI / 72.0
    matrix = pymupdf.Matrix(zoom, zoom)
    for page in doc:
        pix = page.get_pixmap(matrix=matrix, alpha=False)
        rgb = np.array(Image.frombytes("RGB", [pix.width, pix.height], pix.samples))
        Y, _, _ = _rgb_to_ycbcr(rgb)
        _accumulate_votes(Y, ones, totals)
    return _decode_votes(ones, totals)


def extract_watermark(pdf_bytes: bytes) -> str | None:
    """
    Blind extraction: invisible text, embedded-image DCT, then page DCT.
    """
    try:
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    except Exception:
        return None
    try:
        for page in doc:
            match = ID_SCAN_RE.search(page.get_text())
            if match:
                return match.group(0)
        if doc.page_count == 0:
            return None
        result = _extract_from_images(doc)
        if result:
            return result
        return _extract_from_rendered_pages(doc)
    finally:
        doc.close()


def calculate_psnr(original_pdf_bytes: bytes, watermarked_pdf_bytes: bytes) -> float:
    """
    Estimate PSNR between the first pages of the original and watermarked PDFs.
    """
    doc1 = pymupdf.open(stream=original_pdf_bytes, filetype="pdf")
    doc2 = pymupdf.open(stream=watermarked_pdf_bytes, filetype="pdf")
    try:
        zoom = DPI / 72.0
        matrix = pymupdf.Matrix(zoom, zoom)
        pix1 = doc1[0].get_pixmap(matrix=matrix, alpha=False)
        pix2 = doc2[0].get_pixmap(matrix=matrix, alpha=False)
        img1 = np.array(Image.frombytes("RGB", [pix1.width, pix1.height], pix1.samples)).astype(np.float32)
        img2 = np.array(Image.frombytes("RGB", [pix2.width, pix2.height], pix2.samples)).astype(np.float32)
    finally:
        doc1.close()
        doc2.close()
    mse = float(np.mean((img1 - img2) ** 2))
    if mse == 0:
        return float("inf")
    return 20 * np.log10(255.0 / np.sqrt(mse))
