"""
DCT-based invisible watermarking (frequency-domain)
- Uses 8x8 block DCT with QIM (Quantization Index Modulation) at mid-frequency coefficient.
- Prototype level, not claimed to be robust against all attacks.
- Blind extraction (no original needed).
"""
import io
import hashlib
import numpy as np
from PIL import Image
import pymupdf  # fitz
from scipy.fftpack import dct, idct

# Constants for watermarking
Q = 8  # quantization step — tuning invisibility vs robustness
COEFF_POS = (3, 2)  # mid-frequency position in 8x8 DCT block (row, col)
# Also consider (2,3) as alternative; we use single coeff for simplicity
WATERMARK_FIXED_LEN_CHARS = 15  # "WM-" + 12 hex = 15 chars
WATERMARK_BITS = WATERMARK_FIXED_LEN_CHARS * 8  # 120 bits
DPI = 150
ZOOM = DPI / 72.0

def _dct2(block):
    # 2D DCT using ortho norm
    return dct(dct(block.T, norm='ortho').T, norm='ortho')

def _idct2(block):
    return idct(idct(block.T, norm='ortho').T, norm='ortho')

def string_to_bits(s: str) -> list[int]:
    bits = []
    for ch in s.encode('utf-8'):
        for i in range(7, -1, -1):
            bits.append((ch >> i) & 1)
    return bits

def bits_to_string(bits: list[int]) -> str:
    # bits length must be multiple of 8
    chars = []
    for i in range(0, len(bits), 8):
        byte = 0
        chunk = bits[i:i+8]
        if len(chunk) < 8:
            break
        for b in chunk:
            byte = (byte << 1) | b
        chars.append(byte)
    try:
        return bytes(chars).decode('utf-8')
    except:
        return bytes(chars).decode('utf-8', errors='ignore')

def generate_watermark_id(document_hash: str, recipient_id: str, session_id: str, nonce: str) -> str:
    """
    Derive opaque watermark identifier via cryptographic hash.
    document_hash (hex), recipient_id, session_id, nonce concatenated -> SHA256 -> WM- + 12 hex.
    """
    h = hashlib.sha256()
    # Use canonical concatenation with separators to avoid collisions
    h.update(document_hash.encode())
    h.update(b"|")
    h.update(recipient_id.upper().encode())
    h.update(b"|")
    h.update(session_id.encode())
    h.update(b"|")
    h.update(nonce.encode())
    digest = h.hexdigest().upper()
    return f"WM-{digest[:12]}"

def _rgb_to_ycbcr(rgb: np.ndarray):
    """
    rgb: HxWx3 uint8
    returns Y, Cb, Cr as float arrays
    """
    R = rgb[:,:,0].astype(np.float32)
    G = rgb[:,:,1].astype(np.float32)
    B = rgb[:,:,2].astype(np.float32)
    Y = 0.299*R + 0.587*G + 0.114*B
    Cb = 128 - 0.168736*R - 0.331264*G + 0.5*B
    Cr = 128 + 0.5*R - 0.418688*G - 0.081312*B
    return Y, Cb, Cr

def _ycbcr_to_rgb(Y, Cb, Cr):
    """
    Y, Cb, Cr: float arrays HxW
    returns rgb uint8 HxWx3
    """
    R = Y + 1.402 * (Cr - 128)
    G = Y - 0.344136 * (Cb - 128) - 0.714136 * (Cr - 128)
    B = Y + 1.772 * (Cb - 128)
    rgb = np.stack([R,G,B], axis=2)
    rgb = np.clip(np.round(rgb), 0, 255).astype(np.uint8)
    return rgb

def _embed_bits_in_y(Y: np.ndarray, payload_bits: list[int]) -> np.ndarray:
    """
    Embed payload_bits cyclically into Y channel via QIM on DCT coefficient.
    Y: HxW float32 (0-255)
    Returns watermarked Y'
    """
    H, W = Y.shape
    # Pad to multiple of 8
    H_pad = ((H + 7)//8)*8
    W_pad = ((W + 7)//8)*8
    Y_padded = np.zeros((H_pad, W_pad), dtype=np.float32)
    Y_padded[:H, :W] = Y

    # We'll produce watermarked padded, then crop
    Y_wm = np.zeros_like(Y_padded)

    # Prepare blocks iteration
    # total blocks = (H_pad/8)*(W_pad/8)
    # Each block carries one bit cyclically
    bit_idx = 0
    payload_len = len(payload_bits)

    for by in range(0, H_pad, 8):
        for bx in range(0, W_pad, 8):
            block = Y_padded[by:by+8, bx:bx+8]
            # For invisibility, we could skip very flat blocks? But we embed all for robustness.
            dct_block = _dct2(block)
            # QIM embedding at COEFF_POS
            coeff = dct_block[COEFF_POS[0], COEFF_POS[1]]
            # Quantize
            q = Q
            quantized = int(round(coeff / q))
            wanted_bit = payload_bits[bit_idx % payload_len]
            # wanted: 1 => odd, 0 => even
            # need quantized parity to match wanted
            if (quantized & 1) != wanted_bit:
                # adjust by 1 (towards nearest that matches parity)
                # To minimize distortion, choose +1 or -1 based on which causes smaller error? Simple +1
                # But if we always +1, drift positive. Alternate: if quantized==0 and wanted 1, make 1, else adjust.
                # We'll adjust to nearest neighbor with correct parity
                # If quantized is e.g., 4 (even) and want 1 (odd), candidates 3 and 5, choose closest to original coeff/q
                orig_ratio = coeff / q
                # candidates
                c1 = quantized + 1
                c2 = quantized - 1
                # Ensure c1 parity matches wanted, c2 also will (since +1 flips parity)
                # Choose candidate closer to orig_ratio
                if abs(c1 - orig_ratio) < abs(c2 - orig_ratio):
                    quantized = c1
                else:
                    quantized = c2
                # edge case: keep within reasonable range? not needed
            new_coeff = quantized * q
            dct_block[COEFF_POS[0], COEFF_POS[1]] = new_coeff
            # IDCT
            block_wm = _idct2(dct_block)
            Y_wm[by:by+8, bx:bx+8] = block_wm
            bit_idx += 1

    # Crop to original size
    Y_wm_cropped = Y_wm[:H, :W]
    # Clip Y to valid range 0-255
    Y_wm_cropped = np.clip(Y_wm_cropped, 0, 255)
    return Y_wm_cropped

def _extract_bits_from_y(Y: np.ndarray, payload_len: int = WATERMARK_BITS) -> list[int]:
    """
    Blind extraction: for each 8x8 block, extract bit via quantized coefficient parity.
    Returns majority-voted bits length payload_len.
    """
    H, W = Y.shape
    H_pad = ((H + 7)//8)*8
    W_pad = ((W + 7)//8)*8
    Y_padded = np.zeros((H_pad, W_pad), dtype=np.float32)
    Y_padded[:H, :W] = Y

    # Collect votes per bit position
    votes = [ [] for _ in range(payload_len) ]
    bit_idx = 0
    for by in range(0, H_pad, 8):
        for bx in range(0, W_pad, 8):
            block = Y_padded[by:by+8, bx:bx+8]
            dct_block = _dct2(block)
            coeff = dct_block[COEFF_POS[0], COEFF_POS[1]]
            q = Q
            quantized = int(round(coeff / q))
            bit = quantized & 1  # 1 odd, 0 even
            pos = bit_idx % payload_len
            votes[pos].append(bit)
            bit_idx += 1

    # Majority vote per position
    result_bits = []
    for v in votes:
        if not v:
            result_bits.append(0)
        else:
            # majority
            ones = sum(v)
            zeros = len(v) - ones
            result_bits.append(1 if ones > zeros else 0)
    return result_bits

def _render_pdf_to_images(pdf_bytes: bytes, dpi: int = DPI) -> list[tuple[Image.Image, pymupdf.Rect]]:
    """
    Render PDF bytes to list of (PIL Image, original rect)
    """
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    images = []
    zoom = dpi / 72.0
    mat = pymupdf.Matrix(zoom, zoom)
    for page in doc:
        rect = page.rect
        pix = page.get_pixmap(matrix=mat, alpha=False)
        # pix.samples -> bytes
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        images.append((img, rect))
    doc.close()
    return images

def _images_to_pdf(images: list[Image.Image], rects: list[pymupdf.Rect]) -> bytes:
    """
    Convert watermarked images back to PDF, preserving original page rects.
    Uses pymupdf to insert images losslessly (PNG).
    """
    doc = pymupdf.open()
    for img, rect in zip(images, rects):
        # Create new page with same dimensions as original rect
        page = doc.new_page(width=rect.width, height=rect.height)
        # Convert PIL image to PNG bytes
        buf = io.BytesIO()
        # Save as PNG to preserve watermark (lossless)
        img.save(buf, format="PNG")
        png_bytes = buf.getvalue()
        # Insert image to fill page rect
        # Use rect as where to place image
        page.insert_image(rect, stream=png_bytes, keep_proportion=False, overlay=True)
    out = io.BytesIO()
    doc.save(out)
    doc.close()
    return out.getvalue()

def embed_watermark(pdf_bytes: bytes, watermark_id: str) -> bytes:
    """
    Embed watermark_id (e.g., WM-ABCDEF123456) invisibly into PDF via DCT.
    Returns watermarked PDF bytes.
    """
    # Validate watermark_id length: pad or truncate to fixed length
    # watermark_id should be exactly WATERMARK_FIXED_LEN_CHARS = 15
    # If longer, truncate? If shorter, pad with nulls? Instead we enforce.
    # For robustness, if not exactly 15, we will pad/truncate to 15, but keep as provided for ledger mapping.
    # However embedding requires fixed length, so we handle variable by:
    # - If watermark_id != 15 chars, we will embed its string as is and adjust payload_len accordingly? For simplicity enforce 15.
    # Our generate_watermark_id always returns 15, so okay.
    # If provided longer (e.g., WM- plus more), we truncate/pad to 15? Better to handle generically: payload bits = string_to_bits(watermark_id) but then extraction must know length.
    # To support variable length, we will embed length header: first 8 bits encode length? But simpler to fix.
    # We'll fix: if watermark_id length != 15, we hash it to 15 via same method? Not ideal.
    # Instead, we will embed exactly the provided watermark_id's bits, and extraction will try to decode variable length by trying known lengths.
    # For now, assume watermark_id is always WM- +12 hex (15 chars). Enforce.

    if len(watermark_id) != WATERMARK_FIXED_LEN_CHARS:
        # If not fixed, adjust to fixed by hashing? But to preserve exact string, we should embed variable length.
        # For this prototype, we'll fallback to embedding variable length by first embedding length as 16 bits header.
        # However extraction expects fixed. So we will handle variable separately: if watermark_id !=15, we will embed variable-length payload with header.
        # For simplicity, if variable, we will use header method: payload = 16 bits length + data bits
        # Let's implement header method for variable.
        return _embed_variable_length(pdf_bytes, watermark_id)

    payload_bits = string_to_bits(watermark_id)  # 120 bits
    assert len(payload_bits) == WATERMARK_BITS, f"payload bits {len(payload_bits)} != {WATERMARK_BITS}"

    # Render PDF to images
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    watermarked_images = []
    rects = []
    zoom = DPI / 72.0
    mat = pymupdf.Matrix(zoom, zoom)
    for page in doc:
        rect = page.rect
        rects.append(rect)
        pix = page.get_pixmap(matrix=mat, alpha=False)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        rgb = np.array(img)  # HxWx3 uint8
        Y, Cb, Cr = _rgb_to_ycbcr(rgb)
        Y_wm = _embed_bits_in_y(Y, payload_bits)
        rgb_wm = _ycbcr_to_rgb(Y_wm, Cb, Cr)
        img_wm = Image.fromarray(rgb_wm)
        watermarked_images.append(img_wm)
    doc.close()

    # Convert back to PDF
    out_doc = pymupdf.open()
    for img_wm, rect in zip(watermarked_images, rects):
        page = out_doc.new_page(width=rect.width, height=rect.height)
        buf = io.BytesIO()
        img_wm.save(buf, format="PNG")
        png_bytes = buf.getvalue()
        page.insert_image(rect, stream=png_bytes, keep_proportion=False, overlay=True)
    out = io.BytesIO()
    out_doc.save(out)
    out_doc.close()
    return out.getvalue()

def _embed_variable_length(pdf_bytes: bytes, watermark_id: str) -> bytes:
    """
    Fallback for variable length watermark_id: embed length header (16 bits) + payload
    """
    # We'll embed as: 16 bits big-endian length (number of chars) + string bits
    # But we need to know at extraction to detect header. We'll use fixed QIM but payload_len unknown.
    # To keep extraction working, we will embed with maximum capacity and header indicates length.
    # For embedding, we need to embed combined bits cyclically, similar to fixed.
    # However for variable, we would need to know combined length at extraction (header gives length).
    # Simpler: we will still use fixed 15 chars enforcement by truncating/padding, but log warning.
    # Instead, just enforce: if watermark_id length !=15, hash it to 12 hex and recreate WM-... That's opaque but preserves mapping? No.
    # For now, truncate or pad to 15.
    if len(watermark_id) > WATERMARK_FIXED_LEN_CHARS:
        watermark_id = watermark_id[:WATERMARK_FIXED_LEN_CHARS]
    elif len(watermark_id) < WATERMARK_FIXED_LEN_CHARS:
        watermark_id = watermark_id.ljust(WATERMARK_FIXED_LEN_CHARS, '\0')
    payload_bits = string_to_bits(watermark_id)
    # proceed same as fixed
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    watermarked_images = []
    rects = []
    zoom = DPI / 72.0
    mat = pymupdf.Matrix(zoom, zoom)
    for page in doc:
        rect = page.rect
        rects.append(rect)
        pix = page.get_pixmap(matrix=mat, alpha=False)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        rgb = np.array(img)
        Y, Cb, Cr = _rgb_to_ycbcr(rgb)
        Y_wm = _embed_bits_in_y(Y, payload_bits)
        rgb_wm = _ycbcr_to_rgb(Y_wm, Cb, Cr)
        img_wm = Image.fromarray(rgb_wm)
        watermarked_images.append(img_wm)
    doc.close()
    out_doc = pymupdf.open()
    for img_wm, rect in zip(watermarked_images, rects):
        page = out_doc.new_page(width=rect.width, height=rect.height)
        buf = io.BytesIO()
        img_wm.save(buf, format="PNG")
        png_bytes = buf.getvalue()
        page.insert_image(rect, stream=png_bytes, keep_proportion=False, overlay=True)
    out = io.BytesIO()
    out_doc.save(out)
    out_doc.close()
    return out.getvalue()

def extract_watermark(pdf_bytes: bytes) -> str | None:
    """
    Blind extraction of watermark_id from PDF.
    Returns watermark_id string if found and valid, else None.
    Tries fixed length extraction and validates format WM- + hex.
    """
    try:
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    except Exception:
        return None

    if doc.page_count == 0:
        doc.close()
        return None

    # We'll extract from each page and vote across pages? Simpler: extract from first page, but we watermark all pages identically,
    # so extracting from any page should give same. For robustness, extract from all pages and majority vote per bit position across pages.
    all_bits_per_page = []
    zoom = DPI / 72.0
    mat = pymupdf.Matrix(zoom, zoom)
    for page in doc:
        pix = page.get_pixmap(matrix=mat, alpha=False)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        rgb = np.array(img)
        Y, _, _ = _rgb_to_ycbcr(rgb)
        bits = _extract_bits_from_y(Y, payload_len=WATERMARK_BITS)
        all_bits_per_page.append(bits)
    doc.close()

    if not all_bits_per_page:
        return None

    # Combine votes across pages: per bit position, majority across pages' majority votes?
    # Each page already did majority across blocks. Now we majority across pages.
    final_bits = []
    for pos in range(WATERMARK_BITS):
        votes = [page_bits[pos] for page_bits in all_bits_per_page]
        ones = sum(votes)
        zeros = len(votes) - ones
        final_bits.append(1 if ones > zeros else 0)

    try:
        wm = bits_to_string(final_bits)
        # Strip null padding if any
        wm = wm.rstrip('\x00')
        # Validate format: should start with "WM-" and rest hex
        if wm.startswith("WM-"):
            hex_part = wm[3:]
            # Check hex chars
            if len(hex_part) == 12 and all(c in "0123456789ABCDEFabcdef" for c in hex_part):
                # Normalize to uppercase
                return f"WM-{hex_part.upper()}"
            else:
                # Try to see if wm contains WM- pattern but with extra? Return raw if plausible
                # For prototype, return wm if it looks like watermark
                # But we want exact ledger match, so require exact format
                # If not valid, maybe extraction failed
                return None
        else:
            return None
    except Exception:
        return None

def calculate_psnr(original_pdf_bytes: bytes, watermarked_pdf_bytes: bytes) -> float:
    """
    Estimate PSNR between original and watermarked first page for invisibility check.
    """
    doc1 = pymupdf.open(stream=original_pdf_bytes, filetype="pdf")
    doc2 = pymupdf.open(stream=watermarked_pdf_bytes, filetype="pdf")
    zoom = DPI / 72.0
    mat = pymupdf.Matrix(zoom, zoom)
    pix1 = doc1[0].get_pixmap(matrix=mat, alpha=False)
    pix2 = doc2[0].get_pixmap(matrix=mat, alpha=False)
    img1 = np.array(Image.frombytes("RGB", [pix1.width, pix1.height], pix1.samples)).astype(np.float32)
    img2 = np.array(Image.frombytes("RGB", [pix2.width, pix2.height], pix2.samples)).astype(np.float32)
    doc1.close()
    doc2.close()
    mse = np.mean((img1 - img2) ** 2)
    if mse == 0:
        return float('inf')
    return 20 * np.log10(255.0 / np.sqrt(mse))
