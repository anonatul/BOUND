"""
Image watermark handler.

The watermark is QIM-embedded in the luminance channel (same payload, CRC,
repetition and DCT coefficient as the PDF channel) and the image is re-encoded
in its original container: PNG/BMP/TIFF/WebP losslessly, JPEG at quality 90.
"""
import io

import numpy as np
from PIL import Image

from ..dct_watermark import MIN_IMAGE_BLOCKS
from . import common
from .common import ContainerFallback


def embed_image(data: bytes, watermark_id: str, filename: str | None = None) -> bytes:
    """Return the image with the watermark embedded, or raise ContainerFallback."""
    wm = common.validate_id(watermark_id)
    try:
        img = Image.open(io.BytesIO(data))
        fmt = (img.format or "").upper()
        if getattr(img, "is_animated", False) or fmt == "GIF":
            raise ContainerFallback("animated image")
        if img.mode in ("P", "PA"):
            raise ContainerFallback("palette image")
        if ((img.width + 7) // 8) * ((img.height + 7) // 8) < MIN_IMAGE_BLOCKS:
            raise ContainerFallback("image too small to carry the payload")
        alpha = img.getchannel("A") if img.mode in ("RGBA", "LA") else None
        rgb = np.array(img.convert("RGB"))
    except ContainerFallback:
        raise
    except Exception as exc:
        raise ContainerFallback(f"cannot read image: {exc}") from exc

    Y, Cb, Cr = common.rgb_to_ycbcr(rgb)
    Y_wm = common.embed_bits_in_y(Y, common.payload_bits(wm))
    out = Image.fromarray(common.ycbcr_to_rgb(Y_wm, Cb, Cr))
    if alpha is not None:
        out = out.convert("RGBA")
        out.putalpha(alpha)

    buf = io.BytesIO()
    try:
        _save(out, fmt, buf)
    except Exception as exc:
        raise ContainerFallback(f"cannot re-encode image: {exc}") from exc
    return buf.getvalue()


def extract_image(data: bytes) -> str | None:
    """Blind extraction from an image's Y channel; None when nothing validates."""
    try:
        img = Image.open(io.BytesIO(data))
        if getattr(img, "is_animated", False) or img.mode in ("P", "PA"):
            return None
        rgb = np.array(img.convert("RGB"))
    except Exception:
        return None
    Y, _, _ = common.rgb_to_ycbcr(rgb)
    return common.extract_bits_from_y(Y)


def _save(image: Image.Image, fmt: str, buf: io.BytesIO) -> None:
    if fmt == "JPEG":
        image.convert("RGB").save(buf, format="JPEG", quality=90)
    elif fmt == "BMP":
        try:
            image.save(buf, format="BMP")
        except Exception:
            buf.seek(0)
            buf.truncate(0)
            image.convert("RGB").save(buf, format="BMP")
    elif fmt == "TIFF":
        image.save(buf, format="TIFF", compression="tiff_lzw")
    elif fmt == "WEBP":
        try:
            image.save(buf, format="WEBP", lossless=True)
        except Exception:
            buf.seek(0)
            buf.truncate(0)
            image.convert("RGB").save(buf, format="WEBP", quality=90)
    else:
        image.save(buf, format="PNG")
