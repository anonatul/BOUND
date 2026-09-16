"""
Shared watermark primitives for every format handler.

- Payload framing: 29 ASCII id bytes + big-endian CRC32, repetition R=5,
  majority decode gated by CRC. The DCT QIM helpers are the single
  implementation used by the PDF channel (dct_watermark) and the image channel.
- Zero-width marker: bit 0 = U+200B, bit 1 = U+200C, framed by U+2060 guards.
  Text and OOXML handlers use the exact same encoding.
"""
import binascii
import os
import re

import numpy as np

from ..dct_watermark import (
    EXTENDED_BITS,
    ID_RE,
    PAYLOAD_BYTES,
    WATERMARK_ID_LEN,
    _accumulate_votes,
    _decode_votes,
    _embed_bits_in_y,
    _payload_bits,
    _rgb_to_ycbcr,
    _ycbcr_to_rgb,
)

PDF_EXTENSIONS = {".pdf"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}
TEXT_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".log", ".csv", ".tsv", ".json",
    ".xml", ".yaml", ".yml", ".html", ".htm", ".ini", ".cfg",
}
OOXML_EXTENSIONS = {".docx", ".xlsx", ".pptx"}
SUPPORTED_EXTENSIONS = PDF_EXTENSIONS | IMAGE_EXTENSIONS | TEXT_EXTENSIONS | OOXML_EXTENSIONS

ZW_GUARD = "\u2060"
ZW_ZERO = "\u200b"
ZW_ONE = "\u200c"
ZW_RE = re.compile("\u2060([\u200b\u200c]+)\u2060")


class ContainerFallback(Exception):
    """Raised when a format handler cannot embed the watermark safely."""


def file_extension(filename: str | None) -> str:
    """Return the lowercase extension (with dot) of a filename, or ""."""
    if not filename:
        return ""
    name = str(filename).replace("\\", "/").rsplit("/", 1)[-1]
    return os.path.splitext(name)[1].lower()


def validate_id(watermark_id: str) -> str:
    """Return the uppercased id or raise ValueError when it is malformed."""
    wm = str(watermark_id).upper()
    if ID_RE.match(wm) is None:
        raise ValueError(f"invalid watermark id: {watermark_id!r}")
    return wm


def payload_bits(watermark_id: str) -> np.ndarray:
    """ID bytes + CRC32 expanded with the repetition R=5 code."""
    return _payload_bits(watermark_id)


def embed_bits_in_y(Y: np.ndarray, bits: np.ndarray) -> np.ndarray:
    """QIM-embed bits in the Y channel of an image."""
    return _embed_bits_in_y(Y, bits)


def extract_bits_from_y(Y: np.ndarray) -> str | None:
    """Majority-decode the QIM payload from a Y channel, CRC gated."""
    ones = np.zeros(EXTENDED_BITS, dtype=np.int64)
    totals = np.zeros(EXTENDED_BITS, dtype=np.int64)
    _accumulate_votes(Y, ones, totals)
    return _decode_votes(ones, totals)


def rgb_to_ycbcr(rgb: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    return _rgb_to_ycbcr(rgb)


def ycbcr_to_rgb(Y: np.ndarray, Cb: np.ndarray, Cr: np.ndarray) -> np.ndarray:
    return _ycbcr_to_rgb(Y, Cb, Cr)


def payload_from_id(watermark_id: str) -> bytes:
    """ID ASCII bytes followed by the big-endian CRC32 of those bytes."""
    data = validate_id(watermark_id).encode("ascii")
    return data + (binascii.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big")


def bits_to_bytes(bits: str) -> bytes:
    """Pack a '0'/'1' string into bytes, most significant bit first."""
    out = bytearray()
    for index in range(0, len(bits) - 7, 8):
        out.append(int(bits[index:index + 8], 2))
    return bytes(out)


def zw_marker(watermark_id: str) -> str:
    """Encode the payload as a U+2060-guarded zero-width bit string."""
    payload = payload_from_id(watermark_id)
    bits = "".join(f"{byte:08b}" for byte in payload)
    return ZW_GUARD + bits.replace("0", ZW_ZERO).replace("1", ZW_ONE) + ZW_GUARD


def zw_find(text: str) -> list[str]:
    """Return every CRC-valid watermark id found in zero-width markers."""
    found = []
    for match in ZW_RE.finditer(text):
        bits = match.group(1).replace(ZW_ZERO, "0").replace(ZW_ONE, "1")
        payload = bits_to_bytes(bits)
        if len(payload) < PAYLOAD_BYTES:
            continue
        data = payload[:WATERMARK_ID_LEN]
        crc = payload[WATERMARK_ID_LEN:PAYLOAD_BYTES]
        if (binascii.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big") != crc:
            continue
        try:
            watermark_id = data.decode("ascii")
        except UnicodeDecodeError:
            continue
        if ID_RE.match(watermark_id) and watermark_id not in found:
            found.append(watermark_id)
    return found
