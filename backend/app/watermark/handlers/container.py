"""
Generic ZIP container fallback.

The watermark id lives in the archive comment; the original bytes are stored as
a single deflated entry when the input is not already a readable ZIP.
"""
import io
import zipfile

from . import common

COMMENT_PREFIX = b"BOUNDWM1:"
DEFAULT_ENTRY = "payload.bin"


def embed_container(data: bytes, watermark_id: str, filename: str | None = None) -> bytes:
    """Watermark any byte stream by wrapping or commenting a ZIP archive."""
    wm = common.validate_id(watermark_id)
    comment = COMMENT_PREFIX + wm.encode("ascii")
    commented = _set_comment(data, comment)
    if commented is not None:
        return commented
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(_entry_name(filename), data)
        archive.comment = comment
    return buf.getvalue()


def extract_container(data: bytes) -> str | None:
    """Read and validate the watermark id from a ZIP archive comment."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            comment = archive.comment
    except Exception:
        return None
    if not comment.startswith(COMMENT_PREFIX):
        return None
    try:
        watermark_id = comment[len(COMMENT_PREFIX):].decode("ascii")
    except UnicodeDecodeError:
        return None
    return watermark_id if common.ID_RE.match(watermark_id) else None


def _set_comment(data: bytes, comment: bytes) -> bytes | None:
    """Update the comment of an existing ZIP in place, or return None."""
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return None
    buf = io.BytesIO(data)
    try:
        with zipfile.ZipFile(buf, "a") as archive:
            archive.comment = comment
        return buf.getvalue()
    except Exception:
        return None


def _entry_name(filename: str | None) -> str:
    if not filename:
        return DEFAULT_ENTRY
    name = str(filename).replace("\\", "/").rsplit("/", 1)[-1]
    name = name.replace("\x00", "").strip()
    return name or DEFAULT_ENTRY
