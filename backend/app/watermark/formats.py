"""
Format dispatcher for forensic watermarks.

Native handlers cover PDF, images, text-like files and OOXML packages; every
other byte stream goes through the generic ZIP container fallback, so any file
can carry a watermark. PDF is only assumed on the %PDF magic when no filename
is supplied; otherwise unknown data is container-wrapped.
"""
import inspect
import io
import mimetypes
import zipfile

from PIL import Image

from . import dct_watermark
from .handlers import common, container, image, text
from .handlers.common import ContainerFallback, file_extension

PDF_EXTENSIONS = common.PDF_EXTENSIONS
IMAGE_EXTENSIONS = common.IMAGE_EXTENSIONS
TEXT_EXTENSIONS = common.TEXT_EXTENSIONS
OOXML_EXTENSIONS = common.OOXML_EXTENSIONS
SUPPORTED_EXTENSIONS = common.SUPPORTED_EXTENSIONS

_KINDS = ("pdf", "image", "text", "ooxml", "container")
_OOXML_NAMES = ("[Content_Types].xml",)
_OOXML_PREFIXES = ("word/", "xl/", "ppt/")


def is_supported(filename: str) -> bool:
    """
    True when the file can be watermarked.

    Native formats are handled directly and every other extension is supported
    through the generic ZIP container fallback, so any named file qualifies.
    """
    return bool(filename)


def handler_kind(filename: str | None, data: bytes | None = None) -> str:
    """Return "pdf" | "image" | "text" | "ooxml" | "container" for a file."""
    extension = file_extension(filename)
    if extension in PDF_EXTENSIONS:
        return "pdf"
    if extension in IMAGE_EXTENSIONS:
        return "image"
    if extension in TEXT_EXTENSIONS:
        return "text"
    if extension in OOXML_EXTENSIONS:
        return "ooxml"
    return _sniff_kind(data)


def output_filename(original_filename: str) -> str:
    """Native formats keep their name; container fallbacks get a .zip suffix."""
    name = str(original_filename or "")
    if not name:
        return name
    if handler_kind(name) == "container" and not name.lower().endswith(".zip"):
        return name + ".zip"
    return name


def output_media_type(original_filename: str) -> str:
    """Media type guessed from the output filename."""
    guessed = mimetypes.guess_type(output_filename(original_filename))[0]
    return guessed or "application/octet-stream"


def embed_watermark(data: bytes, watermark_id: str, filename: str | None = None,
                    mode: str = "preserve") -> bytes:
    """
    Embed watermark_id using the handler for the file type, falling back to the
    ZIP container whenever a type-specific handler cannot embed safely.
    """
    raw = bytes(data)
    wm = common.validate_id(watermark_id)
    if filename is None:
        kind = "pdf" if raw[:4] == b"%PDF" else "container"
    else:
        kind = handler_kind(filename, raw)
    try:
        result = _embed_with_kind(kind, raw, wm, filename, mode)
        if result is not None:
            return result
    except ContainerFallback:
        pass
    except Exception:
        pass
    return container.embed_container(raw, wm, filename)


def extract_watermark(data: bytes, filename: str | None = None) -> str | None:
    """
    Extract the first CRC-valid watermark id, or None. Never raises.
    """
    raw = bytes(data) if data is not None else b""
    try:
        kind = handler_kind(filename, raw)
    except Exception:
        kind = "container"
    result = None
    try:
        result = _extract_with_kind(kind, raw, filename)
    except Exception:
        result = None
    if result:
        return result
    if kind != "container" and _is_zip(raw):
        result = container.extract_container(raw)
        if result:
            return result
    if kind != "pdf" and raw[:4] == b"%PDF":
        result = dct_watermark.extract_watermark(raw)
        if result:
            return result
    if kind != "text" and _is_text(raw):
        found = common.zw_find(raw.decode("utf-8"))
        if found:
            return found[0]
    return None


def _sniff_kind(data: bytes | None) -> str:
    if not data:
        return "container"
    if bytes(data[:4]) == b"%PDF":
        return "pdf"
    if _is_zip(data):
        return "ooxml" if _zip_is_ooxml(data) else "container"
    if _is_image(data):
        return "image"
    if _is_text(data):
        return "text"
    return "container"


def _embed_with_kind(kind: str, data: bytes, wm: str, filename: str | None,
                     mode: str) -> bytes | None:
    if kind == "pdf":
        return dct_watermark.embed_watermark(data, wm, mode=mode)
    if kind == "image":
        return image.embed_image(data, wm, filename)
    if kind == "text":
        return text.embed_text(data, wm, filename)
    if kind == "ooxml":
        embed = _ooxml_function("embed")
        if embed is None:
            raise ContainerFallback("ooxml handler unavailable")
        extension = file_extension(filename).lstrip(".")
        try:
            parameters = list(inspect.signature(embed).parameters)
        except (TypeError, ValueError):
            parameters = ["data", "watermark_id"]
        if len(parameters) >= 3:
            return embed(data, wm, extension)
        return embed(data, wm)
    return container.embed_container(data, wm, filename)


def _extract_with_kind(kind: str, data: bytes, filename: str | None) -> str | None:
    if kind == "pdf":
        return dct_watermark.extract_watermark(data)
    if kind == "image":
        return image.extract_image(data)
    if kind == "text":
        return text.extract_text(data)
    if kind == "ooxml":
        extract = _ooxml_function("extract")
        if extract is not None:
            result = extract(data)
            if result:
                return result
        return container.extract_container(data)
    return container.extract_container(data)


def _ooxml_function(name: str):
    """Fetch the OOXML handler lazily; None when it is unavailable."""
    try:
        from .handlers import ooxml
    except Exception:
        return None
    for attribute in (f"{name}_ooxml", name):
        function = getattr(ooxml, attribute, None)
        if callable(function):
            return function
    return None


def _is_zip(data: bytes) -> bool:
    try:
        return zipfile.is_zipfile(io.BytesIO(data))
    except Exception:
        return False


def _zip_is_ooxml(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
    except Exception:
        return False
    if not any(name in names for name in _OOXML_NAMES):
        return False
    return any(name.startswith(_OOXML_PREFIXES) for name in names)


def _is_image(data: bytes) -> bool:
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.verify()
        return True
    except Exception:
        return False


def _is_text(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except Exception:
        return False
    return "\x00" not in text
