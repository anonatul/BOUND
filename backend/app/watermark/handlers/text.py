"""
Text-like file watermark handler.

The watermark is hidden in zero-width characters inserted where the file type
allows it without changing the visible content (or, for XML/YAML, where only an
invisible-in-rendering comment is added).
"""
from . import common
from .common import ContainerFallback


def embed_text(data: bytes, watermark_id: str, filename: str | None = None) -> bytes:
    """Return UTF-8 bytes with a zero-width marker, or raise ContainerFallback."""
    wm = common.validate_id(watermark_id)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContainerFallback("text is not valid UTF-8") from exc
    marker = common.zw_marker(wm)
    extension = common.file_extension(filename)
    if extension == ".json":
        updated = _insert_json_string(text, marker)
    elif extension in (".csv", ".tsv"):
        updated = _insert_first_line(text, marker)
    elif extension in (".yaml", ".yml"):
        updated = _append_yaml_comment(text, marker)
    elif extension in (".xml", ".html", ".htm"):
        updated = _insert_xml_comment(text, marker)
    else:
        updated = text + marker
    if updated is None:
        raise ContainerFallback(f"no safe insertion point for {extension or 'text'}")
    return updated.encode("utf-8")


def extract_text(data: bytes) -> str | None:
    """Decode the first CRC-valid zero-width marker, or None."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    found = common.zw_find(text)
    return found[0] if found else None


def _insert_first_line(text: str, marker: str) -> str:
    """Put the marker at the end of the first line, before CR/LF."""
    newline = text.find("\n")
    if newline == -1:
        return text + marker
    if newline > 0 and text[newline - 1] == "\r":
        newline -= 1
    return text[:newline] + marker + text[newline:]


def _append_yaml_comment(text: str, marker: str) -> str:
    """Append a YAML comment line holding the marker."""
    if text and not text.endswith("\n"):
        text += "\n"
    return text + "# " + marker + "\n"


def _insert_xml_comment(text: str, marker: str) -> str:
    """Put an XML/HTML comment before the last closing tag, else at the end."""
    comment = "<!-- " + marker + " -->"
    index = text.rfind("</")
    if index == -1:
        return text + comment
    return text[:index] + comment + text[index:]


def _insert_json_string(text: str, marker: str) -> str | None:
    """Put the marker inside the first complete JSON string literal."""
    index = 0
    length = len(text)
    while index < length:
        if text[index] == '"' and not _is_escaped(text, index):
            if _find_string_end(text, index + 1) is None:
                return None
            return text[:index + 1] + marker + text[index + 1:]
        index += 1
    return None


def _find_string_end(text: str, start: int) -> int | None:
    index = start
    while index < len(text):
        if text[index] == '"' and not _is_escaped(text, index):
            return index
        index += 1
    return None


def _is_escaped(text: str, index: int) -> bool:
    backslashes = 0
    index -= 1
    while index >= 0 and text[index] == "\\":
        backslashes += 1
        index -= 1
    return backslashes % 2 == 1
