"""
Zero-width Unicode watermarking for OOXML documents (docx/xlsx/pptx).

A watermark id is encoded as its ASCII bytes plus a big-endian CRC32, expanded
bit by bit into zero-width characters (U+200B for 0, U+200C for 1) and framed
by U+2060 guard characters. The OOXML zip is rebuilt with every other member
copied byte-for-byte; exactly one XML member is edited with precise string
surgery on the raw XML text so namespaces survive and the visible document is
untouched.
"""
import io
import re
import struct
import zipfile
import zlib

SUPPORTED = ("docx", "xlsx", "pptx")
ID_RE = re.compile(r"^WM-[A-Z2-7]{26}$")
ID_BYTES = 29
CRC_BYTES = 4
PAYLOAD_BYTES = ID_BYTES + CRC_BYTES

ZW_ZERO = "\u200b"
ZW_ONE = "\u200c"
ZW_GUARD = "\u2060"
MARKER_RE = re.compile("\u2060([\u200b\u200c]+)\u2060")

DOCX_MEMBER = "word/document.xml"
SST_MEMBER = "xl/sharedStrings.xml"
CORE_MEMBER = "docProps/core.xml"
PPTT_SLIDE = "ppt/slides/slide1.xml"
SHEET_RE = re.compile(r"^xl/worksheets/sheet[^/]*\.xml$")
SLIDE_RE = re.compile(r"^ppt/slides/slide[^/]*\.xml$")
DC_NS = "http://purl.org/dc/elements/1.1/"


def supported_extensions() -> list[str]:
    return list(SUPPORTED)


def embed(data: bytes, watermark_id: str, extension: str) -> bytes:
    """
    Return a new OOXML byte string carrying watermark_id as a zero-width marker.

    Raises ValueError when the id, the extension or the archive contents make a
    safe, verifiable embedding impossible.
    """
    if not isinstance(watermark_id, str):
        raise ValueError("watermark id must be a string")
    watermark_id = watermark_id.strip().upper()
    if ID_RE.match(watermark_id) is None:
        raise ValueError(f"invalid watermark id: {watermark_id!r}")
    if not isinstance(extension, str):
        raise ValueError("extension must be a string")
    normalized = extension.strip().lower().lstrip(".")
    if normalized not in SUPPORTED:
        raise ValueError(f"unsupported extension: {extension!r}")

    marker = _encode_marker(watermark_id)
    entries = _read_entries(data)
    replacements = _build_replacement(entries, normalized, marker)
    result = _rebuild(entries, replacements)
    _assert_readable(result)
    return result


def extract(data: bytes) -> str | None:
    """
    Decode the first valid watermark id from an OOXML archive, or None.

    Never raises, whatever the input bytes are.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            names = archive.namelist()
            for name in _extraction_order(names):
                try:
                    raw = archive.read(name)
                except Exception:
                    continue
                found = _decode_marker(_decode_text(raw))
                if found is not None:
                    return found
    except Exception:
        return None
    return None


def _encode_marker(watermark_id: str) -> str:
    raw = watermark_id.encode("ascii")
    payload = raw + struct.pack(">I", zlib.crc32(raw) & 0xFFFFFFFF)
    bits = "".join(
        ZW_ONE if (byte >> shift) & 1 else ZW_ZERO
        for byte in payload
        for shift in range(7, -1, -1)
    )
    return ZW_GUARD + bits + ZW_GUARD


def _decode_marker(text: str) -> str | None:
    for match in MARKER_RE.finditer(text):
        bits = match.group(1)
        if len(bits) != PAYLOAD_BYTES * 8:
            continue
        payload = bytearray()
        for index in range(0, len(bits), 8):
            value = 0
            for char in bits[index:index + 8]:
                value = (value << 1) | (1 if char == ZW_ONE else 0)
            payload.append(value)
        payload = bytes(payload)
        crc = struct.unpack(">I", payload[ID_BYTES:PAYLOAD_BYTES])[0]
        if zlib.crc32(payload[:ID_BYTES]) & 0xFFFFFFFF != crc:
            continue
        try:
            watermark_id = payload[:ID_BYTES].decode("ascii")
        except UnicodeDecodeError:
            continue
        if ID_RE.match(watermark_id):
            return watermark_id
    return None


def _read_entries(data: bytes) -> list[tuple[zipfile.ZipInfo, bytes]]:
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            return [(info, archive.read(info)) for info in archive.infolist()]
    except Exception as exc:
        raise ValueError("input is not a readable OOXML zip archive") from exc


def _build_replacement(
    entries: list[tuple[zipfile.ZipInfo, bytes]], extension: str, marker: str
) -> dict[str, bytes]:
    members = {info.filename: raw for info, raw in entries}
    if extension == "docx":
        return {DOCX_MEMBER: _docx_document(members, marker)}
    if extension == "xlsx":
        return _xlsx_replacement(members, marker)
    return {PPTT_SLIDE: _pptx_slide(members, marker)}


def _docx_document(members: dict[str, bytes], marker: str) -> bytes:
    raw = members.get(DOCX_MEMBER)
    if raw is None:
        raise ValueError(f"{DOCX_MEMBER} is missing")
    xml = _decode_xml(raw, DOCX_MEMBER)
    updated = _append_to_first_element(xml, "w:t", marker)
    if updated is None:
        run = f'<w:r><w:t xml:space="preserve">{marker}</w:t></w:r>'
        updated = _insert_before_last(xml, "</w:body>", run)
    if updated is None:
        raise ValueError(f"could not embed into {DOCX_MEMBER}")
    return updated.encode("utf-8")


def _xlsx_replacement(members: dict[str, bytes], marker: str) -> dict[str, bytes]:
    candidates = [SST_MEMBER] + _matching(members, SHEET_RE) + [CORE_MEMBER]
    for name in candidates:
        raw = members.get(name)
        if raw is None:
            continue
        try:
            xml = _decode_xml(raw, name)
        except ValueError:
            continue
        if name == CORE_MEMBER:
            updated = _insert_dc_description(xml, marker)
        else:
            updated = _append_to_first_element(xml, "t", marker)
        if updated is not None:
            return {name: updated.encode("utf-8")}
    raise ValueError("no embeddable member found in xlsx archive")


def _pptx_slide(members: dict[str, bytes], marker: str) -> bytes:
    raw = members.get(PPTT_SLIDE)
    if raw is None:
        raise ValueError(f"{PPTT_SLIDE} is missing")
    xml = _decode_xml(raw, PPTT_SLIDE)
    updated = _append_to_first_element(xml, "a:t", marker)
    if updated is None:
        raise ValueError(f"no <a:t> element found in {PPTT_SLIDE}")
    return updated.encode("utf-8")


def _decode_xml(raw: bytes, name: str) -> str:
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{name} is not valid UTF-8 XML") from exc


def _decode_text(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="ignore")


def _append_to_first_element(xml: str, tag: str, marker: str) -> str | None:
    pattern = re.compile(
        r"<" + re.escape(tag) + r"(?:\s[^>]*)?>(.*?)</" + re.escape(tag) + r">",
        re.DOTALL,
    )
    match = pattern.search(xml)
    if match is None:
        return None
    end = match.end(1)
    return xml[:end] + marker + xml[end:]


def _insert_before_last(xml: str, closer: str, snippet: str) -> str | None:
    index = xml.rfind(closer)
    if index == -1:
        return None
    return xml[:index] + snippet + xml[index:]


def _insert_dc_description(xml: str, marker: str) -> str | None:
    root = re.search(r"<(?:[A-Za-z0-9_.-]+:)?coreProperties\b[^>]*>", xml)
    if root is None:
        return None
    open_tag = root.group(0)
    prefix_match = re.match(r"<([A-Za-z0-9_.-]+):", open_tag)
    prefix = prefix_match.group(1) + ":" if prefix_match else ""
    declaration = f' xmlns:dc="{DC_NS}"'
    needs_namespace = re.search(r"\bxmlns:dc\s*=", open_tag) is None
    element = f"<dc:description>{marker}</dc:description>"
    if open_tag.endswith("/>"):
        new_open = open_tag[:-2].rstrip()
        if needs_namespace:
            new_open += declaration
        replacement = new_open + ">" + element + f"</{prefix}coreProperties>"
        return xml[:root.start()] + replacement + xml[root.end():]
    closer = f"</{prefix}coreProperties>"
    index = xml.rfind(closer)
    if index == -1:
        return None
    if needs_namespace:
        open_tag = open_tag[:-1] + declaration + ">"
    return xml[:root.start()] + open_tag + xml[root.end():index] + element + xml[index:]


def _matching(names, pattern: re.Pattern) -> list[str]:
    return sorted(name for name in names if pattern.match(name))


def _extraction_order(names: list[str]) -> list[str]:
    order = []
    if DOCX_MEMBER in names:
        order.append(DOCX_MEMBER)
    if SST_MEMBER in names:
        order.append(SST_MEMBER)
    order.extend(_matching(names, SHEET_RE))
    order.extend(_matching(names, SLIDE_RE))
    if CORE_MEMBER in names:
        order.append(CORE_MEMBER)
    return order


def _rebuild(
    entries: list[tuple[zipfile.ZipInfo, bytes]], replacements: dict[str, bytes]
) -> bytes:
    buffer = io.BytesIO()
    try:
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for info, original in entries:
                clone = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                clone.compress_type = zipfile.ZIP_DEFLATED
                clone.external_attr = info.external_attr
                clone.internal_attr = info.internal_attr
                clone.create_system = info.create_system
                clone.comment = info.comment
                archive.writestr(clone, replacements.get(info.filename, original))
    except Exception as exc:
        raise ValueError("failed to rebuild the OOXML archive") from exc
    return buffer.getvalue()


def _assert_readable(data: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            if archive.testzip() is not None:
                raise ValueError("rebuilt OOXML archive failed its integrity check")
    except zipfile.BadZipFile as exc:
        raise ValueError("rebuilt OOXML archive is not a readable zip") from exc
