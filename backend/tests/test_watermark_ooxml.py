"""
Tests for the zero-width Unicode OOXML watermark handler (docx/xlsx/pptx).
"""
import io
import re
import struct
import zipfile
import zlib

import pytest

from backend.app.watermark.handlers.ooxml import embed, extract, supported_extensions

WM_ID = "WM-KUJZ7TSMYLSVGXFCQJ744NJ3HE"
ZW_RE = re.compile("[\u200b\u200c\u2060]")

CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Default Extension="rels" '
    'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    "</Types>"
)

RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
    'relationships/officeDocument" Target="word/document.xml"/>'
    "</Relationships>"
)

DOCX_DOCUMENT = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body>"
    "<w:p><w:r><w:t xml:space=\"preserve\">Hello docx body</w:t></w:r></w:p>"
    "</w:body></w:document>"
)

DOCX_NO_TEXT = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body><w:p/></w:body></w:document>"
)

DOCX_BINARY = b"\x89PNG\r\n\x1a\n\x00\x01binary-ooxml-member\xff\xfe"

SST_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'count="1" uniqueCount="1">'
    '<si><t xml:space="preserve">Hello shared string</t></si>'
    "</sst>"
)

SHEET_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    "<sheetData>"
    '<row r="1"><c r="A1" t="inlineStr"><is><t>Hello inline string</t></is></c></row>'
    "</sheetData></worksheet>"
)

WORKBOOK_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>'
    "</workbook>"
)

CORE_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<cp:coreProperties '
    'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
    'xmlns:dcterms="http://purl.org/dc/terms/" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    "<cp:revision>1</cp:revision>"
    "</cp:coreProperties>"
)

CORE_XML_WITH_DC = CORE_XML.replace(
    'xmlns:cp=', 'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:cp=', 1
)

PPTX_SLIDE = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
    "<p:cSld><p:spTree>"
    "<p:sp><p:txBody><a:bodyPr/><a:lstStyle/>"
    "<a:p><a:r><a:t>Hello slide one</a:t></a:r></a:p>"
    "</p:txBody></p:sp>"
    "</p:spTree></p:cSld></p:sld>"
)


def _zip_bytes(members: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            if isinstance(content, str):
                content = content.encode("utf-8")
            archive.writestr(name, content)
    return buffer.getvalue()


def _member(data: bytes, name: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return archive.read(name)


def _names(data: bytes) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return archive.namelist()


def _strip_zw(text: str) -> str:
    return ZW_RE.sub("", text)


def _assert_valid_zip(data: bytes) -> None:
    assert zipfile.is_zipfile(io.BytesIO(data))
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.testzip() is None


def _make_docx(document: str = DOCX_DOCUMENT) -> bytes:
    return _zip_bytes({
        "[Content_Types].xml": CONTENT_TYPES,
        "_rels/.rels": RELS,
        "word/document.xml": document,
        "word/styles.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>'
        ),
        "word/media/image1.bin": DOCX_BINARY,
    })


def _make_xlsx(members: dict) -> bytes:
    base = {"[Content_Types].xml": CONTENT_TYPES, "xl/workbook.xml": WORKBOOK_XML}
    base.update(members)
    return _zip_bytes(base)


def _make_pptx() -> bytes:
    return _zip_bytes({
        "[Content_Types].xml": CONTENT_TYPES,
        "ppt/slides/slide1.xml": PPTX_SLIDE,
    })


def _local_marker(watermark_id: str, flip_crc: bool = False) -> str:
    raw = watermark_id.encode("ascii")
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    if flip_crc:
        crc ^= 0xFFFFFFFF
    payload = raw + struct.pack(">I", crc)
    bits = "".join(
        "\u200c" if (byte >> shift) & 1 else "\u200b"
        for byte in payload
        for shift in range(7, -1, -1)
    )
    return "\u2060" + bits + "\u2060"


def test_supported_extensions():
    assert supported_extensions() == ["docx", "xlsx", "pptx"]


def test_docx_round_trip_and_integrity():
    out = embed(_make_docx(), WM_ID, "docx")
    assert extract(out) == WM_ID
    _assert_valid_zip(out)
    assert set(_names(out)) == set(_names(_make_docx()))


def test_docx_visible_text_unchanged():
    out = embed(_make_docx(), WM_ID, "docx")
    modified = _member(out, "word/document.xml").decode("utf-8")
    assert _strip_zw(modified) == DOCX_DOCUMENT
    assert '<w:t xml:space="preserve">Hello docx body</w:t>' in _strip_zw(modified)


def test_docx_other_members_unchanged():
    original = _make_docx()
    out = embed(original, WM_ID, "docx")
    assert _member(out, "word/media/image1.bin") == DOCX_BINARY
    assert _member(out, "word/styles.xml") == _member(original, "word/styles.xml")
    assert _member(out, "_rels/.rels") == _member(original, "_rels/.rels")


def test_docx_inserts_run_when_no_text_element():
    out = embed(_make_docx(DOCX_NO_TEXT), WM_ID, "docx")
    assert extract(out) == WM_ID
    modified = _member(out, "word/document.xml").decode("utf-8")
    assert modified.rfind('<w:r><w:t xml:space="preserve">') < modified.rfind("</w:body>")
    assert "<w:p/>" in _strip_zw(modified)


def test_extract_decodes_locally_built_marker():
    document = DOCX_DOCUMENT.replace("</w:t>", _local_marker(WM_ID) + "</w:t>", 1)
    data = _make_docx(document)
    assert extract(data) == WM_ID


def test_extract_rejects_marker_with_bad_crc():
    document = DOCX_DOCUMENT.replace(
        "</w:t>", _local_marker(WM_ID, flip_crc=True) + "</w:t>", 1
    )
    data = _make_docx(document)
    assert extract(data) is None


def test_xlsx_shared_strings_round_trip():
    original = _make_xlsx({
        "xl/sharedStrings.xml": SST_XML,
        "xl/worksheets/sheet1.xml": SHEET_XML,
    })
    out = embed(original, WM_ID, "xlsx")
    assert extract(out) == WM_ID
    _assert_valid_zip(out)
    modified = _member(out, "xl/sharedStrings.xml").decode("utf-8")
    assert _strip_zw(modified) == SST_XML
    assert _member(out, "xl/worksheets/sheet1.xml") == _member(original, "xl/worksheets/sheet1.xml")


def test_xlsx_worksheet_only_round_trip():
    original = _make_xlsx({"xl/worksheets/sheet1.xml": SHEET_XML})
    out = embed(original, WM_ID, "xlsx")
    assert extract(out) == WM_ID
    _assert_valid_zip(out)
    modified = _member(out, "xl/worksheets/sheet1.xml").decode("utf-8")
    assert _strip_zw(modified) == SHEET_XML


def test_xlsx_core_properties_only_round_trip():
    original = _make_xlsx({"docProps/core.xml": CORE_XML})
    out = embed(original, WM_ID, "xlsx")
    assert extract(out) == WM_ID
    _assert_valid_zip(out)
    modified = _member(out, "docProps/core.xml").decode("utf-8")
    assert 'xmlns:dc="http://purl.org/dc/elements/1.1/"' in modified
    assert re.search(
        "<dc:description>\u2060[\u200b\u200c]+\u2060</dc:description>", modified
    )
    stripped = _strip_zw(modified)
    assert "<cp:revision>1</cp:revision>" in stripped
    assert "<dc:description></dc:description>" in stripped


def test_xlsx_core_properties_existing_dc_namespace_not_duplicated():
    original = _make_xlsx({"docProps/core.xml": CORE_XML_WITH_DC})
    out = embed(original, WM_ID, "xlsx")
    assert extract(out) == WM_ID
    modified = _member(out, "docProps/core.xml").decode("utf-8")
    assert modified.count("xmlns:dc=") == 1


def test_pptx_round_trip_and_visible_text():
    out = embed(_make_pptx(), WM_ID, "pptx")
    assert extract(out) == WM_ID
    _assert_valid_zip(out)
    modified = _member(out, "ppt/slides/slide1.xml").decode("utf-8")
    assert _strip_zw(modified) == PPTX_SLIDE
    assert "<a:t>Hello slide one</a:t>" in _strip_zw(modified)


def test_extract_on_plain_bytes_returns_none():
    assert extract(b"this is definitely not a zip archive") is None
    assert extract(b"") is None


def test_extract_on_zip_without_marker_returns_none():
    assert extract(_make_docx()) is None
    assert extract(_make_xlsx({"xl/sharedStrings.xml": SST_XML})) is None
    assert extract(_make_pptx()) is None


def test_embed_docx_missing_document_raises():
    data = _zip_bytes({"[Content_Types].xml": CONTENT_TYPES, "word/styles.xml": "<x/>"})
    with pytest.raises(ValueError):
        embed(data, WM_ID, "docx")


def test_embed_xlsx_without_candidate_members_raises():
    data = _zip_bytes({"[Content_Types].xml": CONTENT_TYPES})
    with pytest.raises(ValueError):
        embed(data, WM_ID, "xlsx")


def test_embed_pptx_without_slide_raises():
    data = _zip_bytes({"[Content_Types].xml": CONTENT_TYPES})
    with pytest.raises(ValueError):
        embed(data, WM_ID, "pptx")


def test_embed_unsupported_extension_raises():
    with pytest.raises(ValueError):
        embed(_make_docx(), WM_ID, "pdf")


def test_embed_mismatched_extension_raises():
    with pytest.raises(ValueError):
        embed(_make_docx(), WM_ID, "pptx")


def test_embed_invalid_watermark_id_raises():
    with pytest.raises(ValueError):
        embed(_make_docx(), "WM-TOOSHORT", "docx")
    with pytest.raises(ValueError):
        embed(_make_docx(), "WM-" + "1" * 26, "docx")


def test_embed_non_zip_raises():
    with pytest.raises(ValueError):
        embed(b"not a zip at all", WM_ID, "docx")
