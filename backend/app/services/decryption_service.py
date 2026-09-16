"""
Full recipient decryption flow:
1. Authenticates recipient (checks keys exist)
2. Uses ML-KEM private key to recover the AES key and decrypt the stored document
3. Generates fresh session ID and nonce
4. Creates watermark ID from document_hash + recipient_id + session_id + nonce
5. Watermarks the original format via the format dispatcher (PDF, image, text,
   OOXML or the generic ZIP container fallback)
6. Creates canonical event
7. Signs event with ML-DSA private key
8. Commits to ledger with quorum
9. Saves the watermarked output and returns metadata
"""
import hashlib
import pathlib
import re

from backend.app.encryption.document import decrypt_document
from backend.app.forensic.events import (
    create_decryption_event,
    generate_session_and_nonce,
    sign_event,
)
from backend.app.identity.manager import get_private_keys
from backend.app.ledger.ledger import commit_event, verify_entry_quorum
from backend.app.watermark import formats
from backend.app.watermark.dct_watermark import generate_watermark_id
from backend.app.watermark.handlers import container as container_handler

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[3]
STORAGE_WATERMARKED = PROJECT_ROOT / "storage" / "watermarked"
STORAGE_WATERMARKED.mkdir(parents=True, exist_ok=True)

_STEM_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_STEM_MAX_LEN = 40


def _safe_stem(original_filename: str) -> str:
    """Sanitize the original stem to [A-Za-z0-9._-], capped at 40 chars."""
    stem = pathlib.Path(str(original_filename or "")).stem
    cleaned = _STEM_UNSAFE.sub("", stem).strip("._-")
    return cleaned[:_STEM_MAX_LEN].strip("._-") or "document"


def _suffix_for(original_filename: str, output_format: str) -> str:
    """Container output is always .zip; native formats keep their extension."""
    if output_format == "container":
        return ".zip"
    suffix = pathlib.Path(str(original_filename or "")).suffix
    return suffix if suffix and suffix != "." else ".bin"


def _produced_kind(expected_kind: str, produced: bytes) -> str:
    """Detect a container fallback applied silently by the dispatcher."""
    if expected_kind == "container":
        return expected_kind
    try:
        if container_handler.extract_container(produced) is not None:
            return "container"
    except Exception:
        pass
    return expected_kind


def recipient_decrypt_and_watermark(document_id: str, recipient_id: str, passphrase: str = None) -> dict:
    """
    Implements the correct architecture:
        Sender -> Encrypt -> Recipient -> Decrypt -> Generate session -> Generate watermark -> Watermark/render -> Sign event -> Ledger -> Display
    Do NOT generate final recipient/session watermark at sender encryption time.
    """
    rid = recipient_id.upper()

    # 1. Authenticate (unlocked or passphrase-protected private keys)
    priv = get_private_keys(rid, passphrase)  # raises if locked/not found

    # 2. Decrypt the original bytes using ML-KEM
    document_bytes, document_hash, meta = decrypt_document(document_id, rid, passphrase)
    original_filename = str(meta.get("original_filename") or "")
    embed_name = original_filename or None

    # 4-6. Generate fresh session and nonce, derive watermark
    session_id, nonce = generate_session_and_nonce()
    watermark_id = generate_watermark_id(document_hash, rid, session_id, nonce)

    # 5. Watermark/render with the format dispatcher. Native formats keep their
    # type; anything unsafe or unsupported falls back to a ZIP container.
    expected_kind = formats.handler_kind(embed_name, document_bytes)
    watermarked_bytes = formats.embed_watermark(document_bytes, watermark_id, filename=embed_name)
    output_format = _produced_kind(expected_kind, watermarked_bytes)

    # The output suffix must match what was really produced, not just the name.
    suffix = _suffix_for(original_filename, output_format)
    out_filename = f"{document_id}_{rid}_{session_id}_{_safe_stem(original_filename)}{suffix}"
    out_path = STORAGE_WATERMARKED / out_filename
    out_path.write_bytes(watermarked_bytes)

    # Hash of the watermarked artifact for reference
    watermarked_hash = hashlib.sha256(watermarked_bytes).hexdigest()

    # 6. Create canonical event
    event = create_decryption_event(
        document_id=document_id,
        document_hash=document_hash,
        recipient_id=rid,
        session_id=session_id,
        watermark_id=watermark_id,
        nonce=nonce,
    )

    # 7. Sign event with ML-DSA (recipient's own private key)
    signature_b64, public_key_b64 = sign_event(event, rid, passphrase)

    # 8. Ledger commit with per-node signing and quorum
    ledger_entry = commit_event(event, signature_b64, public_key_b64)
    quorum = verify_entry_quorum(watermark_id)

    return {
        "document_id": document_id,
        "recipient_id": rid,
        "session_id": session_id,
        "watermark_id": watermark_id,
        "nonce": nonce,
        "document_hash": document_hash,
        "original_filename": original_filename,
        "output_format": output_format,
        "output_filename": out_filename,
        "watermarked_hash": watermarked_hash,
        "event": event,
        "signature": signature_b64,
        "public_key_b64": public_key_b64,
        "ledger_entry": ledger_entry,
        "node_quorum": {
            "quorum_ok": quorum["quorum_ok"],
            "valid_nodes": quorum["valid_nodes"],
            "total_nodes": quorum["total_nodes"],
        },
        "watermarked_path": str(out_path),
        "watermarked_bytes_len": len(watermarked_bytes),
        "timestamp": event["timestamp"],
        # For API: need to return watermarked bytes? We'll provide path and also maybe bytes preview
        "_watermarked_bytes": watermarked_bytes,  # internal, caller may want to return
    }


def load_watermarked_pdf(document_id: str, recipient_id: str, session_id: str) -> bytes:
    rid = recipient_id.upper()
    prefix = f"{document_id}_{rid}_{session_id}_"
    matches = sorted(STORAGE_WATERMARKED.glob(prefix + "*"))
    if not matches:
        raise FileNotFoundError(f"Watermarked file {prefix}* not found")
    return matches[0].read_bytes()


def list_watermarked_files():
    files = sorted(p for p in STORAGE_WATERMARKED.iterdir() if p.is_file())
    return [{"filename": f.name, "size": f.stat().st_size, "path": str(f)} for f in files]
