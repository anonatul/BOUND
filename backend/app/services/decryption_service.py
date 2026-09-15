"""
Full recipient decryption flow:
1. Authenticates recipient (checks keys exist)
2. Uses ML-KEM private key to recover AES key and decrypt PDF
3. Generates fresh session ID and nonce
4. Creates watermark ID from document_hash + recipient_id + session_id + nonce
5. Watermarks/render PDF via DCT
6. Creates canonical event
7. Signs event with ML-DSA private key
8. Commits to ledger with quorum
9. Saves watermarked PDF and returns metadata
"""
import os
import pathlib
import time
import hashlib

from backend.app.encryption.document import decrypt_document
from backend.app.watermark.dct_watermark import generate_watermark_id, embed_watermark
from backend.app.forensic.events import create_decryption_event, sign_event, canonical_serialize
from backend.app.ledger.ledger import commit_event, verify_entry_quorum
from backend.app.identity.manager import get_private_keys
from backend.app.forensic.events import generate_session_and_nonce

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[3]
STORAGE_WATERMARKED = PROJECT_ROOT / "storage" / "watermarked"
STORAGE_WATERMARKED.mkdir(parents=True, exist_ok=True)

def recipient_decrypt_and_watermark(document_id: str, recipient_id: str, passphrase: str = None) -> dict:
    """
    Implements the correct architecture:
        Sender -> Encrypt -> Recipient -> Decrypt -> Generate session -> Generate watermark -> Watermark/render -> Sign event -> Ledger -> Display
    Do NOT generate final recipient/session watermark at sender encryption time.
    """
    rid = recipient_id.upper()

    # 1. Authenticate (unlocked or passphrase-protected private keys)
    priv = get_private_keys(rid, passphrase)  # raises if locked/not found

    # 2. Decrypt PDF using ML-KEM
    pdf_bytes, document_hash, meta = decrypt_document(document_id, rid, passphrase)

    # 4-6. Generate fresh session and nonce, derive watermark
    session_id, nonce = generate_session_and_nonce()
    watermark_id = generate_watermark_id(document_hash, rid, session_id, nonce)

    # Watermark/render - DCT embed
    watermarked_pdf = embed_watermark(pdf_bytes, watermark_id)

    # Calculate watermarked PDF hash for reference
    watermarked_hash = hashlib.sha256(watermarked_pdf).hexdigest()

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

    # Save watermarked document locally
    out_filename = f"{document_id}_{rid}_{session_id}.pdf"
    out_path = STORAGE_WATERMARKED / out_filename
    out_path.write_bytes(watermarked_pdf)

    return {
        "document_id": document_id,
        "recipient_id": rid,
        "session_id": session_id,
        "watermark_id": watermark_id,
        "nonce": nonce,
        "document_hash": document_hash,
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
        "watermarked_bytes_len": len(watermarked_pdf),
        "timestamp": event["timestamp"],
        # For API: need to return watermarked pdf bytes? We'll provide path and also maybe bytes preview
        "_watermarked_bytes": watermarked_pdf,  # internal, caller may want to return
    }

def load_watermarked_pdf(document_id: str, recipient_id: str, session_id: str) -> bytes:
    rid = recipient_id.upper()
    pattern = f"{document_id}_{rid}_{session_id}.pdf"
    p = STORAGE_WATERMARKED / pattern
    if not p.exists():
        raise FileNotFoundError(f"Watermarked file {pattern} not found")
    return p.read_bytes()

def list_watermarked_files():
    files = list(STORAGE_WATERMARKED.glob("*.pdf"))
    return [{"filename": f.name, "size": f.stat().st_size, "path": str(f)} for f in files]
