import os
import json
import hashlib
import base64
import mimetypes
import pathlib
import time
from typing import List, Dict, Tuple

from backend.app.crypto.pqcrypto_wrapper import mlkem_encaps, mlkem_decaps, b64e, b64d
from backend.app.encryption.aes import generate_aes_key, aes_gcm_encrypt, aes_gcm_decrypt, wrap_key_with_ss, unwrap_key_with_ss
from backend.app.identity.manager import get_public_keys, get_private_keys, list_recipients

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[3]
STORAGE_ENCRYPTED = PROJECT_ROOT / "storage" / "encrypted"
STORAGE_ENCRYPTED.mkdir(parents=True, exist_ok=True)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def generate_document_id() -> str:
    # Incremental DOC-XXX based on existing files
    existing = list(STORAGE_ENCRYPTED.glob("DOC-*.json"))
    nums = []
    for p in existing:
        try:
            n = int(p.stem.split("-")[1])
            nums.append(n)
        except:
            pass
    next_n = max(nums)+1 if nums else 1
    return f"DOC-{next_n:03d}"

def encrypt_document(pdf_bytes: bytes, original_filename: str, authorized_recipients: List[str], sender_id: str = None) -> Dict:
    """
    1. Calculates SHA-256 hash of original PDF.
    2. Generates random AES-256 key.
    3. Encrypts PDF using AES-256-GCM.
    4. Uses ML-KEM to protect AES key for authorized recipients.
    5. Stores encrypted document locally.
    6. Creates document ID.
    Returns metadata dict.
    """
    if not authorized_recipients:
        raise ValueError("At least one recipient required")
    # Validate recipients exist
    reg = list_recipients()
    for rid in authorized_recipients:
        r = rid.upper()
        if r not in reg:
            raise ValueError(f"Recipient {r} not registered")

    doc_hash = sha256_hex(pdf_bytes)
    doc_id = generate_document_id()
    aes_key = generate_aes_key()
    nonce, ciphertext = aes_gcm_encrypt(aes_key, pdf_bytes)

    filename_text = str(original_filename or "")
    original_extension = pathlib.Path(filename_text).suffix.lower()
    content_type = mimetypes.guess_type(filename_text)[0] or "application/octet-stream"

    wrapped_keys = {}
    for rid in authorized_recipients:
        r = rid.upper()
        pub = get_public_keys(r)
        mlkem_variant = pub.get("mlkem_variant", "768")
        kem_ct, ss = mlkem_encaps(pub["mlkem_pk"], variant=mlkem_variant)
        wrap_nonce, wrapped = wrap_key_with_ss(ss, aes_key)
        wrapped_keys[r] = {
            "kem_ciphertext": b64e(kem_ct),
            "wrapped_key_nonce": b64e(wrap_nonce),
            "wrapped_key": b64e(wrapped),
            "mlkem_variant": mlkem_variant,
        }

    meta = {
        "document_id": doc_id,
        "original_filename": original_filename,
        "original_extension": original_extension,
        "content_type": content_type,
        "sender_id": sender_id.upper() if sender_id else None,
        "document_hash": doc_hash,
        "aes_nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "authorized_recipients": [r.upper() for r in authorized_recipients],
        "wrapped_keys": wrapped_keys,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ciphertext_len": len(ciphertext),
        "original_len": len(pdf_bytes),
    }

    # Store locally
    out_path = STORAGE_ENCRYPTED / f"{doc_id}.json"
    # Also store raw encrypted bytes separately? But JSON suffices
    # Ensure ciphertext does not contain plaintext
    out_path.write_text(json.dumps(meta, indent=2))

    # Also store a .enc binary for demonstration (optional)
    return meta

def list_encrypted_documents() -> List[Dict]:
    docs = []
    for p in sorted(STORAGE_ENCRYPTED.glob("DOC-*.json")):
        try:
            docs.append(json.loads(p.read_text()))
        except:
            pass
    return docs

def load_encrypted_document(document_id: str) -> Dict:
    path = STORAGE_ENCRYPTED / f"{document_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Document {document_id} not found")
    return json.loads(path.read_text())

def decrypt_document(document_id: str, recipient_id: str, passphrase: str = None) -> Tuple[bytes, str, Dict]:
    """
    Decrypt document for recipient.
    Returns (pdf_bytes, document_hash, metadata)
    Uses recipient's ML-KEM private key to recover AES key, then decrypt.
    """
    rid = recipient_id.upper()
    meta = load_encrypted_document(document_id)
    if rid not in meta["wrapped_keys"]:
        raise PermissionError(f"Recipient {rid} not authorized for {document_id}")

    priv = get_private_keys(rid, passphrase)
    wrapped = meta["wrapped_keys"][rid]
    kem_ct = b64d(wrapped["kem_ciphertext"])
    wrap_nonce = b64d(wrapped["wrapped_key_nonce"])
    wrapped_key = b64d(wrapped["wrapped_key"])
    variant = wrapped.get("mlkem_variant", "768")

    ss = mlkem_decaps(priv["mlkem_sk"], kem_ct, variant=variant)
    aes_key = unwrap_key_with_ss(ss, wrap_nonce, wrapped_key)

    nonce = b64d(meta["aes_nonce"])
    ct = b64d(meta["ciphertext"])
    pdf_bytes = aes_gcm_decrypt(aes_key, nonce, ct)

    # Verify hash
    calc_hash = sha256_hex(pdf_bytes)
    if calc_hash != meta["document_hash"]:
        raise ValueError("Document hash mismatch after decryption — possible tampering")

    return pdf_bytes, calc_hash, meta

def get_document_hash(pdf_bytes: bytes) -> str:
    return sha256_hex(pdf_bytes)
