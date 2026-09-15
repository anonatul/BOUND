import json
import hashlib
import uuid
import os
import time
from typing import Dict

from backend.app.identity.manager import get_private_keys, get_public_keys
from backend.app.crypto.pqcrypto_wrapper import mldsa_sign, mldsa_verify, b64e, b64d

def canonical_serialize(event: Dict) -> bytes:
    """
    Deterministic serialization: sorted keys, compact separators.
    Returns bytes.
    """
    return json.dumps(event, sort_keys=True, separators=(',', ':')).encode('utf-8')

def hash_canonical_event(event: Dict) -> str:
    """
    Hash the canonical event serialization (SHA256 hex).
    """
    canon = canonical_serialize(event)
    return hashlib.sha256(canon).hexdigest()

def create_decryption_event(document_id: str, document_hash: str, recipient_id: str, session_id: str, watermark_id: str, nonce: str, timestamp: str = None) -> Dict:
    if timestamp is None:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    event = {
        "event_type": "DOCUMENT_DECRYPTED",
        "document_id": document_id,
        "document_hash": document_hash,
        "recipient_id": recipient_id.upper(),
        "session_id": session_id,
        "watermark_id": watermark_id,
        "nonce": nonce,
        "timestamp": timestamp,
    }
    return event

def sign_event(event: Dict, recipient_id: str) -> tuple[str, str]:
    """
    Sign canonical event using recipient's ML-DSA private key.
    Returns (signature_b64, public_key_b64_ref) . Uses real ML-DSA, not RSA/ECDSA.
    """
    rid = recipient_id.upper()
    priv = get_private_keys(rid)
    pub = get_public_keys(rid)
    variant = pub.get("mldsa_variant", "65")
    canon = canonical_serialize(event)
    sig = mldsa_sign(priv["mldsa_sk"], canon, variant=variant)
    return b64e(sig), b64e(pub["mldsa_pk"])

def verify_event_signature(event: Dict, signature_b64: str, recipient_id: str) -> bool:
    """
    Verify ML-DSA signature over canonical event.
    Retrieves recipient public key.
    Returns True if valid, False otherwise.
    """
    rid = recipient_id.upper()
    pub = get_public_keys(rid)
    variant = pub.get("mldsa_variant", "65")
    canon = canonical_serialize(event)
    sig = b64d(signature_b64)
    return mldsa_verify(pub["mldsa_pk"], canon, sig, variant=variant)

def verify_event_with_provided_pk(event: Dict, signature_b64: str, pk_b64: str, variant: str = "65") -> bool:
    canon = canonical_serialize(event)
    sig = b64d(signature_b64)
    pk = b64d(pk_b64)
    return mldsa_verify(pk, canon, sig, variant=variant)

def generate_session_and_nonce() -> tuple[str, str]:
    """
    Generates fresh cryptographically random session ID and nonce.
    Session: SES- + 6 hex chars from uuid4? But spec says SES-91A72 (5 hex). We'll use 6 hex for uniqueness.
    Nonce: 16 bytes hex (32 hex chars)
    """
    session_id = f"SES-{uuid.uuid4().hex[:6].upper()}"
    nonce = os.urandom(16).hex().upper()
    return session_id, nonce

def create_and_sign_event(document_id: str, document_hash: str, recipient_id: str) -> Dict:
    """
    Full flow: generate session, nonce, watermark, create event, sign.
    Returns dict with event, signature, watermark_id, session_id, nonce
    """
    from backend.app.watermark.dct_watermark import generate_watermark_id
    session_id, nonce = generate_session_and_nonce()
    watermark_id = generate_watermark_id(document_hash, recipient_id, session_id, nonce)
    event = create_decryption_event(document_id, document_hash, recipient_id, session_id, watermark_id, nonce)
    sig_b64, pk_b64 = sign_event(event, recipient_id)
    return {
        "event": event,
        "signature": sig_b64,
        "public_key_b64": pk_b64,
        "watermark_id": watermark_id,
        "session_id": session_id,
        "nonce": nonce,
        "canonical_hash": hash_canonical_event(event),
    }
