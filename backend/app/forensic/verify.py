"""
Forensic verification pipeline:
1. Calculate document hash (of leaked file)
2. Detect/extract watermark
3. Recover watermark ID
4. Search ledger
5. Find matching event
6. Retrieve signature
7. Retrieve recipient public key
8. Verify ML-DSA signature
9. Verify ledger hash chain
10. Display result
"""
import hashlib
from typing import Dict, Optional

from backend.app.watermark.dct_watermark import extract_watermark
from backend.app.ledger.ledger import find_by_watermark, verify_all_ledgers, get_all_entries
from backend.app.forensic.events import canonical_serialize, verify_event_with_provided_pk
from backend.app.identity.manager import get_public_keys

def forensic_verify(leaked_pdf_bytes: bytes) -> Dict:
    """
    Returns detailed verification result:
    {
        "status": "VERIFIED" | "NO_WATERMARK" | "NO_LEDGER_MATCH" | "SIGNATURE_INVALID" | "LEDGER_TAMPERED",
        "watermark_id": ...,
        "document": ...,
        "recipient": ...,
        "session": ...,
        "timestamp": ...,
        "signature_valid": bool,
        "ledger_valid": bool,
        "details": {...}
    }
    """
    result = {
        "leaked_hash": hashlib.sha256(leaked_pdf_bytes).hexdigest(),
        "watermark_id": None,
        "watermark_detected": False,
        "ledger_match_found": False,
        "signature_valid": False,
        "ledger_valid": False,
        "recipient_id": None,
        "session_id": None,
        "document_id": None,
        "timestamp": None,
        "event": None,
        "status": "UNKNOWN",
        "message": "",
    }

    # Step 2: Extract watermark
    watermark_id = extract_watermark(leaked_pdf_bytes)
    if not watermark_id:
        result["status"] = "NO_WATERMARK"
        result["message"] = "No forensic watermark detected in the leaked document."
        return result

    result["watermark_id"] = watermark_id
    result["watermark_detected"] = True

    # Step 4: Search ledger
    entry = find_by_watermark(watermark_id)
    if not entry:
        result["status"] = "NO_LEDGER_MATCH"
        result["message"] = f"Watermark {watermark_id} has no valid ledger match. Possibly fake watermark."
        return result

    result["ledger_match_found"] = True
    result["event"] = entry["event"]
    result["document_id"] = entry.get("document_id") or entry["event"].get("document_id")
    result["recipient_id"] = entry.get("recipient_id") or entry["event"].get("recipient_id")
    result["session_id"] = entry.get("session_id") or entry["event"].get("session_id")
    result["timestamp"] = entry["event"].get("timestamp")

    # Step 8: Verify ML-DSA signature
    # Need to get public key: use stored public_key_b64 or fetch from identity manager
    event = entry["event"]
    sig = entry["signature"]
    # Try to get variant from recipient
    recipient = result["recipient_id"]
    try:
        # Use stored pk first, fallback to manager
        pk_b64 = entry.get("public_key_b64")
        if not pk_b64:
            # fetch from manager
            pub = get_public_keys(recipient)
            import base64
            pk_b64 = base64.b64encode(pub["mldsa_pk"]).decode()
            variant = pub.get("mldsa_variant", "65")
        else:
            # Need variant: try to infer via recipient's current keys
            try:
                pub = get_public_keys(recipient)
                variant = pub.get("mldsa_variant", "65")
            except:
                variant = "65"
        sig_valid = verify_event_with_provided_pk(event, sig, pk_b64, variant=variant)
    except Exception as e:
        sig_valid = False
        result["signature_error"] = str(e)

    result["signature_valid"] = sig_valid

    # Step 9: Verify ledger hash chain
    ledger_valid, details = verify_all_ledgers()
    result["ledger_valid"] = ledger_valid
    result["ledger_details"] = details

    # Final status
    if not sig_valid:
        result["status"] = "SIGNATURE_INVALID"
        result["message"] = "ML-DSA signature verification FAILED — possible tampering."
    elif not ledger_valid:
        result["status"] = "LEDGER_TAMPERED"
        result["message"] = "Ledger integrity check FAILED — chain has been tampered."
    else:
        result["status"] = "VERIFIED"
        result["message"] = f"This leaked artifact matches {recipient}'s recorded decryption session."

    return result

def verify_watermark_extraction_only(pdf_bytes: bytes) -> Dict:
    wm = extract_watermark(pdf_bytes)
    return {
        "watermark_id": wm,
        "detected": wm is not None,
        "hash": hashlib.sha256(pdf_bytes).hexdigest()
    }
