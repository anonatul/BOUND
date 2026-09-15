"""
Identity manager: enrollment for Alice & Bob with ML-DSA and ML-KEM key pairs.
Private keys stored locally (backend/keys/). Public keys registered.
"""
import os
import json
import pathlib
from typing import Dict, Optional

from backend.app.crypto.pqcrypto_wrapper import mlkem_keygen, mldsa_keygen, b64e, b64d

KEYS_DIR = pathlib.Path(__file__).parent.parent.parent / "keys"
# Ensure keys dir for project root alternative:
# project_root = Path(__file__).resolve().parents[3] -> /mnt/newvolume/SIH-Hackathon/PS/v1
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[3]
KEYS_DIR2 = PROJECT_ROOT / "backend" / "keys"
if not KEYS_DIR.exists():
    KEYS_DIR = KEYS_DIR2

RECIPIENTS_FILE = KEYS_DIR / "recipients.json"

DEFAULT_RECIPIENTS = ["ALICE", "BOB"]

def ensure_keys_dir():
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

def recipient_key_paths(recipient_id: str):
    rid = recipient_id.upper()
    return {
        "mldsa_pk": KEYS_DIR / f"{rid}_mldsa_pk.b64",
        "mldsa_sk": KEYS_DIR / f"{rid}_mldsa_sk.b64",
        "mlkem_pk": KEYS_DIR / f"{rid}_mlkem_pk.b64",
        "mlkem_sk": KEYS_DIR / f"{rid}_mlkem_sk.b64",
    }

def create_recipient(recipient_id: str, mlkem_variant="768", mldsa_variant="65") -> Dict:
    """
    Create recipient with ML-DSA and ML-KEM key pairs.
    Stores private keys locally, registers public keys.
    """
    ensure_keys_dir()
    rid = recipient_id.upper()
    # Check if exists
    paths = recipient_key_paths(rid)
    if all(p.exists() for p in paths.values()):
        return load_recipient(rid)

    mlkem_pk, mlkem_sk = mlkem_keygen(variant=mlkem_variant)
    mldsa_pk, mldsa_sk = mldsa_keygen(variant=mldsa_variant)

    # Store as base64 for local file (prototype)
    for p, data in [
        (paths["mlkem_pk"], mlkem_pk),
        (paths["mlkem_sk"], mlkem_sk),
        (paths["mldsa_pk"], mldsa_pk),
        (paths["mldsa_sk"], mldsa_sk),
    ]:
        p.write_text(b64e(data))

    # Update recipients registry
    reg = load_registry()
    reg[rid] = {
        "recipient_id": rid,
        "display_name": recipient_id.capitalize() if rid in ["ALICE","BOB"] else recipient_id,
        "mlkem_pk_b64": b64e(mlkem_pk),
        "mldsa_pk_b64": b64e(mldsa_pk),
        "mldsa_variant": mldsa_variant,
        "mlkem_variant": mlkem_variant,
    }
    save_registry(reg)

    return reg[rid]

def load_recipient(recipient_id: str) -> Optional[Dict]:
    rid = recipient_id.upper()
    reg = load_registry()
    if rid in reg:
        return reg[rid]
    # try to load from files if registry missing
    paths = recipient_key_paths(rid)
    if paths["mlkem_pk"].exists() and paths["mldsa_pk"].exists():
        return {
            "recipient_id": rid,
            "display_name": rid.capitalize(),
            "mlkem_pk_b64": paths["mlkem_pk"].read_text().strip(),
            "mldsa_pk_b64": paths["mldsa_pk"].read_text().strip(),
            "mldsa_variant": "65",
            "mlkem_variant": "768",
        }
    return None

def get_private_keys(recipient_id: str) -> Dict[str, bytes]:
    """
    Retrieve private keys (for authenticated decryption).
    In real system would require auth; prototype loads locally.
    """
    rid = recipient_id.upper()
    paths = recipient_key_paths(rid)
    if not paths["mlkem_sk"].exists() or not paths["mldsa_sk"].exists():
        raise FileNotFoundError(f"Private keys not found for {rid}. Enroll first.")
    return {
        "mlkem_sk": b64d(paths["mlkem_sk"].read_text().strip()),
        "mldsa_sk": b64d(paths["mldsa_sk"].read_text().strip()),
        "mlkem_pk": b64d(paths["mlkem_pk"].read_text().strip()),
        "mldsa_pk": b64d(paths["mldsa_pk"].read_text().strip()),
    }

def get_public_keys(recipient_id: str) -> Dict[str, bytes]:
    rid = recipient_id.upper()
    rec = load_recipient(rid)
    if not rec:
        raise FileNotFoundError(f"Recipient {rid} not found")
    return {
        "mlkem_pk": b64d(rec["mlkem_pk_b64"]),
        "mldsa_pk": b64d(rec["mldsa_pk_b64"]),
        "mldsa_variant": rec.get("mldsa_variant", "65"),
        "mlkem_variant": rec.get("mlkem_variant", "768"),
    }

def load_registry() -> Dict:
    if RECIPIENTS_FILE.exists():
        try:
            return json.loads(RECIPIENTS_FILE.read_text())
        except:
            return {}
    return {}

def save_registry(reg: Dict):
    ensure_keys_dir()
    RECIPIENTS_FILE.write_text(json.dumps(reg, indent=2))

def list_recipients() -> Dict:
    return load_registry()

def ensure_demo_recipients():
    """
    Create Alice and Bob if not exists.
    Returns dict of recipients.
    """
    ensure_keys_dir()
    for rid in DEFAULT_RECIPIENTS:
        create_recipient(rid)
    return load_registry()

def clear_all():
    """For testing: remove keys"""
    if KEYS_DIR.exists():
        for p in KEYS_DIR.glob("*"):
            try:
                p.unlink()
            except:
                pass
