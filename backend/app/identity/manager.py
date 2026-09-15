"""
Identity manager: enrollment for Alice & Bob with ML-DSA and ML-KEM key pairs.
Private keys stored locally (backend/keys/). Public keys registered.

Encrypted accounts created via register_user() keep their private keys
passphrase-protected at rest in backend/keys/<RID>_private.json. Legacy
plaintext accounts (ALICE/BOB) keep working exactly as before.
"""
import hashlib
import json
import os
import pathlib
import re
import tempfile
import threading
import time
from typing import Dict, Optional

from backend.app.crypto.pqcrypto_wrapper import mlkem_keygen, mldsa_keygen, b64e, b64d
from backend.app.encryption.aes import aes_gcm_encrypt, aes_gcm_decrypt

KEYS_DIR = pathlib.Path(__file__).parent.parent.parent / "keys"
# Ensure keys dir for project root alternative:
# project_root = Path(__file__).resolve().parents[3] -> /mnt/newvolume/SIH-Hackathon/PS/v1
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[3]
KEYS_DIR2 = PROJECT_ROOT / "backend" / "keys"
if not KEYS_DIR.exists():
    KEYS_DIR = KEYS_DIR2

RECIPIENTS_FILE = KEYS_DIR / "recipients.json"

DEFAULT_RECIPIENTS = ["ALICE", "BOB"]

DEMO_PASSPHRASE = "demo12345"

UNLOCK_TTL_SECONDS = 30 * 60
KDF_N = 2 ** 14
KDF_R = 8
KDF_P = 1
KDF_DKLEN = 32

_USERNAME_RE = re.compile(r"^[A-Z0-9_]{3,24}$")

_unlock_lock = threading.Lock()
_unlocked: Dict[str, Dict] = {}


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _normalize_rid(recipient_id: str) -> str:
    return (recipient_id or "").strip().upper()


def _private_file(rid: str) -> pathlib.Path:
    return KEYS_DIR / f"{rid}_private.json"


def _derive_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=KDF_DKLEN
    )


def _prune_unlocked() -> None:
    now = time.time()
    expired = [rid for rid, entry in _unlocked.items() if entry["expires_at"] <= now]
    for rid in expired:
        _unlocked.pop(rid, None)


def _atomic_write_text(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, str(path))
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _public_key_bytes(rid: str) -> tuple:
    rec = load_recipient(rid)
    if rec and rec.get("mlkem_pk_b64") and rec.get("mldsa_pk_b64"):
        return b64d(rec["mlkem_pk_b64"]), b64d(rec["mldsa_pk_b64"])
    paths = recipient_key_paths(rid)
    if paths["mlkem_pk"].exists() and paths["mldsa_pk"].exists():
        return (
            b64d(paths["mlkem_pk"].read_text().strip()),
            b64d(paths["mldsa_pk"].read_text().strip()),
        )
    raise FileNotFoundError(f"Public keys not found for {rid}. Register first.")


def _decrypt_private_record(rid: str, record: Dict, passphrase: str) -> Dict[str, bytes]:
    kdf = record.get("kdf") or {}
    salt = b64d(kdf["salt_b64"])
    derived = _derive_key(
        passphrase,
        salt,
        int(kdf.get("n", KDF_N)),
        int(kdf.get("r", KDF_R)),
        int(kdf.get("p", KDF_P)),
    )
    try:
        mlkem_sk = aes_gcm_decrypt(
            derived,
            b64d(record["mlkem_sk_enc"]["nonce_b64"]),
            b64d(record["mlkem_sk_enc"]["ct_b64"]),
        )
        mldsa_sk = aes_gcm_decrypt(
            derived,
            b64d(record["mldsa_sk_enc"]["nonce_b64"]),
            b64d(record["mldsa_sk_enc"]["ct_b64"]),
        )
    except Exception as exc:
        raise PermissionError("invalid passphrase") from exc
    mlkem_pk, mldsa_pk = _public_key_bytes(rid)
    return {
        "mlkem_sk": mlkem_sk,
        "mldsa_sk": mldsa_sk,
        "mlkem_pk": mlkem_pk,
        "mldsa_pk": mldsa_pk,
    }


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


def register_user(username: str, display_name: str, passphrase: str) -> Dict:
    """
    Create a passphrase-protected account.

    The ML-KEM-768 / ML-DSA-65 private keys are encrypted at rest with
    AES-256-GCM under a key derived from the passphrase via scrypt.
    Only public keys and metadata go into the recipients registry.
    """
    rid = _normalize_rid(username)
    if not _USERNAME_RE.match(rid):
        raise ValueError("username must be 3-24 characters of A-Z, 0-9 or underscore")
    if not isinstance(passphrase, str) or len(passphrase) < 8:
        raise ValueError("passphrase must be at least 8 characters")

    ensure_keys_dir()
    private_path = _private_file(rid)
    reg = load_registry()
    if private_path.exists() or rid in reg:
        raise ValueError(f"Recipient {rid} already registered")

    mlkem_pk, mlkem_sk = mlkem_keygen(variant="768")
    mldsa_pk, mldsa_sk = mldsa_keygen(variant="65")

    salt = os.urandom(16)
    derived = _derive_key(passphrase, salt, KDF_N, KDF_R, KDF_P)
    mlkem_nonce, mlkem_ct = aes_gcm_encrypt(derived, mlkem_sk)
    mldsa_nonce, mldsa_ct = aes_gcm_encrypt(derived, mldsa_sk)

    created_at = _iso(time.time())
    record = {
        "user": rid,
        "kdf": {"salt_b64": b64e(salt), "n": KDF_N, "r": KDF_R, "p": KDF_P},
        "mlkem_sk_enc": {"nonce_b64": b64e(mlkem_nonce), "ct_b64": b64e(mlkem_ct)},
        "mldsa_sk_enc": {"nonce_b64": b64e(mldsa_nonce), "ct_b64": b64e(mldsa_ct)},
        "created_at": created_at,
    }
    _atomic_write_text(private_path, json.dumps(record, indent=2))

    reg[rid] = {
        "recipient_id": rid,
        "display_name": display_name or rid.capitalize(),
        "mlkem_pk_b64": b64e(mlkem_pk),
        "mldsa_pk_b64": b64e(mldsa_pk),
        "mldsa_variant": "65",
        "mlkem_variant": "768",
        "key_storage": "encrypted",
        "created_at": created_at,
    }
    save_registry(reg)
    return reg[rid]


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


def get_private_keys(recipient_id: str, passphrase: Optional[str] = None) -> Dict[str, bytes]:
    """
    Retrieve private keys for signing/decryption.

    Encrypted accounts require either a valid passphrase or an active
    in-memory unlock (see unlock_user). Legacy plaintext accounts are
    loaded directly from their *_sk.b64 files as before.
    """
    rid = _normalize_rid(recipient_id)
    private_path = _private_file(rid)
    if private_path.exists():
        with _unlock_lock:
            _prune_unlocked()
            entry = _unlocked.get(rid)
            if entry is not None and entry.get("keys"):
                return dict(entry["keys"])
        if passphrase is None:
            raise PermissionError("private key locked")
        record = json.loads(private_path.read_text(encoding="utf-8"))
        return _decrypt_private_record(rid, record, passphrase)

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
            return json.loads(RECIPIENTS_FILE.read_text(encoding="utf-8"))
        except:
            return {}
    return {}


def save_registry(reg: Dict):
    ensure_keys_dir()
    _atomic_write_text(RECIPIENTS_FILE, json.dumps(reg, indent=2))


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


def unlock_user(recipient_id: str, passphrase: str) -> Dict:
    """
    Verify the passphrase and cache the private keys in memory for 30 minutes.
    Legacy plaintext users only accept DEMO_PASSPHRASE.
    """
    rid = _normalize_rid(recipient_id)
    if not rid:
        raise FileNotFoundError("Recipient id required")
    if not isinstance(passphrase, str) or not passphrase:
        raise PermissionError("invalid passphrase")

    expires_at = time.time() + UNLOCK_TTL_SECONDS
    private_path = _private_file(rid)
    if private_path.exists():
        record = json.loads(private_path.read_text(encoding="utf-8"))
        keys = _decrypt_private_record(rid, record, passphrase)
        with _unlock_lock:
            _prune_unlocked()
            _unlocked[rid] = {"expires_at": expires_at, "keys": keys, "legacy": False}
        return {"unlocked": True, "expires_at": _iso(expires_at)}

    paths = recipient_key_paths(rid)
    if not paths["mlkem_sk"].exists() or not paths["mldsa_sk"].exists():
        raise FileNotFoundError(f"Recipient {rid} not found")
    if passphrase != DEMO_PASSPHRASE:
        raise PermissionError("invalid passphrase")
    with _unlock_lock:
        _prune_unlocked()
        _unlocked[rid] = {"expires_at": expires_at, "keys": None, "legacy": True}
    return {"unlocked": True, "expires_at": _iso(expires_at)}


def lock_user(recipient_id: str) -> None:
    rid = _normalize_rid(recipient_id)
    with _unlock_lock:
        _unlocked.pop(rid, None)


def is_unlocked(recipient_id: str) -> bool:
    rid = _normalize_rid(recipient_id)
    with _unlock_lock:
        _prune_unlocked()
        return rid in _unlocked


def unlock_expiry(recipient_id: str) -> Optional[str]:
    rid = _normalize_rid(recipient_id)
    with _unlock_lock:
        _prune_unlocked()
        entry = _unlocked.get(rid)
        return _iso(entry["expires_at"]) if entry else None


def clear_all():
    """For testing: remove keys"""
    with _unlock_lock:
        _unlocked.clear()
    if KEYS_DIR.exists():
        for p in KEYS_DIR.glob("*"):
            try:
                p.unlink()
            except:
                pass
