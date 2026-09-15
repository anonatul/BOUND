"""
Real PQC implementations using pqcrypto (Rust bindings to liboqs / PQClean).
Do NOT silently replace with RSA/ECDSA. Fail loudly if unavailable.
"""
import base64
from typing import Tuple

# --- ML-KEM (Kyber) ---
# Using ML-KEM-768 (NIST Level 3) as default. Also supports 512/1024 via param.

def mlkem_keygen(variant: str = "768") -> Tuple[bytes, bytes]:
    """
    Generate ML-KEM keypair.
    Returns (public_key_bytes, secret_key_bytes)
    variant: "512", "768", "1024"
    """
    if variant == "512":
        from pqcrypto.kem.ml_kem_512 import keygen
    elif variant == "768":
        from pqcrypto.kem.ml_kem_768 import keygen
    elif variant == "1024":
        from pqcrypto.kem.ml_kem_1024 import keygen
    else:
        raise ValueError(f"Unsupported ML-KEM variant {variant}")
    pk, sk = keygen()
    return pk, sk

def mlkem_encaps(public_key: bytes, variant: str = "768") -> Tuple[bytes, bytes]:
    """
    Encapsulate shared secret.
    Returns (ciphertext, shared_secret)
    """
    if variant == "512":
        from pqcrypto.kem.ml_kem_512 import encaps
    elif variant == "768":
        from pqcrypto.kem.ml_kem_768 import encaps
    elif variant == "1024":
        from pqcrypto.kem.ml_kem_1024 import encaps
    else:
        raise ValueError(f"Unsupported ML-KEM variant {variant}")
    ct, ss = encaps(public_key)
    return ct, ss

def mlkem_decaps(secret_key: bytes, ciphertext: bytes, variant: str = "768") -> bytes:
    """
    Decapsulate shared secret.
    """
    if variant == "512":
        from pqcrypto.kem.ml_kem_512 import decaps
    elif variant == "768":
        from pqcrypto.kem.ml_kem_768 import decaps
    elif variant == "1024":
        from pqcrypto.kem.ml_kem_1024 import decaps
    else:
        raise ValueError(f"Unsupported ML-KEM variant {variant}")
    ss = decaps(secret_key, ciphertext)
    return ss

# --- ML-DSA (Dilithium) ---

def mldsa_keygen(variant: str = "65") -> Tuple[bytes, bytes]:
    """
    Generate ML-DSA keypair.
    variant: "44", "65", "87" (corresponds to NIST Level 2,3,5)
    Returns (public_key, secret_key)
    """
    if variant == "44":
        from pqcrypto.sign.ml_dsa_44 import keygen
    elif variant == "65":
        from pqcrypto.sign.ml_dsa_65 import keygen
    elif variant == "87":
        from pqcrypto.sign.ml_dsa_87 import keygen
    else:
        raise ValueError(f"Unsupported ML-DSA variant {variant}")
    pk, sk = keygen()
    return pk, sk

def mldsa_sign(secret_key: bytes, message: bytes, variant: str = "65") -> bytes:
    if variant == "44":
        from pqcrypto.sign.ml_dsa_44 import sign
    elif variant == "65":
        from pqcrypto.sign.ml_dsa_65 import sign
    elif variant == "87":
        from pqcrypto.sign.ml_dsa_87 import sign
    else:
        raise ValueError(f"Unsupported ML-DSA variant {variant}")
    sig = sign(secret_key, message)
    return sig

def mldsa_verify(public_key: bytes, message: bytes, signature: bytes, variant: str = "65") -> bool:
    """
    Verify ML-DSA signature.
    Returns True if valid, False if invalid.
    Uses real verification; not faked.
    """
    if variant == "44":
        from pqcrypto.sign.ml_dsa_44 import verify
    elif variant == "65":
        from pqcrypto.sign.ml_dsa_65 import verify
    elif variant == "87":
        from pqcrypto.sign.ml_dsa_87 import verify
    else:
        raise ValueError(f"Unsupported ML-DSA variant {variant}")
    try:
        verify(public_key, message, signature)
        return True
    except Exception:
        return False

# --- helpers for storage ---

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())
