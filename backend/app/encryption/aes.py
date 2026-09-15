import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)  # 32 bytes

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
    """
    Returns (nonce, ciphertext_with_tag)
    nonce 12 bytes
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ct

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return pt

def wrap_key_with_ss(shared_secret: bytes, key_to_wrap: bytes) -> tuple[bytes, bytes]:
    """
    Use shared_secret (32 bytes from ML-KEM) as AES-256-GCM key to wrap the AES document key.
    Returns (nonce, wrapped_ct)
    """
    # shared_secret is 32 bytes, suitable as AES key
    # ensure 32 bytes: if longer, hash truncate? but mlkem 768 gives 32
    assert len(shared_secret) == 32, f"ss len {len(shared_secret)} !=32"
    return aes_gcm_encrypt(shared_secret, key_to_wrap)

def unwrap_key_with_ss(shared_secret: bytes, nonce: bytes, wrapped_ct: bytes) -> bytes:
    return aes_gcm_decrypt(shared_secret, nonce, wrapped_ct)
