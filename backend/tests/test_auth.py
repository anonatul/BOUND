import json
import pathlib

import pytest

from backend.app.auth import service
from backend.app.crypto.pqcrypto_wrapper import mldsa_sign, mldsa_verify
from backend.app.identity.manager import (
    DEMO_PASSPHRASE,
    KEYS_DIR,
    ensure_demo_recipients,
    get_private_keys,
    is_unlocked,
    load_registry,
    lock_user,
    register_user,
    save_registry,
    unlock_expiry,
    unlock_user,
)

CAROL = "CAROL"
CAROL_PASS = "carol-pass-123"
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
SESSIONS_FILE = PROJECT_ROOT / "backend" / "data" / "sessions.json"


def _cleanup_carol():
    lock_user(CAROL)
    for p in KEYS_DIR.glob("CAROL_*"):
        try:
            p.unlink()
        except OSError:
            pass
    reg = load_registry()
    if CAROL in reg:
        reg.pop(CAROL)
        save_registry(reg)


@pytest.fixture(scope="module", autouse=True)
def carol_account():
    ensure_demo_recipients()
    _cleanup_carol()
    register_user(CAROL, "Carol", CAROL_PASS)
    yield
    try:
        _cleanup_carol()
    finally:
        try:
            SESSIONS_FILE.unlink()
        except FileNotFoundError:
            pass


def test_register_writes_encrypted_key_file_and_registry_entry():
    private_path = KEYS_DIR / "CAROL_private.json"
    assert private_path.exists()
    record = json.loads(private_path.read_text(encoding="utf-8"))
    assert record["user"] == CAROL
    assert record["kdf"]["n"] == 2 ** 14
    assert record["kdf"]["r"] == 8
    assert record["kdf"]["p"] == 1
    assert record["kdf"]["salt_b64"]
    for field in ("mlkem_sk_enc", "mldsa_sk_enc"):
        assert record[field]["nonce_b64"]
        assert record[field]["ct_b64"]
    assert record["created_at"]

    reg = load_registry()
    assert reg[CAROL]["key_storage"] == "encrypted"
    assert reg[CAROL]["display_name"] == "Carol"
    assert reg[CAROL]["mldsa_variant"] == "65"
    assert reg[CAROL]["mlkem_variant"] == "768"
    assert reg[CAROL]["created_at"]
    assert not (KEYS_DIR / "CAROL_mldsa_sk.b64").exists()
    assert not (KEYS_DIR / "CAROL_mlkem_sk.b64").exists()


def test_register_rejects_invalid_username_and_short_passphrase():
    with pytest.raises(ValueError):
        register_user("no spaces", "Nope", "long-enough-pass")
    with pytest.raises(ValueError):
        register_user("AB", "Nope", "long-enough-pass")
    with pytest.raises(ValueError):
        register_user("DAVE", "Dave", "short")


def test_private_keys_locked_before_unlock():
    lock_user(CAROL)
    assert is_unlocked(CAROL) is False
    assert unlock_expiry(CAROL) is None
    with pytest.raises(PermissionError):
        get_private_keys(CAROL)
    with pytest.raises(PermissionError):
        get_private_keys(CAROL, "wrong-passphrase")


def test_login_success_and_failures():
    result = service.login(CAROL, CAROL_PASS)
    assert result["token"]
    assert result["expires_at"]
    assert result["user"] == {
        "recipient_id": CAROL,
        "username": CAROL,
        "display_name": "Carol",
    }
    with pytest.raises(PermissionError):
        service.login(CAROL, "not-the-passphrase")
    with pytest.raises(PermissionError):
        service.login("NO_SUCH_USER", CAROL_PASS)
    service.logout(result["token"])


def test_unlock_decrypts_keys_and_mldsa_roundtrip():
    lock_user(CAROL)
    info = unlock_user(CAROL, CAROL_PASS)
    assert info["unlocked"] is True
    assert info["expires_at"]
    assert is_unlocked(CAROL) is True
    assert unlock_expiry(CAROL) == info["expires_at"]

    keys = get_private_keys(CAROL)
    assert keys["mldsa_sk"] and keys["mlkem_sk"]
    message = b"forensic auth roundtrip"
    signature = mldsa_sign(keys["mldsa_sk"], message, "65")
    assert mldsa_verify(keys["mldsa_pk"], message, signature, "65") is True

    lock_user(CAROL)
    with pytest.raises(PermissionError):
        get_private_keys(CAROL)
    keys_via_passphrase = get_private_keys(CAROL, CAROL_PASS)
    assert keys_via_passphrase["mldsa_sk"] == keys["mldsa_sk"]
    assert is_unlocked(CAROL) is False
    with pytest.raises(PermissionError):
        unlock_user(CAROL, "bad-passphrase")


def test_legacy_alice_still_works_with_demo_passphrase():
    assert DEMO_PASSPHRASE == "demo12345"
    result = service.login("ALICE", DEMO_PASSPHRASE)
    assert result["user"]["recipient_id"] == "ALICE"
    keys = get_private_keys("ALICE")
    assert keys["mldsa_sk"] and keys["mlkem_sk"]
    assert get_private_keys("ALICE")["mldsa_sk"] == keys["mldsa_sk"]
    with pytest.raises(PermissionError):
        service.login("ALICE", "wrong-demo-pass")
    service.logout(result["token"])


def test_sessions_are_persisted_to_disk():
    result = service.login(CAROL, CAROL_PASS)
    assert SESSIONS_FILE.exists()
    stored = json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
    assert result["token"] in stored
    entry = stored[result["token"]]
    assert entry["user"]["recipient_id"] == CAROL
    assert entry["created_at"]
    assert entry["expires_at"]
    assert service.get_session(result["token"]) == result["user"]
    service.logout(result["token"])
    assert service.get_session(result["token"]) is None


def test_deps_reject_missing_and_invalid_tokens():
    from fastapi import HTTPException

    from backend.app.auth.deps import get_current_user, get_current_user_optional

    with pytest.raises(HTTPException) as exc:
        get_current_user(None)
    assert exc.value.status_code == 401
    with pytest.raises(HTTPException) as exc:
        get_current_user("Bearer not-a-real-token")
    assert exc.value.status_code == 401
    assert get_current_user_optional(None) is None
    assert get_current_user_optional("Bearer not-a-real-token") is None

    result = service.login(CAROL, CAROL_PASS)
    header = f"Bearer {result['token']}"
    assert get_current_user(header)["recipient_id"] == CAROL
    assert get_current_user_optional(header) == result["user"]
    service.logout(result["token"])
    assert get_current_user_optional(header) is None
