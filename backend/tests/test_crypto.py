import io
import hashlib
import base64

def test_mlkem_encrypt_decrypt():
    from backend.app.crypto.pqcrypto_wrapper import mlkem_keygen, mlkem_encaps, mlkem_decaps
    for variant in ["768"]:
        pk, sk = mlkem_keygen(variant)
        ct, ss = mlkem_encaps(pk, variant)
        ss2 = mlkem_decaps(sk, ct, variant)
        assert ss == ss2
        assert len(ss) == 32

def test_aes_encryption_decryption():
    from backend.app.encryption.aes import generate_aes_key, aes_gcm_encrypt, aes_gcm_decrypt
    key = generate_aes_key()
    pt = b"Hello secret PDF content " * 100
    nonce, ct = aes_gcm_encrypt(key, pt)
    pt2 = aes_gcm_decrypt(key, nonce, ct)
    assert pt == pt2
    # tamper should fail
    try:
        aes_gcm_decrypt(key, nonce, ct[:-5] + b"\x00"*5)
        assert False, "tampered ciphertext should fail"
    except Exception:
        pass

def test_mldsa_sign_verify():
    from backend.app.crypto.pqcrypto_wrapper import mldsa_keygen, mldsa_sign, mldsa_verify
    pk, sk = mldsa_keygen("65")
    msg = b"canonical event bytes"
    sig = mldsa_sign(sk, msg, "65")
    assert mldsa_verify(pk, msg, sig, "65") is True

def test_mldsa_modified_rejection():
    from backend.app.crypto.pqcrypto_wrapper import mldsa_keygen, mldsa_sign, mldsa_verify
    pk, sk = mldsa_keygen("65")
    msg = b"original event"
    sig = mldsa_sign(sk, msg, "65")
    assert mldsa_verify(pk, b"tampered event", sig, "65") is False
    # modify signature
    bad_sig = sig[:-10] + bytes([255]*10)
    assert mldsa_verify(pk, msg, bad_sig, "65") is False

def test_watermark_generation_uniqueness():
    from backend.app.watermark.dct_watermark import generate_watermark_id
    wm1 = generate_watermark_id("hash123", "ALICE", "SES-AAA", "nonce1")
    wm2 = generate_watermark_id("hash123", "BOB", "SES-AAA", "nonce1")
    assert wm1 != wm2
    wm3 = generate_watermark_id("hash123", "ALICE", "SES-AAA", "nonce1")
    assert wm1 == wm3  # deterministic same inputs same output
    wm4 = generate_watermark_id("hash123", "ALICE", "SES-BBB", "nonce1")
    assert wm1 != wm4

def test_watermark_extraction():
    from backend.app.watermark.dct_watermark import embed_watermark, extract_watermark, generate_watermark_id
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(100,700,'Watermark test')
    c.showPage()
    c.save()
    pdf = buf.getvalue()
    wm = generate_watermark_id("abc", "ALICE", "SES-123", "nonceXYZ")
    watermarked = embed_watermark(pdf, wm)
    extracted = extract_watermark(watermarked)
    assert extracted == wm, f"expected {wm}, got {extracted}"
    # different watermark should differ after extraction
    wm2 = generate_watermark_id("abc", "BOB", "SES-123", "nonceXYZ")
    wm_pdf2 = embed_watermark(pdf, wm2)
    ext2 = extract_watermark(wm_pdf2)
    assert ext2 == wm2
    assert extracted != ext2

def test_ledger_hash_verification():
    from backend.app.ledger.ledger import clear_ledger, commit_event, verify_all_ledgers
    from backend.app.forensic.events import create_decryption_event, sign_event
    from backend.app.identity.manager import ensure_demo_recipients
    ensure_demo_recipients()
    clear_ledger()
    e1 = create_decryption_event('DOC-TEST', 'hash1', 'ALICE', 'SES-111', 'WM-TEST111111', 'nonce1')
    sig1, pk1 = sign_event(e1, 'ALICE')
    commit_event(e1, sig1, pk1)
    e2 = create_decryption_event('DOC-TEST', 'hash1', 'BOB', 'SES-222', 'WM-TEST222222', 'nonce2')
    sig2, pk2 = sign_event(e2, 'BOB')
    commit_event(e2, sig2, pk2)
    valid, details = verify_all_ledgers()
    assert valid is True
    assert details['node1']['count'] == 2

def test_ledger_tampering_detection():
    from backend.app.ledger.ledger import clear_ledger, commit_event, verify_all_ledgers, tamper_entry
    from backend.app.forensic.events import create_decryption_event, sign_event
    from backend.app.identity.manager import ensure_demo_recipients
    ensure_demo_recipients()
    clear_ledger()
    e = create_decryption_event('DOC-TAMPER', 'hashX', 'ALICE', 'SES-TAMPER', 'WM-TAMPER12345', 'nonceX')
    sig, pk = sign_event(e, 'ALICE')
    commit_event(e, sig, pk)
    # tamper ledger
    tamper_entry('node1', 0, 'current_hash', '0'*64)
    valid, details = verify_all_ledgers()
    assert valid is False
    assert details['node1']['valid'] is False
    clear_ledger()

def test_complete_end_to_end_attribution():
    import pathlib
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from backend.app.identity.manager import ensure_demo_recipients
    from backend.app.encryption.document import encrypt_document
    from backend.app.services.decryption_service import recipient_decrypt_and_watermark
    from backend.app.forensic.verify import forensic_verify
    from backend.app.ledger.ledger import clear_ledger

    root = pathlib.Path(__file__).resolve().parents[2]
    encrypted_dir = root / "storage" / "encrypted"
    watermarked_dir = root / "storage" / "watermarked"

    ensure_demo_recipients()
    clear_ledger()

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(100,700,'E2E test PDF')
    c.showPage()
    c.save()
    pdf = buf.getvalue()

    doc_id = None
    watermarked_paths = []
    try:
        meta = encrypt_document(pdf, 'e2e.pdf', ['ALICE','BOB'], sender_id='ALICE')
        doc_id = meta['document_id']
        alice = recipient_decrypt_and_watermark(doc_id, 'ALICE')
        watermarked_paths.append(pathlib.Path(alice['watermarked_path']))
        bob = recipient_decrypt_and_watermark(doc_id, 'BOB')
        watermarked_paths.append(pathlib.Path(bob['watermarked_path']))
        assert alice['watermark_id'] != bob['watermark_id']
        leaked = pathlib.Path(alice['watermarked_path']).read_bytes()
        result = forensic_verify(leaked)
        assert result['recipient_id'] == 'ALICE'
        assert result['signature_valid'] is True
        assert result['ledger_valid'] is True
        assert result['ledger_quorum_ok'] is True
        assert result['status'] == 'VERIFIED'
    finally:
        if doc_id:
            for p in encrypted_dir.glob(f"{doc_id}.json"):
                p.unlink(missing_ok=True)
        for p in watermarked_paths:
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
        clear_ledger()
