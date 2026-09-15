import io
import json
import pathlib

from fastapi.testclient import TestClient

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
KEYS_DIR = PROJECT_ROOT / "backend" / "keys"
STORAGE_WATERMARKED = PROJECT_ROOT / "storage" / "watermarked"

USERNAME = "DAVE"
PASSPHRASE = "dave-pass-123"


def _pdf(title="Integration test document"):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(100, 700, title)
    c.drawString(100, 680, "Confidential integration content")
    c.showPage()
    c.save()
    return buf.getvalue()


def _cleanup_user():
    from backend.app.identity.manager import load_registry, save_registry

    for p in KEYS_DIR.glob(f"{USERNAME}_*"):
        try:
            p.unlink()
        except OSError:
            pass
    reg = load_registry()
    if USERNAME in reg:
        reg.pop(USERNAME)
        save_registry(reg)


def test_full_api_flow():
    from backend.app.identity.manager import ensure_demo_recipients, lock_user
    from backend.app.ledger.ledger import clear_ledger

    ensure_demo_recipients()
    clear_ledger()
    _cleanup_user()

    from backend.app.main import app

    e2e_doc_id = None
    e2e_files = []
    try:
        with TestClient(app) as client:
            registered = client.post("/api/auth/register", json={
                "username": USERNAME,
                "display_name": "Dave",
                "passphrase": PASSPHRASE,
            })
            assert registered.status_code == 200, registered.text
            assert client.post("/api/auth/register", json={
                "username": USERNAME,
                "display_name": "Dave",
                "passphrase": PASSPHRASE,
            }).status_code == 400

            bad_login = client.post("/api/auth/login", json={"username": USERNAME, "passphrase": "wrong-pass"})
            assert bad_login.status_code == 401

            login = client.post("/api/auth/login", json={"username": USERNAME, "passphrase": PASSPHRASE})
            assert login.status_code == 200, login.text
            token = login.json()["token"]
            headers = {"Authorization": f"Bearer {token}"}

            me = client.get("/api/auth/me", headers=headers)
            assert me.status_code == 200
            assert me.json()["user"]["recipient_id"] == USERNAME

            assert client.get("/api/documents").status_code == 401

            available = client.get(f"/api/auth/username-available?username={USERNAME}")
            assert available.status_code == 200
            assert available.json()["available"] is False
            free = client.get("/api/auth/username-available?username=NEWUSERXYZ")
            assert free.json()["available"] is True

            recipients = client.get("/api/recipients").json()["recipients"]
            assert USERNAME in [r["recipient_id"] for r in recipients]
            assert "ALICE" in [r["recipient_id"] for r in recipients]
            assert all("mldsa_fingerprint" in r and "key_storage" in r for r in recipients)

            profile = client.get(f"/api/recipients/{USERNAME}").json()
            assert profile["recipient_id"] == USERNAME
            assert profile["key_storage"] == "encrypted"
            assert profile["mldsa_fingerprint"] and profile["mlkem_fingerprint"]
            assert client.get("/api/recipients/NOBODY").status_code == 404

            encrypted = client.post(
                "/api/encrypt",
                headers=headers,
                files={"file": ("secret.pdf", _pdf(), "application/pdf")},
                data={"recipients": json.dumps([USERNAME, "ALICE"])},
            )
            assert encrypted.status_code == 200, encrypted.text
            document_id = encrypted.json()["document_id"]
            assert encrypted.json()["sender_id"] == USERNAME

            docs = client.get("/api/documents", headers=headers).json()["documents"]
            own = [d for d in docs if d["document_id"] == document_id]
            assert own and own[0]["role"] == "owner"
            assert own[0]["decryption_count"] == 0

            decrypted = client.post("/api/decrypt", headers=headers, json={"document_id": document_id})
            assert decrypted.status_code == 200, decrypted.text
            body = decrypted.json()
            assert body["recipient_id"] == USERNAME
            assert body["watermark_id"].startswith("WM-")
            assert body["ledger"]["node_quorum"] >= 3

            download = client.get(body["download_url"])
            assert download.status_code == 200
            assert download.headers["content-type"].startswith("application/pdf")
            leaked_bytes = download.content
            assert len(leaked_bytes) > 1000
            assert len(leaked_bytes) < 900_000

            lock_user(USERNAME)
            locked = client.post("/api/decrypt", headers=headers, json={"document_id": document_id})
            assert locked.status_code == 403

            unlocked = client.post("/api/auth/unlock", headers=headers, json={"passphrase": PASSPHRASE})
            assert unlocked.status_code == 200
            assert client.post("/api/decrypt", headers=headers, json={"document_id": document_id}).status_code == 200

            events = client.get(f"/api/documents/{document_id}/events", headers=headers).json()
            assert events["count"] >= 1
            assert all(e["recipient_id"] == USERNAME for e in events["events"])
            assert all(e["quorum_ok"] is True for e in events["events"])

            forged_status = client.get("/api/ledger").json()
            assert forged_status["integrity"] == "VALID"
            assert forged_status["entries"][0]["quorum_ok"] is True
            assert forged_status["details"]["node1"]["merkle_root"]
            assert forged_status["details"]["node1"]["checkpoint_count"] == forged_status["count"]

            forgery = client.post("/api/test/ledger-admin-tampering")
            assert forgery.status_code == 200, forgery.text
            assert forgery.json()["passed"] is True
            assert client.get("/api/ledger").json()["integrity"] == "VALID"

            from backend.app.ledger.ledger import _ledger_path, _load_entries

            healthy_repair = client.post("/api/ledger/repair").json()
            assert healthy_repair["repaired"] == [] and healthy_repair["valid"] is True

            tampered_entries = _load_entries("node1")
            tampered_entries[0]["current_hash"] = "0" * 64
            _ledger_path("node1").write_text(
                "\n".join(json.dumps(e) for e in tampered_entries) + "\n", encoding="utf-8"
            )
            assert client.get("/api/ledger").json()["integrity"] == "FAILED"
            repair = client.post("/api/ledger/repair").json()
            assert "node1" in repair["repaired"]
            assert repair["valid"] is True
            assert client.get("/api/ledger").json()["integrity"] == "VALID"

            verdict = client.post(
                "/api/verify",
                headers=headers,
                files={"file": ("leak.pdf", leaked_bytes, "application/pdf")},
            )
            assert verdict.status_code == 200, verdict.text
            result = verdict.json()
            assert result["status"] == "VERIFIED"
            assert result["recipient_id"] == USERNAME
            assert result["signature_valid"] is True
            assert result["ledger_valid"] is True
            assert result["ledger_quorum_ok"] is True

            fake = client.post("/api/test/fake-watermark")
            assert fake.status_code == 200, fake.text
            assert fake.json()["passed"] is True

            e2e = client.post("/api/test/end-to-end")
            assert e2e.status_code == 200, e2e.text
            assert e2e.json()["passed"] is True
            e2e_body = e2e.json()
            e2e_doc_id = e2e_body.get("document_id")
            for key, rid in (("alice", "ALICE"), ("bob", "BOB")):
                session = (e2e_body.get(key) or {}).get("session")
                if e2e_doc_id and session:
                    e2e_files.append(STORAGE_WATERMARKED / f"{e2e_doc_id}_{rid}_{session}.pdf")

            logout = client.post("/api/auth/logout", headers=headers)
            assert logout.status_code == 200
            assert client.get("/api/auth/me", headers=headers).status_code == 401
    finally:
        _cleanup_user()
        clear_ledger()
        for path in STORAGE_WATERMARKED.glob(f"DOC-*_{USERNAME}_*.pdf"):
            try:
                path.unlink()
            except OSError:
                pass
        for path in (PROJECT_ROOT / "storage" / "encrypted").glob("DOC-*.json"):
            try:
                if json.loads(path.read_text(encoding="utf-8")).get("sender_id") == USERNAME:
                    path.unlink()
            except OSError:
                pass
        if e2e_doc_id:
            (PROJECT_ROOT / "storage" / "encrypted" / f"{e2e_doc_id}.json").unlink(missing_ok=True)
        for path in e2e_files:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
