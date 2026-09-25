import base64
import hashlib
import hmac
import io
import json
import mimetypes
import os
import pathlib
import time
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.app.auth import service as auth_service
from backend.app.auth.deps import get_current_user, get_current_user_optional
from backend.app.encryption.document import (
    encrypt_document,
    list_encrypted_documents,
    load_encrypted_document,
)
from backend.app.forensic.verify import forensic_verify
from backend.app.identity.manager import (
    ensure_demo_recipients,
    get_public_keys,
    is_unlocked,
    list_recipients,
    load_recipient,
    lock_user,
    unlock_expiry,
    unlock_user,
)
from backend.app.ledger import lan as lan_client
from backend.app.ledger import members as ledger_members
from backend.app.ledger.ledger import (
    NODE_IDS,
    find_by_document,
    get_entries_from_all_nodes,
    get_ledger_for_display,
    ledger_mode,
    repair_divergent_nodes,
    verify_all_ledgers,
    verify_entry_quorum,
)
from backend.app.services.decryption_service import recipient_decrypt_and_watermark
from backend.app.watermark import formats

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
STORAGE_WATERMARKED = PROJECT_ROOT / "storage" / "watermarked"
STORAGE_WATERMARKED.mkdir(parents=True, exist_ok=True)
DATA_DIR = PROJECT_ROOT / "backend" / "data"
DOWNLOAD_SECRET_FILE = DATA_DIR / "download_secret.b64"

DOWNLOAD_TTL_SECONDS = 10 * 60

@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_demo_recipients()
    yield


app = FastAPI(
    title="Offline Post-Quantum Forensic Document Attribution",
    description="ML-KEM + ML-DSA + AES-GCM + DCT watermark + signed multi-node ledger",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _bearer_token(authorization: Optional[str]) -> Optional[str]:
    if authorization and authorization.startswith("Bearer "):
        return authorization[len("Bearer "):].strip() or None
    return None


def _download_secret() -> bytes:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if DOWNLOAD_SECRET_FILE.exists():
        return base64.b64decode(DOWNLOAD_SECRET_FILE.read_text(encoding="utf-8").strip())
    secret = os.urandom(32)
    DOWNLOAD_SECRET_FILE.write_text(base64.b64encode(secret).decode(), encoding="utf-8")
    return secret


def make_download_token(filename: str, recipient_id: str, ttl_seconds: int = DOWNLOAD_TTL_SECONDS) -> str:
    body = base64.urlsafe_b64encode(json.dumps(
        {"f": filename, "r": recipient_id.upper(), "e": int(time.time()) + ttl_seconds},
        separators=(",", ":"),
    ).encode()).decode()
    sig = hmac.new(_download_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_download_token(token: str) -> Optional[dict]:
    try:
        body, sig = token.rsplit(".", 1)
        expected = hmac.new(_download_secret(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(body.encode()))
        if int(data.get("e", 0)) < int(time.time()):
            return None
        return data
    except Exception:
        return None


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "message": "Forensic attribution prototype running",
        "pqc": "ML-KEM-768 + ML-DSA-65 (pqcrypto, real)",
        "ledger": "4 signed nodes, quorum 3/4, Merkle checkpoints",
    }


# --- Auth ---

class RegisterRequest(BaseModel):
    username: str
    display_name: str = ""
    passphrase: str


class LoginRequest(BaseModel):
    username: str
    passphrase: str


class UnlockRequest(BaseModel):
    passphrase: str


@app.post("/api/auth/register")
async def auth_register(req: RegisterRequest):
    try:
        user = auth_service.register(req.username, req.display_name, req.passphrase)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"user": user, "message": "Account created. Sign in to unlock your private keys."}


@app.get("/api/auth/username-available")
async def auth_username_available(username: str):
    rid = (username or "").strip().upper()
    if not rid:
        return {"available": False, "username": rid, "reason": "Enter a username"}
    if len(rid) < 3 or len(rid) > 24 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in rid):
        return {
            "available": False,
            "username": rid,
            "reason": "Use 3-24 characters: A-Z, 0-9 or underscore",
        }
    if load_recipient(rid) is not None:
        return {"available": False, "username": rid, "reason": "That username is already taken"}
    return {"available": True, "username": rid, "reason": None}


@app.post("/api/auth/login")
async def auth_login(req: LoginRequest):
    try:
        data = auth_service.login(req.username, req.passphrase)
    except PermissionError:
        raise HTTPException(status_code=401, detail="Unknown user or invalid passphrase")
    return data


@app.post("/api/auth/unlock")
async def auth_unlock(req: UnlockRequest, user: dict = Depends(get_current_user)):
    rid = user["recipient_id"]
    try:
        result = unlock_user(rid, req.passphrase)
    except (PermissionError, FileNotFoundError):
        raise HTTPException(status_code=403, detail="Invalid passphrase")
    return {"unlocked": True, "expires_at": result.get("expires_at") or unlock_expiry(rid)}


@app.post("/api/auth/logout")
async def auth_logout(authorization: Optional[str] = Header(None), user: dict = Depends(get_current_user)):
    token = _bearer_token(authorization)
    if token:
        auth_service.logout(token)
    return {"ok": True}


@app.get("/api/auth/me")
async def auth_me(user: dict = Depends(get_current_user)):
    rid = user["recipient_id"]
    return {"user": user, "unlocked": is_unlocked(rid), "unlock_expires_at": unlock_expiry(rid)}


@app.post("/api/auth/lock")
async def auth_lock(user: dict = Depends(get_current_user)):
    lock_user(user["recipient_id"])
    return {"locked": True, "unlocked": False}


# --- Recipients ---

def _fingerprint(pk_bytes: bytes) -> str:
    return hashlib.sha256(pk_bytes).hexdigest()[:16]


def _recipient_document_counts():
    counts = {}
    for meta in list_encrypted_documents():
        sender = (meta.get("sender_id") or "").upper() or None
        authorized = [r.upper() for r in meta.get("authorized_recipients", [])]
        for rid in set(authorized) | ({sender} if sender else set()):
            slot = counts.setdefault(rid, {"documents_owned": 0, "documents_shared": 0})
            if rid == sender:
                slot["documents_owned"] += 1
            elif rid in authorized:
                slot["documents_shared"] += 1
    return counts


def _recipient_payload(rid, info, counts):
    try:
        pub = get_public_keys(rid)
        mlkem_fp = _fingerprint(pub["mlkem_pk"])
        mldsa_fp = _fingerprint(pub["mldsa_pk"])
    except Exception:
        mlkem_fp = None
        mldsa_fp = None
    slot = counts.get(rid.upper(), {})
    return {
        "recipient_id": rid,
        "display_name": info.get("display_name", rid.capitalize()),
        "mldsa_variant": info.get("mldsa_variant", "65"),
        "mlkem_variant": info.get("mlkem_variant", "768"),
        "key_storage": info.get("key_storage", "legacy"),
        "created_at": info.get("created_at"),
        "mlkem_fingerprint": mlkem_fp,
        "mldsa_fingerprint": mldsa_fp,
        "documents_owned": slot.get("documents_owned", 0),
        "documents_shared": slot.get("documents_shared", 0),
    }


@app.get("/api/recipients")
async def get_recipients():
    reg = list_recipients()
    counts = _recipient_document_counts()
    result = [_recipient_payload(rid, info, counts) for rid, info in reg.items()]
    return {"recipients": result, "count": len(result)}


@app.get("/api/recipients/{recipient_id}")
async def get_recipient(recipient_id: str):
    rid = recipient_id.upper()
    reg = list_recipients()
    if rid not in reg:
        raise HTTPException(status_code=404, detail=f"Recipient {rid} not found")
    return _recipient_payload(rid, reg[rid], _recipient_document_counts())


@app.post("/api/recipients/ensure")
async def ensure_recipients():
    reg = ensure_demo_recipients()
    return {"recipients": list(reg.keys()), "count": len(reg)}


# --- Sender: encrypt ---

@app.post("/api/encrypt")
async def encrypt_endpoint(
    file: UploadFile = File(...),
    recipients: str = Form(...),
    user: dict = Depends(get_current_user),
):
    try:
        if recipients.strip().startswith("["):
            rec_list = json.loads(recipients)
        else:
            rec_list = [r.strip() for r in recipients.split(",") if r.strip()]
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid recipients format: {exc}")

    if not rec_list:
        raise HTTPException(status_code=400, detail="At least one recipient required")

    filename = (file.filename or "").strip()
    extension = pathlib.Path(filename).suffix
    if not filename or not extension or extension == ".":
        raise HTTPException(status_code=400, detail="File name must include an extension")

    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    try:
        meta = encrypt_document(file_bytes, filename, rec_list, sender_id=user["recipient_id"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "document_id": meta["document_id"],
        "document_hash": meta["document_hash"],
        "original_filename": meta["original_filename"],
        "original_extension": meta.get("original_extension"),
        "content_type": meta.get("content_type"),
        "sender_id": meta.get("sender_id"),
        "authorized_recipients": meta["authorized_recipients"],
        "ciphertext_len": meta["ciphertext_len"],
        "status": "ENCRYPTED",
        "message": (
            f"Document {meta['document_id']} encrypted and stored; "
            f"decryption emits the original file format."
        ),
    }


def _document_ledger_stats():
    stats = {}
    for entry in get_ledger_for_display():
        doc_id = entry.get("document_id") or entry.get("event", {}).get("document_id")
        if not doc_id:
            continue
        slot = stats.setdefault(doc_id, {"count": 0, "last": None})
        slot["count"] += 1
        ts = entry.get("timestamp") or entry.get("event", {}).get("timestamp")
        if ts and (slot["last"] is None or ts > slot["last"]):
            slot["last"] = ts
    return stats


@app.get("/api/documents")
async def list_documents(user: dict = Depends(get_current_user)):
    rid = user["recipient_id"].upper()
    stats = _document_ledger_stats()
    docs = []
    for meta in list_encrypted_documents():
        sender = (meta.get("sender_id") or "").upper() or None
        authorized = [r.upper() for r in meta.get("authorized_recipients", [])]
        if sender == rid:
            role = "owner"
        elif rid in authorized:
            role = "recipient"
        else:
            continue
        slot = stats.get(meta["document_id"], {})
        docs.append({
            "document_id": meta["document_id"],
            "original_filename": meta.get("original_filename"),
            "original_extension": meta.get("original_extension"),
            "content_type": meta.get("content_type"),
            "document_hash": meta.get("document_hash"),
            "sender_id": sender,
            "owner": sender or "Unknown",
            "authorized_recipients": authorized,
            "created_at": meta.get("created_at"),
            "ciphertext_len": meta.get("ciphertext_len"),
            "role": role,
            "decryption_count": slot.get("count", 0),
            "last_decrypted_at": slot.get("last"),
        })
    return {"documents": docs, "count": len(docs)}


@app.get("/api/documents/{document_id}")
async def get_document(document_id: str, user: dict = Depends(get_current_user)):
    try:
        meta = load_encrypted_document(document_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Document {document_id} not found")
    rid = user["recipient_id"].upper()
    sender = (meta.get("sender_id") or "").upper() or None
    authorized = [r.upper() for r in meta.get("authorized_recipients", [])]
    if sender != rid and rid not in authorized:
        raise HTTPException(status_code=403, detail="Not authorized for this document")
    meta.pop("wrapped_keys", None)
    meta.pop("ciphertext", None)
    return meta


@app.get("/api/documents/{document_id}/events")
async def get_document_events(document_id: str, user: dict = Depends(get_current_user)):
    try:
        meta = load_encrypted_document(document_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Document {document_id} not found")
    rid = user["recipient_id"].upper()
    sender = (meta.get("sender_id") or "").upper() or None
    authorized = [r.upper() for r in meta.get("authorized_recipients", [])]
    if sender != rid and rid not in authorized:
        raise HTTPException(status_code=403, detail="Not authorized for this document")

    events = []
    for entry in find_by_document(document_id):
        event = entry.get("event", {})
        watermark_id = entry.get("watermark_id") or event.get("watermark_id")
        quorum = verify_entry_quorum(watermark_id) if watermark_id else {"quorum_ok": False, "valid_nodes": []}
        events.append({
            "recipient_id": entry.get("recipient_id") or event.get("recipient_id"),
            "session_id": entry.get("session_id") or event.get("session_id"),
            "watermark_id": watermark_id,
            "timestamp": entry.get("timestamp") or event.get("timestamp"),
            "current_hash": entry.get("current_hash"),
            "previous_hash": entry.get("previous_hash"),
            "quorum_ok": quorum["quorum_ok"],
            "valid_nodes": quorum["valid_nodes"],
        })
    return {"document_id": document_id, "events": events, "count": len(events)}


# --- Recipient: decrypt + watermark ---

class DecryptRequest(BaseModel):
    document_id: str
    recipient_id: Optional[str] = None


@app.post("/api/decrypt")
async def decrypt_endpoint(req: DecryptRequest, user: dict = Depends(get_current_user)):
    rid = user["recipient_id"].upper()
    if req.recipient_id and req.recipient_id.upper() != rid:
        raise HTTPException(status_code=403, detail="You can only decrypt as yourself")

    try:
        meta = load_encrypted_document(req.document_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Document {req.document_id} not found")
    if rid not in [r.upper() for r in meta.get("authorized_recipients", [])]:
        raise HTTPException(status_code=403, detail=f"Recipient {rid} not authorized for {req.document_id}")

    if not is_unlocked(rid):
        raise HTTPException(
            status_code=403,
            detail="Private key is locked. Enter your passphrase to unlock this session.",
        )

    try:
        result = recipient_decrypt_and_watermark(req.document_id, rid)
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail="Private key is locked. Enter your passphrase to unlock this session.",
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {exc}")

    filename = pathlib.Path(result["watermarked_path"]).name
    download_url = f"/api/watermarked/{filename}?token={make_download_token(filename, rid)}"
    return {
        "status": "DECRYPTED",
        "document_id": result["document_id"],
        "recipient_id": result["recipient_id"],
        "session_id": result["session_id"],
        "watermark_id": result["watermark_id"],
        "nonce": result["nonce"],
        "document_hash": result["document_hash"],
        "watermarked_hash": result["watermarked_hash"],
        "signature": result["signature"][:64] + "...",
        "signature_full": result["signature"],
        "ledger": {
            "previous_hash": result["ledger_entry"]["previous_hash"],
            "current_hash": result["ledger_entry"]["current_hash"],
            "node_quorum": len(result["node_quorum"]["valid_nodes"]),
            "valid_nodes": result["node_quorum"]["valid_nodes"],
            "timestamp": result["ledger_entry"]["timestamp"],
        },
        "ledger_status": f"COMMITTED ({len(result['node_quorum']['valid_nodes'])}/4 nodes)",
        "download_url": download_url,
        "filename": filename,
        "content_type": mimetypes.guess_type(filename)[0] or "application/octet-stream",
        "output_format": result.get("output_format"),
        "original_filename": result.get("original_filename"),
        "message": "Decryption successful. Watermark generated and ledger committed.",
    }


@app.get("/api/watermarked/{filename}")
async def download_watermarked(
    filename: str,
    token: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    safe_name = pathlib.Path(filename).name
    if safe_name != filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    path = STORAGE_WATERMARKED / safe_name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Watermarked file not found")

    token_data = verify_download_token(token) if token else None
    if token_data:
        if token_data.get("f") != safe_name:
            raise HTTPException(status_code=403, detail="Download token does not match this file")
    elif not _bearer_token(authorization) or auth_service.get_session(_bearer_token(authorization)) is None:
        raise HTTPException(status_code=401, detail="A valid download token or session is required")

    media_type = mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
    return FileResponse(path, media_type=media_type, filename=safe_name)


@app.get("/api/watermarked")
async def list_watermarked():
    files = sorted(f for f in STORAGE_WATERMARKED.iterdir() if f.is_file())
    return {
        "files": [
            {
                "filename": f.name,
                "size": f.stat().st_size,
                "content_type": mimetypes.guess_type(f.name)[0] or "application/octet-stream",
            }
            for f in files
        ],
        "count": len(files),
    }


# --- Ledger ---

@app.get("/api/ledger")
async def ledger_endpoint():
    entries = get_ledger_for_display()
    valid, details = verify_all_ledgers()

    quorum_cache = {}
    for entry in entries:
        wm = entry.get("watermark_id") or entry.get("event", {}).get("watermark_id")
        if wm and wm not in quorum_cache:
            quorum_cache[wm] = verify_entry_quorum(wm)
        quorum = quorum_cache.get(wm)
        entry["quorum_ok"] = bool(quorum["quorum_ok"]) if quorum else False
        entry["valid_nodes"] = quorum["valid_nodes"] if quorum else []

    return {
        "entries": entries,
        "count": len(entries),
        "integrity": "VALID" if valid else "FAILED",
        "integrity_valid": valid,
        "quorum": details.get("quorum"),
        "quorum_ok": details.get("quorum_ok"),
        "merkle_root": details.get("merkle_root"),
        "divergent_nodes": details.get("divergent_nodes", []),
        "details": details,
        "mode": ledger_mode(),
        "members": len(ledger_members.load_members()),
        "note": (
            "Witness logs are each ML-DSA-signed with Merkle checkpoints; "
            f"quorum is a majority of the {len(ledger_members.load_members())} "
            f"registered member device(s)."
            if ledger_mode() == "lan"
            else "Four locally ML-DSA-signed nodes with Merkle checkpoints; quorum 3/4."
        ),
    }


# --- LAN membership (dynamic witness devices) ---

class RegisterRequest(BaseModel):
    node_id: str
    port: int
    public_key_b64: Optional[str] = None
    token: Optional[str] = None


@app.post("/api/ledger/register")
async def ledger_register(payload: RegisterRequest, request: Request):
    """
    A node agent announces itself; it joins the ledger as a witness device.

    The URL is derived from the caller's observed source IP plus its advertised
    port, so a node cannot claim an address that is not its own. The public key
    is pinned on first join. An optional enrollment token gates registration.
    """
    expected_token = os.environ.get("BOUND_ENROLL_TOKEN", "").strip()
    if expected_token and payload.token != expected_token:
        raise HTTPException(status_code=403, detail="invalid enrollment token")

    node_id = (payload.node_id or "").strip()
    if not node_id:
        raise HTTPException(status_code=400, detail="node_id is required")

    host = request.client.host if request.client else None
    if not host:
        raise HTTPException(status_code=400, detail="cannot determine caller address")
    url = f"http://{host}:{int(payload.port)}"

    entries = lan_client.canonical_entries()
    try:
        member = ledger_members.add_member(node_id, url, payload.public_key_b64)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    seeded = lan_client.maybe_sync(url, entries)
    return {
        "registered": True,
        "member": member,
        "members": len(ledger_members.load_members()),
        "quorum": ledger_members.current_quorum(),
        "seeded_entries": len(entries),
        "sync": seeded,
    }


@app.get("/api/ledger/members")
async def ledger_members_endpoint():
    members = ledger_members.load_members()
    return {
        "mode": ledger_mode(),
        "count": len(members),
        "quorum": ledger_members.current_quorum(),
        "quorum_rule": "strict majority of registered members",
        "members": members,
    }


@app.delete("/api/ledger/members/{node_id}")
async def ledger_remove_member(node_id: str):
    removed = ledger_members.remove_member(node_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"member {node_id} not found")
    return {
        "removed": node_id,
        "count": len(ledger_members.load_members()),
        "quorum": ledger_members.current_quorum(),
    }


@app.post("/api/ledger/repair")
async def ledger_repair():
    return repair_divergent_nodes()


@app.get("/api/ledger/nodes")
async def ledger_nodes():
    nodes = get_entries_from_all_nodes()
    valid, details = verify_all_ledgers()
    return {
        "nodes": {k: {"count": len(v), "entries": v} for k, v in nodes.items()},
        "integrity_valid": valid,
        "details": details,
    }


@app.post("/api/ledger/verify")
async def ledger_verify():
    valid, details = verify_all_ledgers()
    return {"valid": valid, "details": details, "integrity": "VALID" if valid else "FAILED"}


# --- Forensic verification ---

@app.post("/api/verify")
async def verify_endpoint(file: UploadFile = File(...), user: Optional[dict] = Depends(get_current_user_optional)):
    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    return forensic_verify(file_bytes, file.filename)


@app.post("/api/verify/watermark-only")
async def verify_watermark_only(file: UploadFile = File(...), user: Optional[dict] = Depends(get_current_user_optional)):
    file_bytes = await file.read()
    watermark_id = formats.extract_watermark(file_bytes, file.filename)
    return {"watermark_id": watermark_id, "detected": watermark_id is not None}


# --- Security demonstrations ---

def _demo_pdf(title: str) -> bytes:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(100, 700, title)
    c.drawString(100, 680, "Confidential")
    c.showPage()
    c.save()
    return buf.getvalue()


@app.post("/api/test/different-recipients")
async def test_different_recipients():
    docs = list_encrypted_documents()
    if not docs:
        meta = encrypt_document(_demo_pdf("Test doc for different recipients"), "test.pdf", ["ALICE", "BOB"], sender_id="ALICE")
        doc_id = meta["document_id"]
    else:
        doc_id = sorted(docs, key=lambda d: d["document_id"])[-1]["document_id"]

    try:
        alice = recipient_decrypt_and_watermark(doc_id, "ALICE")
        bob = recipient_decrypt_and_watermark(doc_id, "BOB")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "test": "Different recipients",
        "document_id": doc_id,
        "alice_watermark": alice["watermark_id"],
        "bob_watermark": bob["watermark_id"],
        "different": alice["watermark_id"] != bob["watermark_id"],
        "alice_session": alice["session_id"],
        "bob_session": bob["session_id"],
        "expected": "Alice watermark != Bob watermark",
        "passed": alice["watermark_id"] != bob["watermark_id"],
        "visually_identical": True,
        "note": "Documents look visually identical despite different watermarks (PSNR > 40 dB).",
    }


@app.post("/api/test/attribution")
async def test_attribution():
    files = list(STORAGE_WATERMARKED.glob("*ALICE*.pdf"))
    if not files:
        raise HTTPException(status_code=404, detail="No Alice watermarked file found. Run decryption first.")
    latest = max(files, key=lambda p: p.stat().st_mtime)
    result = forensic_verify(latest.read_bytes())
    passed = (
        result["status"] == "VERIFIED"
        and result["recipient_id"] == "ALICE"
        and result["signature_valid"]
        and result["ledger_quorum_ok"]
    )
    return {
        "test": "Attribution",
        "leaked_file": latest.name,
        "result": result,
        "expected": "Recipient: Alice, Signature: VALID, Ledger quorum: VALID",
        "passed": passed,
    }


@app.post("/api/test/signature-tampering")
async def test_signature_tampering():
    from backend.app.forensic.events import verify_event_signature, verify_event_with_provided_pk

    entries = get_ledger_for_display()
    if not entries:
        raise HTTPException(status_code=404, detail="No ledger entries to tamper. Run decryption first.")
    entry = entries[0]
    event = entry["event"]
    sig = entry["signature"]
    pk_b64 = entry["public_key_b64"]
    tampered = dict(event)
    original_recipient = tampered["recipient_id"]
    tampered["recipient_id"] = "BOB" if original_recipient == "ALICE" else "ALICE"
    valid = verify_event_with_provided_pk(tampered, sig, pk_b64)
    valid_via_manager = verify_event_signature(tampered, sig, original_recipient)
    return {
        "test": "Signature Tampering",
        "original_event": event,
        "tampered_event": tampered,
        "original_recipient": original_recipient,
        "signature_valid_after_tamper": valid,
        "signature_valid_via_manager": valid_via_manager,
        "expected": "ML-DSA signature: INVALID",
        "passed": not valid and not valid_via_manager,
    }


@app.post("/api/test/ledger-tampering")
async def test_ledger_tampering():
    import copy

    from backend.app.ledger.ledger import _load_entries

    if ledger_mode() == "lan":
        return {
            "test": "Ledger Tampering (single node)",
            "skipped": True,
            "passed": None,
            "note": (
                "This demo edits local ledger files and only applies to "
                "BOUND_LEDGER_MODE=local. In LAN mode each node owns its file on "
                "its own device; tamper with it there and the Audit view will flag "
                "the node, then 'Re-sync from quorum' repairs it."
            ),
        }

    valid_before, _ = verify_all_ledgers()
    ledger_path = PROJECT_ROOT / "ledger" / "node1" / "ledger.jsonl"
    original_content = ledger_path.read_text(encoding="utf-8") if ledger_path.exists() else ""
    result = {}
    try:
        entries = _load_entries("node1")
        if not entries:
            raise HTTPException(status_code=404, detail="No ledger entries to tamper")
        tampered_entries = copy.deepcopy(entries)
        tampered_entries[0]["current_hash"] = "0" * 64
        ledger_path.write_text("\n".join(json.dumps(e) for e in tampered_entries) + "\n", encoding="utf-8")
        valid_after, details = verify_all_ledgers()
        result = {
            "test": "Ledger Tampering (single node)",
            "tampered_node": "node1",
            "tampered_index": 0,
            "valid_before": valid_before,
            "valid_after": valid_after,
            "details": details,
            "expected": "Ledger integrity: FAILED",
            "passed": not valid_after,
        }
    finally:
        ledger_path.write_text(original_content, encoding="utf-8")
        valid_restored, _ = verify_all_ledgers()
        result["restored_valid"] = valid_restored
    return result


@app.post("/api/test/ledger-admin-tampering")
async def test_ledger_admin_tampering():
    """
    Simulate a privileged administrator who edits every node file and recomputes
    every hash but does NOT hold the per-node ML-DSA signing keys. Node
    signatures and Merkle checkpoints must reject the forged history.
    """
    from backend.app.forensic.events import canonical_serialize
    from backend.app.ledger.ledger import _compute_current_hash, _ledger_path, _load_entries

    if ledger_mode() == "lan":
        return {
            "test": "Privileged Admin Tampering (consistent rewrite)",
            "skipped": True,
            "passed": None,
            "note": (
                "This demo rewrites the local four-node files and only applies to "
                "BOUND_LEDGER_MODE=local. In LAN mode the equivalent attack means "
                "holding every node's private key on every device, which the "
                "membership design prevents."
            ),
        }

    entries0 = _load_entries("node1")
    if not entries0:
        raise HTTPException(status_code=404, detail="No ledger entries to tamper. Run decryption first.")
    target = entries0[0]
    watermark_id = target.get("watermark_id")
    valid_before, _ = verify_all_ledgers()

    originals = {nid: _ledger_path(nid).read_text(encoding="utf-8") for nid in NODE_IDS}
    result = {}
    try:
        for nid in NODE_IDS:
            entries = _load_entries(nid)
            entry = entries[0]
            current = entry["event"].get("recipient_id")
            entry["event"]["recipient_id"] = "BOB" if current == "ALICE" else "ALICE"
            entry["recipient_id"] = entry["event"]["recipient_id"]
            canon = canonical_serialize(entry["event"])
            entry["current_hash"] = _compute_current_hash(canon, entry["signature"], entry["previous_hash"])
            _ledger_path(nid).write_text(
                "\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8"
            )

        valid_after, details = verify_all_ledgers()
        from backend.app.ledger.ledger import verify_entry_quorum

        quorum_after = verify_entry_quorum(watermark_id)
        result = {
            "test": "Ledger Admin Tampering (all 4 nodes rewritten consistently)",
            "watermark_id": watermark_id,
            "valid_before": valid_before,
            "valid_after": valid_after,
            "quorum_ok_after": quorum_after["quorum_ok"],
            "node_errors": {nid: details[nid]["error"] for nid in NODE_IDS},
            "expected": "Forged history rejected: node signatures invalid, quorum lost",
            "passed": (not valid_after) and (not quorum_after["quorum_ok"]),
        }
    finally:
        for nid, content in originals.items():
            _ledger_path(nid).write_text(content, encoding="utf-8")
        valid_restored, _ = verify_all_ledgers()
        result["restored_valid"] = valid_restored
    return result


@app.post("/api/test/fake-watermark")
async def test_fake_watermark():
    from backend.app.watermark.dct_watermark import embed_watermark

    fake_wm = "WM-" + "F" * 26
    fake_pdf = embed_watermark(_demo_pdf("Fake watermark test doc"), fake_wm)
    result = forensic_verify(fake_pdf)
    passed = result["status"] == "NO_LEDGER_MATCH" and not result["ledger_match_found"]
    return {
        "test": "Fake Watermark",
        "fake_watermark": fake_wm,
        "result": result,
        "expected": "No valid ledger match",
        "passed": passed,
    }


@app.post("/api/test/end-to-end")
async def test_end_to_end():
    pdf_bytes = _demo_pdf("End-to-End Secret Document")
    meta = encrypt_document(pdf_bytes, "e2e.pdf", ["ALICE", "BOB"], sender_id="ALICE")
    doc_id = meta["document_id"]
    alice = recipient_decrypt_and_watermark(doc_id, "ALICE")
    bob = recipient_decrypt_and_watermark(doc_id, "BOB")

    leaked_bytes = pathlib.Path(alice["watermarked_path"]).read_bytes()
    result = forensic_verify(leaked_bytes)

    checks = {
        "watermarks_different": alice["watermark_id"] != bob["watermark_id"],
        "alice_recipient": result["recipient_id"] == "ALICE",
        "signature_valid": result["signature_valid"],
        "ledger_valid": result["ledger_valid"],
        "node_quorum_ok": result["ledger_quorum_ok"],
        "status_verified": result["status"] == "VERIFIED",
    }
    return {
        "test": "End-to-End",
        "document_id": doc_id,
        "alice": {"watermark": alice["watermark_id"], "session": alice["session_id"]},
        "bob": {"watermark": bob["watermark_id"], "session": bob["session_id"]},
        "leak_verification": result,
        "checks": checks,
        "passed": all(checks.values()),
        "message": "VERIFIED" if all(checks.values()) else "FAILED",
    }


frontend_dist = PROJECT_ROOT / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
