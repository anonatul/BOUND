"""
Standalone ledger node service for LAN deployment.

Each device on the isolated network runs one instance of this app. The node:

  * generates its own ML-DSA-65 keypair on first start and keeps the private
    key on that device only (it is never sent over the network);
  * owns its own append-only chain (`ledger.jsonl`) and signed Merkle
    checkpoints (`checkpoints.jsonl`) under `BOUND_LEDGER_ROOT/<node_id>/`;
  * independently re-derives `current_hash` for every append and refuses
    anything that does not chain onto its own head;
  * re-signs the whole chain with its own key when explicitly asked to sync
    from a peer (`/node/sync`), so repair does not require trusting file copies.

Run one node per device:

    BOUND_NODE_ID=node1 BOUND_COORDINATOR_URL=http://192.168.50.10:8000 \
      BOUND_NODE_PORT=9101 uv run uvicorn \
      backend.app.ledger.node_agent:app --host 0.0.0.0 --port 9101

The node generates its ML-DSA-65 keypair on first start, keeps the private key
on that device only, and announces itself (id + public key) to the coordinator
so it joins the ledger automatically. Re-announces periodically as a heartbeat.

Plain HTTP is intentional: the isolated LAN (router with no uplink) is the
security boundary.
"""
import json
import os
import pathlib
import threading
import time
import urllib.request
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from backend.app.forensic.events import canonical_serialize
from backend.app.ledger import ledger

NODE_ID = os.environ.get("BOUND_NODE_ID", "node1").strip() or "node1"
COORDINATOR_URL = os.environ.get("BOUND_COORDINATOR_URL", "").strip().rstrip("/")
ENROLL_TOKEN = os.environ.get("BOUND_ENROLL_TOKEN", "").strip()
NODE_PORT = int(os.environ.get("BOUND_NODE_PORT", "9101"))
HEARTBEAT_SECONDS = float(os.environ.get("BOUND_HEARTBEAT_SECONDS", "30"))

app = FastAPI(title=f"BOUND Ledger Node {NODE_ID}")


class AppendRequest(BaseModel):
    seq: int
    event: dict
    signature: str
    public_key_b64: str
    previous_hash: str
    current_hash: str
    timestamp: str


class SyncRequest(BaseModel):
    entries: List[dict]


def _ensure_local_keys() -> bytes:
    pk, _ = ledger._ensure_node_keys(NODE_ID)
    for path in (ledger._pk_path(NODE_ID), ledger._sk_path(NODE_ID)):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return pk


def _head() -> tuple[int, str]:
    entries = ledger._load_entries(NODE_ID)
    last = entries[-1]["current_hash"] if entries else ledger.GENESIS_PREV_HASH
    return len(entries), last


@app.get("/health")
def health() -> Dict:
    return {"status": "ok", "node_id": NODE_ID}


@app.get("/node/info")
def info() -> Dict:
    """Public identity + head. Only the public key is ever exposed."""
    pk = _ensure_local_keys()
    count, last_hash = _head()
    return {
        "node_id": NODE_ID,
        "public_key_b64": ledger.b64e(pk),
        "count": count,
        "last_hash": last_hash,
    }


@app.get("/node/entries")
def all_entries() -> Dict:
    return {"node_id": NODE_ID, "entries": ledger._load_entries(NODE_ID)}


@app.post("/node/verify")
def verify() -> Dict:
    _ensure_local_keys()
    valid, error, entries = ledger.verify_ledger_node(NODE_ID)
    count = len(entries)
    last_hash = entries[-1]["current_hash"] if entries else ledger.GENESIS_PREV_HASH
    merkle_root = (
        ledger._merkle_root([e.get("current_hash") for e in entries])
        if entries
        else ledger.GENESIS_PREV_HASH
    )
    return {
        "node_id": NODE_ID,
        "valid": valid,
        "error": error,
        "count": count,
        "last_hash": last_hash,
        "merkle_root": merkle_root,
    }


@app.get("/node/find")
def find(watermark_id: str) -> Dict:
    _ensure_local_keys()
    entries = ledger._load_entries(NODE_ID)
    for idx, entry in enumerate(entries):
        wm = entry.get("watermark_id") or entry.get("event", {}).get("watermark_id")
        if wm == watermark_id:
            prefix_ok, prefix_err, _ = ledger._verify_entry_chain_prefix(NODE_ID, idx)
            return {
                "node_id": NODE_ID,
                "found": True,
                "valid_prefix": prefix_ok,
                "error": prefix_err,
                "entry": entry,
            }
    return {"node_id": NODE_ID, "found": False}


@app.post("/node/append")
def append(req: AppendRequest) -> Dict:
    """
    Append one coordinator-proposed entry after independently validating it.

    The node only signs if the entry chains onto its current head and
    `current_hash` really is SHA256(event + recipient signature + previous_hash).
    """
    _ensure_local_keys()
    entries = ledger._load_entries(NODE_ID)
    seq = len(entries)
    previous_hash = entries[-1]["current_hash"] if entries else ledger.GENESIS_PREV_HASH

    if req.seq != seq:
        raise HTTPException(status_code=409, detail=f"seq mismatch: expected {seq}, got {req.seq}")
    if req.previous_hash != previous_hash:
        raise HTTPException(
            status_code=409,
            detail=f"previous_hash mismatch: expected {previous_hash[:12]}..., got {req.previous_hash[:12]}...",
        )
    computed = ledger._compute_current_hash(
        canonical_serialize(req.event), req.signature, req.previous_hash
    )
    if computed != req.current_hash:
        raise HTTPException(status_code=400, detail="current_hash does not match event+signature+previous_hash")

    entry = ledger._build_entry(
        NODE_ID, seq, req.event, req.signature, req.public_key_b64,
        req.previous_hash, req.current_hash, req.timestamp,
    )
    merkle_root = ledger._merkle_root(
        [e.get("current_hash") for e in entries] + [req.current_hash]
    )
    checkpoint = ledger._build_checkpoint(NODE_ID, seq, seq + 1, merkle_root, req.timestamp)

    ledger._append_jsonl(ledger._ledger_path(NODE_ID), entry)
    ledger._append_jsonl(ledger._checkpoints_path(NODE_ID), checkpoint)
    return entry


@app.post("/node/sync")
def sync(req: SyncRequest) -> Dict:
    """
    Adopt a peer's canonical chain by re-signing every entry with this node's
    own key and rebuilding its checkpoints. The incoming chain is fully
    re-validated first, and a node will not sync to an empty chain.
    """
    _ensure_local_keys()
    entries = req.entries
    if not entries:
        raise HTTPException(status_code=400, detail="refusing to sync to an empty chain")

    previous = ledger.GENESIS_PREV_HASH
    for idx, entry in enumerate(entries):
        event = entry.get("event")
        signature = entry.get("signature")
        if entry.get("seq") != idx:
            raise HTTPException(status_code=400, detail=f"entry {idx} seq mismatch")
        if entry.get("previous_hash") != previous:
            raise HTTPException(status_code=400, detail=f"entry {idx} previous_hash mismatch")
        if not isinstance(event, dict) or not isinstance(signature, str):
            raise HTTPException(status_code=400, detail=f"entry {idx} missing event/signature")
        computed = ledger._compute_current_hash(canonical_serialize(event), signature, entry["previous_hash"])
        if computed != entry.get("current_hash"):
            raise HTTPException(status_code=400, detail=f"entry {idx} current_hash mismatch")
        previous = entry["current_hash"]

    rebuilt: List[Dict] = []
    hashes: List[str] = []
    checkpoints: List[Dict] = []
    for idx, entry in enumerate(entries):
        rebuilt.append(
            ledger._build_entry(
                NODE_ID, idx, entry["event"], entry["signature"], entry["public_key_b64"],
                entry["previous_hash"], entry["current_hash"], entry["timestamp"],
            )
        )
        hashes.append(entry["current_hash"])
        checkpoints.append(
            ledger._build_checkpoint(
                NODE_ID, idx, idx + 1, ledger._merkle_root(hashes), entry["timestamp"]
            )
        )

    ledger._ledger_path(NODE_ID).write_text(
        "".join(json.dumps(e) + "\n" for e in rebuilt), encoding="utf-8"
    )
    ledger._checkpoints_path(NODE_ID).write_text(
        "".join(json.dumps(c) + "\n" for c in checkpoints), encoding="utf-8"
    )
    return {"node_id": NODE_ID, "synced": True, "count": len(rebuilt)}


# ---------------------------------------------------------------------------
# self-registration with the coordinator (auto-join the ledger)
# ---------------------------------------------------------------------------

def _announce_once() -> Optional[Dict]:
    """Tell the coordinator who we are and where we listen. Returns its reply."""
    if not COORDINATOR_URL:
        return None
    pk = _ensure_local_keys()
    payload = {
        "node_id": NODE_ID,
        "port": NODE_PORT,
        "public_key_b64": ledger.b64e(pk),
    }
    if ENROLL_TOKEN:
        payload["token"] = ENROLL_TOKEN
    request = urllib.request.Request(
        COORDINATOR_URL + "/api/ledger/register",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=_announce_timeout()) as response:
        return json.loads(response.read().decode("utf-8"))


def _announce_timeout() -> float:
    try:
        return float(os.environ.get("BOUND_ANNOUNCE_TIMEOUT", "8"))
    except ValueError:
        return 8.0


def _heartbeat_loop() -> None:
    while True:
        try:
            _announce_once()
        except Exception:
            pass  # coordinator may not be up yet; retry on the next tick
        time.sleep(HEARTBEAT_SECONDS)


@app.on_event("startup")
def _start_heartbeat() -> None:
    if COORDINATOR_URL:
        threading.Thread(target=_heartbeat_loop, daemon=True).start()
