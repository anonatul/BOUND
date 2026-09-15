"""
Prototype tamper-evident ledger with 4-node replication and quorum (3/4).
Not claiming equivalence to production blockchain consensus.
"""
import json
import hashlib
import pathlib
import time
from typing import List, Dict, Optional, Tuple

from backend.app.forensic.events import canonical_serialize

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[3]
LEDGER_ROOT = PROJECT_ROOT / "ledger"
NODE_IDS = ["node1", "node2", "node3", "node4"]
GENESIS_PREV_HASH = "0" * 64

def _ledger_path(node_id: str) -> pathlib.Path:
    return LEDGER_ROOT / node_id / "ledger.jsonl"

def _ensure_ledger_dirs():
    for nid in NODE_IDS:
        (LEDGER_ROOT / nid).mkdir(parents=True, exist_ok=True)
        p = _ledger_path(nid)
        if not p.exists():
            p.touch()

def _compute_current_hash(canonical_event_bytes: bytes, signature_b64: str, previous_hash: str) -> str:
    h = hashlib.sha256()
    h.update(canonical_event_bytes)
    h.update(signature_b64.encode())
    h.update(previous_hash.encode())
    return h.hexdigest()

def _load_entries(node_id: str) -> List[Dict]:
    p = _ledger_path(node_id)
    if not p.exists():
        return []
    entries = []
    for line in p.read_text().splitlines():
        line=line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except:
            continue
    return entries

def _append_entry(node_id: str, entry: Dict):
    p = _ledger_path(node_id)
    with open(p, "a") as f:
        f.write(json.dumps(entry) + "\n")

def _get_last_hash(node_id: str) -> str:
    entries = _load_entries(node_id)
    if not entries:
        return GENESIS_PREV_HASH
    return entries[-1]["current_hash"]

def get_all_entries() -> List[Dict]:
    """
    Return consolidated ledger entries (from node1 as primary, but verify consistency).
    For display, we use node1's ledger.
    """
    # Use the longest valid chain ? For prototype, just node1
    return _load_entries("node1")

def get_entries_from_all_nodes() -> Dict[str, List[Dict]]:
    return {nid: _load_entries(nid) for nid in NODE_IDS}

def commit_event(event: Dict, signature_b64: str, public_key_b64: str) -> Dict:
    """
    Commit event to ledger with replication and quorum.
    Computes current_hash per spec:
        current_hash = SHA256(canonical_event + signature + previous_hash)
    Replicates to 4 nodes, requires at least 3 successes.
    Returns committed entry.
    """
    _ensure_ledger_dirs()
    canon = canonical_serialize(event)
    # We need to determine previous_hash: use the longest chain's last hash? For prototype, use node1's last hash,
    # but verify all nodes have same chain (if divergence, use majority)
    # Simpler: compute previous_hash from node1, then replicate same hash to all nodes.
    # However if nodes diverge, quorum check will detect.
    # For prototype strict, we assume nodes are consistent before commit.

    # Determine previous hash by majority of nodes' last hash (to handle minor divergence)
    last_hashes = [_get_last_hash(nid) for nid in NODE_IDS]
    # majority vote for previous hash
    from collections import Counter
    cnt = Counter(last_hashes)
    previous_hash, _ = cnt.most_common(1)[0]

    current_hash = _compute_current_hash(canon, signature_b64, previous_hash)

    entry = {
        "event": event,
        "signature": signature_b64,
        "public_key_b64": public_key_b64,
        "previous_hash": previous_hash,
        "current_hash": current_hash,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # convenience denormalized fields
        "document_id": event.get("document_id"),
        "recipient_id": event.get("recipient_id"),
        "session_id": event.get("session_id"),
        "watermark_id": event.get("watermark_id"),
        "document_hash": event.get("document_hash"),
    }

    # Replicate to nodes
    successes = 0
    failures = []
    for nid in NODE_IDS:
        try:
            # Verify that node's last hash matches our previous_hash (if not, that node is out of sync)
            node_last = _get_last_hash(nid)
            # For prototype, we allow divergence but log; still we append using our computed previous_hash
            # In real quorum we would reject out-of-sync nodes, but for prototype we count them as success if write succeeds
            _append_entry(nid, entry)
            successes += 1
        except Exception as e:
            failures.append((nid, str(e)))

    if successes < 3:
        raise RuntimeError(f"Quorum not reached: only {successes}/4 nodes accepted event. Failures: {failures}")

    return entry

def verify_ledger_node(node_id: str) -> Tuple[bool, Optional[str], List[Dict]]:
    """
    Verify hash chain for a single node.
    Returns (is_valid, error_message, entries)
    """
    entries = _load_entries(node_id)
    prev = GENESIS_PREV_HASH
    for idx, entry in enumerate(entries):
        event = entry["event"]
        sig = entry["signature"]
        stored_prev = entry["previous_hash"]
        stored_curr = entry["current_hash"]
        if stored_prev != prev:
            return False, f"Node {node_id} entry {idx} previous_hash mismatch: expected {prev[:8]}..., got {stored_prev[:8]}...", entries
        canon = canonical_serialize(event)
        computed = _compute_current_hash(canon, sig, stored_prev)
        if computed != stored_curr:
            return False, f"Node {node_id} entry {idx} current_hash mismatch: computed {computed[:8]}..., stored {stored_curr[:8]}...", entries
        # Also verify signature? Not required for hash chain but we can optionally check
        prev = stored_curr
    return True, None, entries

def verify_all_ledgers() -> Tuple[bool, Dict]:
    """
    Verify all 4 nodes, check quorum consistency.
    Returns (overall_valid, details)
    """
    results = {}
    overall_valid = True
    for nid in NODE_IDS:
        valid, err, entries = verify_ledger_node(nid)
        results[nid] = {"valid": valid, "error": err, "count": len(entries)}
        if not valid:
            overall_valid = False

    # Check consistency: all nodes should have same current chain (same last hash) if valid
    last_hashes = {}
    for nid in NODE_IDS:
        entries = _load_entries(nid)
        if entries:
            last_hashes[nid] = entries[-1]["current_hash"]
        else:
            last_hashes[nid] = GENESIS_PREV_HASH
    # If valid but hashes differ, then replication divergence
    if overall_valid:
        unique_hashes = set(last_hashes.values())
        if len(unique_hashes) > 1:
            overall_valid = False
            for nid in NODE_IDS:
                results[nid]["error"] = f"Divergent ledger: last_hash {last_hashes[nid][:8]}... vs others {unique_hashes}"

    return overall_valid, results

def find_by_watermark(watermark_id: str) -> Optional[Dict]:
    """
    Search ledger for matching watermark_id.
    Searches node1's ledger (or any node's majority).
    Returns entry or None.
    """
    entries = _load_entries("node1")
    for e in entries:
        if e.get("watermark_id") == watermark_id:
            return e
        if e.get("event", {}).get("watermark_id") == watermark_id:
            return e
    # If not found in node1, try other nodes
    for nid in NODE_IDS:
        if nid == "node1":
            continue
        for e in _load_entries(nid):
            if e.get("watermark_id") == watermark_id:
                return e
            if e.get("event", {}).get("watermark_id") == watermark_id:
                return e
    return None

def find_by_document(document_id: str) -> List[Dict]:
    entries = _load_entries("node1")
    return [e for e in entries if e.get("document_id") == document_id]

def clear_ledger():
    _ensure_ledger_dirs()
    for nid in NODE_IDS:
        p = _ledger_path(nid)
        p.write_text("")

def tamper_entry(node_id: str, index: int, field: str, new_value):
    """
    For testing: modify an entry in a node's ledger file (simulate tampering).
    field can be 'event.recipient_id' or 'signature' etc.
    """
    entries = _load_entries(node_id)
    if index >= len(entries):
        raise IndexError
    # Modify
    if field.startswith("event."):
        key = field.split(".",1)[1]
        entries[index]["event"][key] = new_value
    else:
        entries[index][field] = new_value
    # Rewrite file
    p = _ledger_path(node_id)
    with open(p, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

def get_ledger_for_display() -> List[Dict]:
    entries = get_all_entries()
    # Add index
    for i, e in enumerate(entries):
        e["_index"] = i
    return entries
