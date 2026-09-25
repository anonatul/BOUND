"""
Multi-node tamper-evident ledger (v2).

Design:
  * 4 independent nodes (`ledger/node1` .. `ledger/node4`), each with its own
    ML-DSA-65 keypair stored beside its ledger files.
  * Every appended entry carries that node's own `node_id` and `node_signature`,
    so a privileged administrator with file access but WITHOUT the per-node
    private keys cannot rewrite the four files consistently.
  * After every append the node writes a signed Merkle checkpoint to
    `nodeN/checkpoints.jsonl`, which makes silent truncation/rewrites detectable.
  * Commits require at least a 3-of-4 node quorum; attribution survives a single
    corrupted node via `verify_entry_quorum`.

This is a prototype; it is not a production BFT consensus protocol.
"""
import hashlib
import json
import os
import pathlib
import time
from collections import Counter
from typing import Dict, List, Optional, Tuple

from backend.app.crypto.pqcrypto_wrapper import (
    b64d,
    b64e,
    mldsa_keygen,
    mldsa_sign,
    mldsa_verify,
)
from backend.app.forensic.events import canonical_serialize

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[3]
# `BOUND_LEDGER_ROOT` lets a per-device node agent run this exact code against
# its own data directory. Local (single-process) mode leaves it unset.
LEDGER_ROOT = pathlib.Path(
    os.environ.get("BOUND_LEDGER_ROOT", str(PROJECT_ROOT / "ledger"))
)
NODE_IDS = ["node1", "node2", "node3", "node4"]


def ledger_mode() -> str:
    """
    "local" (default): four node directories written by this process.
    "lan": the four nodes are remote services on separate devices, reached over
    the isolated LAN via backend.app.ledger.lan.
    """
    return os.environ.get("BOUND_LEDGER_MODE", "local").strip().lower()


def _dispatch_lan():
    from backend.app.ledger import lan as _lan
    return _lan
GENESIS_PREV_HASH = "0" * 64

QUORUM_SIZE = 3
NODE_KEY_VARIANT = "65"
NODE_PK_FILENAME = "node_mldsa_pk.b64"
NODE_SK_FILENAME = "node_mldsa_sk.b64"
ENTRY_SIGNED_FIELDS = (
    "seq",
    "previous_hash",
    "current_hash",
    "signature",
    "document_id",
    "recipient_id",
    "session_id",
    "watermark_id",
    "timestamp",
)
CHECKPOINT_SIGNED_FIELDS = (
    "checkpoint_index",
    "entry_count",
    "merkle_root",
    "timestamp",
    "node_id",
)


# ---------------------------------------------------------------------------
# paths / per-node identity
# ---------------------------------------------------------------------------

def _node_dir(node_id: str) -> pathlib.Path:
    return LEDGER_ROOT / node_id

def _ledger_path(node_id: str) -> pathlib.Path:
    return _node_dir(node_id) / "ledger.jsonl"

def _checkpoints_path(node_id: str) -> pathlib.Path:
    return _node_dir(node_id) / "checkpoints.jsonl"

def _pk_path(node_id: str) -> pathlib.Path:
    return _node_dir(node_id) / NODE_PK_FILENAME

def _sk_path(node_id: str) -> pathlib.Path:
    return _node_dir(node_id) / NODE_SK_FILENAME

def _ensure_ledger_dirs():
    for nid in NODE_IDS:
        _node_dir(nid).mkdir(parents=True, exist_ok=True)
        _ledger_path(nid).touch(exist_ok=True)
        _checkpoints_path(nid).touch(exist_ok=True)

def _ensure_node_keys(node_id: str) -> Tuple[bytes, bytes]:
    """
    Load the node's ML-DSA-65 keypair, generating and persisting it on first use.
    Existing keys are never overwritten.
    """
    pk_path = _pk_path(node_id)
    sk_path = _sk_path(node_id)
    if pk_path.exists() and sk_path.exists():
        return b64d(pk_path.read_text().strip()), b64d(sk_path.read_text().strip())
    pk, sk = mldsa_keygen(variant=NODE_KEY_VARIANT)
    pk_path.parent.mkdir(parents=True, exist_ok=True)
    pk_path.write_text(b64e(pk))
    sk_path.write_text(b64e(sk))
    return pk, sk

def _load_node_public_key(node_id: str) -> Optional[bytes]:
    p = _pk_path(node_id)
    if not p.exists():
        return None
    try:
        return b64d(p.read_text().strip())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# JSONL helpers
# ---------------------------------------------------------------------------

def _read_jsonl_strict(path: pathlib.Path) -> Tuple[List[Dict], Optional[str]]:
    """
    Read a JSONL file, returning (records, error). Malformed lines are reported
    rather than silently skipped so tampering cannot hide behind parse errors.
    """
    if not path.exists():
        return [], None
    records: List[Dict] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except Exception as e:
            return records, f"malformed JSON at line {lineno}: {e}"
        if not isinstance(record, dict):
            return records, f"line {lineno} is not a JSON object"
        records.append(record)
    return records, None

def _load_entries(node_id: str) -> List[Dict]:
    """Lenient load for display/search helpers (skip unparsable lines)."""
    p = _ledger_path(node_id)
    if not p.exists():
        return []
    entries = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    return entries

def _append_jsonl(path: pathlib.Path, record: Dict):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
        f.flush()
        os.fsync(f.fileno())

def _get_last_hash(node_id: str) -> str:
    entries = _load_entries(node_id)
    if not entries:
        return GENESIS_PREV_HASH
    return entries[-1].get("current_hash", GENESIS_PREV_HASH)


# ---------------------------------------------------------------------------
# hashing / merkle
# ---------------------------------------------------------------------------

def _compute_current_hash(canonical_event_bytes: bytes, signature_b64: str, previous_hash: str) -> str:
    h = hashlib.sha256()
    h.update(canonical_event_bytes)
    h.update(signature_b64.encode())
    h.update(previous_hash.encode())
    return h.hexdigest()

def _merkle_root(current_hashes: List[str]) -> str:
    """
    Standard binary Merkle tree over entry current_hash values (SHA256 internal
    nodes, duplicate last node when the level has an odd count).
    """
    if not current_hashes:
        return GENESIS_PREV_HASH
    level = [bytes.fromhex(h) for h in current_hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


# ---------------------------------------------------------------------------
# entry / checkpoint signing
# ---------------------------------------------------------------------------

def _entry_signature_payload(entry: Dict) -> Dict:
    return {field: entry.get(field) for field in ENTRY_SIGNED_FIELDS}

def _checkpoint_signature_payload(checkpoint: Dict) -> Dict:
    return {field: checkpoint.get(field) for field in CHECKPOINT_SIGNED_FIELDS}

def _build_entry(
    node_id: str,
    seq: int,
    event: Dict,
    signature_b64: str,
    public_key_b64: str,
    previous_hash: str,
    current_hash: str,
    timestamp: str,
) -> Dict:
    entry = {
        "seq": seq,
        "event": event,
        "signature": signature_b64,
        "public_key_b64": public_key_b64,
        "previous_hash": previous_hash,
        "current_hash": current_hash,
        "timestamp": timestamp,
        "node_id": node_id,
        "node_signature": None,
        # convenience denormalized fields
        "document_id": event.get("document_id"),
        "recipient_id": event.get("recipient_id"),
        "session_id": event.get("session_id"),
        "watermark_id": event.get("watermark_id"),
        "document_hash": event.get("document_hash"),
    }
    _, sk = _ensure_node_keys(node_id)
    payload = _entry_signature_payload(entry)
    node_sig = mldsa_sign(sk, canonical_serialize(payload), variant=NODE_KEY_VARIANT)
    entry["node_signature"] = b64e(node_sig)
    return entry

def _verify_entry_node_signature(node_id: str, entry: Dict, node_pk: Optional[bytes]) -> Tuple[bool, Optional[str]]:
    sig_b64 = entry.get("node_signature")
    if not sig_b64:
        return False, "missing node_signature (legacy entry cannot be verified)"
    if node_pk is None:
        return False, f"cannot verify node_signature: {NODE_PK_FILENAME} not found"
    try:
        payload = _entry_signature_payload(entry)
        ok = mldsa_verify(node_pk, canonical_serialize(payload), b64d(sig_b64), variant=NODE_KEY_VARIANT)
    except Exception as e:
        return False, f"node_signature verification error: {e}"
    if not ok:
        return False, "node_signature invalid: entry was not signed by this node's ML-DSA key"
    return True, None

def _build_checkpoint(
    node_id: str,
    checkpoint_index: int,
    entry_count: int,
    merkle_root: str,
    timestamp: str,
) -> Dict:
    payload = {
        "checkpoint_index": checkpoint_index,
        "entry_count": entry_count,
        "merkle_root": merkle_root,
        "timestamp": timestamp,
        "node_id": node_id,
    }
    _, sk = _ensure_node_keys(node_id)
    sig = mldsa_sign(sk, canonical_serialize(payload), variant=NODE_KEY_VARIANT)
    checkpoint = dict(payload)
    checkpoint["node_signature"] = b64e(sig)
    return checkpoint


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------

def _verify_entry_chain_prefix(node_id: str, up_to_index: int) -> Tuple[bool, Optional[str], List[Dict]]:
    """
    Verify seq continuity, previous_hash linkage, current_hash, and per-entry
    node_signature for entries[0..up_to_index] (inclusive).
    """
    entries, parse_error = _read_jsonl_strict(_ledger_path(node_id))
    if parse_error:
        return False, f"Node {node_id} ledger.jsonl {parse_error}", entries
    if up_to_index >= len(entries):
        return False, f"Node {node_id} entry index {up_to_index} out of range ({len(entries)} entries)", entries
    node_pk = _load_node_public_key(node_id)
    prev = GENESIS_PREV_HASH
    for idx in range(up_to_index + 1):
        entry = entries[idx]
        if entry.get("seq") != idx:
            return False, f"Node {node_id} entry {idx} seq mismatch: expected {idx}, got {entry.get('seq')}", entries
        stored_prev = entry.get("previous_hash")
        if stored_prev != prev:
            return False, f"Node {node_id} entry {idx} previous_hash mismatch: expected {prev[:8]}..., got {str(stored_prev)[:8]}...", entries
        event = entry.get("event")
        sig = entry.get("signature")
        if not isinstance(event, dict) or not isinstance(sig, str):
            return False, f"Node {node_id} entry {idx} malformed: missing event/signature", entries
        computed = _compute_current_hash(canonical_serialize(event), sig, stored_prev)
        if computed != entry.get("current_hash"):
            return False, f"Node {node_id} entry {idx} current_hash mismatch: computed {computed[:8]}..., stored {str(entry.get('current_hash'))[:8]}...", entries
        sig_ok, sig_err = _verify_entry_node_signature(node_id, entry, node_pk)
        if not sig_ok:
            return False, f"Node {node_id} entry {idx} {sig_err}", entries
        prev = entry["current_hash"]
    return True, None, entries

def verify_ledger_node(node_id: str) -> Tuple[bool, Optional[str], List[Dict]]:
    """
    Verify a single node: seq/hash chain continuity, per-entry node_signature,
    and all signed Merkle checkpoints.
    Returns (is_valid, error_message, entries).
    """
    entries, parse_error = _read_jsonl_strict(_ledger_path(node_id))
    if parse_error:
        return False, f"Node {node_id} ledger.jsonl {parse_error}", entries

    node_pk = _load_node_public_key(node_id)
    prev = GENESIS_PREV_HASH
    for idx, entry in enumerate(entries):
        if entry.get("seq") != idx:
            return False, f"Node {node_id} entry {idx} seq mismatch: expected {idx}, got {entry.get('seq')}", entries
        stored_prev = entry.get("previous_hash")
        stored_curr = entry.get("current_hash")
        if stored_prev != prev:
            return False, f"Node {node_id} entry {idx} previous_hash mismatch: expected {prev[:8]}..., got {str(stored_prev)[:8]}...", entries
        event = entry.get("event")
        sig = entry.get("signature")
        if not isinstance(event, dict) or not isinstance(sig, str):
            return False, f"Node {node_id} entry {idx} malformed: missing event/signature", entries
        canon = canonical_serialize(event)
        computed = _compute_current_hash(canon, sig, stored_prev)
        if computed != stored_curr:
            return False, f"Node {node_id} entry {idx} current_hash mismatch: computed {computed[:8]}..., stored {str(stored_curr)[:8]}...", entries
        sig_ok, sig_err = _verify_entry_node_signature(node_id, entry, node_pk)
        if not sig_ok:
            return False, f"Node {node_id} entry {idx} {sig_err}", entries
        prev = stored_curr

    checkpoints, cp_parse_error = _read_jsonl_strict(_checkpoints_path(node_id))
    if cp_parse_error:
        return False, f"Node {node_id} checkpoints.jsonl {cp_parse_error}", entries
    if len(checkpoints) != len(entries):
        return False, f"Node {node_id} checkpoint count mismatch: {len(checkpoints)} checkpoints for {len(entries)} entries", entries

    for cp_idx, checkpoint in enumerate(checkpoints):
        if checkpoint.get("checkpoint_index") != cp_idx:
            return False, f"Node {node_id} checkpoint {cp_idx} index mismatch: got {checkpoint.get('checkpoint_index')}", entries
        entry_count = checkpoint.get("entry_count")
        if entry_count != cp_idx + 1:
            return False, f"Node {node_id} checkpoint {cp_idx} entry_count mismatch: expected {cp_idx + 1}, got {entry_count}", entries
        if not isinstance(entry_count, int) or entry_count < 1 or entry_count > len(entries):
            return False, f"Node {node_id} checkpoint {cp_idx} entry_count out of range: {entry_count}", entries
        expected_root = _merkle_root([entries[i]["current_hash"] for i in range(entry_count)])
        if checkpoint.get("merkle_root") != expected_root:
            return False, f"Node {node_id} checkpoint {cp_idx} merkle_root mismatch: stored {str(checkpoint.get('merkle_root'))[:8]}..., computed {expected_root[:8]}...", entries
        if checkpoint.get("node_id") != node_id:
            return False, f"Node {node_id} checkpoint {cp_idx} node_id mismatch: got {checkpoint.get('node_id')}", entries
        cp_sig = checkpoint.get("node_signature")
        if not cp_sig:
            return False, f"Node {node_id} checkpoint {cp_idx} missing node_signature", entries
        if node_pk is None:
            return False, f"Node {node_id} checkpoint {cp_idx} cannot verify: {NODE_PK_FILENAME} not found", entries
        try:
            ok = mldsa_verify(
                node_pk,
                canonical_serialize(_checkpoint_signature_payload(checkpoint)),
                b64d(cp_sig),
                variant=NODE_KEY_VARIANT,
            )
        except Exception as e:
            return False, f"Node {node_id} checkpoint {cp_idx} signature error: {e}", entries
        if not ok:
            return False, f"Node {node_id} checkpoint {cp_idx} node_signature invalid", entries

    return True, None, entries

def verify_all_ledgers() -> Tuple[bool, Dict]:
    """
    Strict overall validity: ALL 4 nodes valid AND all chains identical in
    length and last hash. Per-node details plus quorum/merkle/divergence info.
    """
    if ledger_mode() == "lan":
        return _dispatch_lan().verify_all_ledgers()
    results: Dict = {}
    valid_nodes: List[str] = []
    chain_meta: Dict[str, Tuple[int, str]] = {}

    for nid in NODE_IDS:
        valid, err, entries = verify_ledger_node(nid)
        last_hash = entries[-1]["current_hash"] if entries else GENESIS_PREV_HASH
        checkpoints, _ = _read_jsonl_strict(_checkpoints_path(nid))
        results[nid] = {
            "valid": valid,
            "error": err,
            "count": len(entries),
            "last_hash": last_hash,
            "merkle_root": _merkle_root([e.get("current_hash") for e in entries]) if entries else GENESIS_PREV_HASH,
            "checkpoint_count": len(checkpoints),
        }
        chain_meta[nid] = (len(entries), last_hash)
        if valid:
            valid_nodes.append(nid)

    majority_last_hash = GENESIS_PREV_HASH
    if valid_nodes:
        hashes = Counter(chain_meta[nid][1] for nid in valid_nodes)
        majority_last_hash, _ = hashes.most_common(1)[0]

    merkle_root = GENESIS_PREV_HASH
    for nid in valid_nodes:
        if chain_meta[nid][1] == majority_last_hash:
            merkle_root = _merkle_root([e.get("current_hash") for e in _load_entries(nid)])
            break

    lengths = {chain_meta[nid][0] for nid in valid_nodes}
    last_hashes = {chain_meta[nid][1] for nid in valid_nodes}
    overall_valid = (
        len(valid_nodes) == len(NODE_IDS)
        and len(lengths) == 1
        and len(last_hashes) == 1
    )

    results["quorum"] = len(valid_nodes)
    results["quorum_ok"] = len(valid_nodes) >= QUORUM_SIZE
    results["merkle_root"] = merkle_root
    results["majority_last_hash"] = majority_last_hash
    results["divergent_nodes"] = [
        nid for nid in NODE_IDS
        if (not results[nid]["valid"]) or chain_meta[nid][1] != majority_last_hash
    ]
    return overall_valid, results

def verify_entry_quorum(watermark_id: str) -> Dict:
    """
    Prove a single ledger entry is replicated on a >= 3 node quorum.

    Requires the SAME current_hash present on >= QUORUM_SIZE nodes, each with a
    valid node_signature, and each of those node chains valid up to that seq.
    A single corrupt node therefore cannot destroy attribution.
    """
    if ledger_mode() == "lan":
        return _dispatch_lan().verify_entry_quorum(watermark_id)
    result = {
        "quorum_ok": False,
        "valid_nodes": [],
        "total_nodes": len(NODE_IDS),
        "entry": None,
        "error": None,
    }

    groups: Dict[str, List[Tuple[str, int, Dict]]] = {}
    for nid in NODE_IDS:
        entries, parse_error = _read_jsonl_strict(_ledger_path(nid))
        if parse_error:
            continue
        for idx, entry in enumerate(entries):
            wm = entry.get("watermark_id") or entry.get("event", {}).get("watermark_id")
            if wm == watermark_id:
                groups.setdefault(entry.get("current_hash"), []).append((nid, idx, entry))
                break

    if not groups:
        result["error"] = f"watermark {watermark_id} not found in any node ledger"
        return result

    best: Optional[List[Tuple[str, Dict]]] = None
    for _current_hash, members in groups.items():
        valid_members: List[Tuple[str, Dict]] = []
        for nid, idx, entry in members:
            chain_ok, _chain_err, _ = _verify_entry_chain_prefix(nid, idx)
            if chain_ok:
                valid_members.append((nid, entry))
        if len(valid_members) >= QUORUM_SIZE and (best is None or len(valid_members) > len(best)):
            best = valid_members

    if best is None:
        result["error"] = (
            f"no current_hash for watermark {watermark_id} is validly signed "
            f"and replicated on >= {QUORUM_SIZE} nodes"
        )
        return result

    result["quorum_ok"] = True
    result["valid_nodes"] = [nid for nid, _ in best]
    for nid, entry in best:
        if nid == "node1":
            result["entry"] = entry
            break
    if result["entry"] is None:
        result["entry"] = best[0][1]
    return result


# ---------------------------------------------------------------------------
# commit
# ---------------------------------------------------------------------------

def _node_can_participate(node_id: str, previous_hash: str) -> Tuple[bool, Optional[str]]:
    valid, error, entries = verify_ledger_node(node_id)
    if not valid:
        return False, error
    next_seq = (entries[-1].get("seq", -1) + 1) if entries else 0
    if next_seq != len(entries):
        return False, f"seq continuity broken: next seq {next_seq} != entry count {len(entries)}"
    if _get_last_hash(node_id) != previous_hash:
        return False, (
            f"last hash {_get_last_hash(node_id)[:8]}... != majority previous_hash "
            f"{previous_hash[:8]}..."
        )
    return True, None

def commit_event(event: Dict, signature_b64: str, public_key_b64: str) -> Dict:
    """
    Commit an event to the ledger with per-node signing and 3/4 quorum.

    current_hash = SHA256(canonical_event + signature + previous_hash), where
    previous_hash is the majority of the nodes' last hashes. A node participates
    only if its chain currently verifies, its seq is continuous, and its last
    hash equals previous_hash. Each participating node stores its own line
    (distinct node_id + node_signature) and a signed Merkle checkpoint.
    """
    if ledger_mode() == "lan":
        return _dispatch_lan().commit_event(event, signature_b64, public_key_b64)
    _ensure_ledger_dirs()
    canon = canonical_serialize(event)

    last_hashes = [_get_last_hash(nid) for nid in NODE_IDS]
    counter = Counter(last_hashes)
    previous_hash, _ = counter.most_common(1)[0]

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    current_hash = _compute_current_hash(canon, signature_b64, previous_hash)

    successes = 0
    failures: List[Tuple[str, Optional[str]]] = []
    representative: Optional[Dict] = None

    for nid in NODE_IDS:
        try:
            can_participate, reason = _node_can_participate(nid, previous_hash)
            if not can_participate:
                failures.append((nid, reason))
                continue
            node_entries = _load_entries(nid)
            seq = len(node_entries)
            entry = _build_entry(
                nid, seq, event, signature_b64, public_key_b64,
                previous_hash, current_hash, timestamp,
            )
            merkle_root = _merkle_root(
                [e.get("current_hash") for e in node_entries] + [current_hash]
            )
            checkpoint = _build_checkpoint(nid, seq, seq + 1, merkle_root, timestamp)
            _append_jsonl(_ledger_path(nid), entry)
            _append_jsonl(_checkpoints_path(nid), checkpoint)
            successes += 1
            if representative is None:
                representative = entry
        except Exception as e:
            failures.append((nid, str(e)))

    if successes < QUORUM_SIZE:
        raise RuntimeError(
            f"Quorum not reached: only {successes}/4 nodes accepted event. Failures: {failures}"
        )

    return representative if representative is not None else {}


def repair_divergent_nodes() -> Dict:
    """
    Re-synchronize invalid or divergent nodes from the valid majority chain.

    Requires at least QUORUM_SIZE valid nodes whose chains are byte-identical in
    length and last hash; that majority chain is treated as canonical. Each
    repaired node re-signs every canonical entry with its own ML-DSA key and
    rebuilds its signed Merkle checkpoints. Refuses to act without a quorum.
    """
    if ledger_mode() == "lan":
        return _dispatch_lan().repair_divergent_nodes()
    _, details = verify_all_ledgers()
    valid_nodes = [nid for nid in NODE_IDS if details.get(nid, {}).get("valid")]
    before = {nid: bool(details.get(nid, {}).get("valid")) for nid in NODE_IDS}
    result = {
        "repaired": [],
        "before": before,
        "after": {},
        "valid": False,
        "message": "",
    }

    chains = {}
    for nid in valid_nodes:
        entries, parse_error = _read_jsonl_strict(_ledger_path(nid))
        if parse_error:
            continue
        chains[nid] = (len(entries), entries[-1]["current_hash"] if entries else GENESIS_PREV_HASH)

    signatures = Counter(chains.values())
    if not signatures or signatures.most_common(1)[0][1] < QUORUM_SIZE:
        result["message"] = (
            f"Cannot repair: need at least {QUORUM_SIZE} valid nodes with an identical "
            f"chain to establish a canonical history."
        )
        result["after"] = before
        return result

    canonical_meta = signatures.most_common(1)[0][0]
    source = next(nid for nid in valid_nodes if chains.get(nid) == canonical_meta)
    canonical_entries, parse_error = _read_jsonl_strict(_ledger_path(source))
    if parse_error:
        result["message"] = f"Cannot repair: source node {source} {parse_error}"
        result["after"] = before
        return result

    for nid in NODE_IDS:
        if before.get(nid) and chains.get(nid) == canonical_meta:
            continue
        rebuilt_entries = []
        rebuilt_checkpoints = []
        hashes: List[str] = []
        for idx, entry in enumerate(canonical_entries):
            rebuilt = _build_entry(
                nid,
                idx,
                entry["event"],
                entry["signature"],
                entry["public_key_b64"],
                entry["previous_hash"],
                entry["current_hash"],
                entry["timestamp"],
            )
            rebuilt_entries.append(rebuilt)
            hashes.append(entry["current_hash"])
            rebuilt_checkpoints.append(
                _build_checkpoint(nid, idx, idx + 1, _merkle_root(hashes), entry["timestamp"])
            )
        _ledger_path(nid).write_text(
            "".join(json.dumps(e) + "\n" for e in rebuilt_entries), encoding="utf-8"
        )
        _checkpoints_path(nid).write_text(
            "".join(json.dumps(c) + "\n" for c in rebuilt_checkpoints), encoding="utf-8"
        )
        result["repaired"].append(nid)

    valid_after, details_after = verify_all_ledgers()
    result["after"] = {nid: bool(details_after.get(nid, {}).get("valid")) for nid in NODE_IDS}
    result["valid"] = valid_after
    result["message"] = (
        f"Re-synced {len(result['repaired'])} node(s) from {source}."
        if result["repaired"]
        else "No repair was necessary; all nodes already agree with the canonical chain."
    )
    return result


# ---------------------------------------------------------------------------
# read / search helpers
# ---------------------------------------------------------------------------

def get_all_entries() -> List[Dict]:
    """
    Return consolidated ledger entries (node1 as primary).
    For display, we use node1's ledger.
    """
    if ledger_mode() == "lan":
        return _dispatch_lan().get_all_entries()
    return _load_entries("node1")

def get_entries_from_all_nodes() -> Dict[str, List[Dict]]:
    if ledger_mode() == "lan":
        return _dispatch_lan().get_entries_from_all_nodes()
    return {nid: _load_entries(nid) for nid in NODE_IDS}

def find_by_watermark(watermark_id: str) -> Optional[Dict]:
    """
    Search ledger for matching watermark_id.
    Searches node1's ledger first, then the other nodes.
    """
    if ledger_mode() == "lan":
        return _dispatch_lan().find_by_watermark(watermark_id)
    entries = _load_entries("node1")
    for e in entries:
        if e.get("watermark_id") == watermark_id:
            return e
        if e.get("event", {}).get("watermark_id") == watermark_id:
            return e
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
    if ledger_mode() == "lan":
        return _dispatch_lan().find_by_document(document_id)
    entries = _load_entries("node1")
    return [e for e in entries if e.get("document_id") == document_id]

def get_ledger_for_display() -> List[Dict]:
    entries = get_all_entries()
    for i, e in enumerate(entries):
        e["_index"] = i
    return entries

def clear_ledger():
    """Truncate ledger + checkpoints on all nodes. Node keypairs are preserved."""
    _ensure_ledger_dirs()
    for nid in NODE_IDS:
        _ledger_path(nid).write_text("", encoding="utf-8")
        _checkpoints_path(nid).write_text("", encoding="utf-8")

def tamper_entry(node_id: str, index: int, field: str, new_value):
    """
    For testing: modify an entry in a node's ledger file (simulate tampering).
    field can be 'event.recipient_id' or 'signature' etc.
    """
    entries = _load_entries(node_id)
    if index >= len(entries):
        raise IndexError
    if field.startswith("event."):
        key = field.split(".", 1)[1]
        entries[index]["event"][key] = new_value
    else:
        entries[index][field] = new_value
    p = _ledger_path(node_id)
    with open(p, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
