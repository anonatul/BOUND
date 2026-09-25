"""
Coordinator-side client for LAN ledger mode.

Reaches the per-device node agents described in `node_agent.py` over the
isolated LAN, using only the Python standard library (no new dependencies, no
cloud, works fully offline). Implements the same public surface as the local
file ledger so `backend.app.ledger.ledger` can dispatch to it transparently.

Membership is dynamic: any device that runs the node agent and announces itself
to the coordinator becomes a member (see `members.py`). The quorum is a
majority of registered members, so the number of witnesses is however many real
devices joined -- not a fixed four.
"""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Dict, List, Optional, Tuple

from backend.app.forensic.events import canonical_serialize
from backend.app.ledger import ledger, members

GENESIS_PREV_HASH = ledger.GENESIS_PREV_HASH


def _timeout() -> float:
    return float(os.environ.get("BOUND_LAN_TIMEOUT", "5"))


def _nodes() -> List[Dict]:
    """Registered member devices, as {id, url, public_key_b64, ...}."""
    return members.load_members()


def _quorum() -> int:
    return members.current_quorum()


def _http(method: str, url: str, payload: Optional[Dict] = None) -> Dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=_timeout()) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _try(method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
    try:
        return _http(method, url, payload)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError):
        return None


def _base(node: Dict) -> str:
    return str(node["url"]).rstrip("/")


def sync_member(url: str, entries: List[Dict]) -> Optional[Dict]:
    """Push a canonical chain to a member so it re-signs and adopts it locally."""
    if not entries:
        return None
    return _try("POST", str(url).rstrip("/") + "/node/sync", {"entries": entries})


def member_info(url: str) -> Optional[Dict]:
    return _try("GET", str(url).rstrip("/") + "/node/info")


def maybe_sync(url: str, entries: List[Dict]) -> Optional[Dict]:
    """
    Seed a member that is behind the canonical chain. Skips the transfer when
    the member already reports at least as many entries (heartbeat case).
    """
    if not entries:
        return None
    info = member_info(url)
    if info and int(info.get("count", 0)) >= len(entries):
        return {"synced": False, "reason": "already up to date"}
    return sync_member(url, entries)


def canonical_entries() -> List[Dict]:
    """
    Longest non-empty chain reachable from the current members. Used to seed a
    newly joined device so it starts from the existing history.
    """
    best: List[Dict] = []
    for node in _nodes():
        result = _try("GET", _base(node) + "/node/entries")
        if result:
            entries = result.get("entries", [])
            if len(entries) > len(best):
                best = entries
    return best


def node_infos() -> List[Dict]:
    infos = []
    for node in _nodes():
        info = _try("GET", _base(node) + "/node/info")
        if info:
            infos.append({**info, "configured_id": node.get("id"), "url": node.get("url")})
    return infos


# ---------------------------------------------------------------------------
# public surface (mirrors ledger.py)
# ---------------------------------------------------------------------------

def commit_event(event: Dict, signature_b64: str, public_key_b64: str) -> Dict:
    """Propose one entry to every node; require a quorum to accept it."""
    infos = node_infos()
    if len(infos) < _quorum():
        raise RuntimeError(
            f"Quorum not reachable: only {len(infos)}/{len(_nodes())} nodes responded "
            f"(need {_quorum()})"
        )

    heads = Counter((info["count"], info["last_hash"]) for info in infos)
    (seq, previous_hash), _ = heads.most_common(1)[0]

    canon = canonical_serialize(event)
    current_hash = ledger._compute_current_hash(canon, signature_b64, previous_hash)
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    payload = {
        "seq": seq,
        "event": event,
        "signature": signature_b64,
        "public_key_b64": public_key_b64,
        "previous_hash": previous_hash,
        "current_hash": current_hash,
        "timestamp": timestamp,
    }

    successes: List[Dict] = []
    failures: List[Tuple[str, str]] = []
    for node in _nodes():
        nid = node.get("id", node.get("url"))
        result = _try("POST", _base(node) + "/node/append", payload)
        if result and result.get("current_hash") == current_hash:
            successes.append(result)
        else:
            failures.append((nid, "unreachable or rejected"))

    if len(successes) < _quorum():
        raise RuntimeError(
            f"Quorum not reached: only {len(successes)}/{len(_nodes())} nodes accepted "
            f"the entry. Failures: {failures}"
        )
    return successes[0]


def verify_all_ledgers() -> Tuple[bool, Dict]:
    results: Dict = {}
    valid_nodes: List[str] = []
    meta: Dict[str, Tuple[int, str]] = {}

    for node in _nodes():
        nid = node["id"]
        result = _try("POST", _base(node) + "/node/verify", {})
        if result:
            results[nid] = {
                "valid": bool(result.get("valid")),
                "error": result.get("error"),
                "count": result.get("count", 0),
                "last_hash": result.get("last_hash", GENESIS_PREV_HASH),
                "merkle_root": result.get("merkle_root", GENESIS_PREV_HASH),
                "checkpoint_count": result.get("count", 0),
            }
            meta[nid] = (result.get("count", 0), result.get("last_hash", GENESIS_PREV_HASH))
            if result.get("valid"):
                valid_nodes.append(nid)
        else:
            results[nid] = {
                "valid": False,
                "error": "unreachable",
                "count": 0,
                "last_hash": GENESIS_PREV_HASH,
                "merkle_root": GENESIS_PREV_HASH,
                "checkpoint_count": 0,
            }

    majority_last_hash = GENESIS_PREV_HASH
    if valid_nodes:
        majority_last_hash = Counter(meta[nid][1] for nid in valid_nodes).most_common(1)[0][0]

    merkle_root = GENESIS_PREV_HASH
    for nid in valid_nodes:
        if meta[nid][1] == majority_last_hash:
            merkle_root = results[nid]["merkle_root"]
            break

    lengths = {meta[nid][0] for nid in valid_nodes}
    last_hashes = {meta[nid][1] for nid in valid_nodes}
    overall_valid = (
        len(valid_nodes) == len(_nodes())
        and len(lengths) == 1
        and len(last_hashes) == 1
    )

    results["quorum"] = len(valid_nodes)
    results["quorum_ok"] = len(valid_nodes) >= _quorum()
    results["merkle_root"] = merkle_root
    results["majority_last_hash"] = majority_last_hash
    results["divergent_nodes"] = [
        nid
        for nid in results
        if nid not in ("quorum", "quorum_ok", "merkle_root", "majority_last_hash", "divergent_nodes")
        and (
            not results[nid]["valid"]
            or meta.get(nid, (0, GENESIS_PREV_HASH))[1] != majority_last_hash
        )
    ]
    return overall_valid, results


def verify_entry_quorum(watermark_id: str) -> Dict:
    result = {
        "quorum_ok": False,
        "valid_nodes": [],
        "total_nodes": len(_nodes()),
        "entry": None,
        "error": None,
    }

    groups: Dict[str, List[Tuple[str, Dict]]] = {}
    for node in _nodes():
        query = urllib.parse.urlencode({"watermark_id": watermark_id})
        found = _try("GET", _base(node) + "/node/find?" + query)
        if found and found.get("found"):
            entry = found["entry"]
            if found.get("valid_prefix"):
                groups.setdefault(entry.get("current_hash"), []).append((node["id"], entry))

    best: Optional[List[Tuple[str, Dict]]] = None
    for _current_hash, members in groups.items():
        if len(members) >= _quorum() and (best is None or len(members) > len(best)):
            best = members

    if best is None:
        result["error"] = (
            f"no current_hash for watermark {watermark_id} is validly signed and "
            f"replicated on >= {_quorum()} nodes"
        )
        return result

    result["quorum_ok"] = True
    result["valid_nodes"] = [nid for nid, _ in best]
    entry = None
    for nid, candidate in best:
        if nid == "node1":
            entry = candidate
            break
    result["entry"] = entry or best[0][1]
    return result


def find_by_watermark(watermark_id: str) -> Optional[Dict]:
    query = urllib.parse.urlencode({"watermark_id": watermark_id})
    for node in _nodes():
        found = _try("GET", _base(node) + "/node/find?" + query)
        if found and found.get("found"):
            return found["entry"]
    return None


def find_by_document(document_id: str) -> List[Dict]:
    matches: List[Dict] = []
    for entry in get_all_entries():
        if entry.get("document_id") == document_id or entry.get("event", {}).get("document_id") == document_id:
            matches.append(entry)
    return matches


def get_all_entries() -> List[Dict]:
    for node in _nodes():
        result = _try("GET", _base(node) + "/node/entries")
        if result is not None:
            return result.get("entries", [])
    return []


def get_entries_from_all_nodes() -> Dict[str, List[Dict]]:
    out: Dict[str, List[Dict]] = {}
    for node in _nodes():
        result = _try("GET", _base(node) + "/node/entries")
        out[node["id"]] = result.get("entries", []) if result else []
    return out


def repair_divergent_nodes() -> Dict:
    """Re-sync out-of-date nodes from the canonical majority, peer to peer."""
    _, details = verify_all_ledgers()
    before = {
        nid: bool(details.get(nid, {}).get("valid"))
        for nid in details
        if nid not in ("quorum", "quorum_ok", "merkle_root", "majority_last_hash", "divergent_nodes")
    }
    result = {"repaired": [], "before": before, "after": {}, "valid": False, "message": ""}

    metas = {
        nid: (details[nid]["count"], details[nid]["last_hash"])
        for nid in before
        if details[nid]["valid"]
    }
    if not metas:
        result["message"] = "Cannot repair: no valid nodes reachable."
        result["after"] = before
        return result

    canonical_meta, count = Counter(metas.values()).most_common(1)[0]
    if count < _quorum():
        result["message"] = (
            f"Cannot repair: need at least {_quorum()} valid nodes with an identical "
            f"chain to establish a canonical history."
        )
        result["after"] = before
        return result

    source_id = next(nid for nid, meta in metas.items() if meta == canonical_meta)
    source_node = next(n for n in _nodes() if n["id"] == source_id)
    fetched = _try("GET", _base(source_node) + "/node/entries")
    if not fetched:
        result["message"] = f"Cannot repair: source node {source_id} is not answering."
        result["after"] = before
        return result
    canonical_entries = fetched.get("entries", [])

    for node in _nodes():
        nid = node["id"]
        if metas.get(nid) == canonical_meta:
            continue
        synced = _try("POST", _base(node) + "/node/sync", {"entries": canonical_entries})
        if synced and synced.get("synced"):
            result["repaired"].append(nid)

    valid_after, details_after = verify_all_ledgers()
    result["after"] = {
        nid: bool(details_after.get(nid, {}).get("valid"))
        for nid in details_after
        if nid not in ("quorum", "quorum_ok", "merkle_root", "majority_last_hash", "divergent_nodes")
    }
    result["valid"] = valid_after
    result["message"] = (
        f"Re-synced {len(result['repaired'])} node(s) from {source_id}."
        if result["repaired"]
        else "No repair was necessary; all reachable nodes already agree."
    )
    return result
