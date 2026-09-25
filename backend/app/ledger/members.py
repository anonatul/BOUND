"""
Dynamic ledger membership.

The set of witness devices is whatever real machines have joined the isolated
LAN, not a hardcoded four. Each device runs the node agent and announces itself
to the coordinator (`POST /api/ledger/register`); the coordinator stores it here.

Quorum rule: a **majority of registered members**:

    1 member  -> 1      4 members -> 3
    2 members -> 2      5 members -> 3
    3 members -> 2      6 members -> 4

The threshold is derived from *membership*, not from how many nodes happen to be
online. A coordinator that can knock nodes off the network therefore cannot
lower the bar and forge a record.

Membership is only ever changed by explicit join/remove; a node going offline
just stops answering and is reported unreachable, it is not dropped.
"""
import json
import os
import pathlib
import tempfile
import threading
import time
from typing import Dict, List, Optional

from backend.app.ledger import ledger

_lock = threading.Lock()

MIN_RECOMMENDED_MEMBERS = 2


def members_path() -> pathlib.Path:
    """Resolved on each call so tests and deployments can point it via env."""
    return pathlib.Path(
        os.environ.get(
            "BOUND_MEMBERS_FILE", str(ledger.PROJECT_ROOT / "ledger-members.json")
        )
    )


def quorum_for(member_count: int) -> int:
    """Strict majority: floor(n/2) + 1. Safe under an even split."""
    if member_count <= 0:
        return 1
    return member_count // 2 + 1


def _atomic_write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_members() -> List[Dict]:
    path = members_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    members = data.get("members", data) if isinstance(data, dict) else data
    if not isinstance(members, list):
        return []
    return [m for m in members if isinstance(m, dict) and m.get("id") and m.get("url")]


def save_members(members: List[Dict]) -> None:
    _atomic_write(members_path(), json.dumps({"members": members}, indent=2))


def get_member(node_id: str) -> Optional[Dict]:
    target = (node_id or "").strip()
    for member in load_members():
        if member.get("id") == target:
            return member
    return None


def add_member(
    node_id: str,
    url: str,
    public_key_b64: Optional[str] = None,
    extra: Optional[Dict] = None,
) -> Dict:
    """
    Register or refresh a member. The public key is pinned on first join: a
    later announce with a different key is rejected so an identity cannot be
    silently swapped for a new keypair.
    """
    node_id = (node_id or "").strip()
    url = (url or "").strip().rstrip("/")
    if not node_id or not url:
        raise ValueError("node_id and url are required")

    with _lock:
        members = load_members()
        existing = next((m for m in members if m.get("id") == node_id), None)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if existing is not None:
            if public_key_b64 and existing.get("public_key_b64") and public_key_b64 != existing["public_key_b64"]:
                raise ValueError(
                    f"node {node_id} already registered with a different public key"
                )
            existing["url"] = url
            existing["last_seen"] = now
            if public_key_b64 and not existing.get("public_key_b64"):
                existing["public_key_b64"] = public_key_b64
            if extra:
                existing.update(extra)
            save_members(members)
            return existing

        member = {
            "id": node_id,
            "url": url,
            "public_key_b64": public_key_b64,
            "joined_at": now,
            "last_seen": now,
        }
        if extra:
            member.update(extra)
        members.append(member)
        save_members(members)
        return member


def remove_member(node_id: str) -> bool:
    node_id = (node_id or "").strip()
    with _lock:
        members = load_members()
        remaining = [m for m in members if m.get("id") != node_id]
        if len(remaining) == len(members):
            return False
        save_members(remaining)
        return True


def current_quorum() -> int:
    return quorum_for(len(load_members()))
