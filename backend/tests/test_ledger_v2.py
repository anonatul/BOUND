"""
Tests for the multi-node tamper-evident ledger (v2).

Proves:
  * every node independently ML-DSA-signs every entry it stores
  * one corrupted node cannot destroy attribution (3/4 quorum survives)
  * an administrator with file access but WITHOUT node private keys cannot
    consistently rewrite all four nodes (the key improvement over v1)
  * checkpoint tampering and legacy unsigned entries are detected
"""
import hashlib
import json

from backend.app.forensic.events import (
    canonical_serialize,
    create_decryption_event,
    sign_event,
)
from backend.app.identity.manager import ensure_demo_recipients
from backend.app.ledger import ledger as ledger_mod
from backend.app.ledger.ledger import (
    GENESIS_PREV_HASH,
    NODE_IDS,
    clear_ledger,
    commit_event,
    get_entries_from_all_nodes,
    tamper_entry,
    verify_all_ledgers,
    verify_entry_quorum,
    verify_ledger_node,
)


def _reset():
    ensure_demo_recipients()
    clear_ledger()


def _commit(document_id, recipient_id, watermark_id, session_id, document_hash="doc-hash-l2"):
    event = create_decryption_event(
        document_id=document_id,
        document_hash=document_hash,
        recipient_id=recipient_id,
        session_id=session_id,
        watermark_id=watermark_id,
        nonce=f"NONCE-{watermark_id}",
    )
    signature_b64, public_key_b64 = sign_event(event, recipient_id)
    return commit_event(event, signature_b64, public_key_b64)


def _admin_recompute_current_hash(entry):
    """Same formula as the ledger, used by the 'malicious admin' simulation."""
    h = hashlib.sha256()
    h.update(canonical_serialize(entry["event"]))
    h.update(entry["signature"].encode())
    h.update(entry["previous_hash"].encode())
    return h.hexdigest()


def test_commit_two_events_all_nodes_valid_with_independent_node_signatures():
    _reset()
    _commit("DOC-L2-1", "ALICE", "WM-L2-ALICE", "SES-L2-1")
    _commit("DOC-L2-2", "BOB", "WM-L2-BOB", "SES-L2-2")

    valid, details = verify_all_ledgers()
    assert valid is True
    assert details["quorum"] == 4
    assert details["quorum_ok"] is True
    assert details["divergent_nodes"] == []

    last_hashes = set()
    for nid in NODE_IDS:
        assert details[nid]["valid"] is True, details[nid]["error"]
        assert details[nid]["count"] == 2
        last_hashes.add(details[nid]["last_hash"])
    assert len(last_hashes) == 1

    entries_by_node = get_entries_from_all_nodes()
    node_signatures = {nid: entries_by_node[nid][0]["node_signature"] for nid in NODE_IDS}
    assert len(set(node_signatures.values())) == len(NODE_IDS)

    for nid in NODE_IDS:
        first = entries_by_node[nid][0]
        assert first["node_id"] == nid
        assert first["seq"] == 0
        assert first["previous_hash"] == GENESIS_PREV_HASH
        assert entries_by_node[nid][1]["seq"] == 1
        # per-node keypairs are persisted next to the ledger
        assert (ledger_mod.LEDGER_ROOT / nid / "node_mldsa_pk.b64").exists()
        assert (ledger_mod.LEDGER_ROOT / nid / "node_mldsa_sk.b64").exists()


def test_one_corrupt_node_attribution_survives_quorum():
    _reset()
    _commit("DOC-L2-3", "ALICE", "WM-L2-SURVIVE", "SES-L2-3")
    tamper_entry("node1", 0, "event.recipient_id", "MALLORY")

    valid, details = verify_all_ledgers()
    assert valid is False
    assert details["node1"]["valid"] is False
    assert "node1" in details["divergent_nodes"]
    assert details["quorum"] == 3
    assert details["quorum_ok"] is True

    quorum = verify_entry_quorum("WM-L2-SURVIVE")
    assert quorum["quorum_ok"] is True
    assert quorum["total_nodes"] == 4
    assert set(quorum["valid_nodes"]) == {"node2", "node3", "node4"}
    assert quorum["entry"] is not None
    assert quorum["error"] is None


def test_admin_without_node_keys_cannot_rewrite_all_nodes():
    _reset()
    _commit("DOC-L2-4", "ALICE", "WM-L2-ADMIN", "SES-L2-4")

    entries_by_node = get_entries_from_all_nodes()
    for nid in NODE_IDS:
        entry = entries_by_node[nid][0]
        entry["event"]["recipient_id"] = "BOB"
        entry["recipient_id"] = "BOB"
        entry["current_hash"] = _admin_recompute_current_hash(entry)
        ledger_path = ledger_mod.LEDGER_ROOT / nid / "ledger.jsonl"
        ledger_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    valid, details = verify_all_ledgers()
    assert valid is False
    for nid in NODE_IDS:
        assert details[nid]["valid"] is False
        assert "node_signature" in details[nid]["error"]

    quorum = verify_entry_quorum("WM-L2-ADMIN")
    assert quorum["quorum_ok"] is False
    assert quorum["entry"] is None
    assert quorum["error"]


def test_commit_refuses_without_quorum_after_multi_node_tamper():
    _reset()
    _commit("DOC-L2-5A", "ALICE", "WM-L2-Q1", "SES-L2-5A")
    tamper_entry("node1", 0, "current_hash", "0" * 64)
    tamper_entry("node2", 0, "current_hash", "0" * 64)

    event = create_decryption_event(
        document_id="DOC-L2-5B",
        document_hash="doc-hash-l2",
        recipient_id="BOB",
        session_id="SES-L2-5B",
        watermark_id="WM-L2-Q2",
        nonce="NONCE-WM-L2-Q2",
    )
    signature_b64, public_key_b64 = sign_event(event, "BOB")
    try:
        commit_event(event, signature_b64, public_key_b64)
        assert False, "commit must fail when fewer than 3 nodes can participate"
    except RuntimeError as e:
        assert "Quorum" in str(e)

    # good nodes must not have been mutated by the failed commit
    assert verify_ledger_node("node3")[2][0]["watermark_id"] == "WM-L2-Q1"
    assert verify_ledger_node("node4")[2][0]["watermark_id"] == "WM-L2-Q1"


def test_checkpoint_tamper_detected():
    _reset()
    _commit("DOC-L2-5", "BOB", "WM-L2-CKPT", "SES-L2-5")

    cp_path = ledger_mod.LEDGER_ROOT / "node2" / "checkpoints.jsonl"
    records = [json.loads(line) for line in cp_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(records) == 1
    assert records[0]["merkle_root"]
    records[0]["merkle_root"] = "0" * 64
    cp_path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    ok, err, _ = verify_ledger_node("node2")
    assert ok is False
    assert "merkle_root" in err
    assert verify_ledger_node("node1")[0] is True

    overall, details = verify_all_ledgers()
    assert overall is False
    assert details["node2"]["valid"] is False
    assert details["quorum"] == 3
    assert details["quorum_ok"] is True


def test_legacy_entry_without_node_signature_is_invalid():
    _reset()
    _commit("DOC-L2-6", "ALICE", "WM-L2-LEGACY", "SES-L2-6")

    ledger_path = ledger_mod.LEDGER_ROOT / "node3" / "ledger.jsonl"
    entry = json.loads(ledger_path.read_text(encoding="utf-8").strip())
    del entry["node_signature"]
    ledger_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    ok, err, _ = verify_ledger_node("node3")
    assert ok is False
    assert "node_signature" in err

    overall, details = verify_all_ledgers()
    assert overall is False
    assert details["node3"]["valid"] is False
    assert details["quorum_ok"] is True


def test_clear_ledger_restores_valid_empty_state_and_keeps_keys():
    _reset()
    _commit("DOC-L2-7", "ALICE", "WM-L2-CLEAR", "SES-L2-7")
    assert verify_all_ledgers()[0] is True

    clear_ledger()

    valid, details = verify_all_ledgers()
    assert valid is True
    for nid in NODE_IDS:
        assert details[nid]["valid"] is True
        assert details[nid]["count"] == 0
        assert details[nid]["last_hash"] == GENESIS_PREV_HASH
        assert (ledger_mod.LEDGER_ROOT / nid / "node_mldsa_pk.b64").exists()
        assert (ledger_mod.LEDGER_ROOT / nid / "node_mldsa_sk.b64").exists()

    quorum = verify_entry_quorum("WM-L2-CLEAR")
    assert quorum["quorum_ok"] is False
    assert quorum["entry"] is None
