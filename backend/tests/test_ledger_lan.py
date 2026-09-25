"""
Integration test for LAN ledger mode.

Spawns four real node-agent processes on localhost (one per "device"), points
the coordinator at them through a generated nodes.json, and exercises commit,
full-chain verification, per-entry quorum, divergence detection and repair.

On real hardware these four processes simply live on four devices behind the
isolated router; locally they prove the protocol end to end.
"""
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
NODE_IDS = ["node1", "node2", "node3", "node4"]
PORTS = [19101, 19102, 19103, 19104]


def _wait_health(port: int, timeout: float = 40.0) -> bool:
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if json.loads(resp.read())["status"] == "ok":
                    return True
        except Exception:
            time.sleep(0.25)
    return False


@pytest.fixture(scope="module")
def lan_cluster(tmp_path_factory):
    root = tmp_path_factory.mktemp("lan")
    env_base = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT)}
    procs = []
    logs = []
    for nid, port in zip(NODE_IDS, PORTS):
        (root / nid).mkdir(parents=True, exist_ok=True)
        env = {
            **env_base,
            "BOUND_NODE_ID": nid,
            "BOUND_LEDGER_ROOT": str(root),
        }
        log = open(root / f"{nid}.log", "w")
        logs.append(log)
        procs.append(
            subprocess.Popen(
                [
                    sys.executable, "-m", "uvicorn",
                    "backend.app.ledger.node_agent:app",
                    "--host", "127.0.0.1", "--port", str(port),
                    "--log-level", "warning",
                ],
                cwd=str(PROJECT_ROOT),
                env=env,
                stdout=log,
                stderr=log,
            )
        )

    if not all(_wait_health(port) for port in PORTS):
        for p in procs:
            p.terminate()
        for log in logs:
            log.flush()
        detail = "\n".join(
            f"--- {nid}.log ---\n{(root / f'{nid}.log').read_text()[-800:]}"
            for nid in NODE_IDS
        )
        pytest.skip(f"could not start node agents on localhost\n{detail}")

    config = {
        "quorum": 3,
        "timeout": 5,
        "nodes": [
            {"id": nid, "url": f"http://127.0.0.1:{port}"}
            for nid, port in zip(NODE_IDS, PORTS)
        ],
    }
    config_path = root / "nodes.json"
    config_path.write_text(json.dumps(config))

    yield {"root": root, "config": config_path}

    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()
    for log in logs:
        try:
            log.close()
        except Exception:
            pass


@pytest.fixture
def lan_mode(lan_cluster, monkeypatch):
    monkeypatch.setenv("BOUND_LEDGER_MODE", "lan")
    monkeypatch.setenv("BOUND_NODES_CONFIG", str(lan_cluster["config"]))
    from backend.app.ledger import lan
    lan.CONFIG_PATH = lan_cluster["config"]
    return lan_cluster


def _make_signed_event(recipient: str, doc_hash: str):
    from backend.app.identity.manager import create_recipient
    from backend.app.forensic.events import (
        create_decryption_event,
        generate_session_and_nonce,
        sign_event,
    )
    from backend.app.watermark.dct_watermark import generate_watermark_id

    create_recipient(recipient)
    session_id, nonce = generate_session_and_nonce()
    watermark_id = generate_watermark_id(doc_hash, recipient, session_id, nonce)
    event = create_decryption_event(
        "DOC-LAN", doc_hash, recipient, session_id, watermark_id, nonce
    )
    signature_b64, public_key_b64 = sign_event(event, recipient)
    return event, signature_b64, public_key_b64, watermark_id, session_id


def test_lan_commit_verify_and_quorum(lan_mode):
    from backend.app.ledger import ledger

    doc_hash = "a" * 64
    event, sig, pk, watermark_id, session_id = _make_signed_event("LANALICE", doc_hash)

    entry = ledger.commit_event(event, sig, pk)
    assert entry["current_hash"]
    assert entry["node_signature"]

    valid, details = ledger.verify_all_ledgers()
    assert valid is True
    assert details["quorum"] == 4
    assert details["quorum_ok"] is True
    assert details["merkle_root"] != ledger.GENESIS_PREV_HASH

    quorum = ledger.verify_entry_quorum(watermark_id)
    assert quorum["quorum_ok"] is True
    assert len(quorum["valid_nodes"]) == 4
    assert quorum["entry"]["event"]["recipient_id"] == "LANALICE"
    assert quorum["entry"]["event"]["session_id"] == session_id

    found = ledger.find_by_watermark(watermark_id)
    assert found and found["event"]["recipient_id"] == "LANALICE"

    entries = ledger.get_all_entries()
    assert any(e.get("watermark_id") == watermark_id for e in entries)


def test_lan_divergence_detected_and_repaired(lan_mode):
    from backend.app.ledger import ledger

    doc_hash = "b" * 64
    event, sig, pk, watermark_id, _ = _make_signed_event("LANBOB", doc_hash)
    ledger.commit_event(event, sig, pk)

    assert ledger.verify_all_ledgers()[0] is True

    # Simulate an admin editing node3's copy of the event on its device.
    node3_ledger = lan_mode["root"] / "node3" / "ledger.jsonl"
    lines = node3_ledger.read_text().splitlines()
    record = json.loads(lines[0])
    record["event"]["recipient_id"] = "EVIL"
    lines[0] = json.dumps(record)
    node3_ledger.write_text("\n".join(lines) + "\n")

    valid, details = ledger.verify_all_ledgers()
    assert valid is False
    assert details["node3"]["valid"] is False
    assert details["quorum_ok"] is True  # remaining 3 nodes still form a quorum

    # Attribution still resolves through the honest quorum.
    quorum = ledger.verify_entry_quorum(watermark_id)
    assert quorum["quorum_ok"] is True
    assert "node3" not in quorum["valid_nodes"]

    repair = ledger.repair_divergent_nodes()
    assert "node3" in repair["repaired"]
    assert repair["valid"] is True
    assert ledger.verify_all_ledgers()[0] is True


def test_lan_single_node_missing_still_reaches_quorum(lan_mode):
    from backend.app.ledger import ledger

    doc_hash = "c" * 64
    event, sig, pk, watermark_id, _ = _make_signed_event("LANCAROL", doc_hash)

    entry = ledger.commit_event(event, sig, pk)
    assert entry["current_hash"]

    # Simulate node4 going offline / losing its copy; 3/4 must still attribute.
    (lan_mode["root"] / "node4" / "ledger.jsonl").write_text("")

    quorum = ledger.verify_entry_quorum(watermark_id)
    assert quorum["quorum_ok"] is True
    assert len(quorum["valid_nodes"]) >= 3
    assert "node4" not in quorum["valid_nodes"]
