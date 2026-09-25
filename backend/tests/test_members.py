"""
Unit tests for dynamic ledger membership and the majority quorum rule.
"""
import importlib

import pytest

from backend.app.ledger import members


def test_quorum_is_strict_majority():
    assert members.quorum_for(0) == 1
    assert members.quorum_for(1) == 1
    assert members.quorum_for(2) == 2
    assert members.quorum_for(3) == 2
    assert members.quorum_for(4) == 3
    assert members.quorum_for(5) == 3
    assert members.quorum_for(6) == 4


@pytest.fixture
def members_file(tmp_path, monkeypatch):
    path = tmp_path / "members.json"
    monkeypatch.setenv("BOUND_MEMBERS_FILE", str(path))
    return path


def test_add_list_remove(members_file):
    assert members.load_members() == []
    assert members.current_quorum() == 1

    a = members.add_member("nodeA", "http://10.0.0.2:9101", "pkA")
    assert a["id"] == "nodeA"
    assert a["last_seen"]

    members.add_member("nodeB", "http://10.0.0.3:9101", "pkB")
    assert len(members.load_members()) == 2
    assert members.current_quorum() == 2
    assert members.get_member("nodeA")["public_key_b64"] == "pkA"

    assert members.remove_member("nodeA") is True
    assert members.remove_member("nodeA") is False
    assert len(members.load_members()) == 1


def test_public_key_is_pinned(members_file):
    members.add_member("nodeA", "http://10.0.0.2:9101", "pkA")
    # Re-announcing with the same key refreshes last_seen.
    members.add_member("nodeA", "http://10.0.0.2:9101", "pkA")
    # A different key for an existing id must be rejected.
    with pytest.raises(ValueError):
        members.add_member("nodeA", "http://10.0.0.9:9101", "EVIL")
    assert members.get_member("nodeA")["public_key_b64"] == "pkA"


def test_url_is_updated_on_reannounce(members_file):
    members.add_member("nodeA", "http://10.0.0.2:9101", "pkA")
    members.add_member("nodeA", "http://10.0.0.7:9101", "pkA")
    assert members.get_member("nodeA")["url"] == "http://10.0.0.7:9101"
