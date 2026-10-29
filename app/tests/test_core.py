"""Synthetic fixtures only; no production data."""
import sqlite3

import pytest

from netmon.core import audit


def test_exposure_and_attribution(cfg):
    assert cfg.exposed("10.40.0.240", "tcp", 25)
    assert cfg.exposed("10.40.0.210", "tcp", 8200)          # range 8100-8443
    assert not cfg.exposed("10.40.0.240", "tcp", 22)
    ip, conf, _ = cfg.attribute_public("203.0.113.178", 8006, "tcp")
    assert (ip, conf) == ("10.40.0.254", "high")
    ip, conf, why = cfg.attribute_public("203.0.113.179", 51234, "tcp")
    assert ip is None and conf == "none" and "shared outbound NAT" in why
    # 198.51.100.231 forwards different ports to three hosts: only port-specific mapping is unique
    assert cfg.attribute_public("198.51.100.231", 8007, "tcp")[0] == "10.40.0.8"
    assert cfg.attribute_public("198.51.100.231", 9999, "tcp")[0] is None


def test_audit_append_only(conn):
    audit(conn, "u", "x", {"a": 1})
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE audit SET user='evil'")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM audit")
