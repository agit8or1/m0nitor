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


def test_map_pairs_name_firewall_wan_aliases_nat_and_rdns(cfg, monkeypatch):
    from netmon.dash import Dash
    monkeypatch.setitem(cfg.raw, "fw_addrs", {"198.51.100.230": {"iface": "WAN", "descr": "app.example.com", "site": "site-a"}})
    monkeypatch.setitem(cfg.raw, "binat", [{"external": "198.51.100.230", "internal": "10.40.0.8", "site": "site-a"}])
    assert cfg.fw_label("203.0.113.179") == "WAN"            # the site's own WAN (outbound NAT) address
    assert cfg.fw_label("198.51.100.230") == "WAN alias app.example.com"
    assert cfg.fw_label("192.0.2.9") == ""
    d = Dash(cfg, None)
    d.rdns = type("R", (), {"get": staticmethod(lambda ip: {"45.83.64.9": "scan.example.net"}.get(ip, ""))})()
    p = d.pair("45.83.64.9", "203.0.113.179", 10, 1, "in")
    assert (p["src_rdns"], p["dst_fw"], p["dst"]) == ("scan.example.net", "WAN", "203.0.113.179")
    p = d.pair("45.83.64.9", "10.40.0.8", 10, 1, "in")         # LAN host with a 1:1 NAT: shown as the WAN alias it came in on
    assert (p["dst"], p["dst_fw"], p["dst_name"]) == ("198.51.100.230", "WAN alias app.example.com", "")
    p = d.pair("10.40.0.161", "45.83.64.9", 10, 1, "out")      # no 1:1 NAT: the site's WAN (outbound NAT) address
    assert (p["src"], p["src_fw"], p["dst_rdns"]) == ("203.0.113.179", "WAN", "scan.example.net")
