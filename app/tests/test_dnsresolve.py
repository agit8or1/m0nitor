import socket
import struct
import threading

import pytest

from netmon import dnsresolve as dr


def responder(answers, rcode=0):
    """One-shot UDP DNS responder on loopback: CNAME first (compressed), then the given (type, rdata, ttl) records."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))

    def run():
        q, addr = s.recvfrom(512)
        qid = q[:2]
        qsec = q[12:]
        an = [(5, b"\x03cdn\xc0\x0c", 60)] + answers
        body = qsec
        for t, rdata, ttl in an:
            body += b"\xc0\x0c" + struct.pack(">HHIH", t, 1, ttl, len(rdata)) + rdata
        s.sendto(qid + struct.pack(">HHHHH", 0x8180 | rcode, 1, len(an), 0, 0) + body, addr)
        s.close()
    threading.Thread(target=run, daemon=True).start()
    return s.getsockname()[1]


def test_query_parses_a_and_aaaa_through_cname_and_compression():
    port = responder([(1, socket.inet_aton("203.0.113.7"), 300), (28, socket.inet_pton(socket.AF_INET6, "2001:db8::7"), 120)])
    assert dr.query("www.example.com", "A", "127.0.0.1", port=port) == [("203.0.113.7", 300), ("2001:db8::7", 120)]


def test_query_nxdomain_is_empty_and_bad_names_refused():
    port = responder([], rcode=3)
    assert dr.query("nope.example.com", "A", "127.0.0.1", port=port) == []
    with pytest.raises(ValueError):
        dr.query("a..b", "A", "127.0.0.1", port=port)


def test_settings_validation_and_firewall_note(conn):
    s = dr.save_settings(conn, "site-a", {"resolver": " 10.40.0.1 ", "enabled": True, "fw_mode": "queries", "fw_note": "<b>Log Queries</b>"}, "admin")
    assert s["resolver"] == "10.40.0.1" and s["fw_note"] == "‹b›Log Queries‹/b›" and s["noted_by"] == "admin" and s["noted_at"]
    with pytest.raises(ValueError):
        dr.save_settings(conn, "site-a", {"resolver": "dns.example.com"}, "admin")
    with pytest.raises(ValueError):
        dr.save_settings(conn, "site-a", {"fw_mode": "everything"}, "admin")
    assert dr.resolver_for({"exporter_ip": "10.40.0.1"}, {"resolver": ""}) == ("10.40.0.1", "automatic: the firewall that sends the query log")
    assert dr.resolver_for({"syslog_source": "10.40.0.2", "exporter_ip": "10.40.0.1"}, {"resolver": ""})[0] == "10.40.0.2"
    assert dr.resolver_for({}, {"resolver": "10.40.0.9"}) == ("10.40.0.9", "configured")


class LogCH:
    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def query(self, sql, params):
        self.calls.append(params)
        return self.rows


def test_run_site_resolves_new_names_once_and_advances(conn, monkeypatch):
    rows = [{"query": "www.example.com.", "qtype": "A", "clients": ["::ffff:10.40.0.20"], "t": 1000, "r": 1001},
            {"query": "gone.example.com", "qtype": "A", "clients": ["::ffff:10.40.0.20"], "t": 1000, "r": 1002}]
    seen, inserted = [], []
    monkeypatch.setattr(dr, "query", lambda n, t, server, timeout: seen.append((n, server)) or
                        ([("203.0.113.7", 300)] if n.startswith("www") else []))
    r = dr.NameResolver({}, LogCH(rows), "http://ch")
    r.insert = inserted.extend
    st = r.run_site(conn, {"id": "site-a", "exporter_ip": "10.40.0.1"})
    assert st["names"] == 2 and st["addresses"] == 1 and seen[0] == ("www.example.com.", "10.40.0.1")
    assert inserted == [{"ts": "1970-01-01 00:16:40", "site": "site-a", "query": "www.example.com", "qtype": "A", "addr": "::ffff:203.0.113.7",
                         "ttl": 300, "clients": ["::ffff:10.40.0.20"], "resolver": "10.40.0.1"}]
    assert dr.get_state(conn, "dnsnames:mark:site-a", None)[0] == 1002
    r.run_site(conn, {"id": "site-a", "exporter_ip": "10.40.0.1"})
    assert len(seen) == 2                        # still fresh (TTL): not asked again
    dr.save_settings(conn, "site-a", {"enabled": False}, "t")
    assert r.run_site(conn, {"id": "site-a", "exporter_ip": "10.40.0.1"})["names"] == 0


def test_names_for_prefers_the_hosts_own_lookup():
    ch = LogCH([{"ip": "203.0.113.7", "query": "cdn.example.net", "t": 900, "clients": ["10.40.0.30"]},
                {"ip": "203.0.113.7", "query": "www.example.com", "t": 800, "clients": ["10.40.0.20"]}])
    got = dr.names_for(ch, ["site-a"], {("10.40.0.20", "203.0.113.7"), ("10.40.0.99", "203.0.113.7"), ("10.40.0.20", "198.51.100.1")}, 1000, 2000)
    assert got[("10.40.0.20", "203.0.113.7")]["names"] == ["www.example.com"] and got[("10.40.0.20", "203.0.113.7")]["mine"]
    other = got[("10.40.0.99", "203.0.113.7")]
    assert not other["mine"] and other["names"] == ["cdn.example.net", "www.example.com"] and "several names" in other["basis"]
    assert ("10.40.0.20", "198.51.100.1") not in got
    assert ch.calls[0]["t0"] == 1000 - 86400
    assert dr.names_for(ch, ["site-a"], set(), 0, 1) == {}


def test_query_parses_ptr_names():
    port = responder([(12, b"\x04host\x07example\x03net\x00", 900)])
    assert dr.query("7.113.0.203.in-addr.arpa", "PTR", "127.0.0.1", port=port) == [("host.example.net", 900)]


def test_rdns_wait_returns_name_no_record_or_pending(cfg, monkeypatch):
    import time as _t
    from netmon import rdns
    def fake(name, qtype, server, timeout=2.0):
        if name.startswith("9.64.83.45"):
            return [("scan.example.net.", 300)]
        if name.startswith("10.64.83.45"):
            _t.sleep(1.0)
        return []
    monkeypatch.setattr(rdns, "query", fake)
    r = rdns.RDNS(cfg)
    got = r.wait(["45.83.64.9", "45.83.64.8", "45.83.64.10"], timeout=0.5)
    assert got == {"45.83.64.9": "scan.example.net", "45.83.64.8": "", "45.83.64.10": None}
    assert r.get("45.83.64.9") == "scan.example.net"   # cached


def test_rdns_lookup_failure_is_unknown_not_no_record(cfg, monkeypatch):
    from netmon import rdns
    def boom(*a, **k):
        raise TimeoutError("timed out")
    monkeypatch.setattr(rdns, "query", boom)
    assert rdns.RDNS(cfg).wait(["45.83.64.7"], timeout=1.0) == {"45.83.64.7": None}
