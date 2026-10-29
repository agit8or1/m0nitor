"""Source health alerting, DNS/auth/Zeek parsing (synthetic fixtures only)."""
import time

from netmon import dnsctx, health, logingest, zeek
from netmon.health import Health, check


class FakeCfg:
    sites = [{"id": "s1", "name": "Site 1", "exporter": "fw1"}]

    def get(self, k, d=None):
        return d


def make(conn, states):
    h = Health(FakeCfg(), None, conn, None)
    h.collect = lambda: [check("netflow:s1", "Flows", "NetFlow", states.pop(0), "x")]
    h.started = time.time() - 10_000
    return h


def alerts(conn):
    return [dict(r) for r in conn.execute("SELECT status, severity, title FROM alerts WHERE rule='source_health' ORDER BY id")]


def test_health_hold_down_dedupe_and_recovery(conn):
    h = make(conn, ["fail", "fail", "fail", "ok", "ok"])
    h.run_once()
    assert alerts(conn) == []                       # one failing check is not enough (consecutive = 2)
    h.run_once()
    h.run_once()
    a = alerts(conn)
    assert len(a) == 1 and a[0]["status"] == "open" and a[0]["severity"] == "high"   # de-duplicated
    h.run_once()
    assert alerts(conn)[0]["status"] == "open"      # one good check does not close it
    h.run_once()
    a = alerts(conn)
    assert a[0]["status"] == "closed" and a[0]["title"].endswith("recovered")


def test_health_startup_grace(conn):
    h = make(conn, ["fail"] * 4)
    h.started = time.time()
    for _ in range(4):
        h.run_once()
    assert alerts(conn) == []


def test_health_settings_validation(conn):
    import pytest
    with pytest.raises(ValueError):
        health.save_settings(conn, {"netflow_fail_s": "0"}, "t")
    s = health.save_settings(conn, {"netflow_fail_s": "1200", "notify": "1"}, "t")
    assert s["netflow_fail_s"] == 1200 and s["notify"] is True and health.settings(conn)["enabled"] is False  # unchecked box


def test_prometheus_parser():
    m = health.prom('# HELP x\nakv_lag{group="a"} 12\nakv_lag{group="b"} 3\nother 1e3\n')
    assert health.msum(m, "akv_lag") == 15 and health.msum(m, "akv_lag", group="b") == 3 and health.msum(m, "other") == 1000


def test_unbound_and_auth_parsers():
    line = "1700000000 192.0.2.1 <30>1 2023-11-14T22:13:20+00:00 fw.example.net unbound 123 - [meta sequenceId=\"1\"] [123:0] info: 198.51.100.20 Example.COM. A IN NOERROR 0.000026 0 59\n"
    t, r = logingest.parse_line(line, lambda ip: "s1")
    assert t == "dns_events" and r["query"] == "example.com" and r["qtype"] == "A" and r["rcode"] == "NOERROR" and r["client"].endswith("198.51.100.20")
    t, r = logingest.parse_line(line.replace(" NOERROR 0.000026 0 59", ""), lambda ip: "s1")
    assert t == "dns_events" and r["rcode"] == "" and r["source"] == "unbound-query"
    au = logingest.parse_auth("sshd[42]", "Failed password for invalid user admin from 203.0.113.9 port 50000 ssh2")
    assert au["event"] == "login_failed" and au["user"] == "admin" and au["src"].endswith("203.0.113.9") and au["method"] == "password"
    assert logingest.parse_auth("sshd", "Accepted publickey for deploy from 198.51.100.4 port 1 ssh2")["event"] == "login_ok"
    assert logingest.parse_auth("sudo", "  alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls")["event"] == "sudo"
    assert logingest.parse_auth("cron", "anything") is None


def test_zeek_convert():
    t, r = zeek.convert("dns", {"ts": 1700000000.5, "uid": "C1", "id.orig_h": "198.51.100.20", "id.resp_h": "198.51.100.1",
                                 "query": "Example.org", "qtype_name": "A", "rcode_name": "NOERROR", "answers": ["192.0.2.80"], "TTLs": [300.0]},
                        "s1", "sensor-a", 1700000001)
    assert t == "dns_events" and r["answers"] == ["192.0.2.80"] and r["ttls"] == [300] and r["query"] == "example.org"
    t, r = zeek.convert("conn", {"ts": 1700000000, "id.orig_h": "198.51.100.20", "id.orig_p": 5000, "id.resp_h": "198.51.100.30",
                                  "id.resp_p": 22, "proto": "tcp", "conn_state": "S0", "orig_bytes": 0}, "s1", "sensor-a", 1700000001)
    assert t == "zeek_conn" and r["conn_state"] == "S0" and r["resp_p"] == 22
    t, r = zeek.convert("capture_loss", {"ts": 1700000000, "percent_lost": 0.5, "gaps": 3, "acks": 600}, "s1", "sensor-a", 1)
    assert t == "zeek_stats" and r["percent_lost"] == 0.5


class FakeCH:
    def __init__(self, rows):
        self.rows = rows

    def query(self, sql, p=None):
        return self.rows


def test_dns_correlation_confidence():
    t = 1_700_000_000
    one = [{"client": "198.51.100.20", "query": "app.example.org", "t": t - 30, "ttl": 300}]
    assert dnsctx.correlate(FakeCH(one), ["s1"], "198.51.100.20", "192.0.2.80", t)["confidence"] == "high"
    cdn = one + [{"client": "198.51.100.20", "query": "cdn.example.net", "t": t - 20, "ttl": 300}]
    r = dnsctx.correlate(FakeCH(cdn), ["s1"], "198.51.100.20", "192.0.2.80", t)
    assert r["confidence"] == "medium" and len(r["names"]) == 2
    other = [{"client": "198.51.100.99", "query": "app.example.org", "t": t - 30, "ttl": 300}]
    assert dnsctx.correlate(FakeCH(other), ["s1"], "198.51.100.20", "192.0.2.80", t)["confidence"] == "low"
    expired = [{"client": "198.51.100.20", "query": "app.example.org", "t": t - 4000, "ttl": 300}]
    assert dnsctx.correlate(FakeCH(expired), ["s1"], "198.51.100.20", "192.0.2.80", t)["confidence"] == "low"
    assert dnsctx.correlate(FakeCH([]), ["s1"], "198.51.100.20", "192.0.2.80", t)["confidence"] == "none"


def test_label_score():
    assert dnsctx.label_score("www.example.com")[0] == 3
    L, H = dnsctx.label_score("x9q2kz7f0v1m3n8b4c6d5a2s7e1r0t9y.example.com")
    assert L >= 25 and H > 3.8
