import time

from netmon.detect import Detector, beacon_stats, exception_matches, robust_upper


def test_beacon_stats_regular_vs_random():
    mean, cv = beacon_stats([i * 300 for i in range(12)])
    assert mean == 300 and cv == 0
    mean, cv = beacon_stats([0, 10, 400, 405, 2000, 2100, 5000, 5020])
    assert cv > 0.5
    assert beacon_stats([1]) == (None, None)


def test_robust_upper_ignores_single_spike():
    vals = [100, 110, 90, 105, 95, 100, 10_000]
    assert robust_upper(vals) < 200


def test_exception_matching():
    now = time.time()
    base = dict(enabled=1, expires_at=None, rule="new_dest_country", asset="10.40.0.8", subject="US")
    assert exception_matches(base, "new_dest_country", "10.40.0.8", "US", now)
    assert not exception_matches(base, "new_dest_country", "10.40.0.9", "US", now)
    assert exception_matches({**base, "asset": "*", "subject": "*"}, "new_dest_country", "x", "y", now)
    assert exception_matches({**base, "rule": "*", "subject": "203.0.113.0/24"}, "beaconing", "10.40.0.8", "203.0.113.5", now)
    assert not exception_matches({**base, "expires_at": now - 1}, "new_dest_country", "10.40.0.8", "US", now)


def finding(**kw):
    f = dict(rule="unexpected_inbound", severity="high", confidence="medium", asset="10.40.0.8",
             subject="tcp/22", title="t", window=(0, 1), evidence=[{"x": 1}], query=("SELECT 1", {}),
             baseline="b", alternatives=[], next_steps=[], akvorado_filter="")
    f.update(kw)
    return f


def test_dedup_cooldown_and_exception(cfg, conn):
    d = Detector(cfg, None, conn)
    now = time.time()
    assert d.record(finding(), now) == 1
    assert d.record(finding(), now + 60) == 0          # merged into open alert
    row = conn.execute("SELECT count, status FROM alerts").fetchone()
    assert row["count"] == 2
    conn.execute("UPDATE alerts SET status='closed'")
    assert d.record(finding(), now + 120) == 1          # closed alert -> new one
    conn.execute("INSERT INTO exceptions(rule,asset,subject,owner,reason,created_by,created_at) "
                 "VALUES ('*','10.40.0.8','*','ops','scanner','t',?)", (now,))
    assert d.record(finding(subject="tcp/23"), now + 180) == 0
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 2


class FakeCH:
    """Answers the firewall-state and IDS lookups used by verify_direction."""
    def __init__(self, states=None, ids=None):
        self.states, self.ids = states or {}, ids or []

    def query(self, sql, params):
        if "min(ts)" in sql:
            return [{"t": 1}]
        if "ids_events" in sql:
            return self.ids
        return [{"iface": k, "n": v, "dsts": v} for k, v in self.states.items() if v]


def test_direction_ids_uses_flow_initiator(cfg, conn):
    # reply packet matched (outside -> ours) but our address opened the connection
    d = Detector(cfg, FakeCH(), conn)
    f = finding(rule="ids_alert", asset="203.0.113.179", subject="2100498|198.51.100.37",
                evidence=[{"s": "198.51.100.37", "d": "203.0.113.179", "initiator": "203.0.113.179", "responder": "198.51.100.37"}])
    r = d.verify_direction(f)
    assert r["direction"] == "outbound" and r["direction_verified"] == 1 and "reply" in r["direction_basis"]


def test_direction_from_firewall_states(cfg, conn):
    wan, lan = cfg["wan_if"], cfg["lan_if"]
    bea = finding(rule="beaconing", asset="10.40.0.121", subject="192.0.2.78:443",
                  evidence=[{"local": "10.40.0.121", "peer": "192.0.2.78", "peer_port": 443}], window=(100, 200))
    assert Detector(cfg, FakeCH({wan: 3}), conn).verify_direction(bea)["direction"] == "outbound"
    r = Detector(cfg, FakeCH({lan: 2}), conn).verify_direction(bea)
    assert r["direction"] == "inbound" and r["direction_verified"]
    r = Detector(cfg, FakeCH(), conn).verify_direction(bea)
    assert r["direction"] == "outbound" and not r["direction_verified"]   # port heuristic only
    scan = finding(rule="fw_blocked_scan", asset="", subject="1.2.3.4", evidence=[{"s": "1.2.3.4"}])
    assert Detector(cfg, FakeCH(), conn).verify_direction(scan)["direction"] == "inbound"
