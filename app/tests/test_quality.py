"""WAN / VPN quality: validation and limits, summarising rounds, calm episodes (two bad rounds), status and learning,
facts vs suspected causes (never the provider without first-hop evidence), DNS packet, health and overview, page and
roles (synthetic results only; no packets are sent)."""
import struct
import time

import pytest

from netmon import quality as Q

NOW = 1_800_000_000.0


def _p(conn, kind="icmp", target="198.51.100.1", role="internet", name=None, **kw):
    pid = Q.add(conn, "site-a", kind, target, name or f"{role} {target}", role, "admin", **kw)
    return dict(conn.execute("SELECT * FROM probes WHERE id=?", (pid,)).fetchone())


def _fill(conn, p, start, n, rtt=10.0, loss=0.0, ok=1, step=None):
    step = step or p["interval_s"]
    for i in range(n):
        Q.store(conn, {"probe_id": p["id"], "ts": start + i * step, "ok": ok, "rtt_ms": rtt if ok else None, "loss": loss if ok else 1.0,
                       "jitter_ms": 0.5 if ok else None, "detail": {}})
    conn.commit()


def test_validation_and_limits(conn):
    for bad in [("ftp", "x"), ("https", "http://example.com"), ("tcp", "host"), ("tcp", "host:70000"), ("dns", "not-an-ip"),
                ("icmp", "a b"), ("icmp", "")]:
        with pytest.raises(ValueError):
            Q.add(conn, "site-a", bad[0], bad[1], "x", "internet", "admin", query="example.com")
    with pytest.raises(ValueError):
        Q.add(conn, "site-a", "dns", "192.0.2.53", "x", "service", "admin", query="")
    with pytest.raises(ValueError):
        Q.add(conn, "site-a", "icmp", "192.0.2.1", "x", "internet", "admin", interval_s=5)
    with pytest.raises(ValueError):
        Q.add(conn, "site-a", "icmp", "192.0.2.1", "x", "internet", "admin", interval_s=30, count=10, timeout_s=5)   # too long per round
    with pytest.raises(ValueError):
        Q.add(conn, "site-a", "icmp", "192.0.2.1", "x", "blame-isp", "admin")
    p = _p(conn, "https", "https://example.com/", "service", count=5, timeout_s=5)
    assert p["count"] == 1                                                                    # one request per HTTPS round
    for i in range(Q.MAX_PROBES - 1):
        _p(conn, target=f"192.0.2.{i + 1}")
    with pytest.raises(ValueError):
        _p(conn, target="192.0.2.250")
    assert conn.execute("SELECT count(*) FROM audit WHERE action='probe_added'").fetchone()[0] == Q.MAX_PROBES


def test_summarize_and_dns_packet():
    r = Q.summarize(1, [10.0, None, 14.0, 12.0, None], {})
    assert r["ok"] == 1 and r["loss"] == 0.4 and r["rtt_ms"] == 12.0 and r["jitter_ms"] == 3.0
    assert Q.summarize(1, [None, None], {})["ok"] == 0
    pkt = Q.dns_query("example.com", 0x1234)
    qid, flags, qd = struct.unpack(">HHH", pkt[:6])
    assert qid == 0x1234 and flags == 0x0100 and qd == 1 and b"\x07example\x03com\x00" in pkt


def test_one_bad_round_is_not_an_episode_two_are(conn):
    p = _p(conn)
    _fill(conn, p, NOW - 6 * 86400, 100, rtt=10)                   # history for the baseline
    t = NOW - 3600
    _fill(conn, p, t, 10, rtt=10)
    _fill(conn, p, t + 600, 1, ok=0)                               # single lost round
    _fill(conn, p, t + 660, 10, rtt=10)
    assert Q.episodes(conn, p, t, NOW, NOW) == []
    _fill(conn, p, t + 1500, 3, rtt=80)                            # slow: > 2x usual and > usual + 30 ms
    eps = Q.episodes(conn, p, t, NOW, NOW)
    assert len(eps) == 1 and eps[0]["rounds"] == 3 and eps[0]["summary"].startswith("slow (80 ms, usually 10 ms)")


def test_status_learning_down_no_data_paused(conn):
    p = _p(conn)
    _fill(conn, p, NOW - 600, 5, rtt=10)
    st = Q.status(conn, p, NOW - 300)
    assert st["state"] == "learning" and "of 60 rounds" in st["text"]
    _fill(conn, p, NOW - 120, 2, ok=0)
    assert Q.status(conn, p, NOW)["state"] == "down"
    assert Q.status(conn, p, NOW + 3600)["state"] == "no data"
    Q.set_enabled(conn, p["id"], False, "admin")
    assert Q.status(conn, dict(p, enabled=0), NOW)["state"] == "paused"


def _ep(p, why="40% loss"):
    return {"probe": p["id"], "start": NOW - 600, "end": NOW - 300, "rounds": 5, "why": [why], "summary": why, "failed": 0, "down": False,
            "worst_loss": 0.4, "worst_rtt": 20, "ongoing": False}


def _mk(role, kind="icmp", name=None, target="192.0.2.9"):
    return {"id": hash((role, kind, name)) % 1000, "role": role, "kind": kind, "name": name or role, "target": target, "interval_s": 60}


def test_explain_keeps_facts_and_suspicions_apart():
    gw, a, b, up = _mk("gateway", name="Firewall"), _mk("internet", name="A"), _mk("internet", name="B"), _mk("upstream", name="Provider hop")
    quiet = {"down_mbps": 50, "up_mbps": 5, "minutes": 10, "down_pct": 10.0, "up_pct": 5.0, "peak_pct": 10.0}
    busy = dict(quiet, down_pct=97.0, peak_pct=97.0)
    # every internet probe affected, firewall fine, no first-hop probe: beyond the firewall, the provider is not named
    x = Q.explain(_ep(a), a, [(gw, False), (b, True)], quiet, [])
    assert x["suspect"] == "beyond the firewall" and "provider" in x["why"] and "first hop" in x["why"]
    assert "provider problem" not in x["suspect"]
    assert any(f.startswith("Also affected: B") for f in x["facts"]) and any("Not affected: Firewall" in f for f in x["facts"])
    # with the provider's first hop affected, firewall fine and link quiet: a possible provider problem, with the evidence
    x = Q.explain(_ep(a), a, [(gw, False), (b, True), (up, True)], quiet, [])
    assert "possibly a provider problem" in x["suspect"] and "not busy" in x["why"]
    # same, but the link was full: busy link, not the provider
    x = Q.explain(_ep(a), a, [(gw, False), (b, True), (up, True)], busy, [])
    assert x["suspect"] == "the WAN link was busy" and "97%" in x["why"]
    # firewall affected too: local side
    assert "the local network or the firewall" in Q.explain(_ep(a), a, [(gw, True), (b, True)], quiet, [])["suspect"]
    # only one destination: that destination
    assert Q.explain(_ep(a), a, [(gw, False), (b, False)], quiet, [])["suspect"] == "that destination or the path to it"
    # DNS only
    d = _mk("service", "dns", "DNS")
    assert Q.explain(_ep(d), d, [(a, False), (b, False)], quiet, [])["suspect"] == "the DNS resolver"
    # VPN with internet fine
    v = _mk("vpn", name="Branch")
    assert Q.explain(_ep(v), v, [(a, False)], quiet, [])["suspect"] == "the VPN tunnel or the remote site"
    # a lone probe: no guess, and how to improve
    x = Q.explain(_ep(a), a, [], None, [])
    assert x["suspect"] is None and "not enough probes" in x["why"] and any("unknown" in f for f in x["facts"])
    # events are facts "at the same time", not causes
    x = Q.explain(_ep(a), a, [(b, True)], quiet, [{"t": NOW - 500, "app": "dpinger", "kind": "gateway", "m": "WAN_GW alarm"}])
    assert any("WAN_GW alarm" in f and "not necessarily the cause" in f for f in x["facts"])


class QCH:
    def __init__(self):
        self.sql = []

    def query(self, sql, params):
        self.sql.append((sql, params))
        if "flows_1m0s" in sql:
            return [{"m": 1, "down": 60 * 1e6 / 8 * 90, "up": 60 * 1e6 / 8 * 5}]   # 90 Mb/s down at the peak minute
        return []


def test_episode_report_and_utilization(cfg, conn):
    site = dict(cfg.sites[0], wan_down_mbps=100, wan_up_mbps=20)
    a, b = _p(conn, target="198.51.100.1", name="A"), _p(conn, target="198.51.100.2", name="B")
    gw = _p(conn, target="10.40.0.1", role="gateway", name="Firewall")
    for p in (a, b, gw):
        _fill(conn, p, NOW - 6 * 86400, 100)
        _fill(conn, p, NOW - 3000, 30, rtt=10)
    for p in (a, b):
        _fill(conn, p, NOW - 1200, 4, rtt=10, loss=0.6)
    ch = QCH()
    rep = Q.episode_report(conn, cfg, ch, dict(site, id="site-a"), NOW - 86400, NOW, NOW)
    assert len(rep) == 2 and rep[0]["suspect"] == "the WAN link was busy" and "90%" in rep[0]["why"]
    assert any("90 Mb/s down" in f for f in rep[0]["facts"])
    assert all("{" in s and "LIMIT" in s for s, _ in ch.sql)                                   # parameterised and bounded


def test_health_and_overview(cfg, conn):
    p = _p(conn, name="A")
    now = time.time()
    _fill(conn, p, now - 130, 2, ok=0)
    hc = Q.health_checks(conn, cfg, now)
    assert hc[0]["state"] == "warn" and "A: no answer" in hc[0]["value"]
    ov = Q.overview(conn, cfg, now)
    assert ov["configured"] == 1 and ov["bad"][0]["state"] == "down"


def test_page_roles_and_actions(monkeypatch):
    from test_web import ADMINPW, VIEWPW, client, sid, web
    from netmon import quality_views
    monkeypatch.setattr(quality_views, "ch", QCH())
    web.conn.execute("DELETE FROM probes")
    web.conn.commit()
    v, ad = client("viewer1", VIEWPW), client("admin", ADMINPW)
    page = v.get("/netmon/quality").text
    assert "Probes are opt-in" in page and "never runs bandwidth tests" in page and "Admins add and change probes" in page
    assert v.post("/netmon/quality/recommended", data={"site": "site-a", "csrf": web.csrf_token(sid(v))}).status_code == 403
    tok = web.csrf_token(sid(ad))
    assert "Add the recommended probes" in ad.get("/netmon/quality").text
    r = ad.post("/netmon/quality/recommended", data={"site": "site-a", "csrf": tok}, follow_redirects=False)
    assert r.status_code == 303 and web.conn.execute("SELECT count(*) FROM probes").fetchone()[0] >= 3
    assert ad.post("/netmon/quality/add", data={"site": "site-a", "kind": "https", "target": "http://x", "csrf": tok}).status_code == 400
    pid = web.conn.execute("SELECT id FROM probes ORDER BY id LIMIT 1").fetchone()[0]
    page = v.get("/netmon/quality").text
    assert "learning" in page or "no data" in page
    assert "None: no probe had two bad rounds" in page
    assert ad.post(f"/netmon/quality/{pid}/toggle", data={"csrf": tok}, follow_redirects=False).status_code == 303
    assert web.conn.execute("SELECT enabled FROM probes WHERE id=?", (pid,)).fetchone()[0] == 0
    assert ad.post(f"/netmon/quality/{pid}/delete", data={"csrf": tok}, follow_redirects=False).status_code == 303
    assert ad.post("/netmon/quality/99999/delete", data={"csrf": tok}).status_code == 404
    assert web.conn.execute("SELECT count(*) FROM audit WHERE action LIKE 'probe_%'").fetchone()[0] >= 4
    j = v.get("/netmon/api/attention").json()
    assert "quality_count" in j
