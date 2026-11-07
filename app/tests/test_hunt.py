"""Historical threat hunting: indicator parsing and dedupe, bounded retro search, honest results (publication date,
CDN/shared hosting, stale indicators, NAT attribution, coverage), cancellation, roles (synthetic data only)."""
import json
import time

import pytest

from netmon import hunt as H


def test_classify_and_parse():
    assert H.classify("198.51.100.7") == ("ip", "198.51.100.7")
    assert H.classify("hxxps://Bad[.]Example.COM/path?x=1") == ("domain", "bad.example.com")
    assert H.classify("*.evil.example.") == ("domain", "evil.example")
    assert H.classify("203.0.113.0/24") == ("cidr", "203.0.113.0/24")
    assert H.classify("2001:db8::/32") == ("cidr", "2001:db8::/32")
    for bad in ("10.0.0.1", "192.168.1.0/24", "127.0.0.1", "8.0.0.0/8", "not a thing", "# comment", "", "-bad-.com"):
        assert H.classify(bad) is None, bad
    items, rejected = H.parse_text("value,confidence,published,valid_until\n198.51.100.7,high,2026-10-01,2026-12-31\nbad.example.com\n"
                                   "198.51.100.7\n???\n203.0.113.9 note text\n")
    assert [(x["type"], x["value"], x["confidence"]) for x in items] == [("ip", "198.51.100.7", "high"), ("domain", "bad.example.com", "medium"),
                                                                        ("ip", "203.0.113.9", "medium")]
    assert items[0]["published"] and items[0]["valid_until"] and rejected == 1


def test_store_keeps_known_since_and_feed_replace_marks_inactive(conn):
    lid = H.add_list(conn, "feed a", "feed", "vendor", "medium", "admin", url="https://feeds.example/a.txt")
    H.store(conn, lid, H.parse_text("198.51.100.1\n198.51.100.2")[0], now=1000, replace=True)
    H.store(conn, lid, H.parse_text("198.51.100.2\n198.51.100.3")[0], now=2000, replace=True)
    rows = {r["value"]: (r["known_since"], r["active"]) for r in conn.execute("SELECT * FROM indicators")}
    assert rows == {"198.51.100.1": (1000, 0), "198.51.100.2": (1000, 1), "198.51.100.3": (2000, 1)}
    with pytest.raises(ValueError):
        H.add_list(conn, "x", "feed", "", "medium", "admin", url="http://insecure.example/")


def test_load_dedupes_across_lists(conn):
    a = H.add_list(conn, "A", "manual", "src A", "low", "u")
    b = H.add_list(conn, "B", "manual", "src B", "high", "u")
    H.store(conn, a, H.parse_text("198.51.100.9,low,2026-10-05")[0], now=100)
    H.store(conn, b, H.parse_text("198.51.100.9,high,2026-09-01")[0], now=50)
    d = H.load(conn, [a, b], H.parse_text("198.51.100.9")[0])[("ip", "198.51.100.9")]
    assert d["confidence"] == "high" and d["known_since"] == 50 and len(d["lists"]) == 3 and "pasted for this hunt" in d["lists"]
    assert time.strftime("%Y-%m", time.localtime(d["published"])) == "2026-09"


class HuntCH:
    """ClickHouse stand-in: one flow match via replies (device named), one outbound-only through the shared NAT address
    (folded when replies name a device for the same remote), a DNS lookup of a bad domain, a firewall block."""
    def __init__(self, nat, t):
        self.nat, self.t, self.calls = nat, t, []

    def query(self, sql, params):
        self.calls.append(sql)
        t = self.t
        if "FROM flows WHERE" in sql and "GROUP BY e, l6, r6, inb" in sql:
            if params["d0"] > t or params["d1"] < t:
                return []
            return [{"e": "fw-a", "l": "10.40.0.8", "r": "198.51.100.66", "inb": 1, "first": t, "last": t + 600, "n": 40, "b": 5000, "asn": 64500},
                    {"e": "fw-a", "l": self.nat, "r": "198.51.100.66", "inb": 0, "first": t, "last": t + 600, "n": 40, "b": 900, "asn": 64500},
                    {"e": "fw-a", "l": self.nat, "r": "203.0.113.77", "inb": 0, "first": t, "last": t + 60, "n": 3, "b": 300, "asn": 13335}]
        if "netmon.dns_events" in sql and "GROUP BY site, l, q" in sql:
            if params["d0"] > t or params["d1"] < t:
                return []
            return [{"site": "site-a", "l": "10.40.0.9", "q": "cdn.bad.example", "first": t, "last": t, "n": 2, "ans": ["203.0.113.77"]}]
        if "netmon.fw_events" in sql:
            if params["d0"] > t or params["d1"] < t:
                return []
            return [{"site": "site-a", "action": "block", "s": "198.51.100.66", "d": "10.40.0.20", "first": t, "last": t, "n": 5}]
        if "dns_resolved" in sql:
            return [{"a": "203.0.113.77", "n": 25}]
        if "flows_1h0m0s" in sql:
            return [{"e": "fw-a", "a": params["t0"], "b": params["t1"], "h": 30}]
        if "FROM flows WHERE ExporterName IN" in sql:
            return [{"a": params.get("t0", 0)}]
        if "dns_events" in sql:
            return [{"site": "site-a", "a": params["t0"], "b": params["t1"], "h": 48}]
        return []


def _run(cfg, conn, lists_text, adhoc="", published=None):
    lid = H.add_list(conn, "L", "manual", "intel team", "high", "u")
    H.store(conn, lid, H.parse_text(lists_text)[0])
    now = int(time.time())
    t = now - 3600
    rid = H.create_run(conn, "analyst1", {"lists": [lid], "adhoc": H.parse_text(adhoc)[0], "t0": now - 2 * 86400, "t1": now, "sites": ["site-a"]})
    fake = HuntCH(cfg["outbound_nat_ips"][0], t)
    H.Hunt(cfg, fake, conn, rid).run()
    return rid, fake


def test_hunt_results_are_merged_attributed_and_qualified(cfg, conn):
    rid, fake = _run(cfg, conn, "198.51.100.66,high,2099-01-01\n203.0.113.0/24\nbad.example")
    run = conn.execute("SELECT * FROM hunt_runs WHERE id=?", (rid,)).fetchone()
    assert run["status"] == "done", run["error"]
    s = json.loads(run["summary"])
    ms = [dict(m) | {"d": json.loads(m["detail"])} for m in conn.execute("SELECT * FROM hunt_matches WHERE run_id=?", (rid,))]
    flow66 = [m for m in ms if m["ind_value"] == "198.51.100.66" and m["source"] == "flows"]
    assert [m["device"] for m in flow66] == ["10.40.0.8"]                      # NAT row folded into the device named by replies
    assert s["folded_nat"] == 1
    assert flow66[0]["d"]["before_published"] and flow66[0]["d"]["lists"] == ["L (intel team)"]
    cidr = next(m for m in ms if m["ind_type"] == "cidr" and m["source"] == "flows")
    assert cidr["d"]["nat"] and cidr["d"]["cdn"] == "Cloudflare" and cidr["d"]["shared_names"] == 25
    dom = next(m for m in ms if m["ind_type"] == "domain")
    assert dom["device"] == "10.40.0.9" and dom["matched"] == "cdn.bad.example" and dom["d"]["answers"] == ["203.0.113.77"]
    fw = next(m for m in ms if m["source"] == "firewall")
    assert fw["device"] == "10.40.0.20" and "block" in fw["direction"]
    assert {c["source"] for c in s["coverage"]} == {"traffic records", "DNS query log"}
    main = [q for q in fake.calls if any(g in q for g in ("GROUP BY e, l6, r6, inb", "GROUP BY site, l, q", "GROUP BY site, action"))]
    assert len(main) == 3 * 2 and all("LIMIT 20000" in q for q in main)       # 2 daily chunks x 3 sources, each bounded


def test_one_hunt_at_a_time_cancel_and_limits(cfg, conn):
    now = int(time.time())
    rid = H.create_run(conn, "u", {"lists": [], "adhoc": H.parse_text("198.51.100.1")[0], "t0": now - 86400, "t1": now, "sites": ["site-a"]})
    with pytest.raises(ValueError):
        H.create_run(conn, "u", {"lists": [], "adhoc": [], "t0": now - 86400, "t1": now, "sites": ["site-a"]})
    assert H.cancel(conn, rid, "u")
    H.Hunt(cfg, HuntCH(cfg["outbound_nat_ips"][0], now), conn, rid).run()
    assert conn.execute("SELECT status FROM hunt_runs WHERE id=?", (rid,)).fetchone()[0] == "cancelled"
    many = "\n".join(f"198.51.{i // 250}.{i % 250 + 1}" for i in range(H.MAX_IPS + 10))
    rid2 = H.create_run(conn, "u", {"lists": [], "adhoc": H.parse_text(many)[0], "t0": now - 86400, "t1": now, "sites": ["site-a"]})
    H.Hunt(cfg, HuntCH(cfg["outbound_nat_ips"][0], now), conn, rid2).run()
    assert json.loads(conn.execute("SELECT summary FROM hunt_runs WHERE id=?", (rid2,)).fetchone()[0])["limited"] is True


class FeedClient:
    def __init__(self, body, url="https://feeds.example/a.txt"):
        self.body, self.url = body, url

    def stream(self, method, url):
        outer = self

        class R:
            def __enter__(self):
                self.url = outer.url
                return self

            def __exit__(self, *a):
                return False

            def raise_for_status(self):
                pass

            def iter_bytes(self):
                yield outer.body
        return R()


def test_feed_fetch_https_only_and_size_limited(conn):
    lid = H.add_list(conn, "F", "feed", "vendor", "medium", "admin", url="https://feeds.example/a.txt")
    assert H.fetch_feed(conn, lid, FeedClient(b"198.51.100.4\nbad.example\n")).startswith("ok: 2 indicators")
    assert "redirected away from https" in H.fetch_feed(conn, lid, FeedClient(b"x", url="http://feeds.example/a.txt"))
    assert "larger than" in H.fetch_feed(conn, lid, FeedClient(b"1" * (H.MAX_FEED_BYTES + 1)))
    assert conn.execute("SELECT count(*) FROM indicators WHERE list_id=? AND active=1", (lid,)).fetchone()[0] == 2   # failed fetch kept data


def test_pages_roles_and_finding_from_match(monkeypatch):
    from test_incidents import ANALYSTPW
    from test_web import ADMINPW, VIEWPW, client, sid, web
    from netmon import hunt_views
    monkeypatch.setattr(hunt_views.H, "start", lambda *a: None)
    v, an, ad = client("viewer1", VIEWPW), client("analyst1", ANALYSTPW), client("admin", ADMINPW)
    assert "evidence to investigate, not proof" in v.get("/netmon/hunt").text
    assert v.post("/netmon/hunt/run", data={"adhoc": "198.51.100.5", "csrf": web.csrf_token(sid(v))}).status_code == 403
    tok = web.csrf_token(sid(an))
    assert an.post("/netmon/hunt/lists", data={"name": "feed", "url": "https://feeds.example/x", "csrf": tok}).status_code == 403   # feeds: admin
    r = an.post("/netmon/hunt/lists", data={"name": "IR case 12", "source": "partner CERT", "text": "198.51.100.5\nbad.example", "csrf": tok},
                follow_redirects=False)
    assert r.status_code == 303 and "2%20indicators" in r.headers["location"]
    for x in web.conn.execute("SELECT id FROM hunt_runs WHERE status IN ('queued','running','cancelling')"):
        web.conn.execute("UPDATE hunt_runs SET status='cancelled' WHERE id=?", (x[0],))
    web.conn.commit()
    r = an.post("/netmon/hunt/run", data={"adhoc": "198.51.100.5", "period": "24h", "csrf": tok}, follow_redirects=False)
    rid = int(r.headers["location"].rsplit("/", 1)[1])
    assert "is queued" in an.get(f"/netmon/hunt/{rid}").text
    now = time.time()
    web.conn.execute("UPDATE hunt_runs SET status='done', summary=? WHERE id=?",
                     (json.dumps({"indicators": {"ip": 1}, "matched_indicators": 1, "matches": 1, "devices": 1, "coverage": []}), rid))
    mid = web.conn.execute("INSERT INTO hunt_matches(run_id, ind_type, ind_value, matched, source, site, device, first, last, events, bytes, direction, detail) "
                           "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (rid, "ip", "198.51.100.5", "198.51.100.5", "flows", "site-a", "10.40.0.8", now - 99, now,
                                                                  3, 100, "traffic to it", json.dumps({"lists": ["IR case 12"], "confidence": "high",
                                                                                                        "published": now + 9999, "before_published": True}))).lastrowid
    web.conn.commit()
    page = v.get(f"/netmon/hunt/{rid}").text
    assert "before the indicator was published" in page and "Create a finding" not in page
    r = an.post(f"/netmon/hunt/match/{mid}/finding", data={"csrf": tok}, follow_redirects=False)
    a = web.conn.execute("SELECT * FROM alerts WHERE id=?", (int(r.headers["location"].rsplit("/", 1)[1]),)).fetchone()
    assert a["rule"] == "indicator_match" and a["severity"] == "low" and "not notified" in a["notify_status"]   # before publication: low
    assert "Indicator match" in v.get(f"/netmon/alert/{a['id']}").text
    assert ad.post("/netmon/hunt/lists/999/fetch", data={"csrf": web.csrf_token(sid(ad))}).status_code == 400
