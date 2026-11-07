"""Plain-English search: deterministic interpretation, validation and bounds, fixed templates with typed parameters
(user text never reaches SQL), findings search, shared-NAT honesty, AI output mapping and preview, saved searches,
reviewed detections, and the page with roles (synthetic data only; no AI calls)."""
import json
import time

import pytest

from netmon import nlsearch as N

NOW = 1_800_000_000


def P(cfg, q):
    return N.parse(q, cfg, now=NOW)


def test_parse_examples(cfg):
    s, notes = P(cfg, "Which devices talked to Russia in the last 7 days?")
    assert s == {"range": "7d", "country": "RU", "group": "device"} and not notes
    s, _ = P(cfg, "Connections to port 3389 from the internet yesterday")
    assert s["port"] == 3389 and s["direction"] == "incoming" and s["to"] - s["from"] == 86400
    s, _ = P(cfg, "Which devices looked up example.com this week?")
    assert s["source"] == "dns" and s["domain"] == "example.com" and s["group"] == "device"
    s, _ = P(cfg, "Blocked connections to 10.40.0.8 in the last 24 hours")
    assert s["source"] == "firewall" and s["action"] == "block" and s["device"] == "10.40.0.8"
    s, _ = P(cfg, "High severity findings in the last 30 days")
    assert s["source"] == "findings" and s["severity"] == "high" and s["range"] == "30d"
    s, _ = P(cfg, "Devices that uploaded more than 1.5 GB yesterday")
    assert s["measure"] == "sent" and s["min_bytes"] == 1_500_000_000 and s["group"] == "device"
    s, _ = P(cfg, "Internal SSH connections today")
    assert s["direction"] == "internal" and s["port"] == 22 and s["proto"] == "tcp"
    s, _ = P(cfg, "what did mail-1 connect to owned by google last 6 hours")
    assert s["device"] == "10.40.0.240" and s["org"] == "google" and s["range"] == "6h"     # device by name
    s, notes = P(cfg, "show me sparkly unicorns")
    assert s == {} and "sparkly" in notes[0]                                               # unknown words reported, not guessed
    s, _ = P(cfg, "traffic from 198.51.100.7 to 10.40.0.8 on AS64500")
    assert s["remote"] == "198.51.100.7" and s["device"] == "10.40.0.8" and s["asn"] == 64500
    for q in N.EXAMPLES:
        N.validate(P(cfg, q)[0], cfg, NOW)                                                  # every example is a valid search


def test_validation_bounds_and_drops(cfg):
    with pytest.raises(N.SpecError):
        N.validate({"source": "sql"}, cfg, NOW)
    with pytest.raises(N.SpecError):
        N.validate({"device": "8.8.8.8"}, cfg, NOW)                                         # device must be internal
    with pytest.raises(N.SpecError):
        N.validate({"from": NOW - 40 * 86400, "to": NOW}, cfg, NOW)                         # beyond retention
    with pytest.raises(N.SpecError):
        N.validate({"source": "firewall", "range": "30d"}, cfg, NOW)                        # firewall log kept 14 days
    with pytest.raises(N.SpecError):
        N.validate({"country": "ZZ"}, cfg, NOW)
    with pytest.raises(N.SpecError):
        N.validate({"sites": ["nope"]}, cfg, NOW)
    with pytest.raises(N.SpecError):
        N.validate({"source": "dns", "group": "country"}, cfg, NOW)
    with pytest.raises(N.SpecError):
        N.validate({"domain": "a'; DROP TABLE x"}, cfg, NOW)
    v = N.validate({"source": "dns", "port": 22, "domain": "Example.COM.", "limit": 99999, "evil": "x"}, cfg, NOW)
    assert v["limit"] == N.MAX_LIMIT and v["domain"] == "example.com" and "port" not in v and v["_dropped"] == ["port"] and "evil" not in v
    assert "DNS lookups" in N.describe(v, cfg)


class SCH:
    def __init__(self, rows=None):
        self.rows, self.sql = rows or [], []

    def query(self, sql, params):
        self.sql.append((sql, params))
        return self.rows


def test_templates_use_typed_parameters_only(cfg, conn):
    from test_web import EVIL
    ch = SCH()
    spec = N.validate({"org": EVIL[:60], "remote": "198.51.100.0/24", "device": "10.40.0.8", "port": 443, "country": "DE", "min_bytes": 5,
                       "group": "remote"}, cfg, NOW)
    N.run(conn, cfg, ch, spec, NOW)
    sql, p = ch.sql[0]
    assert "<script>" not in sql and "198.51.100" not in sql and "10.40.0.8" not in sql and "'DE'" not in sql
    assert p["org"] == EVIL[:60] and p["lim"] == 50 and p["t1"] - p["t0"] == 86400 and "LIMIT {lim:UInt32}" in sql
    assert "FROM flows" in sql and "HAVING bytes >= {minb:UInt64}" in sql
    for src in ("dns", "firewall"):
        ch = SCH()
        N.run(conn, cfg, ch, N.validate({"source": src, "domain": "example.com", "device": "10.40.0.0/28"}, cfg, NOW), NOW)
        sql, p = ch.sql[0]
        assert "LIMIT {lim:UInt32}" in sql and "example.com" not in sql and "10.40.0" not in sql
    ch = SCH()
    N.run(conn, cfg, ch, N.validate({"direction": "internal", "port": 22}, cfg, NOW), NOW)
    assert "NOT has({wans:Array(String)}, OutIfName)" in ch.sql[0][0]


def test_sent_volume_is_honest_about_shared_nat(cfg, conn):
    with pytest.raises(N.SpecError, match="shares its public address"):
        N.run(conn, cfg, SCH(), N.validate({"device": "10.40.0.8", "measure": "sent"}, cfg, NOW), NOW)
    cfg.raw.setdefault("binat", []).append({"internal": "10.40.0.8", "external": "198.51.100.230"})
    ch = SCH()
    N.run(conn, cfg, ch, N.validate({"device": "10.40.0.8", "measure": "sent"}, cfg, NOW), NOW)
    assert ch.sql[0][1]["dext"] == ["::ffff:198.51.100.230"]


def test_findings_search(cfg, conn):
    now = time.time()
    for i, (rule, sev, asset) in enumerate([("fanout", "high", "10.40.0.8"), ("fanout", "low", "10.40.0.8"), ("beaconing", "critical", "10.40.0.9"),
                                            ("dns_bypass", "medium", "10.0.0.5")]):
        conn.execute("INSERT INTO alerts(key, rule, severity, confidence, asset, subject, title, first_seen, last_seen, site) VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (f"site-a|{rule}|{asset}|{i}", rule, sev, "high", asset, "x", f"t{i}", now - 100, now - 50, "site-a"))
    conn.commit()
    res = N.run(conn, cfg, None, N.validate({"source": "findings", "severity": "high"}, cfg), now)
    assert {r["rule"] for r in res["rows"]} == {"fanout", "beaconing"}
    res = N.run(conn, cfg, None, N.validate({"source": "findings", "group": "device"}, cfg), now)
    assert res["rows"][0] == {"device": "10.40.0.8", "records": 2, "first": now - 100, "last": now - 50, "worst": "high"}
    res = N.run(conn, cfg, None, N.validate({"source": "findings", "device": "10.40.0.0/28"}, cfg), now)
    assert {r["asset"] for r in res["rows"]} == {"10.40.0.8", "10.40.0.9"}


def test_ai_output_is_only_filters(cfg, conn):
    from netmon.ai import AI
    ai = AI(cfg, conn)
    pv = N.ai_preview(ai, "what did mail-1 and 10.40.0.8 send to 198.51.100.7")
    assert "mail-1" not in pv["text"] and "10.40.0.8" not in pv["text"] and "198.51.100.7" in pv["text"] and len(pv["mapping"]) == 2
    host = pv["mapping"]["10.40.0.8"]
    spec = N.from_ai({"source": "traffic", "device": host, "remote": "host-99", "sql": "DROP TABLE alerts", "country_code": "RU",
                      "group": "device", "measure": None}, pv["mapping"])
    assert spec == {"source": "traffic", "device": "10.40.0.8", "country": "RU", "group": "device"}   # unknown placeholder and keys dropped
    with pytest.raises(N.SpecError, match="changed after the preview"):
        N.ai_interpret(ai, "u", "another question", pv["digest"])
    assert N.AI_SCHEMA["additionalProperties"] is False and "sql" not in N.AI_SCHEMA["properties"]


def test_saved_searches_and_reviewed_detections(cfg, conn):
    from netmon.auth import hash_pw, init
    init(conn)
    for u, role in (("ana", "analyst"), ("adm1", "admin"), ("adm2", "admin")):
        conn.execute("INSERT INTO users(username, pw_hash, role, created_at) VALUES (?,?,?,?)", (u, hash_pw("x" * 14), role, 0))
    conn.commit()
    spec = N.validate({"country": "RU", "group": "device"}, cfg)
    sid = N.save(conn, "ana", "Russia", "devices to Russia", spec)
    other = N.save(conn, "adm1", "Shared", "", spec, shared=True)
    assert [x["name"] for x in N.visible(conn, "ana")] == ["Russia", "Shared"] and [x["name"] for x in N.visible(conn, "zed")] == ["Shared"]
    with pytest.raises(PermissionError):
        N.delete(conn, sid, "zed")
    with pytest.raises(N.SpecError):
        N.propose(conn, sid, "ana", 60, 1, "medium")                                       # interval too short
    fsid = N.save(conn, "ana", "F", "", N.validate({"source": "findings"}, cfg))
    with pytest.raises(N.SpecError):
        N.propose(conn, fsid, "ana", 3600, 1, "medium")                                    # findings cannot raise findings
    N.propose(conn, sid, "ana", 3600, 2, "medium")
    site = cfg.sites[0]
    ch = SCH([{"device": "10.40.0.8", "records": 5, "bytes": 1}, {"device": "10.40.0.9", "records": 1, "bytes": 1}])
    assert N.detection_findings(conn, cfg, ch, site, time.time()) == []                    # proposed: nothing runs
    N.propose(conn, other, "adm1", 3600, 1, "low")
    with pytest.raises(N.SpecError, match="another admin"):
        N.approve(conn, other, "adm1")                                                     # no self-review when another admin exists
    N.approve(conn, sid, "adm1", "ok")
    fs = N.detection_findings(conn, cfg, ch, site, time.time())
    assert len(fs) == 1 and fs[0]["rule"] == "search_detection" and fs[0]["asset"] == "10.40.0.8" and fs[0]["subject"] == f"search:{sid}"
    assert fs[0]["severity"] == "medium" and "approved by adm1" in fs[0]["baseline"]
    p = ch.sql[-1][1]
    assert p["t1"] - p["t0"] == 3600                                                        # the detection's own interval
    assert N.detection_findings(conn, cfg, ch, site, time.time() + 60) == []                # not due again yet
    N.reject(conn, sid, "adm2", "too noisy")
    assert N.get(conn, sid)["detect"] == "none"
    acts = {r[0] for r in conn.execute("SELECT action FROM audit")}
    assert {"search_saved", "detection_proposed", "detection_approved", "detection_stopped"} <= acts


def test_detector_runs_only_approved(cfg, conn):
    from netmon.detect import Detector
    d = Detector(cfg, SCH([{"device": "10.40.0.8", "records": 1, "bytes": 1}]), conn)
    d.site = cfg.sites[0]
    assert d.rule_search_detections(time.time()) == []


def test_page_roles_and_flow(monkeypatch):
    from test_web import ADMINPW, VIEWPW, client, sid, web
    from netmon import search_views
    monkeypatch.setattr(search_views, "ch", SCH([{"device": "10.40.0.8", "records": 3, "bytes": 1234, "first": 1, "last": 2}]))
    v, ad = client("viewer1", VIEWPW), client("admin", ADMINPW)
    p = v.get(search_views.PATH).text
    assert "Ask a question" in p and "Which devices talked to Russia" in p and "nothing is sent anywhere" in p
    p = v.get(search_views.PATH, params={"q": "Which devices talked to Russia in the last 7 days?"}).text
    assert "country Russia" in p and "grouped by device" in p and "backup-1" in p and "1.2 KB" in p
    p = v.get(search_views.PATH, params={"q": "sparkly unicorns"}).text
    assert "could not turn" in p
    p = v.get(search_views.PATH, params={"f": "1", "source": "dns", "range": "999d"}).text
    assert "unknown period" in p
    vt = web.csrf_token(sid(v))
    spec = json.dumps({"source": "traffic", "range": "24h", "country": "RU", "group": "device"})
    r = v.post("/netmon/search/save", data={"name": "mine", "spec": spec, "shared": "1", "csrf": vt}, follow_redirects=False)
    assert r.status_code == 303
    row = web.conn.execute("SELECT * FROM saved_searches WHERE name='mine'").fetchone()
    assert row["shared"] == 0                                                                # viewers cannot share
    assert v.post(f"/netmon/search/saved/{row['id']}/propose", data={"csrf": vt}).status_code == 403
    assert v.get(f"/netmon/search/saved/{row['id']}/review").status_code == 403
    assert "country Russia" in v.get(search_views.PATH, params={"saved": row["id"]}).text
    assert ad.get(search_views.PATH, params={"saved": row["id"]}).status_code == 404       # private to its owner
    assert v.post("/netmon/search/ai/preview", data={"q": "x", "csrf": vt}).status_code == 400   # AI not configured
    assert v.post(f"/netmon/search/saved/{row['id']}/delete", data={"csrf": vt}, follow_redirects=False).status_code == 303


def test_propose_review_approve_pages(monkeypatch):
    from test_incidents import ANALYSTPW
    from test_web import ADMINPW, client, sid, web
    from netmon import search_views
    monkeypatch.setattr(search_views, "ch", SCH([{"device": "10.40.0.8", "records": 3, "bytes": 1234, "first": 1, "last": 2}]))
    an, ad = client("analyst1", ANALYSTPW), client("admin", ADMINPW)
    at, dt = web.csrf_token(sid(an)), web.csrf_token(sid(ad))
    spec = json.dumps({"source": "traffic", "range": "24h", "country": "RU", "group": "device"})
    an.post("/netmon/search/save", data={"name": "to-review", "spec": spec, "shared": "1", "csrf": at})
    row = web.conn.execute("SELECT * FROM saved_searches WHERE name='to-review'").fetchone()
    assert row["shared"] == 1
    assert an.post(f"/netmon/search/saved/{row['id']}/propose", data={"interval_m": "5", "threshold": "1", "severity": "medium",
                                                                      "csrf": at}).status_code == 400            # under 15 min
    assert an.post(f"/netmon/search/saved/{row['id']}/propose", data={"interval_m": "60", "threshold": "1", "severity": "medium", "csrf": at},
                   follow_redirects=False).status_code == 303
    assert an.post(f"/netmon/search/saved/{row['id']}/approve", data={"csrf": at}).status_code == 403            # analysts cannot approve
    page = ad.get(f"/netmon/search/saved/{row['id']}/review").text
    assert "would have fired in" in page and "finding(s) per day" in page and "never blocks anything" in page
    assert ad.post(f"/netmon/search/saved/{row['id']}/approve", data={"csrf": dt}, follow_redirects=False).status_code == 303
    assert web.conn.execute("SELECT detect, reviewed_by FROM saved_searches WHERE id=?", (row["id"],)).fetchone()[:] == ("approved", "admin")
    assert "detection: every 60 min" in an.get(search_views.PATH).text
    assert ad.post(f"/netmon/search/saved/{row['id']}/reject", data={"csrf": dt, "note": "done"}, follow_redirects=False).status_code == 303
