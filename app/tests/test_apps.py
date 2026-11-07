"""Applications: create/validate, members follow identity, observed vs confirmed vs dismissed dependencies, confidence,
'new', confirmed-but-not-seen wording, outage impact, bounded queries, graph accessibility, roles (synthetic data only)."""
import time

import pytest

from netmon import apps as A


@pytest.fixture(autouse=True)
def _fresh_cache():
    A._cache.clear()
    yield
    A._cache.clear()


NOW = 1_800_000_000


class AppCH:
    def __init__(self, internal, external):
        self.internal, self.external, self.sql = internal, external, []

    def query(self, sql, params):
        self.sql.append((sql, params))
        return self.external if "InIfName = {wan:String}" in sql else self.internal


def _row(c, s, port, n=10, days=7, first=NOW - 6 * 86400, last=NOW - 60):
    return {"client": c, "server": s, "proto": 6, "port": port, "n": n, "bytes": n * 100, "first": first, "last": last, "days": days}


INTERNAL = [_row("10.40.0.10", "10.40.0.20", 5432, n=500),                 # mail -> db (another app)
            _row("10.40.0.10", "10.40.0.11", 25, n=40),                    # inside the application: not a dependency
            _row("10.40.0.30", "10.40.0.10", 993, n=80, days=2),           # a client uses mail
            _row("10.40.0.10", "10.40.0.40", 22, n=3, days=1, first=NOW - 3600)]   # new, low confidence
EXTERNAL = [{"member": "10.40.0.10", "asn": 64500, "org": "Example Transit", "proto": 6, "dir": "out", "port": 443, "n": 90, "bytes": 9000,
             "remotes": 3, "sample": "198.51.100.7", "first": NOW - 6 * 86400, "last": NOW - 100, "days": 6},
            {"member": "10.40.0.11", "asn": 64501, "org": "Clients", "proto": 6, "dir": "in", "port": 25, "n": 300, "bytes": 1000,
             "remotes": 120, "sample": "203.0.113.9", "first": NOW - 6 * 86400, "last": NOW - 10, "days": 7}]


def _apps(conn, cfg):
    s = cfg.sites[0]["id"]
    mail = A.create(conn, cfg, s, "Mail", "10.40.0.10 10.40.0.11", "analyst1", critical=True)
    db = A.create(conn, cfg, s, "Database", "10.40.0.20", "analyst1")
    conn.execute("UPDATE apps SET created_at=?", (NOW - 30 * 86400,))
    conn.commit()
    return mail, db


def test_create_validation(cfg, conn):
    s = cfg.sites[0]["id"]
    with pytest.raises(ValueError):
        A.create(conn, cfg, s, "", "10.40.0.10", "u")
    with pytest.raises(ValueError):
        A.create(conn, cfg, s, "X", "not-an-ip", "u")
    with pytest.raises(ValueError):
        A.create(conn, cfg, s, "X", "8.8.8.8", "u")               # external address
    _apps(conn, cfg)
    with pytest.raises(ValueError):
        A.create(conn, cfg, s, "Mail", "", "u")                   # duplicate name
    assert conn.execute("SELECT count(*) FROM audit WHERE action='app_created'").fetchone()[0] == 2


def test_dependencies_observed_confirmed_new(cfg, conn):
    mail, _ = _apps(conn, cfg)
    ch = AppCH(INTERNAL, EXTERNAL)
    res = A.dependencies(conn, cfg, ch, mail, now=NOW)
    by = {d["dkey"]: d for d in res["deps"]}
    assert "int:out:10.40.0.11:tcp/25" not in by                          # internal to the application
    db = by["int:out:10.40.0.20:tcp/5432"]
    assert db["app"][1] == "Database" and db["confidence"] == "high" and db["direction"] == "uses" and not db["new"]
    assert by["int:in:10.40.0.30:tcp/993"]["direction"] == "used by" and by["int:in:10.40.0.30:tcp/993"]["confidence"] == "medium"   # 2 of 7 days
    new = by["int:out:10.40.0.40:tcp/22"]
    assert new["new"] and new["confidence"] == "low"
    ext = by["ext:out:AS64500:tcp/443"]
    assert ext["org"] == "Example Transit" and ext["remotes"] == 3 and ext["kind"] == "internet"
    assert by["ext:in:tcp/25"]["target"] == "internet clients"
    # bounded: period, LIMIT and the member list are parameters, never interpolated
    sql, p = ch.sql[0]
    assert "LIMIT {lim:UInt32}" in sql and p["lim"] == A.MAX_ROWS and p["t1"] - p["t0"] == 7 * 86400 and "10.40.0.10" not in sql


def test_first_seen_is_remembered_so_old_dependencies_are_not_new(cfg, conn):
    mail, _ = _apps(conn, cfg)
    early = [_row("10.40.0.10", "10.40.0.40", 22, n=3, days=1, first=NOW - 5 * 86400 - 3600, last=NOW - 5 * 86400)]
    A.dependencies(conn, cfg, AppCH(early, []), mail, now=NOW - 5 * 86400 + 60)   # seen five days ago
    A._cache.clear()
    later = [_row("10.40.0.10", "10.40.0.40", 22, n=3, days=1, first=NOW - 3600)]
    d = A.dependencies(conn, cfg, AppCH(later, []), mail, now=NOW)["deps"][0]
    assert d["dkey"] == "int:out:10.40.0.40:tcp/22" and not d["new"]


def test_new_application_does_not_call_everything_new(cfg, conn):
    aid = A.create(conn, cfg, cfg.sites[0]["id"], "Fresh", "10.40.0.10", "u")
    conn.execute("UPDATE apps SET created_at=? WHERE id=?", (NOW - 600, aid))
    conn.commit()
    assert not any(d["new"] for d in A.dependencies(conn, cfg, AppCH(INTERNAL, EXTERNAL), aid, now=NOW)["deps"])


def test_confirmed_not_seen_and_dismissed(cfg, conn):
    mail, _ = _apps(conn, cfg)
    A.set_status(conn, mail, "int:out:10.40.0.50:tcp/1433", "confirmed", "analyst1", "month-end reports")
    A.set_status(conn, mail, "ext:out:AS64500:tcp/443", "dismissed", "analyst1")
    with pytest.raises(ValueError):
        A.set_status(conn, mail, "x", "bogus", "analyst1")
    by = {d["dkey"]: d for d in A.dependencies(conn, cfg, AppCH(INTERNAL, EXTERNAL), mail, now=NOW)["deps"]}
    gone = by["int:out:10.40.0.50:tcp/1433"]
    assert not gone["seen"] and gone["status"] == "confirmed" and gone["target"] == "10.40.0.50" and gone["service"] == "tcp/1433"
    assert by["ext:out:AS64500:tcp/443"]["status"] == "dismissed"
    assert conn.execute("SELECT count(*) FROM audit WHERE action LIKE 'app_dependency_%'").fetchone()[0] == 2


def test_members_follow_identity(cfg, conn):
    from netmon import identity as I
    s = cfg.sites[0]["id"]
    I.observe(conn, s, time.time() - 100, ip="10.40.0.10", mac="02:00:00:00:00:10", source="test")
    aid = A.create(conn, cfg, s, "Moving", "10.40.0.10", "u")
    iid = conn.execute("SELECT identity_id FROM app_members WHERE app_id=?", (aid,)).fetchone()[0]
    assert iid
    I.observe(conn, s, time.time(), ip="10.40.0.99", mac="02:00:00:00:00:10", source="test")
    m = A.members(conn, aid)[0]
    assert m["ip"] == "10.40.0.99" and m["stored"] == "10.40.0.10"


def test_impact_and_graph(cfg, conn):
    _apps(conn, cfg)
    A.create(conn, cfg, cfg.sites[0]["id"], "Clients", "10.40.0.10", "u")    # a device can be in two applications
    site = cfg.sites[0]
    rows = [_row("10.40.0.10", "10.40.0.20", 5432, n=500), _row("10.40.0.60", "10.40.0.20", 5432, n=5)]
    im = A.impact(conn, cfg, AppCH(rows, []), site, {"10.40.0.20"}, now=NOW)
    assert [d["ip"] for d in im["devices"]] == ["10.40.0.10", "10.40.0.60"]
    assert sorted(a[1] for a in im["apps"]) == ["Clients", "Mail"] and im["member_of"][0][1] == "Database"
    deps = A.dependencies(conn, cfg, AppCH(INTERNAL, EXTERNAL), 1, now=NOW)["deps"]
    svg = A.graph_svg("Mail <x>", deps)
    assert "role='img'" in svg and "aria-label=" in svg and "Mail &lt;x&gt;" in svg and "<x>" not in svg


def test_pages_roles_and_actions(monkeypatch):
    from test_incidents import ANALYSTPW
    from test_web import ADMINPW, VIEWPW, client, sid, web
    from netmon import apps_views
    monkeypatch.setattr(apps_views, "ch", AppCH(INTERNAL, EXTERNAL))
    v, an, ad = client("viewer1", VIEWPW), client("analyst1", ANALYSTPW), client("admin", ADMINPW)
    site = web.cfg.sites[0]["id"]
    p = v.get("/netmon/apps").text
    assert "lack of traffic does not prove a dependency" in p and "Analysts and admins create applications" in p
    assert v.post("/netmon/apps/new", data={"site": site, "name": "X", "members": "10.40.0.10", "csrf": web.csrf_token(sid(v))}).status_code == 403
    tok = web.csrf_token(sid(an))
    assert an.post("/netmon/apps/new", data={"site": site, "name": "Mail", "csrf": "bad"}).status_code in (400, 403)
    r = an.post("/netmon/apps/new", data={"site": site, "name": "Mail", "members": "10.40.0.10 10.40.0.11", "critical": "1", "csrf": tok},
                follow_redirects=False)
    assert r.status_code == 303
    aid = int(r.headers["location"].split("/netmon/apps/")[1].split("?")[0])
    assert an.post("/netmon/apps/new", data={"site": site, "name": "Bad", "members": "8.8.8.8", "csrf": tok}).status_code == 400
    page = v.get(f"/netmon/apps/{aid}?graph=1").text
    assert "Dependencies" in page and "Example Transit" in page and "class='depgraph'" in page and "Confirm" not in page
    page = an.get(f"/netmon/apps/{aid}").text
    assert "Confirm" in page and "Not a dependency" in page
    assert an.post(f"/netmon/apps/{aid}/deps", data={"dkey": "int:out:10.40.0.50:tcp/1433", "status": "confirmed", "csrf": tok},
                   follow_redirects=False).status_code == 303
    page = v.get(f"/netmon/apps/{aid}").text
    assert "lack of traffic does not prove the dependency is gone" in page and "1</b> confirmed but not seen" in page
    assert v.get("/netmon/apps?device=10.40.0.20").status_code == 200
    assert an.post(f"/netmon/apps/{aid}/members", data={"ip": "1.1.1.1", "csrf": tok}).status_code == 400
    assert v.get("/netmon/apps/99999").status_code == 404
    assert ad.post(f"/netmon/apps/{aid}/delete", data={"csrf": web.csrf_token(sid(ad))}, follow_redirects=False).status_code == 303
    assert web.conn.execute("SELECT count(*) FROM app_members WHERE app_id=?", (aid,)).fetchone()[0] == 0
