"""Per-user firewall restrictions: a viewer/analyst limited to some firewalls sees only those, on every page and API,
and records of other firewalls are not found (synthetic data only)."""
import copy
import json
import time

import pytest

from test_web import ADMINPW, client, sid, web

from netmon import access, auth
from netmon import apps as A
from netmon import nlsearch as N
from netmon.core import rebuild_sites

RPW = "restricted password 123"


@pytest.fixture(autouse=True)
def two_firewalls():
    """site-a (fixture) plus a second firewall site-b; users rv (viewer) and ra (analyst) limited to site-a."""
    before = copy.deepcopy(web.cfg.raw["sites"])
    b = copy.deepcopy(before[0])
    b.update(id="site-b", name="Branch B", exporter="fw-b", exporter_ip="10.99.0.1", syslog_source="10.99.0.1",
             internal_nets=["10.60.0.0/24"], public_nets=[], outbound_nat_ips=[])
    rebuild_sites(web.cfg, before + [b])
    for u, role in (("rv", "viewer"), ("ra", "analyst")):
        web.conn.execute("INSERT OR REPLACE INTO users(username,pw_hash,role,created_at,sites) VALUES (?,?,?,?,?)",
                         (u, auth.hash_pw(RPW), role, time.time(), json.dumps(["site-a"])))
    web.conn.commit()
    yield
    rebuild_sites(web.cfg, before)


def alert(site, title, asset="10.40.0.8", rule="beaconing", sev="high", status="open"):
    t = time.time()
    cur = web.conn.execute(
        "INSERT INTO alerts(key,rule,severity,confidence,asset,subject,title,first_seen,last_seen,window_start,window_end,evidence,query,"
        "baseline,alternatives,next_steps,akvorado_filter,site,status,test) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
        (f"k{time.time_ns()}", rule, sev, "medium", asset, "198.51.100.9", title, t, t, t - 60, t, "[]", "{}", "differs", "[]",
         json.dumps(["Check it"]), "", site, status))
    web.conn.commit()
    return cur.lastrowid


def test_config_and_sql_follow_the_request_restriction():
    assert {s["id"] for s in web.cfg.sites} == {"site-a", "site-b"}
    tok = access.set_allowed({"site-a"})
    try:
        assert [s["id"] for s in web.cfg.sites] == ["site-a"] and [s["id"] for s in web.cfg["sites"]] == ["site-a"]
        assert web.cfg.site("site-b") is None and web.cfg.site("site-a")
        assert [s["id"] for s in web.cfg.all_sites] == ["site-a", "site-b"]
        assert web.conn.execute("SELECT site_ok('site-a'), site_ok('site-b'), site_ok(NULL)").fetchone()[:] == (1, 0, 0)
        sql, p = access.ch_restrict("SELECT count() FROM flows WHERE x", {}, web.cfg.sites)
        assert "ExporterName IN {_ax:Array(String)} AND x" in sql and p["_ax"] == ["fw-a"]
    finally:
        access.reset(tok)
    assert web.conn.execute("SELECT site_ok('site-b'), site_ok(NULL)").fetchone()[:] == (1, 1)


def test_findings_lists_detail_and_triage_are_limited():
    a = alert("site-a", "finding on A")
    b = alert("site-b", "secret finding on B")
    rv, ra, adm = client("rv", RPW), client("ra", RPW), client("admin", ADMINPW)
    sec = rv.get("/netmon/security?status=all").text
    assert "finding on A" in sec and "secret finding on B" not in sec
    assert "secret finding on B" in adm.get("/netmon/security?status=all").text
    assert rv.get(f"/netmon/alert/{b}").status_code == 404 and rv.get(f"/netmon/alert/{a}").status_code == 200
    assert ra.post(f"/netmon/alert/{b}/status", data={"status": "closed", "csrf": web.csrf_token(sid(ra))}).status_code == 404
    # Ack all only touches the analyst's firewall
    tok = web.csrf_token(sid(ra))
    ra.post("/netmon/alerts/ack", data={"max_id": b, "csrf": tok})
    st = dict(web.conn.execute("SELECT id, status FROM alerts WHERE id IN (?,?)", (a, b)).fetchall())
    assert st[a] == "acked" and st[b] == "open"
    ov = rv.get("/netmon/api/overview").json()
    assert all(x.get("site") != "site-b" for x in ov.get("alerts", []))


def test_exceptions_from_a_finding_stay_on_its_firewall():
    a = alert("site-a", "beacon on A")
    ra = client("ra", RPW)
    tok = web.csrf_token(sid(ra))
    r = ra.post(f"/netmon/alert/{a}/normal", data={"scope": "exact", "reason": "known updater", "csrf": tok}, follow_redirects=False)
    assert r.status_code == 303
    x = web.conn.execute("SELECT site FROM exceptions ORDER BY id DESC LIMIT 1").fetchone()
    assert x["site"] == "site-a"
    assert ra.post(f"/netmon/alert/{a}/normal", data={"scope": "device", "reason": "x", "csrf": tok}).status_code == 403
    assert ra.post("/netmon/expected", data={"target": "10.40.0.9", "reason": "x", "csrf": tok}).status_code == 403
    web.conn.execute("INSERT INTO exceptions(rule,asset,subject,owner,reason,created_by,created_at,site) VALUES "
                     "('beaconing','10.99.0.5','*','o','branch only','admin',?, 'site-b')", (time.time(),))
    web.conn.commit()
    xb = web.conn.execute("SELECT max(id) FROM exceptions").fetchone()[0]
    assert "branch only" not in ra.get("/netmon/exceptions").text
    assert ra.post(f"/netmon/exceptions/{xb}/disable", data={"csrf": tok}).status_code == 404
    assert web.conn.execute("SELECT enabled FROM exceptions WHERE id=?", (xb,)).fetchone()[0] == 1


def test_incidents_apps_and_saved_searches_are_limited():
    from netmon import incidents as inc
    b1, b2 = alert("site-b", "B one", rule="beaconing"), alert("site-b", "B two", rule="fanout")
    ib = inc.create(web.conn, web.cfg, [web.conn.execute("SELECT * FROM alerts WHERE id=?", (b1,)).fetchone()], "admin", "test")
    rv, ra = client("rv", RPW), client("ra", RPW)
    assert f"/netmon/incidents/{ib}" not in rv.get("/netmon/incidents?status=all").text
    assert rv.get(f"/netmon/incidents/{ib}").status_code == 404
    tok = web.csrf_token(sid(ra))
    assert ra.post(f"/netmon/incidents/{ib}/dismiss", data={"csrf": tok}).status_code == 404
    a1 = alert("site-a", "A one")
    ia = inc.create(web.conn, web.cfg, [web.conn.execute("SELECT * FROM alerts WHERE id=?", (a1,)).fetchone()], "admin", "test")
    assert ra.post(f"/netmon/incidents/{ia}/add", data={"alert_id": b2, "csrf": tok}).status_code == 404   # cannot pull in B
    assert ra.post(f"/netmon/incidents/{ia}/merge", data={"other": ib, "csrf": tok}).status_code == 404
    aid = A.create(web.conn, web.cfg, "site-b", "Branch app", "10.40.0.10", "admin")
    assert rv.get(f"/netmon/apps/{aid}").status_code == 404 and "Branch app" not in rv.get("/netmon/apps?site=site-b").text
    # a restricted user's "all firewalls" search is stored as their firewalls; another firewall's search is not shown
    tok_a = access.set_allowed({"site-a"})
    try:
        sid_ = N.save(web.conn, "ra", "ra-own-search", "q", {"source": "findings", "range": "24h"}, shared=True)
    finally:
        access.reset(tok_a)
    assert json.loads(N.get(web.conn, sid_)["spec"])["sites"] == ["site-a"]
    other = N.save(web.conn, "admin", "branch", "q", {"source": "findings", "range": "24h", "sites": ["site-b"]}, shared=True)
    tok_a = access.set_allowed({"site-a"})
    try:
        assert other not in {x["id"] for x in N.visible(web.conn, "ra")} and not N.can_see(N.get(web.conn, other), "ra")
    finally:
        access.reset(tok_a)


def test_flow_explorer_capacity_and_firewall_pickers():
    rv, adm = client("rv", RPW), client("admin", ADMINPW)
    page = rv.get("/netmon/security").text
    assert "/visualize" not in page and "/visualize" in adm.get("/netmon/security").text
    assert rv.get("/auth/verify").status_code == 403 and adm.get("/auth/verify").status_code == 200
    assert rv.get("/netmon/settings/capacity").status_code == 403
    fw = rv.get("/netmon/settings/sites").text
    assert "Site A" in fw and "Branch B" not in fw
    assert "Branch B" in adm.get("/netmon/settings/sites").text


def test_admin_sets_firewalls_and_restriction_applies_at_once():
    adm, rv = client("admin", ADMINPW), client("rv", RPW)
    tok = web.csrf_token(sid(adm))
    assert "Branch B" not in rv.get("/netmon/settings/sites").text
    r = adm.post("/netmon/users/rv/sites", data={"all": "1", "csrf": tok}, follow_redirects=False)
    assert r.status_code == 303 and access.stored_sites(web.conn, "rv") is None
    assert "Branch B" in rv.get("/netmon/settings/sites").text          # same session, no new sign-in
    r = adm.post("/netmon/users/rv/sites", data={"csrf": tok}, follow_redirects=False)
    assert "at least one firewall" in r.headers["location"].replace("%20", " ")
    adm.post("/netmon/users/rv/sites", data={"site": ["site-b", "nope"], "csrf": tok})
    assert access.stored_sites(web.conn, "rv") == ["site-b"]
    assert web.conn.execute("SELECT count(*) FROM audit WHERE action='user_sites' AND detail LIKE '%rv%'").fetchone()[0] >= 2
    users = adm.get("/netmon/users").text
    assert "/netmon/users/rv/sites" in users and "admins always see every firewall" in users
    assert rv.post("/netmon/users/rv/sites", data={"all": "1", "csrf": web.csrf_token(sid(rv))}).status_code == 403
    # a restriction to firewalls that no longer exist shows nothing at all
    web.conn.execute("UPDATE users SET sites=? WHERE username='rv'", (json.dumps(["gone"]),))
    web.conn.commit()
    assert rv.get("/netmon/security").status_code == 403
    # admins are never restricted, whatever is stored
    web.conn.execute("UPDATE users SET sites=? WHERE username='admin'", (json.dumps(["site-b"]),))
    web.conn.commit()
    try:
        assert "Site A" in adm.get("/netmon/settings/sites").text
    finally:
        web.conn.execute("UPDATE users SET sites=NULL WHERE username='admin'")
        web.conn.commit()


def test_audit_regressions_devices_incidents_health_and_global_pages():
    from netmon import identity as idn
    from netmon import incidents as inc
    from netmon.health import check_site
    rv, ra, adm = client("rv", RPW), client("ra", RPW), client("admin", ADMINPW)
    # a device only on site-b's own networks: not found, and its name/identity are not shown anywhere
    web.cfg.raw.setdefault("assets", {})["10.60.0.9"] = {"name": "branch-secret-db", "role": "db"}
    idn.observe(web.conn, "site-b", time.time(), ip="10.60.0.9", mac="66:77:88:99:00:aa", hostname="branch-secret-db")
    try:
        assert rv.get("/netmon/servers/10.60.0.9?site=site-b").status_code == 404
        assert rv.get("/netmon/api/server", params={"ip": "10.60.0.9"}).status_code == 404
        assert rv.get("/netmon/api/name", params={"ip": "10.60.0.9"}).json()["name"] == ""
        assert "branch-secret-db" in adm.get("/netmon/api/name", params={"ip": "10.60.0.9"}).text
        assert "branch-secret-db" not in rv.get("/netmon/identities").text
    finally:
        web.cfg.raw["assets"].pop("10.60.0.9", None)
    # an incident that mixes firewalls (grouped by remote address) is hidden from a user limited to one of them
    a1, b1 = alert("site-a", "mixed A"), alert("site-b", "mixed B")
    rows = web.conn.execute("SELECT * FROM alerts WHERE id IN (?,?) ORDER BY id", (a1, b1)).fetchall()
    im = inc.create(web.conn, web.cfg, list(rows), "admin", "same remote")
    assert rv.get(f"/netmon/incidents/{im}").status_code == 404 and adm.get(f"/netmon/incidents/{im}").status_code == 200
    tok = web.csrf_token(sid(ra))
    assert ra.post(f"/netmon/incidents/{im}/update", data={"status": "resolved", "resolution": "fixed", "close_findings": "1",
                                                           "csrf": tok}).status_code == 404
    assert web.conn.execute("SELECT status FROM alerts WHERE id=?", (b1,)).fetchone()[0] == "open"
    # global pages and shared settings are refused, with the reason
    for path in ("/netmon/settings/maintenance", "/netmon/settings/inventory", "/netmon/settings/integrations",
                 "/netmon/settings/response"):
        r = rv.get(path)
        assert r.status_code == 403 and "every firewall" in r.text, path
    assert ra.post("/netmon/settings/maintenance", data={"start": "1", "end": "2", "reason": "x", "csrf": tok}).status_code == 403
    assert ra.post("/netmon/names", data={"ip": "10.40.0.8", "name": "x", "csrf": tok}).status_code == 403
    # health checks and detector errors belong to their firewall
    assert check_site(web.cfg, "netflow:site-b") == "site-b" and check_site(web.cfg, "disk:clickhouse:default") is None
    web.set_state(web.conn, "detector", {"errors": ["site-b: boom", "site-a: fine"], "sites": {"site-a": 3.0, "site-b": 1.0}})
    tok_a = access.set_allowed({"site-a"})
    try:
        st = web.detector_status()
        assert st["errors"] == ["site-a: fine"] and st["learning_days"] == 3.0
        with pytest.raises(ValueError):
            access.ch_restrict("SELECT 1 FROM netmon.fw_events WHERE a=1 OR b=2", {}, web.cfg.sites)
    finally:
        access.reset(tok_a)
    # a wallboard pinned to another firewall is not found
    web.conn.execute("INSERT INTO wallboards(name, layout, created_by, updated_at) VALUES (?,?,?,?)",
                     ("Branch board", json.dumps({"site": "site-b", "range": "1h", "refresh": 30, "widgets": []}), "admin", time.time()))
    web.conn.commit()
    wb = web.conn.execute("SELECT max(id) FROM wallboards").fetchone()[0]
    assert rv.get(f"/netmon/wallboards/{wb}").status_code == 404 and "Branch board" not in rv.get("/netmon/wallboards").text


def test_restricted_users_get_no_forms_that_would_be_refused():
    ra = client("ra", RPW)
    adm = client("admin", ADMINPW)
    assert "New wallboard" not in ra.get("/netmon/wallboards").text
    assert "New wallboard" in adm.get("/netmon/wallboards").text
    page = ra.get("/netmon/servers/10.40.0.8").text
    assert "/netmon/settings/inventory" not in page
    menu = ra.get("/netmon/settings/sites").text
    assert "/netmon/settings/maintenance" not in menu and "/netmon/settings/integrations" not in menu
    assert "/netmon/settings/maintenance" in adm.get("/netmon/settings/sites").text
