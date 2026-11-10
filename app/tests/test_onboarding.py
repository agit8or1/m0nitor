"""Onboarding test: caps only lower NAT attribution tiers, quality recording (loss, duplicates, flowdiag), guided
validation input checks, the page's missing-source guidance, roles, CSRF and per-firewall restrictions. No ClickHouse
or firewall is contacted (the SQL itself is exercised in test_nat_scenarios.py against a throwaway ClickHouse)."""
import copy
import json
import time

import pytest
from fastapi.testclient import TestClient

from test_flowdiag import v9

from netmon import auth, web
from netmon import block as blk
from netmon import onboarding as O
from netmon import onboarding_views as OV
from netmon.core import rebuild_sites
from netmon.flowdiag import Tracker
from netmon.health import Health

PW = "onboarding password 12"
for _u, _role, _sites in (("ob-admin", "admin", None), ("ob-analyst", "analyst", None), ("ob-viewer", "viewer", None),
                          ("ob-ra", "analyst", ["site-a"])):
    web.conn.execute("INSERT OR REPLACE INTO users(username,pw_hash,role,created_at,sites) VALUES (?,?,?,?,?)",
                     (_u, auth.hash_pw(PW), _role, time.time(), json.dumps(_sites) if _sites else None))
web.conn.commit()


class EmptyCH:
    """Answers every query with no rows: every source is 'missing', nothing is contacted."""
    def __init__(self):
        self.sql = []

    def query(self, sql, params=None):
        self.sql.append(sql)
        return []


@pytest.fixture(autouse=True)
def two_firewalls(monkeypatch):
    before = copy.deepcopy(web.cfg.raw["sites"])
    b = copy.deepcopy(before[0])
    b.update(id="site-b", name="Branch B", vendor="fortigate", exporter="fw-b", exporter_ip="10.99.0.1", syslog_source="10.99.0.1",
             internal_nets=["10.60.0.0/24"], public_nets=["198.51.100.96/28"], outbound_nat_ips=["198.51.100.99"], lan_if="internal")
    rebuild_sites(web.cfg, before + [b])
    ch = EmptyCH()
    monkeypatch.setattr(web.dash, "ch", ch)
    monkeypatch.setattr(OV, "ch", ch)
    web.dash._cache.clear()
    OV._CACHE.clear()

    def no_firewall(*a, **k):
        raise AssertionError("the onboarding test must never touch a firewall")
    monkeypatch.setattr(blk, "enforcer", no_firewall)
    for k in ("nat_validation:site-a", "nat_validation:site-b"):
        web.conn.execute("DELETE FROM state WHERE k=?", (k,))
    web.conn.commit()
    yield ch
    rebuild_sites(web.cfg, before)


def client(user):
    c = TestClient(web.app, base_url="https://testserver")
    r = c.post("/login", data={"username": user, "password": PW, "next": "/netmon/security"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return c


def tok(c):
    return web.csrf_token(auth._th(c.cookies.get(auth.SESSION_COOKIE)))


SITES = [{"id": "site-a", "name": "A", "exporter": "fw-a"}, {"id": "site-b", "name": "B", "exporter": "fw-b"}]


# ---------------------------------------------------------------------------------------------------------- caps
def test_cap_tier_only_lowers():
    assert O.cap_tier("high", "low") == "low" and O.cap_tier("low", "high") == "low" and O.cap_tier("medium", "medium") == "medium"
    for t in ("ambiguous", "no_return", "unanswered", "wan_only"):
        assert O.cap_tier(t, "low") == t                          # non-host tiers are never turned into host tiers


def test_caps_by_window_and_site():
    t0, t1 = 10_000, 13_600
    fd = {"site-a": {"ts": t0}, "site-b": {"ts": t0}}
    q = {"loss": [{"ts": t0 + 60, "n": 5, "source": "flowdiag sequence gaps", "site": "site-b"}], "dups": [], "flowdiag": fd}
    c = O.caps(q, SITES, t0, t1)
    assert "fw-a" not in c and c["fw-b"]["max"] == "low" and "export loss" in c["fw-b"]["reasons"][0]
    q["loss"] = [{"ts": t0 + 60, "n": 5, "source": "collector receive drops", "site": None}]
    assert {k: v["max"] for k, v in O.caps(q, SITES, t0, t1).items()} == {"fw-a": "low", "fw-b": "low"}
    q["loss"] = [{"ts": t0 - 3600, "n": 5, "source": "collector receive drops", "site": None}]
    assert O.caps(q, SITES, t0, t1) == {}                       # loss outside the window: no cap
    q = {"loss": [], "dups": [{"ts": t0 + 5, "site": "site-a", "frac": 0.2, "rows": 100}], "flowdiag": fd}
    assert O.caps(q, SITES, t0, t1)["fw-a"]["max"] == "medium"
    q["dups"][0]["frac"] = O.DUP_FRAC / 2
    assert O.caps(q, SITES, t0, t1) == {}
    notes = O.caps({}, SITES, t0, t1)                          # never measured: no cap, but a stated limit per firewall
    assert notes["fw-a"]["max"] == "high" and "not been measured" in notes["fw-a"]["notes"][0]


def test_quality_recording_and_pruning(conn):
    now = time.time()
    O.record_loss(conn, 0, "collector receive drops")           # zero is not an event
    O.record_loss(conn, 3, "collector receive drops", now=now - 9 * 86400)
    O.record_loss(conn, 2, "collector receive drops", now=now)
    assert [x["n"] for x in O.load_quality(conn)["loss"]] == [2]          # older than 8 days pruned
    O.record_duplicates(conn, {"site-a": {"rows": 1000, "dup": 500}, "site-b": {"rows": 1000, "dup": 1}, "site-c": {"rows": 10, "dup": 5}})
    q = O.load_quality(conn)
    assert [d["site"] for d in q["dups"]] == ["site-a"] and q["dup_now"]["site-b"]["frac"] == 0.001


def test_flowdiag_counts_duplicates_separately_from_loss_and_restarts():
    tr = Tracker()
    for seq in (1, 2, 2, 3, 3, 4, 7):
        tr.feed("10.40.0.1", v9(seq), now=1793448000)
    r = tr.report(now=1793448000)[0]
    assert r["duplicates"] == 2 and r["lost"] == 2 and not any("restarted" in i for i in r["issues"])
    assert any("repeated an earlier sequence number" in i for i in r["issues"])


def test_flowdiag_record_matches_firewall_by_exporter_address(conn):
    rep = [{"exporter": "10.40.0.1", "protocol": "netflow_v9", "packets": 400, "lost": 3, "duplicates": 8, "clock_drift_s": 95.0,
            "issues": ["x"]}, {"exporter": "192.0.2.200", "protocol": "ipfix", "packets": 1, "lost": 0}]
    assert O.record_flowdiag(conn, web.cfg, rep, 300) == ["site-a"]
    q = O.load_quality(conn)
    assert q["flowdiag"]["site-a"]["clock_drift_s"] == 95.0 and q["loss"][-1]["site"] == "site-a" and q["dups"][-1]["frac"] == 0.02


def test_health_duplicate_check_records_and_honours_choice(conn):
    class CH:
        def query(self, sql, params=None):
            return [{"e": "fw-a", "n": 1000, "dup": 300}] if "uniqExact(cityHash64" in sql else []
    h = Health(web.cfg, CH(), conn, metrics_urls={})
    out = h.c_duplicates({})
    assert out[0]["id"] == "dupflows:site-a" and out[0]["state"] == "warn"
    assert O.load_quality(conn)["dups"][-1]["site"] == "site-a"


# ---------------------------------------------------------------------------------------------------------- validation
def test_validation_input_is_checked(conn):
    s = web.cfg.site("site-a")
    ok = dict(host_a="10.40.0.21", host_b="10.40.0.22", dest="45.83.64.80", port=443, user="u", confirmed=True)
    bad = [({"confirmed": False}, "Confirm"), ({"host_a": "10.60.0.5"}, "internal networks"), ({"host_b": "10.40.0.21"}, "two different"),
           ({"dest": "192.0.2.10"}, "public address"), ({"dest": "10.40.0.30"}, "public address"), ({"dest": "203.0.113.179"}, "public address"),
           ({"port": 0}, "1-65535"), ({"host_a": "nope"}, "not an IP")]
    for change, msg in bad:
        with pytest.raises(ValueError, match=msg):
            O.start_validation(conn, web.cfg, s, **{**ok, **change})
    v = O.start_validation(conn, web.cfg, s, **ok)
    assert v["status"] == "running" and O.get_validation(conn, "site-a")["dest"] == "45.83.64.80"
    cmds = " ".join(c for *_, c, _x in O.steps(v))
    assert "45.83.64.80" in cmds and "1500000" in cmds and "3000000" in cmds


def test_validation_without_shared_nat_is_refused(conn):
    s = dict(web.cfg.site("site-a"), outbound_nat_ips=[])
    with pytest.raises(ValueError, match="No shared outbound NAT"):
        O.start_validation(conn, web.cfg, s, "10.40.0.21", "10.40.0.22", "45.83.64.80", 443, "u", True)


# ---------------------------------------------------------------------------------------------------------- pages
def test_page_explains_each_missing_source_for_the_vendor():
    v = client("ob-viewer")
    r = v.get("/netmon/onboarding?site=site-a")
    assert r.status_code == 200
    t = r.text
    for k in ("WAN flows", "LAN return flows", "Firewall logs", "Usable NAT evidence"):
        assert k in t
    assert t.count("Cannot answer:") == 4 and "Reporting → NetFlow" in t and "Not ready" in t
    assert "Start validation" not in t and "Analysts and admins can start a validation" in t
    assert "Export loss" in t and "not measured" in t                  # unmeasured loss is stated, not assumed
    b = v.get("/netmon/onboarding?site=site-b").text
    assert "netflow-sampler both" in b and "config log syslogd" in b      # FortiGate guidance for the FortiGate firewall


def test_validation_flow_roles_and_csrf():
    an, vw = client("ob-analyst"), client("ob-viewer")
    data = {"site": "site-a", "host_a": "10.40.0.21", "host_b": "10.40.0.22", "dest": "45.83.64.80", "port": "443", "confirm": "1"}
    assert vw.post("/netmon/onboarding/validate", data={**data, "csrf": tok(vw)}).status_code == 403
    assert an.post("/netmon/onboarding/validate", data={**data, "csrf": "x"}).status_code == 403
    r = an.post("/netmon/onboarding/validate", data={**data, "csrf": tok(an)}, follow_redirects=False)
    assert r.status_code == 303 and "Validation%20started" in r.headers["location"]
    page = an.get("/netmon/onboarding?site=site-a").text
    assert "Evaluate now" in page and "curl" in page and "ambiguous" in page
    r = an.post("/netmon/onboarding/validate/evaluate", data={"site": "site-a", "csrf": tok(an)}, follow_redirects=False)
    assert r.status_code == 303 and "evaluated" in r.headers["location"]
    v = O.get_validation(web.conn, "site-a")
    assert v["result"]["verdict"] == "incomplete"                        # nothing arrived: never a pass
    assert {c["state"] for c in v["result"]["checks"][:2]} == {"not_observed"}
    r = an.post("/netmon/onboarding/validate/cancel", data={"site": "site-a", "csrf": tok(an)}, follow_redirects=False)
    assert r.status_code == 303 and O.get_validation(web.conn, "site-a") is None
    audit = [x["action"] for x in web.conn.execute("SELECT action FROM audit WHERE user='ob-analyst' ORDER BY id DESC LIMIT 3")]
    assert audit == ["nat_validation_end", "nat_validation_evaluate", "nat_validation_start"]


def test_restricted_user_cannot_see_or_act_on_other_firewalls():
    ra = client("ob-ra")
    assert ra.get("/netmon/onboarding?site=site-b").status_code == 404
    assert ra.get("/netmon/api/onboarding?site=site-b").status_code == 404
    data = {"site": "site-b", "host_a": "10.60.0.21", "host_b": "10.60.0.22", "dest": "45.83.64.80", "port": "443", "confirm": "1",
            "csrf": tok(ra)}
    assert ra.post("/netmon/onboarding/validate", data=data).status_code == 404
    assert ra.post("/netmon/onboarding/validate/evaluate", data={"site": "site-b", "csrf": tok(ra)}).status_code == 404
    t = ra.get("/netmon/onboarding").text
    assert "Branch B" not in t and "198.51.100.99" not in t                # other firewall's name and NAT address hidden
    cov = ra.get("/netmon/coverage").text
    assert "Onboarding test per firewall" in cov and "Branch B" not in cov
    j = ra.get("/netmon/api/onboarding?site=site-a").json()
    assert j["site"] == "site-a" and j["sources"]["wan_flows"]["state"] == "missing"


def test_coverage_lists_every_visible_firewall_for_admins():
    t = client("ob-admin").get("/netmon/coverage").text
    assert "Onboarding test per firewall" in t and "Branch B" in t and "/netmon/onboarding?site=site-b" in t


def test_page_says_so_when_clickhouse_is_down(monkeypatch):
    class Down:
        def query(self, sql, params=None):
            raise RuntimeError("connection refused")
    monkeypatch.setattr(web.dash, "ch", Down())
    monkeypatch.setattr(OV, "ch", Down())
    web.dash._cache.clear()
    t = client("ob-viewer").get("/netmon/onboarding?site=site-a").text
    assert "could not query the flow database" in t and "Cannot answer:" not in t
