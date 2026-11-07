"""Segmentation monitoring: groups, expected communication, verdicts (specific beats 'any', services, schedules),
honest matrix (not seen != blocked), firewall's own address excluded, findings with precise exceptions, roles
(synthetic data only)."""
import json
import time

import pytest

from netmon import segments as S


def _setup(conn, site="site-a"):
    g = {n: S.save_group(conn, site, n, c, sens, "admin") for n, c, sens in
         (("Users", "10.40.0.0/25", "normal"), ("Servers", "10.40.0.128/26", "normal"), ("Mgmt", "10.40.0.192/26", "high"), ("Guest", "10.50.0.0/24", "normal"))}
    S.save_policy(conn, site, g["Users"], g["Servers"], "allow", "tcp/443, tcp/22", None, "admin")
    S.save_policy(conn, site, 0, g["Mgmt"], "none", "*", None, "admin")
    S.save_policy(conn, site, g["Users"], g["Mgmt"], "allow", "tcp/443", None, "admin")
    S.save_policy(conn, site, g["Guest"], 0, "none", "*", None, "admin")
    return g


def test_groups_validation_and_most_specific_group(conn):
    with pytest.raises(ValueError):
        S.save_group(conn, "site-a", "x", "not-a-net", "normal", "admin")
    with pytest.raises(ValueError):
        S.save_group(conn, "site-a", "", "10.0.0.0/8", "normal", "admin")
    g = _setup(conn)
    gs = S.groups(conn, "site-a")
    assert S.group_of("10.40.0.130", gs)["name"] == "Servers" and S.group_of("10.40.0.5", gs)["name"] == "Users"
    S.save_group(conn, "site-a", "Printers", "10.40.0.16/28", "normal", "admin")
    assert S.group_of("10.40.0.20", S.groups(conn, "site-a"))["name"] == "Printers"      # most specific range wins
    assert S.group_of("10.99.0.1", gs) is None
    with pytest.raises(ValueError):
        S.save_policy(conn, "site-a", 0, 0, "none", "*", None, "admin")
    with pytest.raises(ValueError):
        S.save_policy(conn, "site-a", g["Users"], g["Servers"], "allow", "tcp/99999", None, "admin")


def test_verdicts(conn):
    g = _setup(conn)
    gs, pols = {x["id"]: x for x in S.groups(conn, "site-a")}, S.policies(conn, "site-a")
    U, SV, M, G = gs[g["Users"]], gs[g["Servers"]], gs[g["Mgmt"]], gs[g["Guest"]]
    assert S.verdict(U, SV, "tcp/443", pols)[0] == "expected"
    assert S.verdict(U, SV, "tcp/3389", pols)[0] == "unexpected"          # allowed only on listed services
    assert S.verdict(SV, U, "tcp/443", pols)[0] == "undefined"            # no rule for that direction
    assert S.verdict(U, M, "tcp/443", pols)[0] == "expected"              # specific allow beats 'any group -> Mgmt: none'
    assert S.verdict(U, M, "tcp/22", pols)[0] == "unexpected"
    assert S.verdict(SV, M, "tcp/443", pols)[0] == "unexpected"
    assert S.verdict(G, U, "udp/53", pols)[0] == "unexpected"
    assert S.verdict(None, M, "tcp/443", pols)[0] == "unexpected"         # an address in no group still reaches 'any group' rules
    names = {x["id"]: x["name"] for x in gs.values()}
    assert S.describe_policy(pols[0], names) == "Users → Servers: communication expected on tcp/22, tcp/443 (other services unexpected)"


def test_schedule_limits_a_rule(conn):
    from netmon.baselines import parse_schedule
    g = {n: S.save_group(conn, "site-a", n, c, "normal", "admin") for n, c in (("Backup", "10.40.0.0/28"), ("NAS", "10.40.0.16/28"))}
    S.save_policy(conn, "site-a", g["Backup"], g["NAS"], "allow", "*", parse_schedule([str(i) for i in range(7)], "01:00", "05:00"), "admin")
    S.save_policy(conn, "site-a", g["Backup"], g["NAS"], "none", "*", None, "admin")
    gs, pols = {x["name"]: x for x in S.groups(conn, "site-a")}, S.policies(conn, "site-a")
    site = {"id": "site-a", "tz": "UTC"}
    night = time.mktime((2026, 11, 3, 2, 0, 0, 0, 0, 0)) - time.timezone
    noon = night + 10 * 3600
    assert S.verdict(gs["Backup"], gs["NAS"], "tcp/445", pols, night, site)[0] == "expected"
    assert S.verdict(gs["Backup"], gs["NAS"], "tcp/445", pols, noon, site)[0] == "unexpected"


def test_templates_create_groups_and_rules_once(conn):
    n = S.apply_template(conn, "site-a", "guest", "admin")
    assert n == 2 and S.apply_template(conn, "site-a", "guest", "admin") == 0
    g = S.groups(conn, "site-a")[0]
    assert g["name"] == "Guest" and json.loads(g["cidrs"]) == [] and "template" in g["note"]
    with pytest.raises(ValueError):
        S.apply_template(conn, "site-a", "nope", "admin")


class SegCH:
    def __init__(self, rows, blocks=None):
        self.rows, self.blocks, self.sql = rows, blocks, []

    def query(self, sql, params):
        self.sql.append((sql, params))
        if "netmon.fw_events" in sql:
            if self.blocks is None:
                raise RuntimeError("no firewall log")
            return self.blocks
        return self.rows


ROWS = [{"client": "10.40.0.5", "server": "10.40.0.130", "proto": 6, "port": 443, "n": 50, "bytes": 1000, "first": 1, "last": int(time.time())},
        {"client": "10.40.0.5", "server": "10.40.0.130", "proto": 6, "port": 3389, "n": 7, "bytes": 100, "first": 1, "last": int(time.time())},
        {"client": "10.40.0.1", "server": "10.40.0.200", "proto": 6, "port": 22, "n": 9, "bytes": 100, "first": 1, "last": int(time.time())},
        {"client": "10.40.0.130", "server": "10.40.0.200", "proto": 6, "port": 22, "n": 3, "bytes": 100, "first": 1, "last": int(time.time())}]


def test_matrix_is_honest_and_excludes_the_firewall(cfg, conn):
    g = _setup(conn)
    site = dict(cfg.sites[0], exporter_ip="10.40.0.1")
    m = S.matrix(conn, cfg, SegCH(ROWS, blocks=[{"client": "10.50.0.9", "server": "10.40.0.5", "proto": 6, "port": 445, "n": 4, "last": 1}]), site, 0, 1)
    us = m["cells"][(g["Users"], g["Servers"])]
    assert us["n"] == 57 and us["unexpected"] == 7
    assert (g["Users"], g["Mgmt"]) not in m["cells"]                     # 10.40.0.1 is the firewall: not device traffic
    assert m["cells"][(g["Servers"], g["Mgmt"])]["unexpected"] == 3
    assert m["cells"][(g["Guest"], g["Users"])]["blocked"] == 4 and m["cells"][(g["Guest"], g["Users"])]["n"] == 0
    assert g["Guest"] not in m["seen_src"] and m["fw_log"]
    assert S.matrix(conn, cfg, SegCH(ROWS, blocks=None), site, 0, 1)["fw_log"] is False
    ch = SegCH(ROWS)
    S.observe(cfg, ch, site, 0, 1)
    assert "LIMIT {lim:UInt32}" in ch.sql[0][0] and ch.sql[0][1]["lim"] == S.MAX_ROWS and "{wan:String}" in ch.sql[0][0]


def test_detector_raises_findings_and_precise_exception_hides_one(cfg, conn):
    from netmon.detect import Detector
    _setup(conn)
    d = Detector(cfg, SegCH(ROWS), conn)
    d.site = dict(cfg.sites[0], exporter_ip="10.40.0.1")
    fs = d.rule_segmentation(time.time())
    assert {(f["asset"], f["subject"], f["severity"]) for f in fs} == {("10.40.0.5", "10.40.0.130:3389", "medium"),
                                                                       ("10.40.0.130", "10.40.0.200:22", "high")}   # Mgmt is sensitive
    f = next(x for x in fs if x["asset"] == "10.40.0.5")
    assert "Users → Servers" in f["title"] and "only tcp/22, tcp/443 is expected" in f["baseline"]
    now = time.time()
    conn.execute("INSERT INTO exceptions(rule,asset,subject,owner,reason,created_by,created_at,peer,service) VALUES "
                 "('segmentation','10.40.0.5','*','ops','rdp jump host','t',?,'10.40.0.130','tcp/3389')", (now,))
    conn.commit()
    assert d.record(dict(f, site="site-a"), now) == 0
    other = next(x for x in fs if x["asset"] == "10.40.0.130")
    assert d.record(dict(other, site="site-a"), now) == 1


def test_page_roles_and_actions(monkeypatch):
    from test_web import ADMINPW, VIEWPW, client, sid, web
    from netmon import segments_views
    monkeypatch.setattr(segments_views, "ch", SegCH(ROWS, blocks=[]))
    v, ad = client("viewer1", VIEWPW), client("admin", ADMINPW)
    for x in web.conn.execute("SELECT id FROM seg_groups").fetchall():
        web.conn.execute("DELETE FROM seg_groups WHERE id=?", (x[0],))
    web.conn.commit()
    p = v.get("/netmon/segments").text
    assert "Define groups of addresses" in p and "Admins define groups" in p and "never means “blocked”" in p
    tok = web.csrf_token(sid(ad))
    assert v.post("/netmon/segments/groups", data={"site": "site-a", "name": "x", "cidrs": "10.40.0.0/25", "csrf": web.csrf_token(sid(v))}).status_code == 403
    for name, cidrs in (("Users", "10.40.0.0/25"), ("Servers", "10.40.0.128/26")):
        assert ad.post("/netmon/segments/groups", data={"site": "site-a", "name": name, "cidrs": cidrs, "sensitivity": "normal", "csrf": tok},
                       follow_redirects=False).status_code == 303
    ids = {r["name"]: r["id"] for r in web.conn.execute("SELECT id, name FROM seg_groups WHERE site='site-a'")}
    assert ad.post("/netmon/segments/rules", data={"site": "site-a", "src": ids["Users"], "dst": ids["Servers"], "expect": "allow",
                                                   "services": "tcp/443", "csrf": tok}, follow_redirects=False).status_code == 303
    assert ad.post("/netmon/segments/rules", data={"site": "site-a", "src": 0, "dst": 0, "expect": "none", "csrf": tok}).status_code == 400
    page = v.get("/netmon/segments").text
    assert "Communication matrix" in page and "7 unexpected" in page and "Users → Servers: communication expected on tcp/443" in page
    cell = v.get(f"/netmon/segments?cell={ids['Users']}:{ids['Servers']}").text
    assert "unexpected traffic" in cell and "View records" in cell
    assert ad.post("/netmon/segments/template", data={"site": "site-a", "key": "mgmt", "csrf": tok}, follow_redirects=False).status_code == 303
    assert web.conn.execute("SELECT count(*) FROM audit WHERE action LIKE 'segment_%'").fetchone()[0] >= 4
