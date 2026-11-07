"""Detection testing and replay: synthetic tables are isolated (only values() CTEs, any other table refused), the
sandbox never records, scenarios generate what the rules need, expected vs actual with why/why not (thresholds,
choices, exceptions, expected devices), proposed settings relative to config.yaml, replay job limits/cancel, pages
and roles (synthetic data only; no ClickHouse needed)."""
import time

import pytest

from netmon import dtest as T


class EchoCH:
    def __init__(self, rows=None):
        self.rows, self.sql = rows or [], []

    def query(self, sql, params):
        self.sql.append(sql)
        return self.rows


def test_isolation_rewrites_and_refuses(cfg):
    evil = "x'), (1); DROP TABLE alerts; --"
    s = T.SyntheticCH(EchoCH(), {"flows": [{"TimeReceived": 1, "SrcAddr": "10.40.0.8", "DstAddr": "192.0.2.1", "SrcCountry": evil}]})
    q = s.rewrite("WITH conv AS (SELECT * FROM flows WHERE x) SELECT a FROM conv WHERE a NOT IN (SELECT a FROM conv) -- from secret_table\n")
    assert q.startswith("WITH __syn_flows AS (SELECT * FROM values(") and "FROM __syn_flows WHERE x" in q and "secret_table" not in q
    assert "toIPv6('::ffff:10.40.0.8')" in q and "'x\\'), (1); DROP TABLE alerts; --'" in q         # quoted and escaped, one literal
    q = s.rewrite("select count() from flows_1h0m0s where 1")                       # lowercase and aggregated tables too
    assert "from __syn_flows" in q and "flows_1h0m0s" not in q
    q = s.rewrite("SELECT max(m) FROM (SELECT max(received) AS m FROM netmon.fw_events UNION ALL SELECT max(received) FROM netmon.ids_events)")
    assert "__syn_fw_events AS (SELECT * FROM values(" in q and "WHERE 0)" in q and "netmon.fw_events" not in q
    for bad in ("SELECT * FROM system.tables", "SELECT * FROM netmon.zeek_conn", "SELECT * FROM url('http://x', CSV, 'a String')",
                "SELECT * FROM default.flows", "SELECT a FROM e JOIN other_table USING (a)"):
        with pytest.raises(T.Isolated):
            s.rewrite(bad)
    assert s.rewrite("SELECT 'FROM real_table' AS x FROM flows").count("__syn_flows") == 2      # strings are not references
    with pytest.raises(ValueError):
        T.SyntheticCH(EchoCH(), {"flows": [{}] * (T.MAX_ROWS + 1)})


def test_real_rule_sql_passes_the_isolation_check(cfg, conn):
    """Every query the scenario rules send is rewritten to synthetic tables only."""
    s = cfg.sites[0]
    for key, sc in T.SCENARIOS.items():
        p = T.scenario_params(key, {"device": "10.40.0.8"}, cfg)
        tables, _ = sc["fn"](cfg, s, int(time.time()), p)
        sch = T.SyntheticCH(EchoCH(), tables)
        det = T.SandboxDetector(cfg, sch, conn)
        det.site = s
        T.evaluate(det, sc["rules"], time.time(), days=7)                              # EchoCH returns no rows: no findings
        assert sch.sql and all("__syn_" in q for q in sch.sql if " FROM " in q.upper())
        for q in sch.sql:
            assert "FROM flows" not in q and "netmon." not in q


def test_sandbox_never_records(cfg, conn):
    det = T.SandboxDetector(cfg, EchoCH(), conn)
    with pytest.raises(RuntimeError, match="never records"):
        det.record({"rule": "x"}, time.time())
    assert det.notifier is None


def test_scenarios_generate_what_the_rules_need(cfg):
    s = cfg.sites[0]
    now = int(time.time())
    ws, we = T._window(cfg, now)
    t, exp = T.sc_new_country(cfg, s, now, {"device": "10.40.0.8", "country": "BR", "records": 5})
    cur = [r for r in t["flows"] if r["TimeReceived"] >= ws]
    assert len(cur) == 5 and all(r["SrcCountry"] == "BR" and r["InIfName"] == s["wan_if"] and r["DstAddr"] == "10.40.0.8" for r in cur)
    assert min(r["TimeReceived"] for r in t["flows"]) < now - 6 * 86400 and exp[0]["subject"] == "BR"
    t, exp = T.sc_port_scan(cfg, s, now, {"device": "10.40.0.8", "destinations": 200})
    assert len({r["DstAddr"] for r in t["flows"]}) == 200 and all(not cfg.is_internal(r["DstAddr"]) for r in t["flows"])
    assert exp[0]["asset"] == "203.0.113.179"                                           # outbound records carry the shared NAT address
    t, _ = T.sc_beaconing(cfg, s, now, {"device": "10.40.0.8", "interval": 300, "port": 443})
    gaps = {b["TimeReceived"] - a["TimeReceived"] for a, b in zip(t["flows"][1:], t["flows"])}
    assert gaps == {300}
    with pytest.raises(ValueError):
        T.scenario_params("exposed_port", {"device": "8.8.8.8"}, cfg)
    with pytest.raises(ValueError):
        T.scenario_params("exposed_port", {"device": "10.40.0.8", "port": 70000}, cfg)
    assert T.default_device(cfg) != "10.40.0.1"                                          # not the firewall


def _stub(monkeypatch, findings):
    monkeypatch.setitem(T.RULE_FN, "unexpected_inbound", lambda d, now, days: [dict(f) for f in findings])
    monkeypatch.setattr(T.SandboxDetector, "verify_direction", lambda self, f: {"direction": None, "direction_verified": 0})


def _finding(asset="10.40.0.8", subject="tcp/3389"):
    return {"rule": "unexpected_inbound", "severity": "medium", "asset": asset, "subject": subject, "title": "t", "window": (0, 1),
            "evidence": [{}], "baseline": "Expected exposure = port forwards"}


def test_expected_vs_actual_and_why(cfg, conn, monkeypatch):
    s = cfg.sites[0]
    p = T.scenario_params("exposed_port", {"device": "10.40.0.8"}, cfg)
    _stub(monkeypatch, [_finding()])
    r = T.run_scenario(conn, cfg, EchoCH(), s, "exposed_port", p)
    assert r["passed"] and r["expected"][0]["why"] == ["Expected exposure = port forwards"]
    # an exception hides it: the test says so
    conn.execute("INSERT INTO exceptions(rule,asset,subject,owner,reason,created_by,created_at) VALUES ('unexpected_inbound','10.40.0.8','*','ops','jump host','t',?)",
                 (time.time(),))
    conn.commit()
    r = T.run_scenario(conn, cfg, EchoCH(), s, "exposed_port", p)
    assert not r["passed"] and "hidden by exception #1" in r["expected"][0]["why"][0]
    assert conn.execute("SELECT hits FROM exceptions").fetchone()[0] in (None, 0)          # the dry check records no hit
    # nothing raised: likely reasons from the settings (a port forward exists for tcp/443 on 10.40.0.250)
    _stub(monkeypatch, [])
    r = T.run_scenario(conn, cfg, EchoCH(), s, "exposed_port", T.scenario_params("exposed_port", {"device": "10.40.0.250", "port": 443}, cfg))
    assert any("port forward exists for tcp/443" in w for w in r["expected"][0]["why"])
    r = T.run_scenario(conn, cfg, EchoCH(), s, "exposed_port", T.scenario_params("exposed_port", {"device": "10.40.0.8", "port": 40000}, cfg))
    assert any("ephemeral floor" in w for w in r["expected"][0]["why"])
    # monitoring choice off
    site = dict(s, monitor={"flows": False})
    r = T.run_scenario(conn, cfg, EchoCH(), site, "exposed_port", p)
    assert any("not monitored" in w for w in r["expected"][0]["why"])
    # unexpected extra finding fails the scenario
    _stub(monkeypatch, [_finding(), _finding("10.40.0.9")])
    conn.execute("DELETE FROM exceptions")
    conn.commit()
    r = T.run_scenario(conn, cfg, EchoCH(), s, "exposed_port", p)
    assert not r["passed"] and r["unexpected"][0]["asset"] == "10.40.0.9"


def test_why_not_thresholds(cfg):
    s = cfg.sites[0]
    w = T.why_not(cfg, s, {"rule": "fanout"}, {"destinations": 10}, 7, [])
    assert "10 destinations; the rule needs 150" in w[0]
    w = T.why_not(cfg, s, {"rule": "beaconing"}, {"interval": 3600, "port": 53}, 7, [])
    assert any("check-ins" in x for x in w) and any("ignored" in x for x in w)
    w = T.why_not(cfg, s, {"rule": "new_dest_country"}, {"records": 1}, 1, [])
    assert any("still learning" in x for x in w) and any("needs at least 2" in x for x in w)
    c = T.with_rules(cfg, {"outbound_volume": {"enabled": False}})
    assert "switched off" in T.why_not(c, s, {"rule": "outbound_volume"}, {"volume": 10 ** 10}, 7, [])[0]


def test_proposed_settings_are_relative_to_config_yaml(cfg, conn):
    from netmon.core import apply_overrides, put_setting
    put_setting(conn, "override:rules", {"fanout": {"min_peers": 500}}, "t")
    apply_overrides(cfg, conn)
    assert cfg["rules"]["fanout"]["min_peers"] == 500
    c = T.with_rules(cfg, {}, {})                                    # proposing the defaults really goes back to them
    assert c["rules"]["fanout"]["min_peers"] == 150 and cfg["rules"]["fanout"]["min_peers"] == 500
    assert T.changes(cfg, {}, {}) == [("fanout", "min_peers", 500, 150)]
    assert T.changed_rules(cfg, {"fanout": {"min_peers": 500}}, {}) == []
    assert "new_dest_country" in T.changed_rules(cfg, {"fanout": {"min_peers": 500}}, {"window_minutes": 30})


def test_replay_limits_cancel_and_no_writes(cfg, conn, tmp_path, monkeypatch):
    from netmon.core import db_connect
    path = str(tmp_path / "r.db")
    db_connect(path)
    calls = []

    def fake_eval(det, rules, now, days=None):
        calls.append((det.cfg["rules"]["fanout"]["min_peers"], now))
        time.sleep(0.01)
        n = 3 if det.cfg["rules"]["fanout"]["min_peers"] < 100 else 1
        return [dict(_finding(f"10.40.0.{i}", "horizontal"), rule="fanout", _rule_group="fanout") for i in range(n)], [], [], 7
    monkeypatch.setattr(T, "evaluate", fake_eval)
    jid = T.start_replay(cfg, EchoCH(), lambda: db_connect(path), cfg.sites[0], {"fanout": {"min_peers": 50}}, {}, 86400, "admin")
    with pytest.raises(ValueError, match="already running"):
        T.start_replay(cfg, EchoCH(), lambda: db_connect(path), cfg.sites[0], {}, {}, 86400, "admin")
    j = T.job(jid)
    j.join(30)
    st = j.state
    assert st["status"] == "done" and st["total"] <= T.REPLAY_MAX_WINDOWS and st["result"]["fanout"]["current"] == 1
    assert st["result"]["fanout"]["proposed"] == 3 and len(st["result"]["fanout"]["added"]) == 2
    assert {c[0] for c in calls} == {150, 50}
    c2 = db_connect(path)
    assert c2.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0                    # nothing recorded
    assert c2.execute("SELECT count(*) FROM audit WHERE action='rules_replayed'").fetchone()[0] == 1
    with pytest.raises(ValueError):
        T.start_replay(cfg, EchoCH(), lambda: db_connect(path), cfg.sites[0], {}, {}, 999, "admin")
    jid = T.start_replay(cfg, EchoCH(), lambda: db_connect(path), cfg.sites[0], {"fanout": {"min_peers": 50}}, {}, 7 * 86400, "admin")
    T.job(jid).cancel.set()
    T.job(jid).join(30)
    assert T.job(jid).state["status"] == "cancelled"


def test_pages_roles(monkeypatch):
    from test_incidents import ANALYSTPW
    from test_web import ADMINPW, VIEWPW, client, sid, web
    from netmon import dtest_views
    monkeypatch.setattr(dtest_views, "ch", EchoCH())
    _stub(monkeypatch, [_finding("10.40.0.8")])
    v, an, ad = client("viewer1", VIEWPW), client("analyst1", ANALYSTPW), client("admin", ADMINPW)
    p = v.get(dtest_views.PATH).text
    assert "never written anywhere" in p and "Analysts and admins run detection tests" in p and "Preview rule changes" in p
    assert v.post(dtest_views.PATH, data={"scenario": "exposed_port", "csrf": web.csrf_token(sid(v))}).status_code == 403
    at = web.csrf_token(sid(an))
    r = an.post(dtest_views.PATH, data={"scenario": "exposed_port", "device": "10.40.0.8", "port": "3389", "peers": "20", "csrf": at})
    assert r.status_code == 200 and "as expected" in r.text and "Nothing was recorded or notified" in r.text
    assert an.post(dtest_views.PATH, data={"scenario": "exposed_port", "device": "8.8.8.8", "csrf": at}).status_code == 400
    assert an.post(dtest_views.PATH, data={"scenario": "nope", "csrf": at}).status_code == 400
    # preview from the rules page (admin only): nothing is saved
    tok = web.csrf_token(sid(ad))
    form = {"preview": "1", "fanout.min_peers": "60"}
    for name, rc in web.cfg["rules"].items():
        if rc.get("enabled"):
            form[f"{name}.enabled"] = "1"
    before = web.conn.execute("SELECT v FROM settings WHERE k='override:rules'").fetchone()
    assert an.post("/netmon/settings/rules", data=dict(form, csrf=at)).status_code == 403
    r = ad.post("/netmon/settings/rules", data=dict(form, csrf=tok))
    assert r.status_code == 200 and "Preview rule changes" in r.text and "min peers" in r.text and "Replay on retained data" in r.text
    assert "Save these rules" in r.text
    assert web.conn.execute("SELECT v FROM settings WHERE k='override:rules'").fetchone() == before
    assert ad.post(f"{dtest_views.PATH}/replay", data={"csrf": tok, "changes": "not json", "span": "86400"}).status_code == 400
    assert v.get(f"{dtest_views.PATH}/replay/last").status_code == 403
    assert "Choose" in an.get(dtest_views.PATH, params={"scenario": "beaconing"}).text
