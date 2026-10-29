"""Auto-response: guardrails, dry run, enforcement with expiry, and netmon-owned OPNsense objects (synthetic data)."""
import json

import httpx
import pytest

from netmon import block as blk
from netmon import respond
from netmon.core import put_setting
from netmon.detect import Detector

ATTACKER = "45.83.64.1"


def cand(addr=ATTACKER, trig="bruteforce"):
    return {"address": addr, "trigger": trig, "title": "40 short connections to 22", "window": (0, 600),
            "query": ("SELECT 1", {}), "evidence": {"s": addr, "attempts": 40}}


class FakeFw:
    vendor, auto_alias, enabled = "OPNsense", "netmon_auto", True

    def __init__(self):
        self.alias_set, self.killed = set(), []

    def add(self, a, name=None):
        self.alias_set.add((name, a))
        return True, {"status": "done"}

    def delete(self, a, name=None):
        self.alias_set.discard((name, a))
        return {"status": "done"}

    def kill_states(self, a):
        self.killed.append(a)
        return 2


@pytest.fixture
def r(cfg, conn, monkeypatch):
    fw = FakeFw()
    monkeypatch.setattr(blk, "enforcer", lambda site: fw)
    monkeypatch.setattr(blk, "OPNsense", FakeFw)  # isinstance checks treat the fake as OPNsense
    monkeypatch.setattr(respond, "ready", lambda conn, site: (True, ""))
    x = respond.Responder(cfg, conn, Detector(cfg, None, conn, None))
    monkeypatch.setattr(x, "established", lambda site, a, s: None)
    monkeypatch.setattr(x, "dependency", lambda site, a: None)
    x.fw = fw
    return x


def test_defaults_are_dry_run_and_scans_excluded(conn):
    s = respond.settings(conn)
    assert s["mode"] == "dry_run" and s["triggers"]["ids"]["exclude_scan"] and "scan" not in s["triggers"]


def test_dry_run_logs_and_blocks_nothing(r, cfg, conn):
    site = cfg.sites[0]
    assert r.decide(site, cand(), respond.settings(conn), 1000.0) == "would_block"
    assert not r.fw.alias_set and conn.execute("SELECT count(*) FROM blocks").fetchone()[0] == 0
    assert r.decide(site, cand(), respond.settings(conn), 1100.0) == "seen"   # one log line per hour


@pytest.mark.parametrize("addr, why", [("10.40.0.5", "private"), ("8.8.8.8", "protected"), ("198.51.100.230", "own network")])
def test_guardrails_from_manual_blocking(r, cfg, conn, addr, why):
    put_setting(conn, "response", {"mode": "on"}, "t")
    assert r.decide(cfg.sites[0], cand(addr), respond.settings(conn), 1000.0) == "skipped"
    reason = conn.execute("SELECT reason FROM response_log").fetchone()[0]
    assert why.split()[0] in reason or "overlaps" in reason


def test_allowlist_label_and_human_unblock(r, cfg, conn):
    put_setting(conn, "response", {"mode": "on", "allowlist": ["45.83.64.0/24"]}, "t")
    s, site = respond.settings(conn), cfg.sites[0]
    assert r.decide(site, cand(), s, 1000.0) == "skipped"
    put_setting(conn, "response", {"mode": "on"}, "t")
    cfg.raw["labels"] = {"45.83.64.2": {"name": "Partner VPN"}}
    assert r.decide(site, cand("45.83.64.2"), respond.settings(conn), 1000.0) == "skipped"
    conn.execute("INSERT INTO blocks(address,alias,reason,requested_by,requested_at,status,auto,removed_by,removed_at,site) "
                 "VALUES ('45.83.64.3','netmon_auto','x','auto-response',900,'removed',1,'admin',950,?)", (site["id"],))
    assert r.decide(site, cand("45.83.64.3"), respond.settings(conn), 1000.0) == "skipped"
    reasons = [x[0] for x in conn.execute("SELECT reason FROM response_log ORDER BY id")]
    assert "allowlisted" in reasons[0] and "Partner VPN" in reasons[1] and "removed auto-block" in reasons[2]


def test_block_expires_and_alerts(r, cfg, conn):
    put_setting(conn, "response", {"mode": "on", "ttl_hours": 2}, "t")
    site = cfg.sites[0]
    assert r.decide(site, cand(), respond.settings(conn), 1000.0) == "blocked"
    b = conn.execute("SELECT * FROM blocks").fetchone()
    assert b["auto"] == 1 and b["alias"] == "netmon_auto" and b["expires_at"] == 1000.0 + 7200 and b["status"] == "applied"
    assert ("netmon_auto", ATTACKER) in r.fw.alias_set and r.fw.killed == [ATTACKER]
    a = conn.execute("SELECT * FROM alerts WHERE rule='auto_block'").fetchone()
    assert a and ATTACKER in a["title"] and json.loads(a["evidence"])[0]["block_id"] == b["id"]
    assert r.decide(site, cand(), respond.settings(conn), 1100.0) == "active"
    assert r.expire(5000.0) == 0 and r.expire(9000.0) == 1
    assert conn.execute("SELECT status FROM blocks").fetchone()[0] == "expired" and not r.fw.alias_set


def test_hourly_cap(r, cfg, conn):
    put_setting(conn, "response", {"mode": "on", "max_per_hour": 2}, "t")
    s, site = respond.settings(conn), cfg.sites[0]
    got = [r.decide(site, cand(f"45.83.64.{i}"), s, 1000.0 + i) for i in range(1, 4)]
    assert got == ["blocked", "blocked", "skipped"]
    assert "hourly cap" in conn.execute("SELECT reason FROM response_log ORDER BY id DESC").fetchone()[0]


def test_settings_validation(conn):
    with pytest.raises(ValueError, match="allowlist"):
        respond.save_settings(conn, {"mode": "on", "allowlist": "not-an-ip"}, "t")
    with pytest.raises(ValueError, match="between"):
        respond.save_settings(conn, {"mode": "on", "ttl_hours": "0"}, "t")
    s = respond.save_settings(conn, {"mode": "off", "allowlist": "198.51.100.7 # office\n203.0.113.0/24", "bf_ports": "22 2222",
                                     "bf_enabled": "1"}, "t")
    assert s["allowlist"] == ["198.51.100.7/32", "203.0.113.0/24"] and s["triggers"]["bruteforce"]["ports"] == [22, 2222]
    assert not s["triggers"]["ids"]["enabled"] and respond.settings(conn)["mode"] == "off"


def opn(tmp_path, handler):
    key = tmp_path / "k"
    key.write_text("key:secret\n")
    fw = blk.OPNsense({"id": "site-a", "name": "Site A", "block": {"base_url": "https://fw.test", "block_alias": "netmon_block", "key_file": str(key)}})
    fw._client = lambda: httpx.Client(base_url=fw.base_url, transport=httpx.MockTransport(handler))
    return fw


def test_opnsense_setup_creates_only_netmon_objects(tmp_path):
    made, rules = [], {}

    def handler(req):
        p = req.url.path
        if req.method == "GET" and p.endswith("/category/search_item"):
            return httpx.Response(200, json={"rows": [{"name": "other", "uuid": "c0"}]})
        if req.method == "GET" and p.endswith("/alias/search_item"):
            return httpx.Response(200, json={"rows": [{"name": "GeoIP_BLOCK", "type": "geoip", "uuid": "a0"}]})
        if p.startswith("/api/firewall/filter/get_rule/"):
            u = p.rsplit("/", 1)[1]
            return httpx.Response(200, json={"rule": rules.get(u) or {}})
        if req.method == "POST" and p.endswith("/add_rule"):
            body = json.loads(req.content)["rule"]
            u = f"r{len(rules)}"
            rules[u] = body
            made.append(("rule", body))
            return httpx.Response(200, json={"result": "saved", "uuid": u})
        if req.method == "POST" and p.endswith("/add_item"):
            body = json.loads(req.content)
            made.append((next(iter(body)), body))
            return httpx.Response(200, json={"result": "saved", "uuid": f"u{len(made)}"})
        if p.endswith(("/reconfigure", "/apply")):
            return httpx.Response(200, json={"status": "ok"})
        if "/toggle_rule/" in p:
            return httpx.Response(200, json={"result": "Disabled"})
        raise AssertionError(f"unexpected call {req.method} {p}")
    fw = opn(tmp_path, handler)
    st, done = fw.setup({})
    kinds = [k for k, _ in made]
    assert kinds == ["category", "alias", "alias", "rule", "rule", "rule", "rule"] and len(done) == 7
    for _, body in made[3:]:
        assert body["action"] == "block" and body["interface"] == "" and body["quick"] == "1"
        assert body["description"].startswith(blk.OWN_PREFIX)
        assert {body["source_net"], body["destination_net"]} - {"any"} <= {"netmon_block", "netmon_auto"}
    made.clear()
    st2, done2 = fw.setup({**st})   # idempotent: nothing recreated
    assert not [k for k, _ in made if k == "rule"] and set(st2["rules"]) == {"block_in", "block_out", "auto_in", "auto_out"}
    assert fw.toggle(st2, "auto_in", False) == "Disabled"
    rules[st2["rules"]["auto_out"]]["description"] = "someone renamed it"
    with pytest.raises(blk.BlockError, match="not a netmon rule"):
        fw.toggle(st2, "auto_out", False)


def test_kill_states_matches_exact_address(tmp_path):
    deleted = []

    def handler(req):
        if req.url.path.endswith("/query_states"):
            return httpx.Response(200, json={"rows": [
                {"id": "aa/01", "src_addr": "45.83.64.1", "dst_addr": "10.40.0.240"},
                {"id": "bb/01", "src_addr": "45.83.64.12", "dst_addr": "10.40.0.240"},
                {"id": "cc/02", "src_addr": "10.40.0.5", "dst_addr": "45.83.64.1"}]})
        deleted.append(req.url.path)
        return httpx.Response(200, json={"result": ""})
    assert opn(tmp_path, handler).kill_states("45.83.64.1") == 2
    assert deleted == ["/api/diagnostics/firewall/del_state/aa/01", "/api/diagnostics/firewall/del_state/cc/02"]


def test_setup_failure_keeps_what_was_created(tmp_path):
    def handler(req):
        p = req.url.path
        if req.method == "GET":
            return httpx.Response(200, json={"rows": []})
        if p.endswith("/add_rule"):
            return httpx.Response(200, json={"result": "failed", "validations": {"rule.interface": "bad"}})
        if p.endswith("/add_item"):
            return httpx.Response(200, json={"result": "saved", "uuid": "u1"})
        return httpx.Response(200, json={"status": "ok"})
    with pytest.raises(blk.BlockError) as ex:
        opn(tmp_path, handler).setup({})
    assert ex.value.state["category"] == "u1" and len(ex.value.state["aliases"]) == 2 and not ex.value.state["rules"]


def test_block_creates_missing_objects_first(r, cfg, conn, monkeypatch):
    put_setting(conn, "response", {"mode": "on"}, "t")
    state = {"ok": False}
    monkeypatch.setattr(respond, "ready", lambda conn, site: (state["ok"], "netmon rules not created"))

    def ensure(conn, site, user="auto-response"):
        state["ok"] = True
        return ["created rule"]
    monkeypatch.setattr(respond, "ensure_objects", ensure)
    assert r.decide(cfg.sites[0], cand(), respond.settings(conn), 1000.0) == "blocked"
    put_setting(conn, "response", {"mode": "on", "auto_setup": False}, "t")
    state["ok"] = False
    assert r.decide(cfg.sites[0], cand("45.83.64.9"), respond.settings(conn), 1000.0) == "skipped"


def test_exception_subject_prefix_wildcard():
    from netmon.detect import exception_matches
    x = {"enabled": 1, "expires_at": None, "rule": "ids_alert", "asset": "10.40.0.74", "subject": "2000328|*"}
    assert exception_matches(x, "ids_alert", "10.40.0.74", "2000328|192.0.2.163", 1.0)
    assert not exception_matches(x, "ids_alert", "10.40.0.74", "2029022|192.0.2.163", 1.0)
    assert not exception_matches(x, "ids_alert", "203.0.113.179", "2000328|192.0.2.163", 1.0)
    assert not exception_matches({**x, "expires_at": 0.5}, "ids_alert", "10.40.0.74", "2000328|1.2.3.4", 1.0)
