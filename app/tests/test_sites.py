"""Multiple firewalls (sites): config model, per-vendor flow semantics, pfSense syslog and blocking (synthetic data)."""
import json

import httpx
import pytest

from netmon import block as blk
from netmon.core import apply_sites, flow_predicates, put_setting
from netmon.logingest import parse_line

PF = {"id": "br1", "name": "Branch 1", "vendor": "pfsense", "exporter": "pfsense-br1", "exporter_ip": "10.20.0.1",
      "syslog_source": "10.20.0.1", "wan_if": "igb0", "lan_if": "", "internal_nets": ["10.20.0.0/24"],
      "public_nets": ["203.0.113.8/29"], "outbound_nat_ips": ["203.0.113.9"], "wan_down_mbps": 500, "wan_up_mbps": 100,
      "block": {"base_url": "https://10.20.0.1", "block_alias": "netmon_block", "key_file": ""}}


def test_first_site_inherits_legacy_settings(cfg):
    s = cfg.sites[0]
    assert s["vendor"] == "opnsense" and s["flow_mode"] == "routed"
    assert s["block"]["block_alias"] == cfg["opnsense"]["block_alias"]
    assert s["outbound_nat_ips"] == cfg["outbound_nat_ips"]


def test_ui_site_merges_and_extends_networks(cfg, conn):
    put_setting(conn, "sites:added", [PF], "t")
    apply_sites(cfg, conn)
    assert [x["id"] for x in cfg.sites] == ["site-a", "br1"]
    br = cfg.site("br1")
    assert br["flow_mode"] == "capture"
    assert cfg.is_internal("10.20.0.5") and cfg.is_ours("203.0.113.10")
    assert "203.0.113.9" in cfg["outbound_nat_ips"]
    assert cfg["exporter"] == "fw-a"   # legacy keys keep pointing at the first site


def test_flow_predicates_per_vendor(cfg, conn):
    put_setting(conn, "sites:added", [PF], "t")
    apply_sites(cfg, conn)
    m, p = flow_predicates(cfg, cfg.sites)
    assert (p["fd_re0"], p["fd_rw0"], p["fd_rl0"]) == ("fw-a", "ix0", "bridge0")
    assert "ExporterName = {fd_re0:String} AND InIfName = {fd_rw0:String}" in m["INB"]
    assert "OutIfName = {fd_rl0:String}" in m["TOLAN"] and p["fd_rexp"] == ["fw-a"]
    assert not any("has(" in v for v in m.values())   # per-row tuple has() was ~30x slower on ClickHouse
    # pfSense softflowd: same ifindex both ways -> direction by address on the WAN capture
    assert p["fd_c0"] == "pfsense-br1" and p["fd_ci0"] == "igb0" and "10.20.0.0/24" in p["fd_cn0"]
    assert "isIPAddressInRange" in m["INB"] and "OutIfName" in m["OUTB"]
    m1, p1 = flow_predicates(cfg, [cfg.site("br1")])
    assert "fd_re0" not in p1 and "fd_c0" in p1 and m1["TOLAN"].startswith("((ExporterName = {fd_c0")
    m0, _ = flow_predicates(cfg, [])
    assert m0["INB"] == m0["OUTB"] == m0["TOLAN"] == "(0)"            # no site in scope: matches nothing


def test_pfsense_bsd_syslog_without_hostname():
    site = lambda ip: "br1" if ip == "10.20.0.1" else ip  # noqa: E731
    line = ("1793290000 10.20.0.1 <134>Oct 29 18:00:00 filterlog[63458]: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,"
            "6,tcp,60,198.51.100.7,203.0.113.10,51515,22,0,S,123,,64240,,mss")
    t, r = parse_line(line, site)
    assert t == "fw_events" and r["site"] == "br1" and r["iface"] == "igb0" and r["dport"] == 22 and r["tcpflags"] == "S"
    v6 = ("1793290000 10.20.0.1 <134>Oct 29 18:00:00 filterlog[1]: 5,,,1000000103,igb0,match,block,in,6,0x00,0x00000,64,"
          "tcp,6,20,2001:db8::1,2001:db8::2,443,51000,0,S,1,,64800,,")
    t, r = parse_line(v6, site)
    assert t == "fw_events" and r["src"] == "2001:db8::1"
    # OPNsense BSD format with a hostname still parses the same way
    t, r = parse_line("1793290000 10.40.0.1 <134>Oct 29 12:21:53 fw filterlog[123]: 5,,,abc,ix0,match,block,in,4,"
                      "0x0,,242,54321,0,none,6,tcp,40,198.51.100.7,203.0.113.10,51515,3389,0,S,123,,1024,,", site)
    assert t == "fw_events" and r["dport"] == 3389


def test_pfsense_enforcer_read_modify_write(tmp_path, monkeypatch):
    key = tmp_path / "k"
    key.write_text("abc123\n")
    alias = {"id": 4, "name": "netmon_block", "type": "host", "address": ["198.51.100.1"], "detail": ["old"]}
    seen = []

    def handler(req):
        assert req.headers["X-API-Key"] == "abc123"
        seen.append((req.method, req.url.path))
        if req.method == "GET":
            return httpx.Response(200, json={"code": 200, "data": [alias]})
        body = json.loads(req.content)
        assert len(body["detail"]) <= len(body["address"])
        alias.update(address=body["address"], detail=body["detail"])
        return httpx.Response(200, json={"code": 200, "data": alias})

    site = dict(PF, block={"base_url": "https://fw.test", "block_alias": "netmon_block", "key_file": str(key)})
    fw = blk.enforcer(site)
    monkeypatch.setattr(type(fw), "_client", lambda self: httpx.Client(base_url=self.base_url, transport=httpx.MockTransport(handler),
                                                                       **self._auth()))
    assert isinstance(fw, blk.PfSense) and fw.enabled and fw.alias_exists()
    ok, _ = fw.add("198.51.100.61")
    assert ok and alias["address"] == ["198.51.100.1", "198.51.100.61"] and alias["detail"][0] == "old"
    fw.delete("198.51.100.1")
    assert alias["address"] == ["198.51.100.61"] and len(alias["detail"]) == 1
    assert ("PATCH", "/api/v2/firewall/alias") in seen


def test_opnsense_is_default_enforcer(cfg):
    fw = blk.enforcer(cfg.sites[0])
    assert isinstance(fw, blk.OPNsense) and "alias_util/add/" in fw.describe("198.51.100.61")


@pytest.mark.parametrize("bad, msg", [
    ({"sid": "Bad Id"}, "site id"),
    ({"exporter_ip": "127.0.0.1"}, "not usable"),
    ({"exporter_ip": "10.40.0.1"}, "already used"),
    ({"wan_if": "igb0; rm -rf /"}, "WAN interface"),
    ({"internal_nets": "", "public_nets": ""}, "networks"),
    ({"block_url": "http://10.20.0.1"}, "https"),
])
def test_add_firewall_validation(bad, msg):
    from netmon import admin
    form = {"vendor": "pfsense", "sid": "br9", "name": "B9", "exporter_ip": "10.29.0.1", "wan_if": "igb0",
            "internal_nets": "10.29.0.0/24", **bad}
    with pytest.raises(ValueError, match=msg):
        admin.build_site(form)


def test_add_firewall_ok():
    from netmon import admin
    s = admin.build_site({"vendor": "opnsense", "sid": "dc2", "name": "DC2", "exporter_ip": "10.30.0.1", "wan_if": "igb0",
                          "wan_idx": "1", "lan_if": "igb1", "lan_idx": "2", "down": "1000", "up": "1000"})
    assert s["exporter"] == "opnsense-dc2" and s["flow_mode"] == "routed" and s["syslog_source"] == "10.30.0.1"
    assert s["ifindexes"]["1"]["description"] == "WAN" and s["wan_down_mbps"] == 1000


def test_assets_live_in_db_and_seed_once(cfg, conn):
    from netmon.core import apply_assets, get_setting
    apply_assets(cfg, conn)
    seeded = get_setting(conn, "assets:db")
    assert seeded and cfg.asset(next(iter(seeded)))["name"] == next(iter(seeded.values()))["name"]
    put_setting(conn, "assets:db", {"10.40.0.50": {"name": "web-1", "role": "web", "sensitive": True, "notes": ""}}, "t")
    put_setting(conn, "labels:db", {"198.51.100.7": {"name": "Office VPN", "notes": ""}}, "t")
    cfg._assets_yaml = {"10.40.0.99": {"name": "ignored"}}   # config.yaml no longer wins once the DB has a copy
    apply_assets(cfg, conn)
    assert cfg.asset("10.40.0.50")["sensitive"] and cfg.asset_label("10.40.0.50") == "web-1 (10.40.0.50)"
    assert cfg.asset("10.40.0.99")["name"] == "10.40.0.99"
    assert cfg.label("198.51.100.7") == "Office VPN" and cfg.label("198.51.100.8") == ""


@pytest.mark.parametrize("name", ["<script>", 'a"b', "x'y", "`id`"])
def test_name_rejects_markup(name):
    from netmon.inventory import NAME_RE, clean
    with pytest.raises(ValueError):
        clean(name, NAME_RE, "Name", 64)


def test_vip_sync_imports_names_and_keeps_manual_labels(monkeypatch):
    from netmon import block as blk
    from netmon import inventory as inv
    from netmon.core import get_setting
    rows = [{"subnet": "203.0.113.182", "descr": "mail.example.net", "mode": "ipalias", "interface": "wan"},
            {"subnet": "203.0.113.188", "descr": "web<script>-b", "mode": "ipalias", "interface": "wan"},
            {"subnet": "203.0.113.181", "descr": "", "mode": "ipalias", "interface": "wan"},
            {"subnet": "203.0.113.185", "descr": "cloud.example.net", "mode": "ipalias", "interface": "wan"}]

    class Fw(blk.OPNsense):
        enabled = True

        def _call(self, *a, **k):
            return {"rows": rows}
    monkeypatch.setattr(blk, "enforcer", lambda site: Fw(site))
    put_setting(inv.conn, "labels:db", {"203.0.113.185": {"name": "Cloud (mine)", "notes": ""},
                                        "203.0.113.190": {"name": "gone", "source": "vip:site-a"}}, "t")
    res = inv.sync_vips("t")
    db = get_setting(inv.conn, "labels:db")
    assert res["site-a"] == 2 and db["203.0.113.182"]["name"] == "mail.example.net" and db["203.0.113.182"]["source"] == "vip:site-a"
    assert db["203.0.113.188"]["name"] == "web script -b" and "203.0.113.181" not in db
    assert db["203.0.113.185"]["name"] == "Cloud (mine)" and "203.0.113.190" not in db
    assert inv.cfg.asset_label("203.0.113.182") == "mail.example.net (203.0.113.182)"


def test_one_to_one_nat_sync_attributes_outbound(monkeypatch):
    from netmon import block as blk
    from netmon import inventory as inv
    vips = [{"subnet": "203.0.113.181", "descr": "", "mode": "ipalias", "interface": "wan"}]
    n11 = [{"enabled": "1", "type": "binat", "source_net": "10.40.0.74", "external": "203.0.113.181", "description": "web-a.example.com"},
           {"enabled": "1", "type": "binat", "source_net": "10.40.0.0/24", "external": "203.0.113.176/28", "description": "net"},
           {"enabled": "0", "type": "binat", "source_net": "10.40.0.9", "external": "203.0.113.183", "description": "off"}]

    class Fw(blk.OPNsense):
        enabled = True

        def _call(self, method, path, *a, **k):
            return {"rows": n11 if "one_to_one" in path else vips}
    monkeypatch.setattr(blk, "enforcer", lambda site: Fw(site))
    put_setting(inv.conn, "labels:db", {}, "t")
    inv.sync_vips("t")
    c = inv.cfg
    assert c.binat == {"203.0.113.181": "10.40.0.74"} and c.binat_ext("10.40.0.74") == ["203.0.113.181"]
    assert c.attribute_public("203.0.113.181", 45000, "tcp")[:2] == ("10.40.0.74", "high")
    assert c.label("203.0.113.181") == "web-a.example.com" and "1:1 NAT" in c.raw["labels"]["203.0.113.181"]["notes"]
    assert c.attribute_public("203.0.113.179", 45000, "tcp")[1] == "none"   # shared NAT stays unattributable
