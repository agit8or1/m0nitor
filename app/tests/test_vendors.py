"""Multi-vendor parsing, device ownership and capability honesty. All fixtures are synthetic, written from the
vendors' documented log formats, with documentation (RFC 5737 / RFC 3849) and private addresses only."""
import os

import pytest

from netmon import parsers, vendors
from netmon.logingest import RateLimit, parse_line

M4 = lambda a: "::ffff:" + a  # noqa: E731
FGT = {"id": "fgt1", "site": "s1", "name": "FortiGate", "vendor": "fortigate", "wan_if": "wan1"}
PAN = {"id": "pa1", "site": "s2", "name": "PA-440", "vendor": "panos", "wan_if": "ethernet1/1"}
GEN = {"id": "sw1", "site": "s1", "name": "Switch", "vendor": "generic"}
MTK = {"id": "mt1", "site": "s1", "name": "hEX", "vendor": "mikrotik", "wan_if": "ether1"}
SENDERS = {"192.0.2.10": FGT, "192.0.2.20": PAN, "192.0.2.30": GEN, "192.0.2.40": MTK}


def run(sender, msg, recv=1793290000):
    return parse_line(f"{recv} {sender} {msg}", lambda ip: "unknown-site", SENDERS.get)


def rows(res, table):
    t, r = res
    if t == "multi":
        return [x for tt, x in r if tt == table]
    return [r] if t == table else []


# ---- FortiGate ---------------------------------------------------------------------------------------------------
FGT_DENY = ('<189>date=2026-10-31 time=12:00:00 devname="FGT60F" devid="FGT60F0000000000" eventtime=1793448000000000000 '
            'tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=198.51.100.7 '
            'srcport=51515 srcintf="wan1" srcintfrole="wan" dstip=10.20.0.5 dstport=22 dstintf="internal" dstintfrole="lan" '
            'sessionid=12345 proto=6 action="deny" policyid=0 policytype="policy" service="SSH" sentbyte=0 rcvdbyte=0')


def test_fortigate_traffic_deny_is_a_block_with_direction():
    fw = rows(run("192.0.2.10", FGT_DENY), "fw_events")
    assert len(fw) == 1
    r = fw[0]
    assert r["action"] == "block" and r["dir"] == "in" and r["src"] == M4("198.51.100.7") and r["dport"] == 22
    assert r["device"] == "fgt1" and r["vendor"] == "fortigate" and r["site"] == "s1" and r["proto"] == "tcp"
    assert r["ts"] == 1793448000.0


def test_fortigate_ips_and_vpn_and_login():
    ips = ('<185>date=2026-10-31 time=12:01:00 tz="+0000" logid="0419016384" type="utm" subtype="ips" level="alert" '
           'severity="critical" srcip=198.51.100.9 dstip=10.20.0.5 srcport=4444 dstport=443 proto=6 action="dropped" '
           'attack="Example.Exploit.Test" attackid=55555 srcintf="wan1" srcintfrole="wan"')
    r = rows(run("192.0.2.10", ips), "ids_events")[0]
    assert r["action"] == "blocked" and r["sig_id"] == 55555 and r["severity"] == 1 and r["signature"] == "Example.Exploit.Test"
    vpn = ('<189>date=2026-10-31 time=12:02:00 tz="+0000" logid="0101037138" type="event" subtype="vpn" level="notice" '
           'action="tunnel-down" remip=203.0.113.50 vpntunnel="branch-a" logdesc="IPsec tunnel down"')
    ev = rows(run("192.0.2.10", vpn), "events")[0]
    assert ev["category"] == "vpn" and ev["outcome"] == "down" and ev["object"] == "branch-a" and ev["src"] == M4("203.0.113.50")
    login = ('<190>date=2026-10-31 time=12:03:00 tz="+0000" logid="0100032002" type="event" subtype="system" level="alert" '
             'logdesc="Admin login failed" user="admin" ui="https(198.51.100.77)" action="login" status="failed"')
    a = rows(run("192.0.2.10", login), "auth_events")[0]
    assert a["event"] == "login_failed" and a["user"] == "admin" and a["src"] == M4("198.51.100.77") and a["device"] == "fgt1"


# ---- PAN-OS ------------------------------------------------------------------------------------------------------
def pan_traffic(action, sub="end"):
    f = ["1", "2026/10/31 12:00:00", "012345678901", "TRAFFIC", sub, "2560", "2026/10/31 12:00:00", "198.51.100.7",
         "10.30.0.5", "0.0.0.0", "0.0.0.0", "deny-inbound", "", "", "ssh", "vsys1", "untrust", "trust", "ethernet1/1",
         "ethernet1/2", "fwd", "", "4242", "1", "51515", "22", "0", "0", "0x0", "tcp", action, "120", "60", "60", "2"]
    return "<14>Oct 31 12:00:00 PA-440 " + ",".join(f)


def test_panos_traffic_csv_and_start_lines_not_double_counted():
    r = rows(run("192.0.2.20", pan_traffic("deny")), "fw_events")[0]
    assert r["action"] == "block" and r["dir"] == "in" and r["dport"] == 22 and r["site"] == "s2" and r["device"] == "pa1"
    assert rows(run("192.0.2.20", pan_traffic("allow")), "fw_events")[0]["action"] == "pass"
    assert run("192.0.2.20", pan_traffic("allow", "start"))[0] == "skip"


def test_panos_threat_and_config():
    f = ["1", "2026/10/31 12:00:00", "012345678901", "THREAT", "vulnerability", "2560", "2026/10/31 12:00:00",
         "198.51.100.8", "10.30.0.5", "", "", "allow-web", "", "", "web-browsing", "vsys1", "untrust", "dmz", "ethernet1/1",
         "ethernet1/3", "fwd", "", "77", "1", "40000", "80", "0", "0", "0x0", "tcp", "reset-both", "", "Example RCE(91234)",
         "code-execution", "critical", "client-to-server"]
    r = rows(run("192.0.2.20", "<14>Oct 31 12:00:00 PA-440 " + ",".join(f)), "ids_events")[0]
    assert r["sig_id"] == 91234 and r["signature"] == "Example RCE" and r["action"] == "blocked" and r["severity"] == 1
    c = ["1", "2026/10/31 12:05:00", "012345678901", "CONFIG", "0", "2560", "2026/10/31 12:05:00", "198.51.100.200", "vsys1",
         "edit", "admin", "Web", "Succeeded", "vsys vsys1 rulebase security rules allow-web"]
    ev = rows(run("192.0.2.20", "<14>Oct 31 12:05:00 PA-440 " + ",".join(c)), "events")[0]
    assert ev["category"] == "config" and ev["user"] == "admin" and ev["outcome"] == "change"


# ---- Cisco -------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("line,act,src,dport", [
    ('%ASA-4-106023: Deny tcp src outside:198.51.100.7/51515 dst inside:10.40.0.5/22 by access-group "OUTSIDE_IN" [0x0, 0x0]', "block", "198.51.100.7", 22),
    ("%ASA-2-106001: Inbound TCP connection denied from 198.51.100.7/51515 to 10.40.0.5/23 flags SYN  on interface outside", "block", "198.51.100.7", 23),
    ("%ASA-6-302013: Built inbound TCP connection 77 for outside:198.51.100.7/51515 (198.51.100.7/51515) to inside:10.40.0.5/443 (203.0.113.5/443)", "allow", "198.51.100.7", 443),
    ("%FTD-4-106023: Deny udp src outside:2001:db8::7/5353 dst inside:2001:db8:1::5/53 by access-group \"X\" [0x0, 0x0]", "block", "2001:db8::7", 53),
    ("%SEC-6-IPACCESSLOGP: list OUTSIDE-IN denied tcp 198.51.100.7(51515) (GigabitEthernet0/0 ) -> 203.0.113.2(22), 1 packet", "block", "198.51.100.7", 22),
])
def test_cisco_traffic(line, act, src, dport):
    dev = {"id": "c1", "site": "s1", "name": "asa", "vendor": "cisco_asa", "wan_if": "outside"}
    evs = parsers.get("cisco").parse("<164>Oct 31 2026 12:00:00: " + line, "", line, dev)
    assert evs[0]["action"] == act and evs[0]["src"] == parsers.ip(src) and evs[0]["dport"] == dport


def test_cisco_teardown_recognized_not_stored_and_state_events():
    p = parsers.get("cisco").parse
    assert p("%ASA-6-302014: Teardown TCP connection 77 for outside:198.51.100.7/51515 to inside:10.40.0.5/443 duration 0:00:01 bytes 100 TCP FINs", "", "", {}) == []
    e = p("%ASA-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = admin : user IP = 198.51.100.9", "", "", {})[0]
    assert e["category"] == "auth" and e["outcome"] == "failure" and e["user"] == "admin" and e["src"] == parsers.ip("198.51.100.9")
    assert p("%ASA-1-104001: (Secondary) Switching to ACTIVE - Service card in other unit has failed.", "", "", {})[0]["category"] == "ha"
    e = p("%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down", "", "", {})[0]
    assert e["category"] == "interface" and e["outcome"] == "down" and e["object"] == "GigabitEthernet0/1"
    e = p("%BGP-5-ADJCHANGE: neighbor 192.0.2.254 Down BGP Notification sent", "", "", {})[0]
    assert e["category"] == "routing" and e["outcome"] == "down"
    e = p("%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 198.51.100.4] [localport: 22] [Reason: Login Authentication Failed]", "", "", {})[0]
    assert e["outcome"] == "failure" and e["src"] == parsers.ip("198.51.100.4")


# ---- Junos, MikroTik, netfilter family, Meraki, kv firewalls, WatchGuard, Huawei -----------------------------------
def test_junos_sd_syslog():
    line = ('<14>1 2026-10-31T12:00:00.000Z srx1 RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.129 source-address="198.51.100.7" '
            'source-port="51515" destination-address="10.50.0.5" destination-port="22" service-name="junos-ssh" protocol-id="6" '
            'policy-name="deny-all" source-zone-name="untrust" destination-zone-name="trust" packet-incoming-interface="ge-0/0/0.0" '
            'reason="policy deny"] session denied')
    e = parsers.get("junos").parse(line, "RT_FLOW", "", {"wan_zones": ["untrust"]})[0]
    assert e["action"] == "block" and e["dir"] == "in" and e["rule"] == "deny-all" and e["proto"] == "tcp"
    assert parsers.get("junos").parse(line.replace("SESSION_DENY", "SESSION_CREATE"), "RT_FLOW", "", {}) == []
    c = parsers.get("junos").parse("<29>Oct 31 12:00:00 srx1 mgd[123]: UI_COMMIT: User 'admin' requested 'commit' operation", "mgd", "", {})[0]
    assert c["category"] == "config" and c["user"] == "admin"


def test_mikrotik_action_only_from_prefix():
    base = ("in:ether1 out:bridge, connection-state:new src-mac 00:00:5e:00:53:01, proto TCP (SYN), "
            "198.51.100.7:51515->10.60.0.5:22, len 60")
    no_prefix = run("192.0.2.40", f"<30>Oct 31 12:00:00 hEX firewall,info forward: {base}")
    assert rows(no_prefix, "fw_events") == []                       # action unknown: never a block
    ev = rows(no_prefix, "events")[0]
    assert ev["category"] == "traffic" and ev["action"] == "unknown"
    with_prefix = run("192.0.2.40", f"<30>Oct 31 12:00:00 hEX firewall,info DROP forward: {base}")
    r = rows(with_prefix, "fw_events")[0]
    assert r["action"] == "block" and r["dir"] == "in" and r["dport"] == 22
    a = rows(run("192.0.2.40", "<30>Oct 31 12:00:00 hEX system,error,critical login failure for user admin from 198.51.100.66 via ssh"), "auth_events")[0]
    assert a["event"] == "login_failed" and a["src"] == M4("198.51.100.66")


@pytest.mark.parametrize("msg,act", [
    ("[WAN_IN-default-D]IN=eth0 OUT=eth1 MAC=00 SRC=198.51.100.7 DST=10.70.0.5 LEN=60 TOS=0x00 PROTO=TCP SPT=51515 DPT=22 SYN", "block"),
    ("[ipv4-FWD-filter-10-A]IN=eth0 OUT=eth1 SRC=198.51.100.7 DST=10.70.0.5 LEN=52 PROTO=UDP SPT=5353 DPT=53", "allow"),
    ("m0nitor DROP: IN=eth0 OUT= MAC=00 SRC=2001:db8::7 DST=2001:db8:1::1 LEN=80 PROTO=TCP SPT=1 DPT=443", "block"),
    ("drop wan in: IN=wan OUT= SRC=198.51.100.7 DST=203.0.113.1 LEN=40 PROTO=TCP SPT=1 DPT=23", "block"),
    ("IN=eth0 OUT= SRC=198.51.100.7 DST=203.0.113.1 LEN=40 PROTO=TCP SPT=1 DPT=23", "unknown"),
])
def test_netfilter_prefixes(msg, act):
    e = parsers.get("netfilter").parse("", "kernel", msg, {"wan_if": "eth0"})[0]
    assert e["action"] == act and e["src"] is not None


def test_meraki_header_and_actions():
    flows = "<134>1 1793448000.123456789 MX68 flows deny src=198.51.100.7 dst=10.80.0.5 mac=00:00:5E:00:53:01 protocol=tcp sport=51515 dport=22"
    e = parsers.get("meraki").parse(flows, "", flows, {})[0]
    assert e["action"] == "block" and e["ts"] == pytest.approx(1793448000.12, abs=0.01)
    old = "<134>1 1793448000.1 MX68 firewall src=10.80.0.5 dst=198.51.100.53 protocol=udp sport=5353 dport=53 pattern: allow all"
    assert parsers.get("meraki").parse(old, "", old, {})[0]["action"] == "allow"
    vpn = "<134>1 1793448000.1 MX68 events type=vpn_connectivity_change vpn_type='site-to-site' peer_contact='203.0.113.9:51856' peer_ident='abc' connectivity='false'"
    assert parsers.get("meraki").parse(vpn, "", vpn, {})[0]["outcome"] == "down"


def test_sonicwall_sophos_checkpoint():
    p = parsers.get("kv").parse
    sw = ('<134>id=firewall sn=0017C5000000 time="2026-10-31 12:00:00" fw=203.0.113.1 pri=6 c=262144 m=537 msg="Connection Closed" '
          'src=198.51.100.7:51515:X1 dst=10.90.0.5:443:X0 proto=tcp/https sent=1200 rcvd=3400 fw_action="drop"')
    e = p(sw, "", sw, {"wan_if": "X1"})[0]
    assert e["action"] == "block" and e["dir"] == "in" and e["bytes"] == 4600
    assert p(sw.replace('m=537 msg="Connection Closed"', 'm=98 msg="Connection Opened"').replace(' fw_action="drop"', ""), "", "", {}) == []
    so = ('<30>device="SFW" date=2026-10-31 time=12:00:00 timezone="UTC" device_name="XG" log_id=010101600001 log_type="Firewall" '
          'log_component="Firewall Rule" log_subtype="Denied" status="Deny" fw_rule_id=5 src_ip=198.51.100.7 dst_ip=10.91.0.5 '
          'protocol="TCP" src_port=51515 dst_port=3389 src_zone_type="WAN" dst_zone_type="LAN"')
    e = p(so, "", so, {})[0]
    assert e["action"] == "block" and e["dir"] == "in" and e["dport"] == 3389
    cp = ('<134>1 2026-10-31T12:00:00Z gw1 CheckPoint 1234 - [action:"Drop"; ifdir:"inbound"; ifname:"eth1"; src:"198.51.100.7"; '
          'dst:"10.92.0.5"; proto:"6"; s_port:"51515"; service:"22"; product:"VPN-1 & FireWall-1"; rule_name:"Cleanup"]')
    e = p(cp, "", cp, {"wan_if": "eth1"})[0]
    assert e["action"] == "block" and e["dir"] == "in" and e["rule"] == "Cleanup" and e["proto"] == "tcp"


def test_watchguard_and_huawei():
    wg = ('<142>Oct 31 12:00:00 Firebox (2026-10-31T12:00:00) firewall: msg_id="3000-0148" Deny 0-External Firebox 60 tcp 20 51 '
          '198.51.100.7 203.0.113.2 51515 22 offset 10 S 1234 win 1024 (Unhandled External Packet-00)')
    e = parsers.get("watchguard").parse(wg, "", "", {"wan_if": "0-External"})[0]
    assert e["action"] == "block" and e["dport"] == 22 and e["dir"] == "in" and e["rule"] == "Unhandled External Packet-00"
    hw = ("<190>Oct 31 2026 12:00:00 USG6000 %%01POLICY/6/POLICYDENY(l):vsys=public, protocol=6, source-ip=198.51.100.7, "
          "source-port=51515, destination-ip=10.93.0.5, destination-port=22, time=2026/10/31 12:00:00, source-zone=untrust, "
          "destination-zone=trust, rule-name=deny_ssh.")
    e = parsers.get("huawei").parse(hw, "", "", {"wan_zones": ["untrust"]})[0]
    assert e["action"] == "block" and e["dir"] == "in" and e["rule"] == "deny_ssh"


# ---- ownership, generic devices, malformed input -------------------------------------------------------------------
def test_two_vendors_and_generic_simultaneously_without_cross_contamination():
    a = rows(run("192.0.2.10", FGT_DENY), "fw_events")[0]
    b = rows(run("192.0.2.20", pan_traffic("deny")), "fw_events")[0]
    c = run("192.0.2.30", "<187>Oct 31 12:00:00 sw1 %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down")
    assert (a["device"], a["site"]) == ("fgt1", "s1") and (b["device"], b["site"]) == ("pa1", "s2")
    ev = rows(c, "events")
    assert ev and ev[0]["device"] == "sw1" and ev[0]["category"] == "interface" and rows(c, "fw_events") == []


def test_generic_device_never_yields_firewall_decisions():
    line = "<134>Oct 31 12:00:00 sw1 kernel: DROP IN=eth0 OUT= SRC=198.51.100.7 DST=203.0.113.1 LEN=40 PROTO=TCP SPT=1 DPT=23"
    res = run("192.0.2.30", line)
    assert rows(res, "fw_events") == []
    assert res[0] == "sys_events" and res[1]["kind"] == "unparsed" and res[1]["device"] == "sw1"   # kept, not dropped
    assert vendors.PROFILES["generic"]["decisions"] is False


@pytest.mark.parametrize("junk", ["", "<", "<999999>", "<13>" + "A" * 50000, "<14>Oct 31 12:00:00 x %ASA-4-106023: Deny",
                                  "<14>1 - - - - - - " + "\x00\xff" * 10, 'id=firewall m=1 src=::::::: dst="', "logid= type=",
                                  "<14>Oct 31 12:00:00 PA 1,2026/10/31 12:00:00,1,TRAFFIC,end,1"])
def test_malformed_input_never_raises(junk):
    for s in SENDERS:
        t, r = run(s, junk)
        assert t in (None, "sys_events", "multi", "skip", "auth_events")


def test_rate_limit_is_per_receipt_second_and_per_sender():
    rl = RateLimit(3)
    assert [rl.ok("a", "100") for _ in range(4)] == [True, True, True, False]
    assert rl.ok("b", "100") and rl.ok("a", "101")


def test_opnsense_path_unchanged_with_device_registry():
    opn = {"id": "s1", "site": "s1", "name": "fw", "vendor": "opnsense"}
    line = ("1793290000 10.40.0.1 <134>1 2026-10-29T12:21:53+00:00 fw filterlog 123 - [meta sequenceId=\"1\"] "
            "5,,,abc,ix0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.7,203.0.113.2,51515,22,0,S,1,,64240,,mss")
    t, r = parse_line(line, lambda ip: "s1", {"10.40.0.1": opn}.get)
    t0, r0 = parse_line(line, lambda ip: "s1")
    assert t == t0 == "fw_events" and {k: v for k, v in r.items() if k not in ("device", "vendor")} == r0
    assert r["device"] == "s1"


# ---- capabilities, enforcement, docs -----------------------------------------------------------------------------
def test_profiles_are_consistent_and_parsers_exist():
    for k, p in vendors.PROFILES.items():
        assert p["status"] in (vendors.VERIFIED, vendors.PARTIAL, vendors.GENERIC, vendors.UNSUPPORTED)
        assert set(p["flows"]) == set(vendors.FLOW_PROTOCOLS) and set(p["categories"]) <= set(vendors.CATEGORIES)
        if p["parser"] and p["parser"] != "opnsense":
            assert parsers.get(p["parser"]) is not None, k
        if p["status"] == vendors.PARTIAL:
            assert p["parser"], f"{k}: PARTIAL needs an implemented parser"
        if p["decisions"]:
            assert "traffic" in p["categories"]
    assert [k for k, p in vendors.PROFILES.items() if p["status"] == vendors.VERIFIED] == ["opnsense"]


def test_enforcement_only_where_an_adapter_exists():
    from netmon import block
    assert block.enforcer({"vendor": "opnsense"}).__class__.__name__ == "OPNsense"
    assert block.enforcer({"vendor": "pfsense"}).__class__.__name__ == "PfSense"
    f = block.enforcer({"vendor": "fortigate", "block": {"base_url": "https://192.0.2.10", "key_file": "/nonexistent"}})
    assert not f.enabled
    with pytest.raises(block.BlockError):
        f.add("198.51.100.7")


def test_vendor_matrix_doc_matches_profiles():
    doc = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "vendors.md")
    if not os.path.exists(doc):
        pytest.skip("docs not in this tree (app image)")
    assert vendors.matrix_markdown() in open(doc).read()


def test_schema_migrations_are_additive():
    from netmon import schema
    assert all(s.startswith("ALTER TABLE netmon.") and "ADD COLUMN IF NOT EXISTS" in s for s in schema.MIGRATIONS)
    assert all("IF NOT EXISTS" in s for s in schema.statements())


# ---- detection over normalized device events ---------------------------------------------------------------------
class EventCH:
    """Answers the device-event queries with synthetic rows; records the SQL so site/device scoping can be checked."""

    def __init__(self, rows):
        self.rows, self.sql = rows, []

    def query(self, sql, params):
        self.sql.append((sql, params))
        for key, rows in self.rows.items():
            if key in sql:
                return rows
        return []


def test_event_rules_name_device_and_cite_evidence(cfg, conn):
    from netmon.detect import Detector
    cfg.raw["devices"] = [{"id": "fgt1", "site": "site-a", "name": "Branch FortiGate", "vendor": "fortigate",
                           "syslog_source": "192.0.2.10"}]
    ch = EventCH({"category = 'vpn'": [{"device": "fgt1", "object": "branch-a", "events": 2, "by_user": "", "state": "down",
                                       "kinds": ["event/vpn"], "messages": ["IPsec tunnel down"], "last": 1793448000,
                                       "original": ["<189>date=... action=\"tunnel-down\""]}],
                  "event = 'login_failed'": [{"device": "fgt1", "s": "198.51.100.77", "events": 12, "users": ["admin"],
                                          "via": ["https"], "last": 1793448000}]})
    d = Detector(cfg, ch, conn)
    d.site = cfg.sites[0]
    f = d.rule_events(1793448100)
    vpn = next(x for x in f if x["rule"] == "vpn_tunnel_down")
    assert vpn["asset"] == "fgt1" and "Branch FortiGate" in vpn["title"] and "branch-a" in vpn["title"]
    assert vpn["evidence"][0]["original"] and vpn["confidence"] == "high" and vpn["next_steps"]
    au = next(x for x in f if x["rule"] == "device_auth_failures")
    assert au["subject"] == "198.51.100.77" and "12 failed logins" in au["title"]
    assert all(p.get("site") == "site-a" for _, p in ch.sql if "site" in p)      # scoped to the site being evaluated
    # ClickHouse rejects an aggregate alias that shadows a column used in WHERE (ILLEGAL_AGGREGATION)
    import re
    for sql, _ in ch.sql:
        where = sql.split("WHERE", 1)[1].split("GROUP BY")[0] if "WHERE" in sql else ""
        for alias in re.findall(r"\)\s+AS\s+(\w+)", sql.split("FROM", 1)[0]):
            assert not re.search(rf"\b{alias}\b", where), f"alias {alias} shadows a WHERE column"


def test_event_rules_tolerate_unmigrated_schema(cfg, conn):
    from netmon.detect import Detector

    class Old:
        def query(self, sql, params):
            raise RuntimeError("ClickHouse 404: Code: 60. DB::Exception: Table netmon.events does not exist. (UNKNOWN_TABLE)")
    d = Detector(cfg, Old(), conn)
    d.site = cfg.sites[0]
    assert d.rule_events(1793448100) == []


def test_event_rule_defaults_seeded_for_existing_configs(cfg):
    for k in ("vpn_tunnel_down", "interface_down", "device_auth_failures", "ha_failover", "config_change", "device_silence"):
        assert cfg["rules"][k]["enabled"] is True
