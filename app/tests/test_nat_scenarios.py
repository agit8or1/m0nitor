"""NAT attribution under onboarding failure modes, against a REAL ClickHouse (the attribution is SQL).

Runs only when NETMON_TEST_CH_URL points at a throwaway ClickHouse (CI starts one; locally:
  docker run -d --name nat-ch -e CLICKHOUSE_SKIP_USER_SETUP=1 clickhouse/clickhouse-server:26.3
  NETMON_TEST_CH_URL=http://nat-ch:8123/ pytest tests/test_nat_scenarios.py   (same docker network)
It creates its own database `natsc` and a `netmon.fw_events` table, and refuses to run against anything that looks
like a real install. Synthetic documentation/private addresses only.

Scenarios: WAN-only capture, several hosts behind one shared NAT, asymmetric routing, unanswered connections, clock
skew / export delay, duplicate exports and export loss. The invariant checked for each: compared with the clean
version of the same traffic, no host gains bytes at a higher tier, and wherever the raw evidence alone would
overstate (loss, duplicates) the recorded problem caps the tier and is named.
"""
import copy
import json
import os
import time

import httpx
import pytest

from netmon import access
from netmon import onboarding as O
from netmon.core import ClickHouse, rebuild_sites
from netmon.dash import Dash

URL = os.environ.get("NETMON_TEST_CH_URL", "")
pytestmark = pytest.mark.skipif(not URL, reason="needs NETMON_TEST_CH_URL (throwaway ClickHouse)")

NAT_A, NAT_C = "203.0.113.179", "198.51.100.10"
A, B, C1 = "10.40.0.21", "10.40.0.22", "10.70.0.5"
R, R2 = "192.0.2.80", "192.0.2.81"
DDL = """CREATE TABLE natsc.flows (TimeReceived DateTime, SamplingRate UInt64, ExporterAddress LowCardinality(IPv6),
 ExporterName LowCardinality(String), SrcAddr IPv6, DstAddr IPv6, SrcAS UInt32, DstAS UInt32, SrcCountry FixedString(2),
 DstCountry FixedString(2), InIfName LowCardinality(String), OutIfName LowCardinality(String),
 InIfBoundary Enum8('undefined' = 0, 'external' = 1, 'internal' = 2), OutIfBoundary Enum8('undefined' = 0, 'external' = 1, 'internal' = 2),
 EType UInt32, Proto UInt32, SrcPort UInt16, DstPort UInt16, Bytes UInt64, Packets UInt64, TCPFlags UInt16)
 ENGINE = MergeTree ORDER BY TimeReceived SETTINGS allow_suspicious_low_cardinality_types = 1"""


def raw(sql, body=None, db=None):
    r = httpx.post(URL, params={"query": sql, **({"database": db} if db else {})}, content=body, timeout=30)
    assert r.status_code == 200, r.text[:300]
    return r.text


@pytest.fixture(scope="module", autouse=True)
def database():
    have = raw("SELECT count() FROM system.tables WHERE database = 'netmon' AND total_rows > 10000").strip()
    if have != "0":
        pytest.skip("NETMON_TEST_CH_URL looks like a real install (netmon tables with data): refusing")
    raw("DROP DATABASE IF EXISTS natsc")
    raw("CREATE DATABASE natsc")
    raw(DDL)
    raw("CREATE DATABASE IF NOT EXISTS netmon")
    raw("DROP TABLE IF EXISTS netmon.fw_events")
    raw("CREATE TABLE netmon.fw_events (received DateTime, ts DateTime, site LowCardinality(String), action LowCardinality(String)) "
        "ENGINE = MergeTree ORDER BY received")
    yield
    raw("DROP DATABASE IF EXISTS natsc")
    raw("DROP TABLE IF EXISTS netmon.fw_events")


@pytest.fixture
def sites(cfg):
    """site-a (routed, fixture), site-b (routed, other tenant), site-c (WAN-only capture)."""
    a = copy.deepcopy(cfg.raw["sites"][0])
    b = copy.deepcopy(a)
    b.update(id="site-b", name="Branch B", exporter="fw-b", exporter_ip="10.99.0.1", syslog_source="10.99.0.1",
             internal_nets=["10.40.0.0/24"], public_nets=["198.51.100.96/28"], outbound_nat_ips=["198.51.100.99"], vendor="opnsense")
    c = copy.deepcopy(a)
    c.update(id="site-c", name="Branch C", vendor="pfsense", flow_mode="capture", exporter="fw-c", exporter_ip="10.70.0.1",
             syslog_source="10.70.0.1", wan_if="igb0", lan_if="", internal_nets=["10.70.0.0/24"], public_nets=["198.51.100.0/28"],
             outbound_nat_ips=[NAT_C])
    rebuild_sites(cfg, [a, b, c])
    return cfg


@pytest.fixture
def T0():
    raw("TRUNCATE TABLE natsc.flows")
    raw("TRUNCATE TABLE netmon.fw_events")
    return int(time.time()) // 300 * 300 - 1800        # a 5-minute boundary half an hour ago


def test_ch():
    c = ClickHouse(URL)
    c.client = httpx.Client(timeout=60, params={"database": "natsc"})    # the module's own database, not `default`
    return c


def dash_of(cfg):
    d = Dash(cfg, test_ch())
    d.quality_source = None
    return d


def row(t, ex, src, dst, sp, dp, nbytes, in_if, out_if, flags=0x18, proto=6):
    return {"TimeReceived": t, "SamplingRate": 1, "ExporterAddress": "::ffff:10.40.0.1", "ExporterName": ex,
            "SrcAddr": "::ffff:" + src, "DstAddr": "::ffff:" + dst, "SrcAS": 0, "DstAS": 0, "SrcCountry": "", "DstCountry": "",
            "InIfName": in_if, "OutIfName": out_if, "InIfBoundary": "undefined", "OutIfBoundary": "undefined", "EType": 2048,
            "Proto": proto, "SrcPort": sp, "DstPort": dp, "Bytes": nbytes, "Packets": max(1, nbytes // 1400), "TCPFlags": flags}


def up(t, host_port, nbytes, dst=R, dport=443, ex="fw-a", nat=NAT_A, flags=0x18, wan="ix0", lan="bridge0"):
    """One NATed upload on a routed exporter: WAN egress (post-NAT) record."""
    return row(t, ex, nat, dst, host_port, dport, nbytes, lan, wan, flags)


def reply(t, host, host_port, nbytes=4000, src=R, sport=443, ex="fw-a", wan="ix0", lan="bridge0"):
    """The reply delivered to the LAN host (InIf WAN -> OutIf LAN, destination = real host)."""
    return row(t, ex, src, host, sport, host_port, nbytes, wan, lan)


def insert(rows):
    raw("INSERT INTO natsc.flows FORMAT JSONEachRow", "\n".join(json.dumps(r) for r in rows).encode())


def attribute(cfg, T0, quality=None, site="site-a", rip=""):
    d = dash_of(cfg)
    sc = d.scope(site=site, range_key="custom", start=T0 - 60, end=T0 + 1500, rip=rip)
    return d.nat_attribution(sc, quality=quality)


def by_host(att):
    out = {}
    for h in att["hosts"]:
        out.setdefault(h["host"], {})[h["confidence"]] = out.get(h["host"], {}).get(h["confidence"], 0) + h["bytes"]
    return out


def at_least(att, tier):
    """{host: bytes attributed at `tier` or better}."""
    want = [t for t, r in O.RANK.items() if r >= O.RANK[tier]]
    return {h: sum(b for t, b in tiers.items() if t in want) for h, tiers in by_host(att).items()}


def assert_no_gain(clean, degraded, scale=1):
    """Per-byte monotonicity, in aggregate: bytes at high, at medium-or-better and at low-or-better never exceed the clean
    run of the same traffic (times `scale` when the degraded run legitimately carries more bytes, e.g. duplicates)."""
    for tier in ("high", "medium", "low"):
        c = scale * sum(at_least(clean, tier).values())
        d = sum(at_least(degraded, tier).values())
        assert d <= c, f"{d - c} more bytes at >= {tier} than in the clean run"


def clean_two_hosts(T0):
    return [up(T0 + 10, 40001, 1_500_000), reply(T0 + 12, A, 51001),
            up(T0 + 190, 40002, 3_000_000), reply(T0 + 192, B, 51002)]


def test_clean_two_hosts_different_minutes_are_high(sites, T0):
    insert(clean_two_hosts(T0))
    att = attribute(sites, T0)
    assert by_host(att) == {A: {"high": 1_500_000}, B: {"high": 3_000_000}}
    assert att["ambiguous"] == att["no_return"] == att["unanswered"] == att["wan_only"] == 0
    assert att["total"] == 4_500_000                            # accounting boundary unchanged: WAN egress bytes


def test_shared_nat_same_minute_stays_ambiguous(sites, T0):
    insert([up(T0 + 10, 40001, 1_000_000), up(T0 + 20, 40002, 2_000_000), reply(T0 + 12, A, 51001), reply(T0 + 22, B, 51002)])
    att = attribute(sites, T0)
    assert att["hosts"] == [] and att["ambiguous"] == 3_000_000           # never split, never one host


def test_wan_only_capture_never_names_the_nat_address_or_a_host(sites, T0):
    # capture exporter: the reply is seen on the WAN with the NAT address as destination; no LAN-side record exists
    insert([row(T0 + 10, "fw-c", NAT_C, R, 40001, 443, 2_000_000, "igb0", ""),
            row(T0 + 12, "fw-c", R, NAT_C, 443, 40001, 5000, "igb0", "")])
    att = attribute(sites, T0, site="site-c")
    assert att["hosts"] == [] and att["wan_only"] == 2_000_000 and att["high"] == att["medium"] == att["low"] == 0


def test_asymmetric_return_on_another_firewall_is_not_attributed(sites, T0):
    insert([up(T0 + 10, 40001, 1_500_000), reply(T0 + 12, A, 51001)])
    clean = attribute(sites, T0)
    assert by_host(clean) == {A: {"high": 1_500_000}}
    raw("TRUNCATE TABLE natsc.flows")
    # egress leaves fw-a, the reply comes back through fw-b (other firewall, same internal range): no pairing across exporters
    insert([up(T0 + 10, 40001, 1_500_000), reply(T0 + 12, A, 51001, ex="fw-b")])
    for site in ("site-a", "site-a,site-b", "all"):
        att = attribute(sites, T0, site=site)
        assert att["hosts"] == [] and att["no_return"] == 1_500_000, site
        assert_no_gain(clean, att)


def test_unanswered_attempt_is_never_folded_into_an_answered_host(sites, T0):
    # A's answered upload and B's unanswered SYNs share (remote, port, minute): B's bytes must not become A's
    insert([up(T0 + 10, 40001, 1_000_000), reply(T0 + 12, A, 51001),
            up(T0 + 15, 40002, 180, flags=0x02), up(T0 + 18, 40003, 120, flags=0x02)])
    att = attribute(sites, T0)
    assert by_host(att) == {A: {"high": 1_000_000}}
    assert att["unanswered"] == 300 and att["unanswered_flows"] == 2
    # unanswered alone (nobody else talks to that remote): unanswered, no host
    raw("TRUNCATE TABLE natsc.flows")
    insert([up(T0 + 15, 40002, 180, dst=R2, flags=0x02)])
    att = attribute(sites, T0)
    assert att["hosts"] == [] and att["unanswered"] == 180


def test_clock_skew_and_export_delay_only_lower_confidence(sites, T0):
    insert(clean_two_hosts(T0))
    clean = attribute(sites, T0)
    raw("TRUNCATE TABLE natsc.flows")
    # the replies are received 2 and 7 minutes after the uploads (delayed export from a firewall with a skewed clock)
    insert([up(T0 + 10, 40001, 1_500_000), reply(T0 + 130, A, 51001), up(T0 + 190, 40002, 3_000_000), reply(T0 + 610, B, 51002)])
    skew = attribute(sites, T0)
    # nothing stays high; B's upload pairs with the only host that got replies in its 5 minutes (A) at MEDIUM: the
    # weaker tiers name the only candidate, which is why they are labelled weaker and why decisions use high
    assert skew["high"] == 0 and by_host(skew) == {A: {"medium": 4_500_000}}
    assert_no_gain(clean, skew)


def test_duplicate_exports_never_raise_tiers_and_recorded_duplicates_cap(sites, T0, conn):
    rows = clean_two_hosts(T0)
    insert(rows)
    clean = attribute(sites, T0)
    insert(rows)                                         # every record exported twice
    dup = attribute(sites, T0)
    assert_no_gain(clean, dup, scale=2)
    assert by_host(dup) == {A: {"high": 3_000_000}, B: {"high": 6_000_000}}     # same tiers, never higher
    assert dup["total"] == 2 * clean["total"]            # bytes doubled: visible, which is why it is detected and capped
    q = {"dups": [{"ts": T0 + 300, "site": "site-a", "frac": 0.5, "rows": 4}], "loss": [], "flowdiag": {}}
    capped = attribute(sites, T0, quality=q)
    assert capped["high"] == 0 and capped["medium"] == dup["high"] and capped["capped"]["bytes"] == dup["high"]
    assert any("duplicate" in r for r in capped["capped"]["reasons"])


def test_duplicate_detector_sees_double_exports(sites, conn):
    raw("TRUNCATE TABLE natsc.flows")
    now = int(time.time()) - 120
    rows = [up(now, 40000 + i, 1000 + i) for i in range(100)]
    insert(rows + rows[:50])
    per = O.measure_duplicates(test_ch(), sites.sites)
    assert per["site-a"] == {"rows": 150, "dup": 50}
    O.record_duplicates(conn, per)
    q = O.load_quality(conn)
    assert q["dups"][-1]["site"] == "site-a" and q["dups"][-1]["frac"] == pytest.approx(1 / 3, abs=1e-3)


def test_export_loss_cannot_silently_promote_the_survivor(sites, T0, conn):
    # A and B upload in the same minute; B's reply record is lost on the way. The surviving evidence names only A.
    lossy = [up(T0 + 10, 40001, 1_000_000), up(T0 + 20, 40002, 2_000_000), reply(T0 + 12, A, 51001)]
    insert(lossy)
    plain = attribute(sites, T0)
    assert by_host(plain) == {A: {"high": 3_000_000}}           # what the raw evidence would claim...
    assert any("not been measured" in x for x in plain["limits"])  # ...is never presented without the stated limit
    O.record_loss(conn, 1, "flowdiag sequence gaps", site="site-a", now=T0 + 30)
    att = attribute(sites, T0, quality=O.load_quality(conn))
    assert att["high"] == 0 and att["medium"] == 0 and by_host(att) == {A: {"low": 3_000_000}}
    assert att["capped"]["bytes"] == 3_000_000 and any("export loss" in r for r in att["capped"]["reasons"])
    # collector drops (site None) cap every firewall in the window; loss outside the window does not
    q = {"loss": [{"ts": T0 + 30, "n": 4, "source": "collector receive drops", "site": None}], "dups": [], "flowdiag": {}}
    assert attribute(sites, T0, quality=q)["high"] == 0
    q = {"loss": [{"ts": T0 - 7200, "n": 4, "source": "collector receive drops", "site": None}], "dups": [], "flowdiag": {}}
    assert attribute(sites, T0, quality=q)["high"] == 3_000_000


def test_measured_clean_export_path_removes_the_note(sites, T0):
    insert(clean_two_hosts(T0))
    q = {"loss": [], "dups": [], "flowdiag": {"site-a": {"ts": T0, "lost": 0}}}
    att = attribute(sites, T0, quality=q)
    assert att["limits"] == [] and att["high"] == 4_500_000


def test_restricted_user_sees_only_own_firewall(sites, T0, conn):
    insert(clean_two_hosts(T0) + [up(T0 + 10, 40009, 7_000_000, ex="fw-b", nat="198.51.100.99"), reply(T0 + 12, A, 51009, ex="fw-b")])
    tok = access.set_allowed({"site-a"})
    try:
        att = attribute(sites, T0, site="all")
        assert att["total"] == 4_500_000 and att["nat_ips"] == [NAT_A]          # fw-b's NAT egress and address not included
        d = dash_of(sites)
        with pytest.raises(Exception) as ex:
            O.evaluate(sites, d.ch, d, conn, sites.raw["sites"][1])
        assert getattr(ex.value, "status_code", None) == 404
    finally:
        access.reset(tok)
    assert attribute(sites, T0, site="site-b")["hosts"] == [{"host": A, "bytes": 7_000_000, "confidence": "high"}]


def test_onboarding_sources_against_real_tables(sites, T0, conn):
    now = int(time.time())
    insert([up(now - 120, 40001, 100_000), reply(now - 118, A, 51001), row(now - 100, "fw-a", R, A, 443, 51001, 900, "ix0", "bridge0"),
            row(now - 120, "fw-c", NAT_C, R, 40001, 443, 2000, "igb0", ""), row(now - 118, "fw-c", R, NAT_C, 443, 40001, 900, "igb0", "")])
    raw("INSERT INTO netmon.fw_events FORMAT JSONEachRow", json.dumps({"received": now - 30, "ts": now - 30, "site": "site-a", "action": "block"}).encode())
    d = dash_of(sites)
    ra = O.evaluate(sites, d.ch, d, conn, sites.site("site-a"), monitor="10.40.0.161")
    assert {k: v["state"] for k, v in ra["sources"].items()} == {"wan_flows": "fresh", "lan_return": "fresh", "fw_logs": "fresh", "nat": "fresh"}
    rc = O.evaluate(sites, d.ch, d, conn, sites.site("site-c"), monitor="10.40.0.161")
    st = {k: v["state"] for k, v in rc["sources"].items()}
    assert st["wan_flows"] == "fresh" and st["lan_return"] == "not_possible" and st["nat"] == "not_possible" and st["fw_logs"] == "missing"
    assert "softflowd" in rc["sources"]["lan_return"]["inspect"] and rc["sources"]["lan_return"]["cannot_answer"]
    assert any(q["label"] == "WAN-only capture" and q["state"] == "problem" for q in rc["quality"])
    rb = O.evaluate(sites, d.ch, d, conn, sites.site("site-b"), monitor="10.40.0.161")
    assert rb["verdict"] == "not_ready" and rb["sources"]["wan_flows"]["state"] == "missing"
    assert "10.40.0.161:2055" in rb["sources"]["wan_flows"]["inspect"]


def test_interface_name_mismatch_is_named(sites, T0, conn):
    now = int(time.time())
    insert([row(now - 60, "fw-a", NAT_A, R, 40001, 443, 1000, "em1", "em0")])
    d = dash_of(sites)
    r = O.evaluate(sites, d.ch, d, conn, sites.site("site-a"))
    w = r["sources"]["wan_flows"]
    assert w["state"] == "missing" and "em0" in w["warn"] and "ix0" in w["warn"]


def test_guided_validation_end_to_end(sites, T0, conn):
    s = sites.site("site-a")
    V = "45.83.64.80"            # never contacted: synthetic rows only
    v = O.start_validation(conn, sites, s, A, B, V, 443, "admin", True, now=T0 - 30)
    assert v["status"] == "running" and len(O.steps(v)) == 4
    insert([up(T0 + 10, 40001, 1_520_000, dst=V), reply(T0 + 12, A, 51001, src=V),                     # step 1
            up(T0 + 190, 40002, 3_050_000, dst=V), reply(T0 + 192, B, 51002, src=V),                   # step 2
            up(T0 + 370, 40003, 520_000, dst=V), up(T0 + 372, 40004, 515_000, dst=V),                  # step 3
            reply(T0 + 371, A, 51003, src=V), reply(T0 + 373, B, 51004, src=V),
            up(T0 + 430, 40005, 120, dst=V, dport=9, flags=0x02),                                      # step 4
            up(T0 + 50, 40006, 9_000_000), reply(T0 + 52, "10.40.0.99", 51006)])                       # other traffic: not in the result
    d = dash_of(sites)
    r = O.evaluate_validation(conn, sites, d, s, now=T0 + 900)
    st = {c["check"].split(" (")[0]: c["state"] for c in r["checks"]}
    assert r["verdict"] == "pass", r["checks"]
    assert st["Simultaneous uploads kept ambiguous"] == "pass" and r["totals"]["ambiguous"] == 1_035_000
    assert st["Unanswered attempt not attributed"] == "pass" and r["totals"]["unanswered"] == 120
    # a lost reply during the run: the result is marked as limited, never a silent single-host claim
    O.record_loss(conn, 3, "collector receive drops", now=T0 + 200)
    r = O.evaluate_validation(conn, sites, d, s, now=T0 + 900)
    assert any(c["state"] == "limited" for c in r["checks"]) and r["totals"]["high"] == 0
