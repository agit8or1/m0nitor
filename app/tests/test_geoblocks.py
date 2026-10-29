"""Logged firewall blocks by country: direction attribution, coverage states, de-duplication (synthetic fixtures only)."""
import ipaddress
import time

import pytest

from netmon import geoblocks as gb

OURS = [ipaddress.ip_network(n) for n in ("10.40.0.0/24", "203.0.113.176/28")]
SITE = {"id": "site-a", "name": "Site A"}
GEO_RULE = "00000000-0000-4000-8000-000000000001"


@pytest.mark.parametrize("src, dst, want", [
    ("::ffff:198.51.100.61", "::ffff:203.0.113.179", ("in", "198.51.100.61")),     # to the firewall's public address: source country
    ("198.51.100.61", "10.40.0.250", ("in", "198.51.100.61")),                    # after rdr/binat the destination is internal
    ("10.40.0.74", "198.51.100.76", ("out", "198.51.100.76")),            # outbound: destination country
    ("::ffff:203.0.113.181", "1.2.3.4", ("out", "1.2.3.4")),
    ("10.9.9.9", "203.0.113.179", ("ambiguous", None)),                      # private "external" end is never given a country
    ("fe80::1", "ff02::1:2", ("ambiguous", None)),
    ("198.51.100.61", "8.8.8.8", ("ambiguous", None)),                            # both external
    ("10.40.0.5", "203.0.113.179", ("ambiguous", None)),                  # both ours
])
def test_direction_relative_to_protected_network(src, dst, want):
    assert gb.classify(OURS, src, dst) == want


def row(src, dst, events=1, rid="r", nbytes=60, last=100, site="site-a", iface="ix0"):
    return {"site": site, "rid": rid, "iface": iface, "src": src, "dst": dst, "events": events, "bytes": nbytes, "last": last, "nolen": 0}


GEO = {"198.51.100.61": "FR", "198.51.100.62": "GF", "198.51.100.76": "US"}


def test_aggregate_keeps_fr_and_gf_apart_and_splits_geoip_rule():
    rows = [row("198.51.100.61", "203.0.113.179", 3, rid="default"), row("198.51.100.62", "10.40.0.250", 5, rid=GEO_RULE, last=200),
            row("10.40.0.74", "198.51.100.76", 2, nbytes=120), row("10.0.0.1", "203.0.113.179", 7),
            row("203.0.113.9", "203.0.113.179", 4)]
    per, amb, nogeo = gb.aggregate(rows, {"site-a": OURS}, {GEO_RULE}, lambda ip: GEO.get(ip, ""))
    assert per["FR"]["in"] == 3 and per["FR"]["in_geo"] == 0
    assert per["GF"]["in"] == 5 and per["GF"]["in_geo"] == 5 and per["GF"]["last"] == 200
    assert per["US"]["out"] == 2 and per["US"]["in"] == 0 and per["US"]["out_bytes"] == 120
    assert amb["events"] == 7 and nogeo["events"] == 4          # never folded into a country
    assert per["GF"]["rules"] == {("site-a", GEO_RULE, "ix0", "in"): [5, 60, 200]}


class FakeCH:
    def __init__(self, cov, rows, raw):
        self.cov, self.rows, self.raw = cov, rows, raw

    def query(self, sql, p=None):
        if "min(received)" in sql:
            return self.cov
        if "SELECT DISTINCT" in sql:
            return self.rows
        return [{"n": self.raw}]


class FakeCfg:
    def site_ours(self, s):
        return [str(n) for n in OURS]


def make(cov, rows=(), raw=0, unlogged=(), known=True):
    b = gb.Blocks(FakeCfg(), FakeCH(cov, list(rows), raw), lambda s: {"rules": [{"uuid": GEO_RULE, "blocks": True}]}, None)
    b.geo.cc = lambda ip: GEO.get(ip, "")
    b.geo.provenance = lambda: {"database": "fixture"}
    b.rules = lambda s: {"known": known, "index": {}, "unlogged": [{"description": d, "interface": "wan"} for d in unlogged]}
    return b


def test_coverage_states():
    now = time.time()
    t0, t1 = now - 900, now
    assert make([]).coverage([SITE], t0, t1)[0]["state"] == "unavailable"
    stale = make([{"site": "site-a", "first": now - 9000, "last": now - 3600}]).coverage([SITE], t0, t1)[0]
    assert stale["state"] == "stale" and "last line received" in stale["note"]
    part = make([{"site": "site-a", "first": now - 9000, "last": now}], unlogged=["Block X"]).coverage([SITE], t0, t1)[0]
    assert part["state"] == "partial" and part["note"].startswith("Logged blocks only")
    late = make([{"site": "site-a", "first": now - 300, "last": now}]).coverage([SITE], t0, t1)[0]
    assert late["state"] == "partial" and "when log collection started" in late["note"]
    assert make([{"site": "site-a", "first": now - 9000, "last": now}]).coverage([SITE], t0, t1)[0]["state"] == "ok"


def test_stats_reports_duplicates_and_unavailable():
    now = time.time()
    rows = [row("198.51.100.61", "203.0.113.179", 3), row("198.51.100.62", "203.0.113.179", 2, rid=GEO_RULE)]
    v = make([{"site": "site-a", "first": now - 9000, "last": now}], rows, raw=7).stats([SITE], now - 900, now)
    assert v["events"] == 5 and v["duplicates"] == 2 and v["state"] == "ok" and v["bytes_complete"]
    pub = make([{"site": "site-a", "first": now - 9000, "last": now}], rows, raw=5).public(v)
    assert "ips" not in pub["countries"]["FR"] and "rules" not in pub["countries"]["FR"]
    assert make([]).stats([SITE], now - 900, now)["state"] == "unavailable"
