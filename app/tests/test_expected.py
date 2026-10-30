"""Expected devices: operator-declared legitimate traffic is excluded from findings (synthetic data only)."""
import time

from netmon import web
from netmon.core import EXPECTED_KEY, expected_devices, expected_match, get_setting, put_setting
from netmon.detect import Detector
from test_web import ADMINPW, VIEWPW, client, sid


def finding(**kw):
    f = dict(rule="beaconing", severity="low", confidence="low", asset="10.40.0.121", subject="198.51.100.66:443", title="t",
             window=(1, 2), evidence=[{}], query=("SELECT 1", {}), baseline="", alternatives=[], next_steps=[], akvorado_filter="")
    return f | kw


def test_match_and_expiry(conn):
    put_setting(conn, EXPECTED_KEY, {"10.40.0.121": {"reason": "crawler"}, "10.40.0.32/28": {"reason": "crawler pool"},
                                     "10.40.0.9": {"reason": "old", "expires_at": time.time() - 1}}, "t")
    exp = expected_devices(conn)
    assert expected_match(exp, "10.40.0.121") == "10.40.0.121" and expected_match(exp, "10.40.0.40") == "10.40.0.32/28"
    assert expected_match(exp, "10.40.0.9") is None and expected_match(exp, "not-an-ip") is None


def test_record_skips_expected_asset_and_peer(cfg, conn):
    d = Detector(cfg, None, conn)
    put_setting(conn, EXPECTED_KEY, {"10.40.0.121": {"reason": "crawler"}, "198.51.100.70": {"reason": "partner"}}, "t")
    assert d.record(finding(), time.time()) == 0
    assert d.record(finding(asset="10.40.0.122", subject="198.51.100.70:443"), time.time()) == 0
    assert d.record(finding(asset="10.40.0.122", subject="2000328|198.51.100.70"), time.time()) == 0
    assert d.record(finding(asset="10.40.0.122"), time.time()) == 1                     # not expected: raised


def test_expected_only_needs_every_peer_explained(cfg, conn):
    d = Detector(cfg, None, conn)
    put_setting(conn, EXPECTED_KEY, {"10.40.0.121": {"reason": "crawler"}}, "t")
    f = finding(rule="new_dest_country", asset="203.0.113.179", evidence=[{"sample_peers": ["198.51.100.66", "198.51.100.67"]}])
    d.reply_hosts = lambda peers, ws, we: {"10.40.0.121"}
    assert d.expected_only(f)
    d.reply_hosts = lambda peers, ws, we: {"10.40.0.121", "10.40.0.122"}
    assert not d.expected_only(f)                                                       # another host also involved
    d.reply_hosts = lambda peers, ws, we: {""}
    assert not d.expected_only(f)                                                       # no reply: not attributable
    assert not d.expected_only(finding(asset="10.40.0.122", evidence=[{"peer": "198.51.100.66"}]))   # not a NAT finding


def test_ui_add_remove_and_guards():
    a = client("admin", ADMINPW)
    tok = web.csrf_token(sid(a))
    assert a.post("/netmon/expected", data={"target": "203.0.113.179", "reason": "x", "csrf": tok}).status_code == 400   # shared NAT
    assert a.post("/netmon/expected", data={"target": "10.40.0.0/16", "reason": "x", "csrf": tok}).status_code == 400    # too broad
    assert a.post("/netmon/expected", data={"target": "10.40.0.121", "reason": "", "csrf": tok}).status_code == 400
    r = a.post("/netmon/expected", data={"target": "10.40.0.121", "reason": "contact crawler", "csrf": tok}, follow_redirects=False)
    assert r.status_code == 303 and "10.40.0.121" in get_setting(web.conn, EXPECTED_KEY, {})
    assert "contact crawler" in a.get("/netmon/exceptions").text
    v = client("viewer1", VIEWPW)
    assert v.post("/netmon/expected", data={"target": "10.40.0.122", "reason": "x", "csrf": web.csrf_token(sid(v))}).status_code == 403
    a.post("/netmon/expected/remove", data={"target": "10.40.0.121", "csrf": tok})
    assert "10.40.0.121" not in get_setting(web.conn, EXPECTED_KEY, {})


def test_new_country_findings_group_per_host(cfg, conn):
    d = Detector(cfg, None, conn)
    mk = lambda host, cc, b: dict(rule="new_dest_country", severity="medium", confidence="low", asset=host, subject=cc,  # noqa: E731
                                  title="t", window=(1, 2), evidence=[{"bytes": b}], query=("", {}),
                                  baseline=f"No traffic between this host and country {cc} in the baseline", alternatives=["x"],
                                  next_steps=[], akvorado_filter="")
    out = [mk("10.40.0.131", cc, i) for i, cc in enumerate(["CN", "RU", "BR", "VN", "IN"])] + [mk("10.40.0.20", "DE", 1)]
    g = d.group_new_dest(out, "country", 4)
    assert len(g) == 2
    many = next(f for f in g if f["asset"] == "10.40.0.131")
    assert many["subject"] == "many" and "5 new countries" in many["title"] and many["title"].index("IN") < many["title"].index("CN")
    assert len(many["evidence"]) == 5 and "any of the listed" in many["baseline"]
    assert next(f for f in g if f["asset"] == "10.40.0.20")["subject"] == "DE"           # below the threshold: unchanged


def test_nat_hosts_counts_destinations_shared_by_expected_devices(cfg, conn):
    d = Detector(cfg, None, conn)
    d.exposed_public_ports = lambda: []
    put_setting(conn, EXPECTED_KEY, {"10.40.0.121": {"reason": "crawler"}, "10.40.0.122": {"reason": "crawler"}}, "t")
    d.q = lambda sql, p: [
        {"k": "one", "host": "10.40.0.121", "several": [], "dsts": 50},
        {"k": "one", "host": "10.40.0.20", "several": [], "dsts": 5},
        {"k": "many", "host": "", "several": ["10.40.0.121", "10.40.0.122"], "dsts": 30},   # only crawlers: theirs
        {"k": "many", "host": "", "several": ["10.40.0.121", "10.40.0.20"], "dsts": 4},     # mixed: stays ambiguous
        {"k": "none", "host": "", "several": [], "dsts": 7}]
    r = d.nat_hosts("203.0.113.179", 0, 600)
    assert r["dsts_expected"] == 80 and r["dsts_ambiguous"] == 4 and r["dsts_no_reply"] == 7
    assert r["expected_hosts"] == ["10.40.0.121", "10.40.0.122"]


def test_nat_hosts_never_attributes_hosts_with_their_own_1to1_nat(cfg, conn):
    d = Detector(cfg, None, conn)
    d.exposed_public_ports = lambda: []
    cfg.raw["binat"] = [{"external": "203.0.113.181", "internal": "10.40.0.74"},
                        {"external": "203.0.113.179/32", "internal": "10.40.0.9/32"}]
    seen = {}
    d.q = lambda sql, p: seen.update(p) or []
    d.nat_hosts("203.0.113.179", 0, 600)
    assert seen["own"] == ["10.40.0.74"]   # its traffic leaves via .181; a host 1:1-mapped to src itself stays a candidate
