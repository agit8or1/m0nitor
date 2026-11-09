"""Pages and steps a security review found untested: block approval, the Coverage page, and the finding page's
evidence / baseline / next steps (synthetic data only; no firewall or ClickHouse is contacted)."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from netmon import auth, web
from netmon import block as blk

PW = "review paths password 1"
TARGET = "45.83.64.20"          # globally routable, so validate_target accepts it

for _u, _role in (("rv-admin", "admin"), ("rv-admin2", "admin"), ("rv-analyst", "analyst"), ("rv-viewer", "viewer")):
    web.conn.execute("INSERT OR REPLACE INTO users(username,pw_hash,role,created_at) VALUES (?,?,?,?)",
                     (_u, auth.hash_pw(PW), _role, time.time()))
web.conn.commit()


def client(user):
    c = TestClient(web.app, base_url="https://testserver")
    r = c.post("/login", data={"username": user, "password": PW, "next": "/netmon/security"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return c


def tok(c):
    return web.csrf_token(auth._th(c.cookies.get(auth.SESSION_COOKIE)))


class FakeFw:
    vendor, enabled, alias = "OPNsense", True, "netmon_block"

    def __init__(self):
        self.added = []

    def describe(self, a, op="add"):
        return f"POST /api/firewall/alias_util/{op}/{self.alias} {a}"

    def alias_exists(self):
        return True

    def add(self, a, name=None):
        self.added.append(a)
        return True, {"status": "done"}


@pytest.fixture
def fw(monkeypatch):
    f = FakeFw()
    monkeypatch.setattr(blk, "enforcer", lambda site: f)
    monkeypatch.setattr(blk, "impact", lambda det, address, site, days=7: [])
    return f


def request(c, address=TARGET):
    site = web.cfg.sites[0]["id"]
    r = c.post("/netmon/blocks", data={"address": address, "reason": "review test", "sites": [site], "csrf": tok(c)},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/netmon/block/"), r.text
    return int(r.headers["location"].rsplit("/", 1)[1])


def status(bid):
    return web.conn.execute("SELECT status, requested_by, approved_by FROM blocks WHERE id=?", (bid,)).fetchone()


def test_block_request_is_pending_until_admin_approves(fw):
    an, ad = client("rv-analyst"), client("rv-admin")
    bid = request(an)
    assert status(bid)["status"] == "pending" and not fw.added
    page = an.get(f"/netmon/block/{bid}").text
    assert "Exact change" in page and "Apply block" not in page          # analysts see the preview, not the approve form
    assert an.post(f"/netmon/block/{bid}/apply", data={"confirm": TARGET, "csrf": tok(an)}).status_code == 403
    assert "Apply block" in ad.get(f"/netmon/block/{bid}").text
    r = ad.post(f"/netmon/block/{bid}/apply", data={"confirm": TARGET, "csrf": tok(ad)}, follow_redirects=False)
    assert r.status_code in (200, 303)
    s = status(bid)
    assert s["status"] == "applied" and s["requested_by"] == "rv-analyst" and s["approved_by"] == "rv-admin"
    assert fw.added == [TARGET]


def test_block_apply_needs_typed_address_and_csrf(fw):
    ad = client("rv-admin")
    bid = request(ad)
    assert ad.post(f"/netmon/block/{bid}/apply", data={"confirm": "45.83.64.21", "csrf": tok(ad)}).status_code == 400
    assert ad.post(f"/netmon/block/{bid}/apply", data={"confirm": TARGET, "csrf": "x"}).status_code in (400, 403)
    assert status(bid)["status"] == "pending" and not fw.added


def test_viewer_cannot_request_and_rejected_request_never_applies(fw):
    v, ad = client("rv-viewer"), client("rv-admin")
    site = web.cfg.sites[0]["id"]
    assert v.post("/netmon/blocks", data={"address": TARGET, "reason": "x", "sites": [site], "csrf": tok(v)}).status_code == 403
    bid = request(ad)
    ad.post(f"/netmon/block/{bid}/remove", data={"csrf": tok(ad)})
    assert status(bid)["status"] == "rejected"
    assert ad.post(f"/netmon/block/{bid}/apply", data={"confirm": TARGET, "csrf": tok(ad)}).status_code == 200
    assert status(bid)["status"] == "rejected" and not fw.added


def test_requester_admin_can_approve_own_request(fw):
    """Documented behaviour: approval is a confirmation step, not two-person control (docs/BLOCKING.md)."""
    ad = client("rv-admin2")
    bid = request(ad)
    ad.post(f"/netmon/block/{bid}/apply", data={"confirm": TARGET, "csrf": tok(ad)})
    s = status(bid)
    assert s["status"] == "applied" and s["requested_by"] == s["approved_by"] == "rv-admin2"


def test_coverage_page_renders_for_viewer_and_admin():
    v = client("rv-viewer").get("/netmon/coverage")
    assert v.status_code == 200
    assert "Source health" in v.text and "What is visible" in v.text and "Payload content" in v.text
    assert "Health alert thresholds" not in v.text                       # thresholds are admin only
    a = client("rv-admin").get("/netmon/coverage")
    assert a.status_code == 200 and "Health alert thresholds" in a.text


def test_finding_page_shows_evidence_baseline_and_next_steps():
    now = time.time()
    cur = web.conn.execute(
        "INSERT INTO alerts(key,rule,severity,confidence,asset,subject,title,first_seen,last_seen,window_start,window_end,"
        "evidence,query,baseline,alternatives,next_steps,akvorado_filter) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("rv" + str(now), "beaconing", "medium", "medium", "10.40.0.8", "s", "Review finding", now, now, now, now,
         json.dumps([{"peer": "198.51.100.77", "interval": 60, "jitter": 0.02}]), json.dumps({"sql": "SELECT 1", "params": {}}),
         "Usual: no contact with this peer in 14 days", json.dumps(["Software update check"]),
         json.dumps(["Check which process on 10.40.0.8 opens these connections"]), "SrcAddr = 10.40.0.8"))
    web.conn.commit()
    try:
        t = client("rv-viewer").get(f"/netmon/alert/{cur.lastrowid}").text
    finally:   # an open medium finding with a peer would make later map tests query ClickHouse
        web.conn.execute("UPDATE alerts SET status='closed' WHERE id=?", (cur.lastrowid,))
        web.conn.commit()
    assert "<h2>Evidence</h2>" in t and "198.51.100.77" in t
    assert "Why it differs from normal" in t and "Usual: no contact with this peer in 14 days" in t
    assert "Next investigation steps" in t and "Check which process on 10.40.0.8 opens these connections" in t
    assert "Other possible explanations" in t and "Software update check" in t
