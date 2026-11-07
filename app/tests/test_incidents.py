"""Incidents: deterministic grouping with reasons, manual split/merge that sticks, triage history, calm notifications,
access-controlled evidence export (synthetic data only)."""
import json
import time

from test_web import EVIL, VIEWPW, client, sid, web

from netmon import auth
from netmon import identity as idn
from netmon import incidents as inc

ANALYSTPW = "analyst password 123"
web.conn.execute("INSERT OR REPLACE INTO users(username,pw_hash,role,created_at) VALUES (?,?,?,?)",
                 ("analyst1", auth.hash_pw(ANALYSTPW), "analyst", time.time()))
web.conn.commit()


def alert(rule="beaconing", asset="10.50.0.8", subject="198.51.100.77", sev="medium", t=None, site="site-a", identity=None, test=0, title=None):
    t = t or time.time()
    cur = web.conn.execute(
        "INSERT INTO alerts(key,rule,severity,confidence,asset,subject,title,first_seen,last_seen,window_start,window_end,evidence,query,"
        "baseline,alternatives,next_steps,akvorado_filter,site,identity_id,test) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (f"k{time.time_ns()}", rule, sev, "medium", asset, subject, title or f"{rule} {asset}", t, t, t - 60, t,
         json.dumps([{"remote": subject}]), json.dumps({"sql": "SELECT 1", "params": {}}), "differs from usual", "[]",
         json.dumps(["Check the device"]), "", site, identity, test))
    web.conn.commit()
    return cur.lastrowid


def corr(aid):
    return inc.correlate(web.conn, web.cfg, aid)


def test_single_finding_is_not_an_incident_and_info_alone_never_starts_one():
    a = alert(asset="10.50.1.1", subject="198.51.100.11")
    assert corr(a) is None
    i1 = alert(rule="new_dest_country", asset="10.50.1.2", subject="NL")
    i2 = alert(rule="new_dest_asn", asset="10.50.1.2", subject="AS64500")
    assert corr(i1) is None and corr(i2) is None


def test_same_device_groups_with_reason_even_after_address_change():
    now = time.time()
    dev = idn.observe(web.conn, "site-a", now - 7200, ip="10.50.2.1", mac="00:50:02:00:00:01")
    web.conn.commit()
    a = alert(asset="10.50.2.1", subject="198.51.100.21", identity=dev, t=now - 3600)
    assert corr(a) is None
    b = alert(rule="fanout", asset="10.50.2.9", subject="*", identity=dev, t=now)    # same device, new address
    iid = corr(b)
    assert iid and {m["id"] for m in inc.members(web.conn, iid)} == {a, b}
    assert all("same device" in m["link_reason"] for m in inc.members(web.conn, iid))
    c = alert(rule="dns_bypass", asset="10.50.2.9", subject="8.8.8.8", identity=dev)
    assert corr(c) == iid                                  # later related findings join the open incident


def test_same_remote_address_across_devices_and_window_bound():
    now = time.time()
    a = alert(asset="10.50.3.1", subject="203.0.113.99", t=now - 600)
    corr(a)
    b = alert(rule="unexpected_inbound", asset="10.50.3.2", subject="203.0.113.99:22", t=now)
    iid = corr(b)
    assert iid and "same remote address (203.0.113.99)" in inc.members(web.conn, iid)[0]["link_reason"]
    old = alert(asset="10.50.3.7", subject="198.51.100.200", t=now - inc.CORRELATE_WINDOW - 7200)
    new = alert(asset="10.50.3.8", subject="198.51.100.200", t=now)
    corr(old)
    assert corr(new) is None                               # outside the time window: not related


def test_shared_nat_health_and_test_findings_are_not_grouped():
    nat = web.cfg["outbound_nat_ips"][0]
    a, b = alert(asset=nat, subject="*", rule="fanout"), alert(asset=nat, subject="*", rule="beaconing")
    corr(a)
    assert corr(b) is None
    h1, h2 = alert(rule="exporter_silence", asset="10.50.4.1", subject="x"), alert(rule="exporter_silence", asset="10.50.4.1", subject="y")
    corr(h1)
    assert corr(h2) is None
    t1, t2 = alert(asset="10.50.4.2", test=1), alert(asset="10.50.4.2", test=1)
    corr(t1)
    assert corr(t2) is None


def test_split_sticks_and_merge_and_resolution_history():
    a, b = alert(asset="10.50.5.1", subject="198.51.100.51"), alert(rule="fanout", asset="10.50.5.1", subject="*")
    corr(a)
    iid = corr(b)
    inc.unlink(web.conn, iid, b, "analyst1")
    c = alert(rule="dns_bypass", asset="10.50.5.1", subject="9.9.9.9")
    assert corr(c) == iid
    assert b not in {m["id"] for m in inc.members(web.conn, iid)}
    x, y = alert(asset="10.50.5.9", subject="198.51.100.59"), alert(rule="fanout", asset="10.50.5.9", subject="*")
    corr(x)
    other = corr(y)
    inc.merge(web.conn, iid, other, "analyst1")
    assert {x, y} <= {m["id"] for m in inc.members(web.conn, iid)}
    assert web.conn.execute("SELECT resolution FROM incidents WHERE id=?", (other,)).fetchone()[0] == "duplicate"
    try:
        inc.update(web.conn, iid, "analyst1", status="resolved")
        raise AssertionError("resolved without a reason")
    except ValueError:
        pass
    inc.update(web.conn, iid, "analyst1", status="resolved", resolution="false_positive", note="lab test", close_findings=True)
    assert web.conn.execute("SELECT count(*) FROM alerts WHERE id IN (?,?) AND status='closed'", (a, c)).fetchone()[0] == 2
    acts = [h["action"] for h in inc.history(web.conn, iid)]
    assert acts[0] == "created" and "finding_removed" in acts and "merged_from" in acts and "note" in acts and "findings_closed" in acts
    d = alert(rule="beaconing", asset="10.50.5.1", subject="198.51.100.52")
    assert corr(d) != iid                                  # a resolved incident is not reopened automatically


def test_notification_dedup_per_channel_and_higher_severity_still_sent():
    from netmon.notify import Notifier
    a, b = alert(asset="10.50.6.1", subject="198.51.100.61", sev="medium"), alert(rule="fanout", asset="10.50.6.1", subject="*", sev="medium")
    corr(a)
    iid = corr(b)
    web.conn.execute("INSERT INTO channels(name,type,config,min_severity,categories,max_per_hour) VALUES ('c1','webhook','{}','low','[\"security\"]',100)")
    web.conn.commit()
    chn = web.conn.execute("SELECT * FROM channels WHERE name='c1'").fetchone()
    web.conn.execute("INSERT INTO deliveries(ts,channel_id,channel,alert_id,kind,status) VALUES (?,?,?,?,?,?)",
                     (time.time(), chn["id"], "c1", a, "alert", "delivered"))
    web.conn.commit()
    n = Notifier(web.cfg, web.conn, "https://m.example")
    n.conn = web.conn
    rb = web.conn.execute("SELECT * FROM alerts WHERE id=?", (b,)).fetchone()
    assert n.matches(chn, rb, time.time()) == f"grouped into incident #{iid}, already notified"
    hi = alert(rule="unexpected_inbound", asset="10.50.6.1", subject="198.51.100.61:22", sev="high")
    assert corr(hi) == iid
    assert n.matches(chn, web.conn.execute("SELECT * FROM alerts WHERE id=?", (hi,)).fetchone(), time.time()) is None
    assert f"incident #{iid}" in n.format_alert(rb)["text"]
    web.conn.execute("DELETE FROM channels WHERE id=?", (chn["id"],))
    web.conn.commit()


def test_pages_roles_escaping_and_export_audit():
    a = alert(asset="10.50.7.1", subject="198.51.100.71", title=EVIL)
    b = alert(rule="fanout", asset="10.50.7.1", subject="*")
    corr(a)
    iid = corr(b)
    v = client("viewer1", VIEWPW)
    page = v.get(f"/netmon/incidents/{iid}").text
    assert "What happened" in page and "Affected devices" in page and "Timeline" in page and "<script>alert(1)" not in page
    assert "Handle this incident" not in page
    assert f"incident #{iid}" in v.get("/netmon/security").text
    assert f"/netmon/incidents/{iid}" in v.get(f"/netmon/alert/{a}").text
    assert "#" + str(iid) in v.get("/netmon/incidents").text
    assert v.get(f"/netmon/incidents/{iid}/export.json").status_code == 403
    assert v.post(f"/netmon/incidents/{iid}/update", data={"note": "x", "csrf": web.csrf_token(sid(v))}).status_code == 403
    an = client("analyst1", ANALYSTPW)
    tok = web.csrf_token(sid(an))
    assert an.post(f"/netmon/incidents/{iid}/update", data={"status": "investigating", "assignee": "analyst1", "note": EVIL, "csrf": tok},
                   follow_redirects=False).status_code == 303
    assert an.post(f"/netmon/incidents/{iid}/update", data={"assignee": "viewer1", "csrf": tok}).status_code == 400
    assert an.post(f"/netmon/incidents/{iid}/update", data={"note": "x", "csrf": "bad"}).status_code in (400, 403)
    p2 = an.get(f"/netmon/incidents/{iid}").text
    assert "Investigating" in p2 and "assigned to analyst1" in p2 and "<script>alert(1)" not in p2
    r = an.get(f"/netmon/incidents/{iid}/export.json")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    d = r.json()
    assert d["format"] == "m0nitor-incident-1" and {f["id"] for f in d["findings"]} == {a, b} and "does not mean one caused" in d["note"]
    assert web.conn.execute("SELECT count(*) FROM audit WHERE action='incident_exported' AND user='analyst1'").fetchone()[0] >= 1
    s = alert(asset="10.50.7.9", subject="198.51.100.79")
    r = an.post("/netmon/incidents/new", data={"alert_id": s, "csrf": tok}, follow_redirects=False)
    assert r.status_code == 303 and inc.incident_of(web.conn, s)
    att = an.get("/netmon/api/attention").json()
    assert att["incidents"] >= 1 and "health_count" in att


def test_detector_record_correlates_before_notifying():
    from netmon.detect import Detector
    calls = []

    class N:
        def alert(self, aid):
            calls.append((aid, inc.incident_of(web.conn, aid)))
    d = Detector.__new__(Detector)
    d.cfg, d.conn, d.notifier = web.cfg, web.conn, N()
    now = time.time()
    base = dict(severity="medium", confidence="medium", asset="10.50.8.1", window=(now - 60, now), evidence=[], query=("SELECT 1", {}),
                baseline="b", alternatives=[], next_steps=[], akvorado_filter="", site="site-a")
    assert d.record({**base, "rule": "beaconing", "subject": "198.51.100.81", "title": "t1"}, now) == 1
    assert d.record({**base, "rule": "fanout", "subject": "*", "title": "t2"}, now) == 1
    assert calls[0][1] is None and calls[1][1] is not None


def test_dismiss_button_per_incident_keeps_findings_and_can_reopen():
    a = alert(asset="10.50.8.1", subject="198.51.100.81")
    b = alert(rule="fanout", asset="10.50.8.1", subject="*")
    corr(a)
    iid = corr(b)
    v = client("viewer1", VIEWPW)
    assert f"/netmon/incidents/{iid}/dismiss" not in v.get("/netmon/incidents").text      # viewers see no button
    assert v.post(f"/netmon/incidents/{iid}/dismiss", data={"csrf": web.csrf_token(sid(v))}).status_code == 403
    an = client("analyst1", ANALYSTPW)
    tok = web.csrf_token(sid(an))
    lst = an.get("/netmon/incidents?status=open").text
    assert f"/netmon/incidents/{iid}/dismiss" in lst and "data-confirm" in lst
    assert f"/netmon/incidents/{iid}/dismiss" in an.get(f"/netmon/incidents/{iid}").text
    assert an.post(f"/netmon/incidents/{iid}/dismiss", data={"csrf": "bad"}).status_code in (400, 403)
    r = an.post(f"/netmon/incidents/{iid}/dismiss", data={"back": "/netmon/incidents?status=open", "csrf": tok}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/netmon/incidents?status=open&msg=")
    row = web.conn.execute("SELECT status, resolution FROM incidents WHERE id=?", (iid,)).fetchone()
    assert tuple(row) == ("resolved", "dismissed")
    st = {x[0] for x in web.conn.execute("SELECT status FROM alerts WHERE id IN (?,?)", (a, b))}
    assert "closed" not in st                                                         # findings untouched
    assert web.conn.execute("SELECT count(*) FROM incident_events WHERE incident_id=? AND user='analyst1'", (iid,)).fetchone()[0] >= 1
    assert "Dismissed" in an.get(f"/netmon/incidents/{iid}").text
    assert f"/netmon/incidents/{iid}/dismiss" not in an.get("/netmon/incidents?status=open").text
    # off-site back is ignored; an already-resolved incident keeps its reason
    r = an.post(f"/netmon/incidents/{iid}/dismiss", data={"back": "https://evil.example/", "csrf": tok}, follow_redirects=False)
    assert r.headers["location"].startswith(f"/netmon/incidents/{iid}?msg=")
    assert f"/netmon/incidents/{iid}/reopen" in an.get("/netmon/incidents?status=resolved").text
    an.post(f"/netmon/incidents/{iid}/reopen", data={"csrf": tok})
    assert web.conn.execute("SELECT status, resolution FROM incidents WHERE id=?", (iid,)).fetchone()[0] == "open"
    assert an.post("/netmon/incidents/999999/dismiss", data={"csrf": tok}).status_code == 404
