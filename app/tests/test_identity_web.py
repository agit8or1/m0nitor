"""Identity review UI, address history on the device page, per-firewall monitoring choices, firewall picker,
missing-permission hints."""
import time

from test_web import ADMINPW, EVIL, VIEWPW, client, sid, web

from netmon import identity as idn


def test_address_history_and_review_pages():
    now = time.time()
    a = idn.observe(web.conn, "site-a", now - 7200, ip="10.40.0.8", mac="e4:43:4b:00:00:08", hostname="backup-1")
    idn.observe(web.conn, "site-a", now - 60, ip="10.40.0.9", mac="e4:43:4b:00:00:08")
    idn.observe(web.conn, "site-a", now - 30, ip="10.40.0.8", mac="00:12:34:56:78:9a", hostname=EVIL[:60])
    web.conn.commit()
    v = client("viewer1", VIEWPW)
    page = v.get("/netmon/servers/10.40.0.9").text
    assert "Address history" in page and "e4:43:4b:00:00:08" in page and "10.40.0.8" in page and "used 2 addresses" in page
    p8 = v.get("/netmon/servers/10.40.0.8").text
    assert "2 different devices have used 10.40.0.8" in p8 and "<script>alert(1)" not in p8
    rv = v.get("/netmon/identities").text
    assert "Needs your review" in rv and "moved from 10.40.0.8 to 10.40.0.9" in rv
    assert "Same device: merge" not in rv          # viewers cannot act
    assert v.get(f"/netmon/identities/{a}").status_code == 200
    assert v.post("/netmon/identities/merge", data={"keep": a, "gone": a + 1, "csrf": web.csrf_token(sid(v))}).status_code == 403


def test_admin_merge_rename_and_undo_via_ui():
    now = time.time()
    a = idn.observe(web.conn, "site-a", now, ip="10.40.0.160", mac="00:14:5e:aa:00:01", hostname="ibm-box")
    b = idn.observe(web.conn, "site-a", now, ip="10.40.0.163", mac="00:14:5e:aa:00:02", hostname="ibm-box")
    web.conn.commit()
    ad = client("admin", ADMINPW)
    tok = web.csrf_token(sid(ad))
    assert "Same device: merge" in ad.get("/netmon/identities").text
    r = ad.post("/netmon/identities/merge", data={"keep": a, "gone": b, "reason": "two NICs", "csrf": tok}, follow_redirects=False)
    assert r.status_code == 303 and idn.resolve(web.conn, b) == a
    ad.post(f"/netmon/identities/{a}/rename", data={"name": "IBM storage", "csrf": tok})
    assert idn.name_of(web.conn, web.cfg, a) == "IBM storage"
    assert "merged into" in ad.get(f"/netmon/identities/{b}").text
    ad.post(f"/netmon/identities/{b}/unmerge", data={"csrf": tok})
    assert idn.resolve(web.conn, b) == b


def test_finding_shows_device_at_the_time_and_moved_warning():
    now = time.time()
    a = idn.observe(web.conn, "site-a", now - 86400 * 2, ip="10.40.0.33", mac="00:33:00:00:00:01")
    idn.observe(web.conn, "site-a", now - 60, ip="10.40.0.33", mac="00:33:00:00:00:02")
    web.conn.commit()
    cur = web.conn.execute("INSERT INTO alerts(key,rule,severity,confidence,asset,subject,title,first_seen,last_seen,window_start,window_end,"
                           "evidence,query,baseline,alternatives,next_steps,akvorado_filter,site) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           ("k-id-1", "beaconing", "low", "low", "10.40.0.33", "198.51.100.5", "t", now - 86400 * 2, now - 86400 * 2,
                            now - 86400 * 2, now - 86400 * 2 + 60, "[]", "{}", "b", "[]", "[]", "", "site-a"))
    web.conn.commit()
    page = client("viewer1", VIEWPW).get(f"/netmon/alert/{cur.lastrowid}").text
    assert "Device at the time" in page and f"/netmon/identities/{a}" in page and "now belongs to a different device" in page


def test_per_firewall_monitoring_choice_saved_and_honoured():
    ad = client("admin", ADMINPW)
    tok = web.csrf_token(sid(ad))
    page = ad.get("/netmon/settings/sites").text
    assert "What to monitor on this firewall" in page and "Time zone" in page
    on = ["flows", "syslog", "dns", "snmp", "device_events", "discovery_arp", "discovery_ndp", "discovery_dhcp", "probes", "segmentation"]
    r = ad.post("/netmon/settings/sites/site-a/monitor", data={"on": on, "csrf": tok}, follow_redirects=False)
    assert r.status_code == 303
    from netmon.ux import monitored
    s = web.cfg.site("site-a")
    assert not monitored(s, "ids") and monitored(s, "flows")
    # health: the IDS source is "not monitored (your choice)", never failing
    from netmon.health import Health
    h = Health.__new__(Health)
    h.cfg = web.cfg
    out = h.apply_choices([{"id": "ids:site-a", "state": "fail", "value": "no alerts", "action": ""},
                           {"id": "netflow:site-a", "state": "fail", "value": "x", "action": ""}])
    assert out[0]["state"] == "not_configured" and out[0]["off"] and out[1]["state"] == "fail"
    # detector skips the IDS rule for this firewall
    called = []
    det = web.Detector(web.cfg, None, web.conn)
    det.site = s
    det.learning = lambda: 30.0
    for n in ("rule_new_dest", "rule_unexpected_inbound", "rule_outbound_volume", "rule_fanout", "rule_beaconing", "rule_fw_blocks",
              "rule_dns", "rule_events", "rule_health"):
        setattr(det, n, lambda *a, _n=n: called.append(_n) or [])
    det.rule_ids = lambda now: called.append("rule_ids") or []
    det.run_site(time.time())
    assert "rule_ids" not in called and "rule_beaconing" in called
    ad.post("/netmon/settings/sites/site-a/monitor", data={"on": on + ["ids"], "csrf": tok})
    assert monitored(web.cfg.site("site-a"), "ids")
    assert ad.post("/netmon/settings/sites/site-a", data={"name": "Site A", "tz": "Not/AZone", "csrf": tok}).status_code == 400


def test_scope_accepts_several_firewalls():
    sc = web.dash.scope(site="site-a,nope")
    assert [x["id"] for x in sc.sites] == ["site-a"]
    assert len(web.dash.scope(site="all").sites) == len(web.cfg.sites)


def test_missing_permission_names_the_privilege():
    from netmon.fwperms import missing_html, missing_text, privilege_for
    assert privilege_for("/api/diagnostics/interface/search_ndp") == "Diagnostics: NDP Table"
    assert privilege_for("/api/dhcpv4/leases/search_lease") == "Services: ISC DHCPv4: Leases"
    msg = "OPNsense HTTP 403: " + missing_text("/api/diagnostics/interface/search_arp")
    h = missing_html(web.e, msg)
    assert "Missing firewall permission: <b>Diagnostics: ARP Table</b>" in h and "/netmon/settings/permissions?check=1" in h
    assert "warnline" in missing_html(web.e, "error: timeout")
