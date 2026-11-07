"""Smarter baselines and precise exceptions: schedules in the firewall's time zone, destination/service-limited
exceptions that cannot hide unrelated activity, preview before saving, telemetry gaps not counted as zero
(synthetic data only)."""
import json
import time
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from netmon import baselines as bl
from netmon.detect import Detector

NY = {"id": "site-a", "tz": "America/New_York"}


def ts(y, mo, d, h, mi=0, tz="America/New_York"):
    return datetime(y, mo, d, h, mi, tzinfo=ZoneInfo(tz)).timestamp()


def test_schedule_local_time_overnight_and_dst():
    nightly = bl.parse_schedule(["0", "1", "2", "3", "4"], "22:00", "04:00")       # Mon-Fri nights
    assert bl.schedule_active(nightly, ts(2026, 11, 2, 23), NY)                   # Monday 23:00
    assert bl.schedule_active(nightly, ts(2026, 11, 3, 3, 30), NY)                # Tuesday 03:30 = Monday's night
    assert not bl.schedule_active(nightly, ts(2026, 11, 2, 3, 30), NY)            # Monday 03:30 = Sunday's night
    assert bl.schedule_active(nightly, ts(2026, 11, 7, 2), NY)                    # Saturday 02:00 = Friday's night
    assert not bl.schedule_active(nightly, ts(2026, 11, 7, 23), NY)               # Saturday evening
    day = bl.parse_schedule(["6"], "01:00", "02:00")                              # Sunday 01:00-02:00 local
    assert bl.schedule_active(day, ts(2026, 11, 1, 1, 30), NY)                    # fall-back Sunday, still local 01:30
    assert not bl.schedule_active(day, ts(2026, 11, 1, 1, 30, "UTC"), NY)
    assert bl.schedule_text(nightly) == "Mon–Fri 22:00–04:00 (firewall's local time)"
    for bad in ((["0"], "25:00", "01:00"), ([], "01:00", "02:00"), (["0"], "01:00", "01:00")):
        with pytest.raises(ValueError):
            bl.parse_schedule(*bad)
    assert bl.parse_schedule([], "", "") is None


def exc(**kw):
    return {"rule": "outbound_volume", "asset": "10.40.0.8", "subject": "*", "peer": "*", "service": "*", "schedule": None, "site": None,
            "enabled": 1, "expires_at": None} | kw


def _fnd(**kw):
    return {"rule": "outbound_volume", "asset": "10.40.0.8", "subject": "10.40.0.8", "site": "site-a", "window": (0, 1),
            "evidence": [{"top_dsts": ["198.51.100.10"]}]} | kw


fnd = _fnd


def bfnd(**kw):
    return _fnd(**({"rule": "beaconing", "subject": "198.51.100.10|443"} | kw))


def test_destination_service_and_schedule_limited_exceptions():
    now = ts(2026, 11, 3, 2)
    assert not bl.exception_applies(exc(peer="198.51.100.0/28"), fnd(), now, NY)    # volume: subtracted in the rule, never hidden here
    assert not bl.exception_applies(exc(rule="fanout", peer="198.51.100.0/28"), fnd(rule="fanout", subject="horizontal"), now, NY)
    backup = exc(rule="beaconing", peer="198.51.100.0/28")
    assert bl.exception_applies(backup, bfnd(), now, NY)
    assert not bl.exception_applies(backup, bfnd(subject="203.0.113.50|443"), now, NY)                             # another peer
    assert not bl.exception_applies(backup, bfnd(evidence=[{"top_dsts": ["198.51.100.10", "203.0.113.50"]}]), now, NY)  # and another
    assert not bl.exception_applies(backup, bfnd(subject="x", evidence=[{}]), now, NY)   # no named peer: cannot verify, not hidden
    assert not bl.exception_applies(backup, bfnd(asset="10.40.0.9"), now, NY)
    svc = exc(rule="unexpected_inbound", service="tcp/22")
    assert bl.exception_applies(svc, fnd(rule="unexpected_inbound", subject="203.0.113.7:22", evidence=[]), now, NY)
    assert not bl.exception_applies(svc, fnd(rule="unexpected_inbound", subject="203.0.113.7:3389", evidence=[]), now, NY)
    sched = exc(rule="beaconing", peer="198.51.100.0/28", schedule=json.dumps(bl.parse_schedule(["0", "1", "2", "3", "4"], "01:00", "05:00")))
    assert bl.exception_applies(sched, bfnd(window=(now, now + 3600)), now, NY)
    noon = ts(2026, 11, 3, 12)
    assert not bl.exception_applies(sched, bfnd(window=(noon, noon + 3600)), noon, NY)
    assert not bl.exception_applies(exc(site="site-b"), fnd(), now, NY)
    assert not bl.exception_applies(exc(expires_at=now - 1), fnd(), now, NY)
    assert "to 198.51.100.0/28" in bl.describe(sched) and "Mon–Fri 01:00–05:00" in bl.describe(sched)
    for bad in ("0.0.0.0/0", "10.0.0.0/8", "nope"):
        with pytest.raises(ValueError):
            bl.norm_peer(bad)
    assert bl.norm_service("443") == "tcp/443" and bl.norm_service("UDP/53") == "udp/53"
    with pytest.raises(ValueError):
        bl.norm_service("tcp/0")


def test_baseline_leaves_out_gaps_and_suspicious_hours_and_matches_day_kind():
    ws = int(ts(2026, 11, 4, 2))           # Wednesday 02:00 local
    hours = {}
    have = set()
    for d in range(1, 15):
        day = datetime.fromtimestamp(ws - d * 86400, ZoneInfo("America/New_York"))
        h = int(datetime(day.year, day.month, day.day, 2, tzinfo=ZoneInfo("America/New_York")).timestamp())
        if d in (3, 4):
            continue                            # no telemetry those nights: not zero
        have.add(h)
        hours[h] = 9e9 if day.weekday() >= 5 else 1e6
    vals, desc = bl.baseline_values(hours, ws, 14, NY, have)
    assert len(vals) == 10 and set(vals) == {1e6}              # 12 nights with data; the 10 weekdays (weekend backups apart)
    assert "2 day(s) without telemetry" in desc and "weekdays" in desc and "America/New_York" in desc
    skip = {sorted(have)[-1]}
    vals2, desc2 = bl.baseline_values(hours, ws, 14, NY, have, skip)
    assert len(vals2) == len(vals) - 1 and "not learned" in desc2


def test_suspicious_hours_not_learned(conn):
    now = time.time()
    conn.execute("INSERT INTO alerts(key,rule,severity,confidence,asset,subject,title,first_seen,last_seen,window_start,window_end,site,status) "
                 "VALUES ('k1','outbound_volume','high','medium','10.40.0.8','203.0.113.179','t',?,?,?,?,'site-a','open')",
                 (now - 7200, now - 3600, now - 7200, now - 3600))
    conn.execute("INSERT INTO alerts(key,rule,severity,confidence,asset,subject,title,first_seen,last_seen,window_start,window_end,site,status) "
                 "VALUES ('k2','outbound_volume','high','medium','10.40.0.8','203.0.113.179','t',?,?,?,?,'site-a','closed')",
                 (now - 90000, now - 86400, now - 90000, now - 86400))
    conn.commit()
    h = bl.suspicious_hours(conn, "site-a", "outbound_volume", "203.0.113.179", now - 3 * 86400, now)
    assert int((now - 7200) // 3600 * 3600) in h and int((now - 90000) // 3600 * 3600) not in h


class VolCH:
    """ClickHouse stand-in for the outbound-volume rule."""
    def __init__(self, cur_bytes, by_dst, hist, have):
        self.cur, self.by_dst, self.hist, self.have = cur_bytes, by_dst, hist, have

    def query(self, sql, params):
        if "min(TimeReceived) AS first" in sql:
            return [{"first": time.time() - 20 * 86400}]
        if "flows_1h0m0s" in sql:
            return [{"h": h} for h in self.have]
        if "GROUP BY dst, dport, proto" in sql:
            return self.by_dst
        if "uniqExact(dst)" in sql:
            return [{"src": "203.0.113.179", "bytes": self.cur, "dsts": 2, "top_dsts": [x["dst"] for x in self.by_dst], "top_sports": [40000],
                     "protos": [6]}]
        if "GROUP BY src, h" in sql:
            return [{"src": "203.0.113.179", "h": h, "bytes": b} for h, b in self.hist.items()]
        return []


def _vol_detector(cfg, conn, cur, by_dst, missing_days=()):
    now = time.time()
    d = Detector(cfg, None, conn)
    ws, we, bs = d.windows(now)
    hist, have = {}, set()
    for k in range(1, 15):
        h = int((ws - k * 86400) // 3600 * 3600)
        have.update({h, h + 3600})
        if k not in missing_days:
            hist[h] = 50_000_000
    for k in missing_days:
        h = int((ws - k * 86400) // 3600 * 3600)
        have.discard(h)
    d.ch = VolCH(cur, by_dst, hist, have)
    cfg.raw.setdefault("sites", [])[0]["tz"] = "UTC"
    d.site = cfg.sites[0]
    return d, now


def test_backup_exception_subtracts_only_its_destination(cfg, conn):
    big = [{"dst": "198.51.100.10", "dport": 443, "proto": 6, "b": 2_000_000_000}, {"dst": "203.0.113.50", "dport": 443, "proto": 6, "b": 900_000_000}]
    d, now = _vol_detector(cfg, conn, 2_900_000_000, big)
    assert d.rule_outbound_volume(now, 20)                                     # without an exception: flagged
    conn.execute("INSERT INTO exceptions(rule,asset,subject,owner,reason,created_by,created_at,peer) VALUES "
                 "('outbound_volume','203.0.113.179','*','ops','nightly backup','t',?,'198.51.100.0/28')", (now,))
    conn.commit()
    out = d.rule_outbound_volume(now, 20)
    assert out and out[0]["evidence"][0]["excluded_by_exceptions"] == 2_000_000_000   # the other 900 MB still alerts
    assert "was not counted" in out[0]["baseline"]
    only_backup = [big[0], {"dst": "203.0.113.50", "dport": 443, "proto": 6, "b": 10_000_000}]
    d2, now = _vol_detector(cfg, conn, 2_010_000_000, only_backup)
    assert d2.rule_outbound_volume(now, 20) == []                              # only the backup: nothing to explain


def test_missing_telemetry_days_do_not_lower_the_baseline(cfg, conn):
    flows = [{"dst": "203.0.113.50", "dport": 443, "proto": 6, "b": 150_000_000}]
    d, now = _vol_detector(cfg, conn, 150_000_000, flows)
    assert d.rule_outbound_volume(now, 20) == []                               # 150 MB vs usual 50 MB: under 4x
    d, now = _vol_detector(cfg, conn, 150_000_000, flows, missing_days=range(1, 12))
    assert d.rule_outbound_volume(now, 20) == []                               # gaps are not zeros: still under 4x


def test_record_uses_precise_exception_and_counts_hits(cfg, conn):
    from test_detect import finding
    d = Detector(cfg, None, conn)
    now = time.time()
    conn.execute("INSERT INTO exceptions(rule,asset,subject,owner,reason,created_by,created_at,service) VALUES "
                 "('unexpected_inbound','10.40.0.8','*','ops','vpn','t',?,'udp/51820')", (now,))
    conn.commit()
    assert d.record(finding(subject="203.0.113.9:51820", evidence=[{"proto": "udp", "port": 51820}]), now) == 0
    assert d.record(finding(subject="203.0.113.9:22", evidence=[{"port": 22}]), now) == 1     # other service still alerts
    assert conn.execute("SELECT hits FROM exceptions").fetchone()[0] == 1


def test_normal_preview_then_save_and_review(cfg):
    from test_web import ADMINPW, client, sid, web
    now = time.time()
    ids = []
    for peer in ("198.51.100.10", "198.51.100.11", "203.0.113.60"):
        ids.append(web.conn.execute(
            "INSERT INTO alerts(key,rule,severity,confidence,asset,subject,title,first_seen,last_seen,window_start,window_end,evidence,query,"
            "baseline,alternatives,next_steps,akvorado_filter,site) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"bv{peer}{now}", "beaconing", "medium", "medium", "10.40.0.77", f"{peer}|443", f"beacon {peer}", now, now, now - 60, now,
             json.dumps([{"remote": peer}]), "{}", "", "[]", "[]", "", "site-a")).lastrowid)
    web.conn.commit()
    a = client("admin", ADMINPW)
    tok = web.csrf_token(sid(a))
    assert "Preview what this hides" in a.get(f"/netmon/alert/{ids[0]}").text
    form = {"scope": "dest", "peer": "198.51.100.0/28", "service": "", "reason": "telemetry to vendor", "until": "2099-01-01", "close": "1",
            "csrf": tok, "preview": "1"}
    p = a.post(f"/netmon/alert/{ids[0]}/normal", data=form)
    assert p.status_code == 200 and "Check before saving" in p.text
    import re
    assert "would have hidden <b>2</b>" in p.text, re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", p.text[p.text.find("Check before"):][:1500])) and "1 other finding(s) for this device" in p.text
    assert web.conn.execute("SELECT count(*) FROM exceptions WHERE peer='198.51.100.0/28'").fetchone()[0] == 0   # nothing saved yet
    form.pop("preview")
    r = a.post(f"/netmon/alert/{ids[0]}/normal", data=form, follow_redirects=False)
    assert r.status_code == 303
    st = {x[0]: x[1] for x in web.conn.execute(f"SELECT id, status FROM alerts WHERE id IN ({','.join('?' * 3)})", ids)}
    assert st[ids[0]] == "closed" and st[ids[1]] == "closed" and st[ids[2]] == "open"     # the unrelated destination stays
    x = web.conn.execute("SELECT * FROM exceptions WHERE peer='198.51.100.0/28'").fetchone()
    assert x["expires_at"] > now
    page = a.get("/netmon/exceptions").text
    assert "Periodic connections (beacon-like) for" in page and "to 198.51.100.0/28" in page and "Baselines" in page
    old = x["expires_at"]
    a.post(f"/netmon/exceptions/{x['id']}/extend", data={"csrf": tok})
    assert web.conn.execute("SELECT expires_at FROM exceptions WHERE id=?", (x["id"],)).fetchone()[0] >= old + 30 * 86400 - 1
    bad = dict(form, scope="dest", peer="", service="")
    assert a.post(f"/netmon/alert/{ids[2]}/normal", data=bad).status_code == 400
    assert a.post(f"/netmon/alert/{ids[2]}/normal", data=dict(form, days="1", start="9", end="")).status_code == 400
