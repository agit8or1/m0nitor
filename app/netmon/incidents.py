"""Incidents: related findings grouped into one case, with the reason for every link.

Grouping is deterministic and explained; it never claims that one finding caused another:
  - same device: findings for the same device identity (or, without one, the same address at the same firewall)
    within CORRELATE_WINDOW of each other;
  - same remote address: findings on different devices involving the same external IP within the window.
An incident starts only when two related findings exist and at least one of them is a security or auto-response
finding of medium severity or higher (low-severity and informational findings, e.g. "new country", never start one;
they can join as context). An incident covers at most MAX_SPAN of activity; later findings start a new one. Health and
TEST findings are not grouped automatically. Findings on the shared NAT address are not grouped by device: many
devices share it.

People decide the rest: group or split findings by hand (a removed finding is never re-added automatically),
merge incidents, assign, add notes, set status and resolution. Every action is in the incident's history and the
audit log. Grouping also keeps notifications calm: a channel that already received a finding of an incident within
NOTIFY_DEDUP is not sent another one of the same or lower severity (notify.Notifier.matches).
"""
import ipaddress
import json
import time

from .core import audit

CORRELATE_WINDOW = 6 * 3600
MAX_SPAN = 24 * 3600        # an incident covers at most a day of activity; later findings start a new one
NOTIFY_DEDUP = 6 * 3600
STATUSES = ("open", "investigating", "resolved")
RESOLUTIONS = {"fixed": "Fixed / contained", "expected": "Expected or authorized activity", "false_positive": "False positive",
               "duplicate": "Duplicate of another incident", "undetermined": "Could not be determined",
               "dismissed": "Dismissed (no action needed)"}
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STARTERS = {"security", "response"}
LOCAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


def category(rule):
    from .notify import category as c
    return c(rule)


def _ext_ip(cfg, v):
    """The external IP a finding's subject names, if any ('198.51.100.5', '198.51.100.5:443', 'x|198.51.100.5')."""
    v = str(v or "").split("|")[-1]
    if v.count(":") == 1:
        v = v.split(":")[0]
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or any(ip in n for n in LOCAL_NETS if n.version == ip.version):
        return None
    try:
        return None if cfg.is_internal(str(ip)) else str(ip)
    except ValueError:
        return None


def _event(conn, iid, user, action, detail=None):
    conn.execute("INSERT INTO incident_events(incident_id, ts, user, action, detail) VALUES (?,?,?,?,?)",
                 (iid, time.time(), user, action, json.dumps(detail or {}, default=str)))


def incident_of(conn, alert_id):
    r = conn.execute("SELECT incident_id FROM incident_alerts WHERE alert_id=? AND removed=0 ORDER BY added_at DESC LIMIT 1",
                     (alert_id,)).fetchone()
    return r[0] if r else None


def members(conn, iid):
    return conn.execute("SELECT a.*, ia.reason AS link_reason, ia.added_by AS link_by, ia.added_at AS link_at FROM incident_alerts ia "
                        "JOIN alerts a ON a.id = ia.alert_id WHERE ia.incident_id=? AND ia.removed=0 ORDER BY a.first_seen", (iid,)).fetchall()


def _removed_from(conn, alert_id, iid):
    return conn.execute("SELECT 1 FROM incident_alerts WHERE alert_id=? AND incident_id=? AND removed=1", (alert_id, iid)).fetchone()


def _shared(cfg, asset):
    return asset in (cfg.get("outbound_nat_ips") or [])


def _same_device_sql(a, shared, p=""):
    """WHERE fragment + params matching alerts (table alias prefix p) for the same device as alert row `a`."""
    if shared or not a["asset"]:
        return None, ()
    if a["identity_id"]:
        return (f"({p}identity_id = ? OR ({p}identity_id IS NULL AND {p}asset = ? AND {p}site IS ?))",
                (a["identity_id"], a["asset"], a["site"]))
    return f"({p}asset = ? AND {p}site IS ?)", (a["asset"], a["site"])


def correlate(conn, cfg, alert_id, now=None):
    """Attach a new finding to a related open incident, or start one with a related ungrouped finding.
    Returns the incident id or None. Never raises into the detector."""
    try:
        return _correlate(conn, cfg, alert_id, now or time.time())
    except Exception as ex:   # grouping is a convenience; a failure must not lose the finding
        audit(conn, "incidents", "correlate_error", {"alert": alert_id, "error": f"{type(ex).__name__}: {ex}"[:300]})
        return None


# an open incident with recent activity near this finding, still inside its MAX_SPAN
OPEN_INC = ("SELECT i.id FROM incidents i WHERE i.status != 'resolved' AND i.anchor = ? AND coalesce(i.started_at, i.first_seen) >= ? "
            "AND EXISTS (SELECT 1 FROM incident_alerts ia JOIN alerts x ON x.id = ia.alert_id WHERE ia.incident_id = i.id AND ia.removed = 0 "
            "AND x.last_seen >= ? AND x.first_seen <= ?) ")


def _correlate(conn, cfg, alert_id, now):
    a = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not a or a["test"] or category(a["rule"]) == "health":
        return None
    existing = incident_of(conn, alert_id)
    if existing:      # already grouped (e.g. picked up when a related finding was correlated first)
        return existing
    t0 = (a["window_start"] or a["first_seen"]) - CORRELATE_WINDOW   # related = within the window on either side
    t1 = a["last_seen"] + CORRELATE_WINDOW
    shared = _shared(cfg, a["asset"])
    dev_sql, dev_p = _same_device_sql(a, shared)
    peer = _ext_ip(cfg, a["subject"])
    # 1. an open incident anchored on the same device, or on the same remote address (no chaining through other members)
    cands = []
    if dev_sql:
        xs, xp = _same_device_sql(a, shared, "i.")
        cands += [(r[0], "same device") for r in conn.execute(OPEN_INC + f"AND {xs} ORDER BY i.last_seen DESC",
                                                             ("device", a["last_seen"] - MAX_SPAN, t0, t1, *xp))]
    if peer:
        cands += [(r[0], "same remote address") for r in conn.execute(OPEN_INC + "AND i.peer = ? ORDER BY i.last_seen DESC",
                                                                     ("peer", a["last_seen"] - MAX_SPAN, t0, t1, peer))]
    for iid, why in cands:
        if _removed_from(conn, alert_id, iid):
            continue
        reason = _reason_text(why, a, peer)
        link(conn, iid, alert_id, "correlator", reason)
        return iid
    # 2. a related ungrouped finding: start an incident (needs a security / response finding among the two)
    pair, reasons = None, []
    if dev_sql:
        pair = conn.execute(f"SELECT * FROM alerts WHERE id != ? AND test=0 AND status != 'closed' AND last_seen >= ? AND first_seen <= ? "
                            f"AND {dev_sql} AND id NOT IN (SELECT alert_id FROM incident_alerts WHERE removed=0) ORDER BY last_seen DESC LIMIT 20",
                            (alert_id, t0, t1, *dev_p)).fetchall()
        pair = [p for p in pair if category(p["rule"]) != "health"]
        reasons = ["same device"]
    if not pair and peer:
        pair = [p for p in conn.execute("SELECT * FROM alerts WHERE id != ? AND test=0 AND status != 'closed' AND last_seen >= ? "
                                        "AND first_seen <= ? AND subject LIKE ? AND id NOT IN (SELECT alert_id FROM incident_alerts "
                                        "WHERE removed=0) ORDER BY last_seen DESC LIMIT 20", (alert_id, t0, t1, f"%{peer}%")).fetchall()
                if _ext_ip(cfg, p["subject"]) == peer and category(p["rule"]) != "health"]
        reasons = ["same remote address"]
    if not pair:
        return None
    group = [a, *pair]
    if not any(category(x["rule"]) in STARTERS and SEV.get(x["severity"], 0) >= SEV["medium"] for x in group):
        return None     # low-severity and informational findings can join an incident, but not start one
    anchor = "device" if reasons[0] == "same device" else "peer"
    return create(conn, cfg, group, "correlator", _reason_text(reasons[0], a, peer), anchor=anchor,
                  peer=peer if anchor == "peer" else None, started_at=min(x["window_start"] or x["first_seen"] for x in group))


def _reason_text(why, a, peer):
    if why == "same device":
        return f"same device ({a['asset']}) within {CORRELATE_WINDOW // 3600} hours"
    return f"same remote address ({peer}) within {CORRELATE_WINDOW // 3600} hours"


def title_for(cfg, conn, rows, peer=None):
    from . import identity as idn
    from .web import RULE_LABEL
    top = max(rows, key=lambda x: SEV.get(x["severity"], 0))
    assets = list(dict.fromkeys(x["asset"] for x in rows if x["asset"]))
    if len(assets) == 1:
        who = idn.label(conn, cfg, cfg.binat.get(assets[0], assets[0]), top["site"])["name"] if not _shared(cfg, assets[0]) else "Shared NAT address"
    else:
        who = f"{len(assets)} devices"
    if peer:
        who = f"{peer} and {who}"
    kinds = list(dict.fromkeys(RULE_LABEL.get(x["rule"], x["rule"]) for x in sorted(rows, key=lambda x: -SEV.get(x["severity"], 0))))
    return f"{who}: {', '.join(kinds[:3]).lower()}{' and more' if len(kinds) > 3 else ''}"[:200]


def create(conn, cfg, rows, user, reason, title=None, anchor="manual", peer=None, started_at=None):
    """New incident from finding rows; returns its id. `anchor` says what later findings must share to join automatically:
    'device' (same device), 'peer' (same remote address) or 'manual' (people add findings)."""
    now = time.time()
    top = max(rows, key=lambda x: SEV.get(x["severity"], 0))
    dev = top if anchor != "peer" else {"identity_id": None, "asset": None}
    cur = conn.execute("INSERT INTO incidents(site, title, status, severity, identity_id, asset, anchor, peer, started_at, first_seen, last_seen, "
                       "created_at, created_by, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (top["site"], title or title_for(cfg, conn, rows, peer), "open", top["severity"], dev["identity_id"], dev["asset"],
                        anchor, peer, started_at or min(x["first_seen"] for x in rows),
                        min(x["first_seen"] for x in rows), max(x["last_seen"] for x in rows), now, user, now))
    iid = cur.lastrowid
    for x in rows:
        _link_row(conn, iid, x["id"], user, reason)
    _event(conn, iid, user, "created", {"findings": [x["id"] for x in rows], "reason": reason})
    conn.commit()
    audit(conn, user, "incident_created", {"incident": iid, "findings": [x["id"] for x in rows], "reason": reason})
    return iid


def _link_row(conn, iid, alert_id, user, reason):
    conn.execute("INSERT INTO incident_alerts(incident_id, alert_id, added_at, added_by, reason, removed) VALUES (?,?,?,?,?,0) "
                 "ON CONFLICT(alert_id, incident_id) DO UPDATE SET removed=0, added_at=excluded.added_at, added_by=excluded.added_by, "
                 "reason=excluded.reason", (iid, alert_id, time.time(), user, reason))


def refresh(conn, iid):
    """Keep the incident's time span and severity in line with its findings."""
    r = conn.execute("SELECT min(a.first_seen), max(a.last_seen) FROM incident_alerts ia JOIN alerts a ON a.id=ia.alert_id "
                     "WHERE ia.incident_id=? AND ia.removed=0", (iid,)).fetchone()
    sev = [x[0] for x in conn.execute("SELECT a.severity FROM incident_alerts ia JOIN alerts a ON a.id=ia.alert_id "
                                      "WHERE ia.incident_id=? AND ia.removed=0", (iid,))]
    if r[0] is not None:
        conn.execute("UPDATE incidents SET first_seen=?, last_seen=?, severity=?, updated_at=? WHERE id=?",
                     (r[0], r[1], max(sev, key=lambda s: SEV.get(s, 0)), time.time(), iid))


def link(conn, iid, alert_id, user, reason):
    """Add a finding to an incident (moves it out of any other incident). Resolved incidents are reopened only by people."""
    inc = conn.execute("SELECT status FROM incidents WHERE id=?", (iid,)).fetchone()
    if not inc or not conn.execute("SELECT 1 FROM alerts WHERE id=?", (alert_id,)).fetchone():
        raise ValueError("no such incident or finding")
    old = incident_of(conn, alert_id)
    if old == iid:
        return
    if old:
        conn.execute("UPDATE incident_alerts SET removed=1 WHERE alert_id=? AND incident_id=?", (alert_id, old))
        _event(conn, old, user, "finding_moved", {"finding": alert_id, "to": iid})
        refresh(conn, old)
    _link_row(conn, iid, alert_id, user, reason)
    _event(conn, iid, user, "finding_added", {"finding": alert_id, "reason": reason})
    refresh(conn, iid)
    conn.commit()
    if user != "correlator":
        audit(conn, user, "incident_finding_added", {"incident": iid, "finding": alert_id, "reason": reason})


def unlink(conn, iid, alert_id, user):
    """Split a finding out of an incident. It stays out: the correlator never re-adds it to this incident."""
    if not conn.execute("UPDATE incident_alerts SET removed=1 WHERE incident_id=? AND alert_id=? AND removed=0", (iid, alert_id)).rowcount:
        raise ValueError("that finding is not part of this incident")
    _event(conn, iid, user, "finding_removed", {"finding": alert_id})
    refresh(conn, iid)
    conn.commit()
    audit(conn, user, "incident_finding_removed", {"incident": iid, "finding": alert_id})


def merge(conn, keep, gone, user):
    if keep == gone:
        raise ValueError("pick a different incident")
    if not conn.execute("SELECT 1 FROM incidents WHERE id=?", (gone,)).fetchone() or \
            not conn.execute("SELECT 1 FROM incidents WHERE id=?", (keep,)).fetchone():
        raise ValueError("no such incident")
    ids = [r[0] for r in conn.execute("SELECT alert_id FROM incident_alerts WHERE incident_id=? AND removed=0", (gone,))]
    for aid in ids:
        conn.execute("UPDATE incident_alerts SET removed=1 WHERE incident_id=? AND alert_id=?", (gone, aid))
        _link_row(conn, keep, aid, user, f"merged from incident #{gone}")
    conn.execute("UPDATE incidents SET status='resolved', resolution='duplicate', resolution_note=?, resolved_at=?, updated_at=? WHERE id=?",
                 (f"merged into incident #{keep}", time.time(), time.time(), gone))
    _event(conn, gone, user, "merged_into", {"incident": keep, "findings": ids})
    _event(conn, keep, user, "merged_from", {"incident": gone, "findings": ids})
    refresh(conn, keep)
    conn.commit()
    audit(conn, user, "incident_merged", {"keep": keep, "gone": gone, "findings": ids})


def update(conn, iid, user, status=None, assignee=None, resolution=None, note=None, close_findings=False):
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
    if not inc:
        raise ValueError("no such incident")
    changes = {}
    if status is not None:
        if status not in STATUSES:
            raise ValueError("unknown status")
        if status == "resolved" and resolution not in RESOLUTIONS:
            raise ValueError("choose a resolution reason")
        if status != inc["status"]:
            changes["status"] = [inc["status"], status]
    if assignee is not None and assignee != (inc["assignee"] or ""):
        changes["assignee"] = [inc["assignee"] or "", assignee]
    if changes.get("status") or (status == "resolved" and resolution != inc["resolution"]):
        res = resolution if status == "resolved" else None
        conn.execute("UPDATE incidents SET status=?, resolution=?, resolution_note=?, resolved_at=?, updated_at=? WHERE id=?",
                     (status, res, (note or "")[:1000] if res else None, time.time() if res else None, time.time(), iid))
        if res:
            changes["resolution"] = res
    if "assignee" in changes:
        conn.execute("UPDATE incidents SET assignee=?, updated_at=? WHERE id=?", (assignee or None, time.time(), iid))
    if changes:
        _event(conn, iid, user, "updated", changes)
    if note:
        _event(conn, iid, user, "note", {"text": note[:2000]})
        conn.execute("UPDATE incidents SET updated_at=? WHERE id=?", (time.time(), iid))
    closed = []
    if close_findings and status == "resolved":
        for r in conn.execute("SELECT alert_id FROM incident_alerts ia JOIN alerts a ON a.id=ia.alert_id WHERE ia.incident_id=? "
                              "AND ia.removed=0 AND a.status != 'closed'", (iid,)).fetchall():
            conn.execute("UPDATE alerts SET status='closed', acked_by=?, acked_at=? WHERE id=?", (user, time.time(), r[0]))
            closed.append(r[0])
        if closed:
            _event(conn, iid, user, "findings_closed", {"findings": closed})
    conn.commit()
    if changes or note or closed:
        audit(conn, user, "incident_updated", {"incident": iid, **changes, "note": bool(note), "closed_findings": closed})
    return changes


def history(conn, iid):
    return [dict(r) | {"detail": json.loads(r["detail"] or "{}")} for r in
            conn.execute("SELECT * FROM incident_events WHERE incident_id=? ORDER BY ts, id", (iid,))]


def already_notified(conn, alert, channel_id, now=None):
    """The incident id when this channel already received a finding of the same incident, of the same or higher
    severity, within NOTIFY_DEDUP; else None. Higher-severity findings are always sent."""
    try:
        aid = alert["id"]
    except (KeyError, IndexError):
        return None
    iid = incident_of(conn, aid)
    if not iid:
        return None
    now = now or time.time()
    r = conn.execute("SELECT a.severity FROM deliveries d JOIN incident_alerts ia ON ia.alert_id = d.alert_id AND ia.incident_id=? "
                     "AND ia.removed=0 JOIN alerts a ON a.id = d.alert_id WHERE d.channel_id=? AND d.kind='alert' AND d.status='delivered' "
                     "AND d.ts > ? AND d.alert_id != ?", (iid, channel_id, now - NOTIFY_DEDUP, aid)).fetchall()
    best = max((SEV.get(x[0], 0) for x in r), default=-1)
    return iid if best >= SEV.get(alert["severity"], 0) else None


def export(conn, cfg, iid):
    """Evidence bundle for one incident (JSON-serializable): incident, findings with evidence and queries, history."""
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
    if not inc:
        raise ValueError("no such incident")
    fs = []
    for a in members(conn, iid):
        d = dict(a)
        for k in ("evidence", "query", "alternatives", "next_steps"):
            try:
                d[k] = json.loads(d[k] or "null")
            except ValueError:
                pass
        fs.append(d)
    from . import __version__
    return {"format": "m0nitor-incident-1", "generated_by": f"m0nitor {__version__}", "generated_at": time.time(),
            "note": "Findings are grouped because they share a device or remote address in time; grouping does not mean one caused another.",
            "incident": dict(inc), "findings": fs, "history": history(conn, iid)}


BACKFILL_DAYS, BACKFILL_MAX = 7, 5000


def backfill(cfg, conn=None, now=None):
    """One-time grouping of open findings raised before incidents existed (last BACKFILL_DAYS, at most BACKFILL_MAX),
    oldest first, exactly as if they had arrived now. Runs once per database. Returns how many incidents it touched."""
    from .core import db_connect, get_state, set_state
    conn = conn or db_connect()
    if get_state(conn, "incidents:backfilled")[0]:
        return 0
    now = now or time.time()
    touched = set()
    for (aid,) in conn.execute("SELECT id FROM alerts WHERE status IN ('open','acked') AND test=0 AND last_seen >= ? ORDER BY first_seen "
                               "LIMIT ?", (now - BACKFILL_DAYS * 86400, BACKFILL_MAX)).fetchall():
        iid = correlate(conn, cfg, aid, now)
        if iid:
            touched.add(iid)
    set_state(conn, "incidents:backfilled", {"ts": now, "incidents": len(touched)})
    audit(conn, "incidents", "incidents_backfill", {"incidents": len(touched), "days": BACKFILL_DAYS})
    return len(touched)
