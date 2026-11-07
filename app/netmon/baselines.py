"""Smarter baselines and precise exceptions.

Baselines (used by the outbound-volume rule):
  - compare the same *local* hour in the firewall's time zone (DST-aware), not the same UTC hour;
  - prefer the same kind of day (weekday vs weekend) when at least MIN_SAME_KIND such days exist;
  - hours without telemetry for the firewall are left out, never counted as zero traffic;
  - hours covered by an unresolved finding of the same kind for the same source are left out, so a suspicious
    period is not learned as normal.

Exceptions are precise by default. Besides rule / device / subject, an exception can be limited to
  - one destination (IP or CIDR) and/or service ("tcp/443"),
  - a schedule (days of the week + a local time window, overnight allowed) in the firewall's time zone,
  - one firewall,
  - an expiry date.
An exception with a destination or service only matches a finding that names exactly that destination / service; a
finding involving many destinations (scanning, fan-out) is never hidden by it. For outbound volume, traffic to the
excepted destinations is *subtracted* and the rest is checked again, so a normal backup cannot hide other uploads.
"""
import ipaddress
import json
import time
from datetime import datetime

from .ux import site_tz

MIN_SAME_KIND = 3
DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
PREVIEW_DAYS = 30
SUBJECT_IS_SOURCE = {"outbound_volume"}   # rules whose subject is the (post-NAT) source, not a peer
# findings about many destinations: their evidence lists only a sample, so a destination-limited exception can never
# prove it covers them all (volume is handled by subtracting the excepted traffic before the check instead)
MANY_PEERS = {"fanout", "outbound_volume", "dns_bypass", "dns_anomaly", "fw_blocked_outbound"}


# ---- schedules -----------------------------------------------------------------------------------------------
def parse_schedule(days, start, end):
    """Form values -> {"days": [0..6], "start": "HH:MM", "end": "HH:MM"} (local time) or None. Raises ValueError."""
    if not days and not start and not end:
        return None
    ds = sorted({int(d) for d in days if str(d).isdigit() and 0 <= int(d) <= 6})
    if not ds:
        raise ValueError("choose at least one day for the schedule")
    for v in (start, end):
        try:
            h, m = (int(x) for x in v.split(":"))
            assert 0 <= h <= 23 and 0 <= m <= 59
        except (ValueError, AssertionError, AttributeError):
            raise ValueError("schedule times must be HH:MM")
    if start == end:
        raise ValueError("the schedule needs different start and end times")
    return {"days": ds, "start": start, "end": end}


def schedule_active(sched, ts, site=None):
    """True when ts falls in the schedule (site-local, DST-aware). Overnight windows (22:00-04:00) belong to the
    day they start on."""
    if not sched:
        return True
    d = datetime.fromtimestamp(ts, site_tz(site))
    mins = d.hour * 60 + d.minute
    sh, sm = (int(x) for x in sched["start"].split(":"))
    eh, em = (int(x) for x in sched["end"].split(":"))
    s, e = sh * 60 + sm, eh * 60 + em
    if s < e:
        return d.weekday() in sched["days"] and s <= mins < e
    return (d.weekday() in sched["days"] and mins >= s) or ((d.weekday() - 1) % 7 in sched["days"] and mins < e)


def schedule_text(sched):
    if not sched:
        return ""
    ds = sched["days"]
    days = ("every day" if len(ds) == 7 else "Mon–Fri" if ds == [0, 1, 2, 3, 4] else "weekends" if ds == [5, 6]
            else ", ".join(DAY_NAMES[d] for d in ds))
    return f"{days} {sched['start']}–{sched['end']} (firewall's local time)"


# ---- what a finding names --------------------------------------------------------------------------------------
def _ip(v):
    try:
        return ipaddress.ip_address(str(v).strip())
    except ValueError:
        return None


def finding_peers(f):
    """External/peer addresses a finding names (subject 'ip', 'ip:port', 'x|ip', evidence peer/dst/top_dsts)."""
    out = []
    for part in str(f.get("subject") or "").split("|"):     # 'ip', 'ip:port', 'sig|ip', 'ip|port'
        if part.count(":") == 1:
            part = part.split(":")[0]
        if _ip(part) and f.get("rule") not in SUBJECT_IS_SOURCE:
            out.append(str(_ip(part)))
    ev = f.get("evidence")
    if isinstance(ev, str):
        try:
            ev = json.loads(ev or "[]")
        except ValueError:
            ev = []
    for x in ev if isinstance(ev, list) else [ev]:
        if not isinstance(x, dict):
            continue
        for k in ("peer", "dst", "top_dst", "peers", "top_dsts", "sample_peers"):
            v = x.get(k)
            for y in (v if isinstance(v, list) else [v] if v else []):
                if _ip(y):
                    out.append(str(_ip(y)))
    own = {str(f.get("asset") or "")} | ({str(f.get("subject") or "")} if f.get("rule") in SUBJECT_IS_SOURCE else set())
    return [x for x in dict.fromkeys(out) if x not in own]


def finding_service(f):
    """'tcp/443' when the finding names one service (subject 'ip:port' or evidence port/dport), else None."""
    ev = f.get("evidence")
    if isinstance(ev, str):
        try:
            ev = json.loads(ev or "[]")
        except ValueError:
            ev = []
    evs = [x for x in (ev if isinstance(ev, list) else [ev]) if isinstance(x, dict)]
    port, proto = None, None
    subj = str(f.get("subject") or "")
    m = subj.rsplit(":", 1)
    parts = subj.split("|")
    if len(m) == 2 and m[1].isdigit() and _ip(m[0].split("|")[-1]):
        port = int(m[1])
    elif len(parts) == 2 and _ip(parts[0]) and parts[1].isdigit():          # 'ip|port'
        port = int(parts[1])
    for x in evs:
        p = x.get("port") or x.get("dport")
        if port is None and (isinstance(p, int) or (isinstance(p, str) and p.isdigit())):
            port = int(p)
        if proto is None and x.get("proto") is not None:
            proto = "udp" if str(x["proto"]).lower() in ("17", "udp") else "tcp"
    if port is None:
        return None
    return f"{proto or ('udp' if 'udp' in subj.lower() else 'tcp')}/{port}"


def norm_service(v):
    v = (v or "").strip().lower()
    if v in ("", "*"):
        return "*"
    proto, _, port = v.partition("/")
    if not port:
        proto, port = "tcp", proto
    if proto not in ("tcp", "udp") or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("service must look like tcp/443 or udp/53")
    return f"{proto}/{int(port)}"


def norm_peer(v):
    v = (v or "").strip()
    if v in ("", "*"):
        return "*"
    try:
        n = ipaddress.ip_network(v, strict=False)
    except ValueError:
        raise ValueError("destination must be an IP address or CIDR")
    if n.prefixlen < (16 if n.version == 4 else 32):
        raise ValueError("destination range too broad (at most a /16 or /32)")
    return str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n)


def _in(peer, ip):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(peer, strict=False)
    except ValueError:
        return False


# ---- matching --------------------------------------------------------------------------------------------------
def _col(exc, k, default=None):
    try:
        return exc[k]
    except (KeyError, IndexError):
        return default


def exception_applies(exc, f, now, site=None):
    """Precise match of one exception against a finding dict (rule, asset, subject, evidence, site, window)."""
    from .detect import exception_matches
    if not exception_matches(exc, f["rule"], f.get("asset"), f.get("subject"), now):
        return False
    xs = _col(exc, "site")
    if xs and xs != (f.get("site") or (site or {}).get("id")):
        return False
    sched = _col(exc, "schedule")
    if sched:
        sched = json.loads(sched) if isinstance(sched, str) else sched
        w = f.get("window") or (f.get("window_start"), f.get("window_end"))
        t = (w[0] if w and w[0] else None) or now
        if not schedule_active(sched, t, site):
            return False
    peer = _col(exc, "peer") or "*"
    if peer != "*":
        if f["rule"] in MANY_PEERS:
            return False
        ps = finding_peers(f)
        # every named peer must be inside the excepted destination; a finding with no or many unrelated peers stays
        if not ps or not all(_in(peer, p) for p in ps):
            return False
    svc = _col(exc, "service") or "*"
    if svc != "*" and finding_service(f) != svc:
        return False
    return True


def matching_exception(conn, f, now, site=None):
    """First enabled exception that applies to finding f, or None. Records the hit."""
    for x in conn.execute("SELECT * FROM exceptions WHERE enabled=1 ORDER BY id").fetchall():
        if exception_applies(x, f, now, site):
            conn.execute("UPDATE exceptions SET hits = coalesce(hits, 0) + 1, last_hit = ? WHERE id = ?", (now, x["id"]))
            conn.commit()
            return x
    return None


def volume_exceptions(conn, rule, asset, src, now, site=None):
    """Active destination-limited exceptions for an outbound-volume candidate: [(id, peer, service)]. Traffic to
    these is subtracted before the threshold check (exception rule '*' or this rule, device = asset or src)."""
    out = []
    for x in conn.execute("SELECT * FROM exceptions WHERE enabled=1").fetchall():
        if x["expires_at"] and x["expires_at"] < now or x["rule"] not in ("*", rule):
            continue
        if x["asset"] not in ("*", asset, src) or (_col(x, "peer") or "*") == "*":
            continue
        if _col(x, "site") and _col(x, "site") != (site or {}).get("id"):
            continue
        sched = _col(x, "schedule")
        if sched and not schedule_active(json.loads(sched), now, site):
            continue
        out.append((x["id"], x["peer"], _col(x, "service") or "*"))
    return out


# ---- describe / preview ----------------------------------------------------------------------------------------
def describe(exc, cfg=None, rule_label=None):
    """One plain sentence: what this exception hides."""
    rl = (rule_label or {}).get(exc["rule"], exc["rule"]) if exc["rule"] != "*" else "any finding"
    dev = "any device" if exc["asset"] == "*" else (cfg.asset_label(exc["asset"]) if cfg else exc["asset"])
    if dev == f"{exc['asset']} ({exc['asset']})":   # unnamed device
        dev = exc["asset"]
    parts = [f"{rl} for {dev}"]
    if exc["subject"] not in ("*", ""):
        parts.append(f"about {exc['subject']}")
    peer, svc = _col(exc, "peer") or "*", _col(exc, "service") or "*"
    if peer != "*" or svc != "*":
        parts.append("to " + " ".join(x for x in (peer if peer != "*" else "any destination", f"on {svc}" if svc != "*" else "") if x))
    sched = _col(exc, "schedule")
    if sched:
        parts.append("only " + schedule_text(json.loads(sched) if isinstance(sched, str) else sched))
    if _col(exc, "site"):
        parts.append(f"on firewall {exc['site']}")
    return ", ".join(parts)


def preview(conn, exc, cfg, now=None, days=PREVIEW_DAYS, limit=5):
    """What an exception would have hidden over the last `days`: counts and examples of matching findings, and
    how many findings for the same device it would NOT hide (so the scope is visible before saving)."""
    now = now or time.time()
    match, other, n = [], 0, 0
    for a in conn.execute("SELECT * FROM alerts WHERE test=0 AND last_seen >= ? AND site_ok(site) ORDER BY last_seen DESC LIMIT 5000",
                          (now - days * 86400,)).fetchall():
        f = dict(a) | {"window": (a["window_start"], a["window_end"])}
        site = cfg.site(a["site"]) if a["site"] else None
        probe = dict(exc) | {"enabled": 1, "expires_at": None}
        if exception_applies(probe, f, now, site):
            n += 1
            if len(match) < limit:
                match.append({"id": a["id"], "title": a["title"], "last_seen": a["last_seen"], "status": a["status"]})
        elif exc["asset"] not in ("*", "") and a["asset"] == exc["asset"]:
            other += 1
    return {"matches": n, "examples": match, "same_device_not_hidden": other, "days": days}


# ---- baselines -------------------------------------------------------------------------------------------------
def telemetry_hours(det, bs, ws):
    """Set of hour-start epochs with any flow record from this firewall (Akvorado's hourly table: cheap)."""
    rows = det.q("SELECT DISTINCT toUInt32(toStartOfHour(TimeReceived)) AS h FROM flows_1h0m0s WHERE ExporterName = {exporter:String} "
                 "AND TimeReceived >= toDateTime({bs:UInt32}) AND TimeReceived < toDateTime({ws:UInt32})", {"bs": bs, "ws": ws})
    return {int(r["h"]) for r in rows}


def suspicious_hours(conn, site_id, rule, subject, bs, ws):
    """Hour-start epochs covered by unresolved findings of this rule for this subject (not learned as normal).
    Closed findings count as reviewed; findings in incidents resolved as 'fixed' stay excluded."""
    hours = set()
    rows = conn.execute("SELECT a.window_start, a.window_end, a.last_seen, a.status, (SELECT i.resolution FROM incident_alerts ia "
                        "JOIN incidents i ON i.id = ia.incident_id WHERE ia.alert_id = a.id AND ia.removed = 0 LIMIT 1) AS res "
                        "FROM alerts a WHERE a.rule = ? AND a.subject = ? AND a.site IS ? AND a.test = 0 AND a.last_seen >= ? AND a.first_seen < ?",
                        (rule, subject, site_id, bs, ws)).fetchall()
    for r in rows:
        if r["status"] == "closed" and r["res"] != "fixed":
            continue
        t0 = int((r["window_start"] or r["last_seen"]) // 3600 * 3600)
        t1 = int(max(r["window_end"] or r["last_seen"], r["last_seen"]))
        for h in range(t0, t1 + 1, 3600):
            hours.add(h)
    return hours


def baseline_values(hist_by_hour, ws, ndays, site, have=None, skip=frozenset(), win_h=1.0):
    """Comparable values for the window starting at ws: the same local hour on earlier days, same kind of day
    (weekday/weekend) when MIN_SAME_KIND exist. Hours without telemetry (`have` given and missing) or in `skip`
    are left out. Returns (values, description)."""
    tz = site_tz(site)
    cur = datetime.fromtimestamp(ws, tz)
    weekend = cur.weekday() >= 5
    same, other, gaps, skipped = [], [], 0, 0
    for d in range(1, ndays + 1):
        day = datetime.fromtimestamp(ws - d * 86400, tz)
        h = datetime(day.year, day.month, day.day, cur.hour, tzinfo=tz)
        hs = int(h.timestamp()) // 3600 * 3600
        if have is not None and hs not in have:
            gaps += 1
            continue
        if hs in skip:
            skipped += 1
            continue
        v = hist_by_hour.get(hs, 0) * win_h
        (same if (h.weekday() >= 5) == weekend else other).append(v)
    if len(same) >= MIN_SAME_KIND:
        vals, kind = same, "weekend days" if weekend else "weekdays"
    else:
        vals, kind = same + other, "days"
    desc = (f"same local hour ({cur:%H}:00 {tz.key}) on {len(vals)} earlier {kind}"
            + (f"; {gaps} day(s) without telemetry left out" if gaps else "")
            + (f"; {skipped} hour(s) with unresolved findings not learned" if skipped else ""))
    return vals, desc


def learning_progress(conn, cfg, det_status):
    """Per firewall: days of history vs what the baselines need, in plain terms."""
    d = cfg["detector"]
    out = []
    per = (det_status or {}).get("sites") or {}
    for s in cfg.sites:
        days = float(per.get(s["id"], 0) or 0)
        out.append({"site": s["id"], "name": s["name"], "days": days, "need": d["baseline_days"], "min": d["min_learning_days"],
                    "tz": site_tz(s).key, "pct": min(100, int(100 * days / max(1, d["baseline_days"]))),
                    "state": "complete" if days >= d["baseline_days"] else "learning" if days >= d["min_learning_days"] else "starting"})
    return out
