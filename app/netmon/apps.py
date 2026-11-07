"""Applications and their dependencies: group devices into an application (e.g. a mail server with its database and
backup target) and see what it depends on and what depends on it.

Observed vs confirmed: dependencies come from traffic records (internal conversations, and reply records for the
internet side, which name the device even behind the shared NAT address). People confirm or dismiss them. Each
observed dependency says on how many days of the searched period it was seen (its confidence), when it was first and
last seen, the service and the direction. A dependency first seen in the last 24 hours is "new". A confirmed
dependency that was not seen is listed as such: **lack of traffic does not prove a dependency is gone** (it may be
used monthly, or fail over). Members follow their device identity, so an address change does not drop them.
"""
import ipaddress
import json
import time

from .core import audit

PERIODS = {"24h": 86400, "7d": 7 * 86400}
NEW_WINDOW = 86400
MAX_ROWS = 5000
_cache = {}


# ---- applications ----------------------------------------------------------------------------------------------
def _ips(text):
    out = []
    for v in (text or "").replace(",", " ").split():
        try:
            out.append(str(ipaddress.ip_address(v.strip())))
        except ValueError:
            raise ValueError(f"not an IP address: {v[:60]}")
    return out


def create(conn, cfg, site, name, members_text, user, owner="", critical=False, note=""):
    name = " ".join((name or "").split())[:60]
    if not name:
        raise ValueError("give the application a name")
    ips = _ips(members_text)
    for ip in ips:
        if not cfg.is_internal(ip):
            raise ValueError(f"{ip} is not an internal address")
    try:
        aid = conn.execute("INSERT INTO apps(site, name, note, owner, critical, created_by, created_at) VALUES (?,?,?,?,?,?,?)",
                           (site, name, note[:300], owner[:80], 1 if critical else 0, user, time.time())).lastrowid
    except Exception:
        raise ValueError(f"an application called {name} already exists")
    for ip in ips:
        add_member(conn, aid, site, ip, user, commit=False)
    conn.commit()
    audit(conn, user, "app_created", {"id": aid, "site": site, "name": name, "members": ips})
    return aid


def update(conn, aid, user, name=None, owner=None, critical=None, note=None):
    a = get(conn, aid)
    conn.execute("UPDATE apps SET name=?, owner=?, critical=?, note=? WHERE id=?",
                 (" ".join((name or a["name"]).split())[:60], (owner if owner is not None else a["owner"] or "")[:80],
                  int(critical) if critical is not None else a["critical"], (note if note is not None else a["note"] or "")[:300], aid))
    conn.commit()
    audit(conn, user, "app_updated", {"id": aid})


def delete(conn, aid, user):
    for t in ("app_members", "app_deps"):
        conn.execute(f"DELETE FROM {t} WHERE app_id=?", (aid,))
    conn.execute("DELETE FROM apps WHERE id=?", (aid,))
    conn.commit()
    audit(conn, user, "app_deleted", {"id": aid})


def get(conn, aid):
    a = conn.execute("SELECT * FROM apps WHERE id=? AND site_ok(site)", (aid,)).fetchone()   # other firewalls: not found
    if not a:
        raise ValueError("no such application")
    return a


def add_member(conn, aid, site, ip, user, role="", commit=True):
    from .identity import owner_at
    ip = str(ipaddress.ip_address(ip))
    try:
        iid = owner_at(conn, site, ip, time.time())["identity"]
    except Exception:
        iid = None
    conn.execute("INSERT OR IGNORE INTO app_members(app_id, ip, identity_id, role, added_by, added_at) VALUES (?,?,?,?,?,?)",
                 (aid, ip, iid, role[:60], user, time.time()))
    if commit:
        conn.commit()
        audit(conn, user, "app_member_added", {"app": aid, "ip": ip})


def remove_member(conn, aid, ip, user):
    conn.execute("DELETE FROM app_members WHERE app_id=? AND ip=?", (aid, ip))
    conn.commit()
    audit(conn, user, "app_member_removed", {"app": aid, "ip": ip})


def members(conn, aid):
    """[(current ip, stored ip, identity id, role)]: a member follows its identity's current address."""
    from .identity import current_ip, resolve
    out = []
    for m in conn.execute("SELECT * FROM app_members WHERE app_id=? ORDER BY ip", (aid,)).fetchall():
        ip = m["ip"]
        if m["identity_id"]:
            try:
                ip = current_ip(conn, resolve(conn, m["identity_id"])) or ip
            except Exception:
                pass
        out.append({"ip": ip, "stored": m["ip"], "identity_id": m["identity_id"], "role": m["role"]})
    return out


def apps_of_ip(conn, site):
    """{ip: [(app id, app name), ...]} for all members at a site (current addresses); a device can be in several."""
    out = {}
    for a in conn.execute("SELECT id, name FROM apps WHERE site=? ORDER BY id", (site,)).fetchall():
        for m in members(conn, a["id"]):
            out.setdefault(m["ip"], []).append((a["id"], a["name"]))
    return out


def app_of_ip(conn, site):
    """{ip: (app id, app name)}: the first application of each member address (for labelling the other side)."""
    return {ip: v[0] for ip, v in apps_of_ip(conn, site).items()}


def set_status(conn, aid, dkey, status, user, note=""):
    if status not in ("confirmed", "dismissed", "observed"):
        raise ValueError("unknown status")
    conn.execute("INSERT INTO app_deps(app_id, dkey, status, note, by, ts) VALUES (?,?,?,?,?,?) ON CONFLICT(app_id, dkey) DO UPDATE SET "
                 "status=excluded.status, note=excluded.note, by=excluded.by, ts=excluded.ts", (aid, dkey, status, note[:200], user, time.time()))
    conn.commit()
    audit(conn, user, "app_dependency_" + status, {"app": aid, "dependency": dkey})
    _cache.clear()


# ---- observation -----------------------------------------------------------------------------------------------
def _v6(ip):
    from .hunt import _v6 as v
    return v(ip)


def bucket_of(span):
    """Confidence counts in how many fixed periods of the window a dependency was seen: days, or 4-hour periods for 24 hours."""
    return (86400, "days") if span >= 2 * 86400 else (4 * 3600, "4-hour periods")


def observe(cfg, ch, site, ips, t0, t1):
    """Raw observations for member addresses: internal conversations both ways, and the internet side from reply
    records. Bounded (period, LIMIT, ClickHouse execution time)."""
    from .segments import _ranges, firewall_addrs
    if not ips:
        return [], []
    lo, hi = _ranges(cfg)
    m6 = [_v6(x) for x in ips]
    p = {"exp": site["exporter"], "wan": site["wan_if"], "t0": int(t0), "t1": int(t1), "lo": lo, "hi": hi, "m6": m6, "lim": MAX_ROWS, "b": bucket_of(t1 - t0)[0]}
    internal = ch.query("""SELECT replaceOne(IPv6NumToString(c), '::ffff:', '') AS client, replaceOne(IPv6NumToString(s), '::ffff:', '') AS server,
        proto, port, count() AS n, sum(b) AS bytes, toUInt32(min(t)) AS first, toUInt32(max(t)) AS last, uniqExact(intDiv(toUInt32(t) - {t0:UInt32}, {b:UInt32})) AS days FROM (
          SELECT TimeReceived AS t, if(DstPort <= SrcPort, SrcAddr, DstAddr) AS c, if(DstPort <= SrcPort, DstAddr, SrcAddr) AS s,
                 Proto AS proto, least(SrcPort, DstPort) AS port, Bytes * SamplingRate AS b
          FROM flows WHERE ExporterName = {exp:String} AND TimeReceived >= toDateTime({t0:UInt32}) AND TimeReceived < toDateTime({t1:UInt32})
            AND InIfName != '' AND InIfName != {wan:String} AND OutIfName != {wan:String} AND (has({m6:Array(IPv6)}, SrcAddr) OR has({m6:Array(IPv6)}, DstAddr))
            AND arrayExists((a, z) -> SrcAddr >= a AND SrcAddr <= z, {lo:Array(IPv6)}, {hi:Array(IPv6)})
            AND arrayExists((a, z) -> DstAddr >= a AND DstAddr <= z, {lo:Array(IPv6)}, {hi:Array(IPv6)}))
        GROUP BY client, server, proto, port ORDER BY n DESC LIMIT {lim:UInt32}""", p)
    own = firewall_addrs(site)
    internal = [r for r in internal if r["client"] not in own and r["server"] not in own]
    external = ch.query("""SELECT replaceOne(IPv6NumToString(DstAddr), '::ffff:', '') AS member, SrcAS AS asn,
        dictGetOrDefault('asns', 'name', toUInt64(SrcAS), '') AS org, Proto AS proto,
        if(SrcPort < DstPort, 'out', 'in') AS dir, if(SrcPort < DstPort, SrcPort, DstPort) AS port,
        count() AS n, sum(Bytes * SamplingRate) AS bytes, uniqExact(SrcAddr) AS remotes, any(replaceOne(IPv6NumToString(SrcAddr), '::ffff:', '')) AS sample,
        toUInt32(min(TimeReceived)) AS first, toUInt32(max(TimeReceived)) AS last, uniqExact(intDiv(toUInt32(TimeReceived) - {t0:UInt32}, {b:UInt32})) AS days
        FROM flows WHERE ExporterName = {exp:String} AND TimeReceived >= toDateTime({t0:UInt32}) AND TimeReceived < toDateTime({t1:UInt32})
          AND InIfName = {wan:String} AND has({m6:Array(IPv6)}, DstAddr)
        GROUP BY member, asn, org, proto, dir, port ORDER BY n DESC LIMIT {lim:UInt32}""", p)
    return internal, external


def _svc(proto, port):
    from .segments import svc_name
    return svc_name(proto, port)


def dependencies(conn, cfg, ch, aid, span=7 * 86400, now=None):
    """Observed + confirmed dependencies of one application, both directions, with status and confidence."""
    now = int(now or time.time())
    key = (id(conn), aid, span, now // 300)
    if key in _cache:
        return _cache[key]
    a = get(conn, aid)
    site = cfg.site(a["site"]) or cfg.sites[0]
    ms = members(conn, aid)
    ips = {m["ip"] for m in ms}
    t0 = now - span
    internal, external = observe(cfg, ch, site, sorted(ips), t0, now)
    apps_by_ip = app_of_ip(conn, a["site"])
    bsec, unit = bucket_of(span)
    days_in = max(1, round(span / bsec))
    deps = {}

    def put(dkey, **kw):
        d = deps.setdefault(dkey, {"dkey": dkey, "n": 0, "bytes": 0, "first": kw["first"], "last": kw["last"], "days": 0, "members": set(),
                                   **{k: v for k, v in kw.items() if k not in ("n", "bytes", "first", "last", "days", "member")}})
        d["n"] += kw["n"]
        d["bytes"] += kw["bytes"]
        d["first"], d["last"] = min(d["first"], kw["first"]), max(d["last"], kw["last"])
        d["days"] = max(d["days"], kw["days"])
        d["members"].add(kw["member"])

    for r in internal:
        svc = _svc(r["proto"], r["port"])
        if r["client"] in ips and r["server"] in ips:
            continue   # inside the application
        if r["client"] in ips:
            other = apps_by_ip.get(r["server"])
            put(f"int:out:{r['server']}:{svc}", kind="internal", direction="uses", target=r["server"], app=other, service=svc, member=r["client"],
                n=r["n"], bytes=r["bytes"], first=r["first"], last=r["last"], days=r["days"])
        else:
            other = apps_by_ip.get(r["client"])
            put(f"int:in:{r['client']}:{svc}", kind="internal", direction="used by", target=r["client"], app=other, service=svc, member=r["server"],
                n=r["n"], bytes=r["bytes"], first=r["first"], last=r["last"], days=r["days"])
    for r in external:
        svc = _svc(r["proto"], r["port"])
        if r["dir"] == "out":
            put(f"ext:out:AS{r['asn']}:{svc}", kind="internet", direction="uses", target=f"AS{r['asn']}", org=r["org"], service=svc, member=r["member"],
                remotes=r["remotes"], sample=r["sample"], n=r["n"], bytes=r["bytes"], first=r["first"], last=r["last"], days=r["days"])
        else:
            put(f"ext:in:{svc}", kind="internet", direction="used by", target="internet clients", service=svc, member=r["member"],
                remotes=r["remotes"], n=r["n"], bytes=r["bytes"], first=r["first"], last=r["last"], days=r["days"])
    stored = {r["dkey"]: dict(r) for r in conn.execute("SELECT * FROM app_deps WHERE app_id=?", (aid,))}
    for k, d in deps.items():   # remember when netmon first saw each dependency (beyond the searched period)
        st = stored.get(k)
        if st is None:
            conn.execute("INSERT OR IGNORE INTO app_deps(app_id, dkey, status, by, ts, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
                         (aid, k, "observed", "netmon", now, d["first"], d["last"]))
            stored[k] = {"status": "observed", "first_seen": d["first"], "note": "", "by": "netmon", "ts": now}
        else:
            conn.execute("UPDATE app_deps SET first_seen=min(coalesce(first_seen, ?), ?), last_seen=max(coalesce(last_seen, 0), ?) WHERE app_id=? AND dkey=?",
                         (d["first"], d["first"], d["last"], aid, k))
            st["first_seen"] = min(st.get("first_seen") or d["first"], d["first"])
    conn.commit()
    created = a["created_at"]
    out = []
    for k, d in deps.items():
        st = stored.get(k, {})
        ratio = d["days"] / days_in
        conf = "high" if ratio >= 0.6 else "medium" if ratio >= 0.25 else "low"
        first_known = st.get("first_seen") or d["first"]
        new = first_known >= now - NEW_WINDOW and created < now - NEW_WINDOW and first_known > t0
        out.append(d | {"members": sorted(d["members"]), "status": st.get("status", "observed"), "confidence": conf, "new": new,
                        "note": st.get("note") or "", "first_known": first_known, "seen": True})
    for k, st in stored.items():   # confirmed but not seen in this period
        if k not in deps and st["status"] == "confirmed":
            kind, direction, rest = k.split(":", 2)
            target, _, svc = rest.rpartition(":")
            out.append({"dkey": k, "kind": "internal" if kind == "int" else "internet", "direction": "uses" if direction == "out" else "used by",
                        "target": target, "service": svc, "app": apps_by_ip.get(target), "status": "confirmed", "seen": False, "n": 0, "bytes": 0,
                        "days": 0, "members": [], "confidence": "confirmed", "new": False, "note": st.get("note") or "",
                        "first_known": st.get("first_seen"), "last": st.get("last_seen"), "first": st.get("first_seen")})
    out.sort(key=lambda x: (x["status"] == "dismissed", not x["new"], x["direction"] != "uses", -x["n"]))
    res = {"app": dict(a), "members": ms, "deps": out, "t0": t0, "t1": now, "days": days_in, "unit": unit,
           "truncated": len(internal) >= MAX_ROWS or len(external) >= MAX_ROWS}
    _cache[key] = res
    for k in [k for k in _cache if k[3] < now // 300 - 2]:
        _cache.pop(k, None)
    return res


def impact(conn, cfg, ch, site, ips, span=7 * 86400, now=None):
    """Outage impact for a device (or a set of devices): which applications and devices used it in the period."""
    now = int(now or time.time())
    internal, external = observe(cfg, ch, site, sorted(ips), now - span, now)
    apps_by_ip = apps_of_ip(conn, site["id"])
    users, apps_hit = {}, {}
    for r in internal:
        if r["server"] in ips and r["client"] not in ips:
            svc = _svc(r["proto"], r["port"])
            u = users.setdefault(r["client"], {"ip": r["client"], "services": set(), "n": 0, "last": 0, "apps": apps_by_ip.get(r["client"], [])})
            u["services"].add(svc)
            u["n"] += r["n"]
            u["last"] = max(u["last"], r["last"])
            for ap in u["apps"]:
                apps_hit.setdefault(ap, set()).add(svc)
    inet = [r for r in external if r["dir"] == "in"]
    return {"devices": sorted(users.values(), key=lambda x: -x["n"]), "apps": apps_hit,
            "internet": [{"service": _svc(r["proto"], r["port"]), "remotes": r["remotes"], "n": r["n"]} for r in inet][:20],
            "member_of": sorted({ap for i in ips for ap in apps_by_ip.get(i, [])})}


def graph_svg(name, deps, width=640, height=360, limit=12):
    """Optional picture: the application in the middle, its top dependencies around it (the list is the source of truth)."""
    import math
    from html import escape
    ds = [d for d in deps if d["status"] != "dismissed"][:limit]
    cx, cy, r = width / 2, height / 2, min(width, height) / 2 - 50
    parts = [f"<svg viewBox='0 0 {width} {height}' class='depgraph' role='img' aria-label='{escape(name)} and its {len(ds)} main dependencies; "
             "the list below has the same information'>",
             "<defs><marker id='arr' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='6' markerHeight='6' orient='auto-start-reverse'>"
             "<path d='M0,0L10,5L0,10z' class='arrhead'/></marker></defs>"]
    for i, d in enumerate(ds):
        ang = 2 * math.pi * i / max(1, len(ds)) - math.pi / 2
        x, y = cx + r * math.cos(ang), cy + r * math.sin(ang)
        cls = "dep-new" if d["new"] else "dep-conf" if d["status"] == "confirmed" else "dep-gone" if not d["seen"] else "dep-obs"
        x1, y1, x2, y2 = (cx, cy, x, y) if d["direction"] == "uses" else (x, y, cx, cy)
        sx, sy = x1 + (x2 - x1) * 0.18, y1 + (y2 - y1) * 0.18
        ex, ey = x1 + (x2 - x1) * 0.82, y1 + (y2 - y1) * 0.82
        dash = " stroke-dasharray='5 4'" if not d["seen"] else ""
        parts.append(f"<line x1='{sx:.0f}' y1='{sy:.0f}' x2='{ex:.0f}' y2='{ey:.0f}' class='edge {cls}' marker-end='url(#arr)'{dash}/>")
        label = (d.get("app") or [None, None])[1] or d.get("org") or d["target"]
        parts.append(f"<g class='node {cls}'><circle cx='{x:.0f}' cy='{y:.0f}' r='7'/><text x='{x:.0f}' y='{y + 20:.0f}' text-anchor='middle'>"
                     f"{escape(str(label)[:22])}</text><text x='{x:.0f}' y='{y + 33:.0f}' text-anchor='middle' class='sub'>{escape(d['service'])}</text></g>")
    parts.append(f"<g class='node center'><circle cx='{cx:.0f}' cy='{cy:.0f}' r='26'/><text x='{cx:.0f}' y='{cy + 4:.0f}' text-anchor='middle'>"
                 f"{escape(name[:16])}</text></g></svg>")
    return "".join(parts)


def dump(res):
    return json.dumps(res, default=list)
