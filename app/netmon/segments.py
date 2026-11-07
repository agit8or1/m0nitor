"""Segmentation monitoring: compare observed internal traffic with the communication you expect between groups.

Monitoring only: nothing here changes the firewall. Groups are address ranges per firewall (e.g. Guest Wi-Fi, IoT,
Servers, Management). Rules say what communication is expected from one group to another:
  - allow:  communication is expected (optionally only on listed services; other services are then unexpected);
  - none:   no communication is expected (optionally only for listed services);
optionally only during a schedule (outside it the rule does not apply). Pairs without a rule are "not defined".

What can be seen: traffic records the firewall exports where both ends are internal (between its interfaces, its
bridge members and VPN clients). Traffic between devices on the same switch or VLAN never reaches the firewall and is
invisible. So **no traffic seen never means "blocked"**: the matrix says "not seen" and explains why; it shows
"blocked" only when the firewall log recorded blocks. Who opened a connection is inferred from ports (the lower port is
treated as the service) and labelled as inferred.
"""
import ipaddress
import json
import time

from .core import audit

SENSITIVITY = ("normal", "high")
EXPECT = {"allow": "communication expected", "none": "no communication expected"}
MAX_ROWS = 20000
TEMPLATES = {
    "guest": {"label": "Guest network isolated",
              "text": "Guest devices reach the internet only: nothing expected from Guest to any other group, or to Guest from others.",
              "groups": ["Guest"], "rules": [("Guest", "*", "none", "*"), ("*", "Guest", "none", "*")]},
    "iot": {"label": "IoT kept apart",
            "text": "IoT devices are not expected to open connections to other groups; Users may reach IoT (apps, casting).",
            "groups": ["IoT", "Users"], "rules": [("IoT", "*", "none", "*"), ("Users", "IoT", "allow", "*")]},
    "servers": {"label": "Servers on listed services only",
                "text": "Users reach Servers only on web, mail and file services; Servers are not expected to open connections to Users.",
                "groups": ["Users", "Servers"],
                "rules": [("Users", "Servers", "allow", "tcp/80,tcp/443,tcp/25,tcp/587,tcp/993,tcp/445,udp/53,tcp/53"), ("Servers", "Users", "none", "*")]},
    "mgmt": {"label": "Management only from admins",
             "text": "Only the Admins group reaches Management interfaces (switches, firewalls, hypervisors); every other group is not expected to.",
             "groups": ["Management", "Admins"], "rules": [("Admins", "Management", "allow", "*"), ("*", "Management", "none", "*")]},
}


# ---- groups and rules ------------------------------------------------------------------------------------------
def parse_cidrs(text):
    out = []
    for v in (text or "").replace(",", " ").split():
        try:
            n = ipaddress.ip_network(v.strip(), strict=False)
        except ValueError:
            raise ValueError(f"not an address or range: {v[:60]}")
        out.append(str(n))
    if not out:
        raise ValueError("a group needs at least one address range")
    return sorted(set(out), key=lambda x: (ipaddress.ip_network(x).version, ipaddress.ip_network(x)))


def parse_services(text):
    from .baselines import norm_service
    t = (text or "").strip()
    if t in ("", "*"):
        return "*"
    return ",".join(sorted({norm_service(x) for x in t.replace(" ", ",").split(",") if x.strip()}))


def groups(conn, site):
    return [dict(r) | {"nets": [ipaddress.ip_network(c) for c in json.loads(r["cidrs"])]} for r in
            conn.execute("SELECT * FROM seg_groups WHERE site=? ORDER BY name", (site,))]


def policies(conn, site):
    return [dict(r) for r in conn.execute("SELECT * FROM seg_policies WHERE site=? AND enabled=1 ORDER BY id", (site,))]


def save_group(conn, site, name, cidrs_text, sensitivity, user, gid=None, note=""):
    name = " ".join((name or "").split())[:60]
    if not name or name == "*":
        raise ValueError("give the group a name")
    if sensitivity not in SENSITIVITY:
        raise ValueError("unknown sensitivity")
    cidrs = parse_cidrs(cidrs_text) if cidrs_text.strip() else []
    if gid:
        conn.execute("UPDATE seg_groups SET name=?, cidrs=?, sensitivity=?, note=? WHERE id=? AND site=?",
                     (name, json.dumps(cidrs), sensitivity, note[:200], gid, site))
    else:
        try:
            gid = conn.execute("INSERT INTO seg_groups(site, name, cidrs, sensitivity, note, created_by, created_at) VALUES (?,?,?,?,?,?,?)",
                               (site, name, json.dumps(cidrs), sensitivity, note[:200], user, time.time())).lastrowid
        except Exception:
            raise ValueError(f"a group called {name} already exists")
    conn.commit()
    audit(conn, user, "segment_group_saved", {"site": site, "id": gid, "name": name, "cidrs": cidrs, "sensitivity": sensitivity})
    return gid


def delete_group(conn, site, gid, user):
    conn.execute("DELETE FROM seg_policies WHERE site=? AND (src=? OR dst=?)", (site, gid, gid))
    conn.execute("DELETE FROM seg_groups WHERE site=? AND id=?", (site, gid))
    conn.commit()
    audit(conn, user, "segment_group_deleted", {"site": site, "id": gid})


def save_policy(conn, site, src, dst, expect, services, schedule, user, note=""):
    if expect not in EXPECT:
        raise ValueError("unknown expectation")
    ids = {g["id"] for g in groups(conn, site)}
    if (src != 0 and src not in ids) or (dst != 0 and dst not in ids) or (src == 0 and dst == 0):
        raise ValueError("choose the groups (one side may be 'any group')")
    svc = parse_services(services)
    pid = conn.execute("INSERT INTO seg_policies(site, src, dst, expect, services, schedule, note, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                       (site, src, dst, expect, svc, json.dumps(schedule) if schedule else None, (note or "")[:200], user, time.time())).lastrowid
    conn.commit()
    audit(conn, user, "segment_rule_added", {"site": site, "id": pid, "src": src, "dst": dst, "expect": expect, "services": svc, "schedule": schedule})
    return pid


def delete_policy(conn, site, pid, user):
    conn.execute("UPDATE seg_policies SET enabled=0 WHERE site=? AND id=?", (site, pid))
    conn.commit()
    audit(conn, user, "segment_rule_removed", {"site": site, "id": pid})


def apply_template(conn, site, key, user):
    """Create the template's groups (empty when missing: you add their address ranges) and its rules."""
    t = TEMPLATES.get(key)
    if not t:
        raise ValueError("unknown template")
    by = {g["name"]: g["id"] for g in groups(conn, site)}
    for name in t["groups"]:
        if name not in by:
            by[name] = save_group(conn, site, name, "", "high" if name == "Management" else "normal", user, note=f"from template: {t['label']}")
    n = 0
    have = {(p["src"], p["dst"], p["expect"], p["services"]) for p in policies(conn, site)}
    for s, d, ex, svc in t["rules"]:
        key_ = (by.get(s, 0), by.get(d, 0), ex, parse_services(svc))
        if key_ not in have:
            save_policy(conn, site, key_[0], key_[1], ex, svc, None, user, note=f"template: {t['label']}")
            n += 1
    return n


def group_of(ip, gs):
    """Most specific group containing ip, or None."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best = None
    for g in gs:
        for n in g["nets"]:
            if a.version == n.version and a in n and (best is None or n.prefixlen > best[1]):
                best = (g, n.prefixlen)
    return best[0] if best else None


def _svc_in(svc, services):
    return services == "*" or svc in services.split(",")


def verdict(src_g, dst_g, svc, pols, ts=None, site=None):
    """(status, policy) for traffic src_g -> dst_g on svc: 'expected', 'unexpected', or 'undefined'."""
    from .baselines import schedule_active
    s_id, d_id = (src_g or {}).get("id", -1), (dst_g or {}).get("id", -1)
    cands = []
    for p in pols:
        if p["src"] not in (0, s_id) or p["dst"] not in (0, d_id):
            continue
        if p["schedule"] and ts and not schedule_active(json.loads(p["schedule"]), ts, site):
            continue
        cands.append(p)
    specific = lambda p: (p["src"] != 0) + (p["dst"] != 0)  # noqa: E731   specific group pairs beat 'any group'
    cands.sort(key=lambda p: -specific(p))
    for level in sorted({specific(p) for p in cands}, reverse=True):
        tier = [p for p in cands if specific(p) == level]
        allow = [p for p in tier if p["expect"] == "allow" and _svc_in(svc, p["services"])]
        if allow:
            return "expected", allow[0]
        deny = [p for p in tier if p["expect"] == "none" and _svc_in(svc, p["services"])]
        if deny:
            return "unexpected", deny[0]
        only = [p for p in tier if p["expect"] == "allow"]   # allowed on other services only
        if only:
            return "unexpected", only[0]
    return "undefined", None


def describe_policy(p, names):
    s = names.get(p["src"], "any group") if p["src"] else "any group"
    d = names.get(p["dst"], "any group") if p["dst"] else "any group"
    svc = "" if p["services"] == "*" else f" on {p['services'].replace(',', ', ')}"
    if p["expect"] == "allow":
        text = f"{s} → {d}: communication expected{svc}" + (" (other services unexpected)" if svc else "")
    else:
        text = f"{s} → {d}: no communication expected{svc}"
    if p["schedule"]:
        from .baselines import schedule_text
        text += f", only {schedule_text(json.loads(p['schedule']))}"
    return text


# ---- observation -------------------------------------------------------------------------------------------------
def _ranges(cfg):
    from .hunt import _v6
    out = []
    for n in cfg.internal_nets:
        out.append((_v6(str(n.network_address)), _v6(str(n.broadcast_address))))
    return [a for a, _ in out], [b for _, b in out]


def firewall_addrs(site):
    """The firewall's own internal addresses (its proxies and NAT reflection are not device-to-device traffic)."""
    out = set()
    for v in (site.get("exporter_ip"), site.get("syslog_source"), (site.get("snmp") or {}).get("host"), *(site.get("own_ips") or [])):
        try:
            out.add(str(ipaddress.ip_address(v)))
        except (TypeError, ValueError):
            pass
    return out


def observe(cfg, ch, site, t0, t1):
    """Internal-to-internal conversations seen by this firewall: client, server, service, records, bytes, first/last.
    Client = the side with the higher port (inferred). Conversations of the firewall's own addresses are left out."""
    lo, hi = _ranges(cfg)
    own = firewall_addrs(site)
    return [r for r in _observe(ch, site, t0, t1, lo, hi) if r["client"] not in own and r["server"] not in own]


def _observe(ch, site, t0, t1, lo, hi):
    return ch.query("""SELECT replaceOne(IPv6NumToString(c), '::ffff:', '') AS client, replaceOne(IPv6NumToString(s), '::ffff:', '') AS server,
        proto, port, count() AS n, sum(b) AS bytes, toUInt32(min(t)) AS first, toUInt32(max(t)) AS last FROM (
          SELECT TimeReceived AS t, if(DstPort <= SrcPort, SrcAddr, DstAddr) AS c, if(DstPort <= SrcPort, DstAddr, SrcAddr) AS s,
                 Proto AS proto, least(SrcPort, DstPort) AS port, Bytes * SamplingRate AS b
          FROM flows WHERE ExporterName = {exp:String} AND TimeReceived >= toDateTime({t0:UInt32}) AND TimeReceived < toDateTime({t1:UInt32})
            AND InIfName != '' AND InIfName != {wan:String} AND OutIfName != {wan:String}
            AND arrayExists((a, z) -> SrcAddr >= a AND SrcAddr <= z, {lo:Array(IPv6)}, {hi:Array(IPv6)})
            AND arrayExists((a, z) -> DstAddr >= a AND DstAddr <= z, {lo:Array(IPv6)}, {hi:Array(IPv6)}))
        GROUP BY client, server, proto, port ORDER BY n DESC LIMIT {lim:UInt32}""",
                    {"exp": site["exporter"], "wan": site["wan_if"], "t0": int(t0), "t1": int(t1), "lo": lo, "hi": hi, "lim": MAX_ROWS})


def blocked(cfg, ch, site, t0, t1):
    """Firewall-log blocks where both ends are internal (the only evidence of enforcement netmon has)."""
    lo, hi = _ranges(cfg)
    try:
        return ch.query("""SELECT replaceOne(IPv6NumToString(src), '::ffff:', '') AS client, replaceOne(IPv6NumToString(dst), '::ffff:', '') AS server,
            proto, dport AS port, count() AS n, toUInt32(max(ts)) AS last FROM netmon.fw_events
            WHERE site = {site:String} AND action = 'block' AND ts >= toDateTime64({t0:UInt32}, 3) AND ts < toDateTime64({t1:UInt32}, 3)
              AND arrayExists((a, z) -> src >= a AND src <= z, {lo:Array(IPv6)}, {hi:Array(IPv6)})
              AND arrayExists((a, z) -> dst >= a AND dst <= z, {lo:Array(IPv6)}, {hi:Array(IPv6)})
            GROUP BY client, server, proto, port ORDER BY n DESC LIMIT {lim:UInt32}""",
                        {"site": site["id"], "t0": int(t0), "t1": int(t1), "lo": lo, "hi": hi, "lim": MAX_ROWS})
    except Exception:
        return None


def svc_name(proto, port):
    p = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}.get(int(proto) if str(proto).isdigit() else -1, str(proto).lower())
    return p if p == "icmp" else f"{p}/{int(port)}"


def matrix(conn, cfg, ch, site, t0, t1):
    """Group-pair view: expectation, observed traffic, firewall blocks, status, and the top conversations per cell."""
    gs = groups(conn, site["id"])
    pols = policies(conn, site["id"])
    obs = observe(cfg, ch, site, t0, t1)
    blk = blocked(cfg, ch, site, t0, t1)
    other = {"id": -1, "name": "Not in a group", "sensitivity": "normal", "nets": []}
    cells, seen_src = {}, set()
    for r in obs:
        sg, dg = group_of(r["client"], gs) or other, group_of(r["server"], gs) or other
        svc = svc_name(r["proto"], r["port"])
        st, pol = verdict(sg, dg, svc, pols, r["last"], site)
        c = cells.setdefault((sg["id"], dg["id"]), {"src": sg, "dst": dg, "n": 0, "bytes": 0, "blocked": 0, "unexpected": 0, "rows": [],
                                                    "services": {}, "last": 0})
        c["n"] += r["n"]
        c["bytes"] += r["bytes"]
        c["last"] = max(c["last"], r["last"])
        c["services"][svc] = c["services"].get(svc, 0) + r["n"]
        if st == "unexpected":
            c["unexpected"] += r["n"]
        if len(c["rows"]) < 25:
            c["rows"].append(dict(r, svc=svc, status=st, policy=(pol or {}).get("id")))
        seen_src.add(sg["id"])
    for r in blk or []:
        sg, dg = group_of(r["client"], gs) or other, group_of(r["server"], gs) or other
        c = cells.setdefault((sg["id"], dg["id"]), {"src": sg, "dst": dg, "n": 0, "bytes": 0, "blocked": 0, "unexpected": 0, "rows": [],
                                                    "services": {}, "last": 0})
        c["blocked"] += r["n"]
    return {"groups": gs, "policies": pols, "cells": cells, "seen_src": seen_src, "fw_log": blk is not None, "rows": len(obs),
            "own": sorted(firewall_addrs(site)),
            "truncated": len(obs) >= MAX_ROWS, "other": other}


def violations(conn, cfg, ch, site, t0, t1):
    """Observed conversations a rule says are unexpected (for the detector)."""
    gs = groups(conn, site["id"])
    pols = policies(conn, site["id"])
    if not gs or not pols:
        return []
    out = []
    for r in observe(cfg, ch, site, t0, t1):
        sg, dg = group_of(r["client"], gs), group_of(r["server"], gs)
        if not sg and not dg:
            continue
        svc = svc_name(r["proto"], r["port"])
        st, pol = verdict(sg, dg, svc, pols, r["last"], site)
        if st == "unexpected":
            out.append(dict(r, svc=svc, src_group=(sg or {}).get("name", "not in a group"), dst_group=(dg or {}).get("name", "not in a group"),
                            sensitive=(dg or {}).get("sensitivity") == "high", policy=pol))
    return out
