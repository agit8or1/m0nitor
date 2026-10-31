"""Palo Alto Networks PAN-OS syslog, default CSV log format (field order per the PAN-OS 10.x/11.x "Syslog Field
Descriptions"). Custom formats are not parsed (returned as unrecognized).

TRAFFIC/THREAT: 0 FUTURE_USE, 1 receive time, 2 serial, 3 type, 4 subtype, 5 FUTURE_USE, 6 generated time, 7 src,
8 dst, 9 NAT src, 10 NAT dst, 11 rule, 12 src user, 13 dst user, 14 application, 15 vsys, 16 from zone, 17 to zone,
18 inbound if, 19 outbound if, 20 log action, 21 FUTURE_USE, 22 session id, 23 repeat count, 24 sport, 25 dport,
26 NAT sport, 27 NAT dport, 28 flags, 29 protocol, 30 action, then TRAFFIC 31 bytes, 32 bytes sent, 33 bytes received,
34 packets; THREAT 31 URL/filename, 32 threat id 'name(id)', 33 category, 34 severity, 35 direction.
SYSTEM: 4 subtype, 6 generated time, 8 event id, 9 object, 12 module, 13 severity, 14 description.
CONFIG: 4 subtype, 6 generated time, 7 host, 9 command, 10 admin, 11 client, 12 result, 13 configuration path.
"""
import csv
import re

from . import action_of, direction, event, ip, num, severity_of

IDS_SUB = {"vulnerability", "spyware", "scan", "flood", "packet"}
THREAT_SEV = {"critical": 1, "high": 1, "medium": 2, "low": 3, "informational": 4}
RE_TID = re.compile(r"^(.*)\((\d+)\)\s*$")
RE_START = re.compile(r"(?:^|\s)(\d+,\d{4}/\d\d/\d\d \d\d:\d\d:\d\d,[^,]*,(?:TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|USERID),.*)$")


def _ts(s):
    from . import ts_parse
    return None if not s else ts_parse(s, "%Y/%m/%d %H:%M:%S")   # device-local time, treated as UTC only if the device is


def parse(raw, app, msg, dev):
    m = RE_START.search(raw)
    if not m:
        return None
    try:
        f = next(csv.reader([m.group(1)]))
    except (csv.Error, StopIteration):
        return None
    g = lambda i: f[i] if len(f) > i else ""  # noqa: E731
    typ, sub = g(3), g(4)
    ts = _ts(g(6)) if (dev or {}).get("device_tz_utc") else None
    if typ in ("TRAFFIC", "THREAT"):
        if len(f) < 31:
            return None
        common = dict(ts=ts, src=ip(g(7)), dst=ip(g(8)), rule=g(11), user=g(12), zone_in=g(16), zone_out=g(17),
                      iface_in=g(18), iface_out=g(19), sport=num(g(24)), dport=num(g(25)), proto=g(29),
                      dir=direction(dev, g(18), g(19), g(16), g(17)), subtype=f"{typ.lower()}/{sub}")
        if typ == "TRAFFIC":
            if sub == "start":   # the 'end' line of the same session carries the counters
                return []
            return [event("traffic", action=action_of(g(30)), bytes=num(g(31)), packets=num(g(34)), message=g(14), **common)]
        tm = RE_TID.match(g(32))
        name, tid = (tm.group(1).strip(), num(tm.group(2))) if tm else (g(32), 0)
        act = "block" if action_of(g(30)) == "block" or g(30) in ("block-url", "sinkhole", "block-ip") else "allow"
        cat = "ids" if sub in IDS_SUB else "threat"
        sev = THREAT_SEV.get(g(34).lower(), 3) if cat == "ids" else severity_of(g(34))
        return [event(cat, action=act, sig_id=tid, signature=name, threat_class=g(33), object=g(31), severity=sev,
                      message=g(14), **common)]
    if typ == "SYSTEM":
        evid, desc, sev = g(8), g(14), severity_of(g(13))
        base = dict(ts=ts, severity=sev, message=desc, object=g(9), subtype=f"system/{sub}")
        low = (evid + " " + desc).lower()
        if sub in ("vpn", "globalprotect") or "tunnel" in low:
            out = "up" if re.search(r"\bup\b|established|connected", low) else "down" if re.search(r"\bdown\b|disconnect|fail", low) else ""
            return [event("vpn", outcome=out, **base)]
        if sub == "ha" or evid.startswith("ha"):
            return [event("ha", outcome="change", **base)]
        if sub == "routing" or "bgp" in low or "ospf" in low:
            return [event("routing", outcome="change", **base)]
        if sub == "auth" or evid.startswith("auth") or "login" in low:
            fail = "fail" in low
            u = re.search(r"[Uu]ser '([^']+)'", desc)
            s = re.search(r"From: ([0-9a-fA-F:.]+)", desc)
            return [event("auth", outcome="failure" if fail else "success", user=u.group(1) if u else "",
                          src=ip(s.group(1)) if s else None, **base)]
        if evid in ("link-change", "port-down", "port-up") or "link" in low and ("down" in low or "up" in low):
            return [event("interface", outcome="down" if "down" in low else "up", **base)]
        return [event("system", **base)]
    if typ == "CONFIG":
        return [event("config", ts=ts, outcome="change" if g(12).lower() == "succeeded" else g(12).lower() or "change",
                      user=g(10), src=ip(g(7)), object=g(13), message=f"{g(9)} {g(13)} via {g(11)}".strip(),
                      subtype="config")]
    if typ == "GLOBALPROTECT":
        return [event("vpn", ts=ts, message=",".join(f[7:12]), subtype="globalprotect")]
    return None
