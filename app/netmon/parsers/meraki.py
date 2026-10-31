"""Cisco Meraki MX syslog (Meraki's own header: '<pri>1 <epoch.frac> <device> <type> ...').

flows / firewall / vpn_firewall / cellular_firewall:  'src=.. dst=.. protocol=tcp sport=.. dport=.. pattern: allow all'
  newer firmware: 'flows allow src=..' / 'flows deny src=..'. The action is read from the leading allow/deny token
  or the pattern text; otherwise unknown.
ids-alerts / security_event ids_alerted: 'signature=1:28423:1 priority=1 ... src=ip:port dst=ip:port ... message: ..'
events type=vpn_connectivity_change ... connectivity='true|false'
"""
import re

from . import action_of, event, ip, kv, num

RE_HDR = re.compile(r"^(?:<\d+>)?1 (\d{9,11}(?:\.\d+)?) (\S+) (\S+) ?(.*)$")
RE_PAT = re.compile(r"pattern: ?(.*)$")


def _ep(v):
    a, _, p = (v or "").rpartition(":")
    return (ip(a), num(p)) if a and p.isdigit() and ip(a) else (ip(v), 0)


def parse(raw, app, msg, dev):
    m = RE_HDR.match(raw) or RE_HDR.match(msg)
    if not m:
        return None
    ts, _host, typ, rest = float(m.group(1)), m.group(2), m.group(3), m.group(4)
    f = kv(rest)
    if typ in ("flows", "firewall", "vpn_firewall", "cellular_firewall", "l7_firewall"):
        first = rest.split(" ", 1)[0]
        pat = RE_PAT.search(rest)
        act = action_of(first) if first in ("allow", "deny") else "unknown"
        if act == "unknown" and pat:
            p = pat.group(1).lower()
            act = "block" if "deny" in p or "block" in p else "allow" if "allow" in p else "unknown"
        return [event("traffic", ts=ts, action=act, src=ip(f.get("src")), dst=ip(f.get("dst")), sport=num(f.get("sport")),
                      dport=num(f.get("dport")), proto=f.get("protocol", ""), rule=pat.group(1)[:200] if pat else "",
                      subtype=typ)]
    if typ in ("ids-alerts", "security_event"):
        if typ == "security_event" and "ids_alerted" not in rest[:40] and "signature=" not in rest:
            return [event("threat", ts=ts, message=rest[:500], subtype=typ)]
        sig = (f.get("signature") or "0:0:0").split(":")
        (s, sp), (d, dp) = _ep(f.get("src")), _ep(f.get("dst"))
        msgtxt = rest.split("message:", 1)[1].strip() if "message:" in rest else ""
        dec = (f.get("decision") or f.get("action") or "").lower()
        return [event("ids", ts=ts, action="block" if dec in ("blocked", "block", "deny") else "allow", src=s, sport=sp,
                      dst=d, dport=dp, proto=(f.get("protocol") or "").split("/")[0], sig_id=num(sig[1] if len(sig) > 1 else 0),
                      signature=msgtxt, severity=min(max(num(f.get("priority"), 3), 1), 4), subtype=typ)]
    if typ == "events":
        if "vpn_connectivity_change" in rest:
            c = (f.get("connectivity") or "").strip("'")
            return [event("vpn", ts=ts, outcome="up" if c == "true" else "down" if c == "false" else "",
                          object=(f.get("peer_ident") or f.get("peer_contact") or "").strip("'"), message=rest[:500], subtype=typ)]
        return [event("system", ts=ts, message=rest[:500], subtype=typ)]
    return [event("system", ts=ts, message=rest[:500], subtype=typ)]
