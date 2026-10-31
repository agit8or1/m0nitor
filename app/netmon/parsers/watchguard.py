"""WatchGuard Firebox (Fireware) traffic log lines.

  msg_id="3000-0148" Deny 0-External Firebox 60 tcp 20 51 198.51.100.7 203.0.113.2 51515 22 offset 10 S ... (Policy-00)
  msg_id="3000-0151" Allow 1-Trusted 0-External 52 udp 20 64 10.0.1.2 198.51.100.53 54321 53 (Outgoing-00)
Fields after the action: source interface, destination interface, length, protocol, IP header length, TTL, source,
destination, then source and destination ports for TCP/UDP. The policy name is the trailing '(...)'.
"""
import re

from . import action_of, direction, event, ip, num

RE_WG = re.compile(r'msg_id="(\d{4}-\d{4})" (Allow|Deny) (\S+) (\S+) (\d+) (\w+) \d+ \d+ ([0-9a-fA-F.:]+) ([0-9a-fA-F.:]+)'
                   r'(?: (\d+) (\d+))?.*?(?:\(([^()]*)\))?\s*$')


def parse(raw, app, msg, dev):
    m = RE_WG.search(raw)
    if not m:
        return None
    mid, act, si, di, ln, pr, s, d, sp, dp, pol = m.groups()
    return [event("traffic", action=action_of(act), iface_in=si, iface_out=di, proto=pr.lower(), src=ip(s), dst=ip(d),
                  sport=num(sp), dport=num(dp), bytes=num(ln), packets=1, rule=pol or "", subtype=mid,
                  dir=direction(dev, si, di))]
