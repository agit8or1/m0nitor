"""MikroTik RouterOS remote syslog.

Firewall:  '[topics] [log-prefix] <chain>: in:<if> out:<if>, [connection-state:..] [src-mac ..,] proto TCP (SYN),
            198.51.100.7:51515->203.0.113.2:22, [NAT ...,] len 60'
RouterOS does not log the rule action. It is taken only from a log-prefix naming it (DROP/REJECT/ACCEPT...);
otherwise 'unknown', never counted as a block.
System:    'login failure for user X from A via ssh', 'user X logged in from A via winbox', '... changed by X',
           '<iface> link down|up'
"""
import re

from . import action_of, direction, event, ip, num

RE_FW = re.compile(r"(?:^|\s)(?:(\S.*?)\s+)?([\w-]+): in:(\S+?) out:(\S+?)(?:\(unknown \d+\))?, .*?proto (\w+)(?: \(([^)]*)\))?, "
                   r"(\[?[0-9a-fA-F.:]+?\]?)(?::(\d+))?->(\[?[0-9a-fA-F.:]+?\]?)(?::(\d+))?(?:,|$)(?:.*?len (\d+))?")
RE_WORD = re.compile(r"\b(drop|deny|reject|block|accept|allow|pass)\b", re.I)
TOPICS = re.compile(r"^(?:[a-z0-9-]+(?:,[a-z0-9-]+)+)\s+")


def parse(raw, app, msg, dev):
    text = msg if msg else raw
    if app and "," in app:          # bsd-syslog puts topics where the tag would be
        text = msg
    text = TOPICS.sub("", text.strip())
    m = RE_FW.search(text)
    if m:
        pre, chain, iin, iout, prot, _flags, s, sp, d, dp, ln = m.groups()
        pre = (pre or "").strip()
        w = RE_WORD.search(pre)
        act = action_of(w.group(1)) if w else "unknown"
        return [event("traffic", action=act, rule=(pre + " " + chain).strip(), src=ip(s), sport=num(sp), dst=ip(d),
                      dport=num(dp), proto=prot.lower(), iface_in=iin, iface_out=iout, bytes=num(ln), packets=1,
                      dir=direction(dev, iin, iout), subtype=chain)]
    m = re.search(r"login failure for user (\S+) from ([0-9a-fA-F.:]+) via (\S+)", text)
    if m:
        return [event("auth", outcome="failure", user=m.group(1), src=ip(m.group(2)), object=m.group(3), message=text)]
    m = re.search(r"user (\S+) logged in from ([0-9a-fA-F.:]+) via (\S+)", text)
    if m:
        return [event("auth", outcome="success", user=m.group(1), src=ip(m.group(2)), object=m.group(3), message=text)]
    m = re.search(r"(?:changed|added|removed|moved) by (\S+?)(?: \(|$|\s)", text)
    if m:
        return [event("config", outcome="change", user=m.group(1).split("/")[0], message=text)]
    m = re.search(r"^(\S+) link (up|down)\b", text)
    if m:
        return [event("interface", outcome=m.group(2), object=m.group(1), message=text)]
    m = re.search(r"<?(l2tp|pptp|sstp|ovpn|ipsec|wg)[^ ]*>?:? .*?\b(connected|disconnected|established|terminated)\b", text)
    if m:
        return [event("vpn", outcome="up" if m.group(2) in ("connected", "established") else "down", message=text)]
    return None
