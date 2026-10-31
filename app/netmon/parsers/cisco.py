"""Cisco ASA / Firepower Threat Defense (LINA) and IOS / IOS-XE syslog, by documented message ID.

ASA/FTD: %ASA-<sev>-<id>: / %FTD-<sev>-<id>:  (Cisco Secure Firewall ASA Series Syslog Messages)
IOS:     %FACILITY-<sev>-MNEMONIC:
Built/Teardown pairs: only Built (302013/302015) is stored as an allowed connection; Teardown is recognized but not
stored, so one connection counts once.
"""
import re

from . import action_of, direction, event, ip, num

RE_ASA = re.compile(r"%(ASA|FTD|PIX|FWSM)-(\d)-(\d{6}): ?(.*)$")
RE_IOS = re.compile(r"%([A-Z][A-Z0-9_]*)-(\d)-([A-Z0-9_]+): ?(.*)$")


def _ep(s):
    """'outside:198.51.100.7/51515' or '2001:db8::1/443' -> (iface, ip, port)."""
    s = s.strip().rstrip(",")
    port = 0
    if "/" in s:
        s, _, p = s.rpartition("/")
        port = num(p)
    iface = ""
    if ip(s) is None and ":" in s:
        iface, _, s = s.partition(":")
    return iface, ip(s), port


ASA = {
    "106023": re.compile(r"Deny (\S+) src (\S+) dst (\S+) (?:\(type \d+, code \d+\) )?by access-group \"([^\"]+)\""),
    "106100": re.compile(r"access-list (\S+) (permitted|denied|est-allowed) (\S+) (\S+?)\((\d+)\) -> (\S+?)\((\d+)\)"),
    "106001": re.compile(r"Inbound (TCP) connection denied from (\S+) to (\S+) flags .*? on interface (\S+)"),
    "106006": re.compile(r"Deny inbound (UDP) from (\S+) to (\S+) (?:due to .*? )?on interface (\S+)"),
    "106007": re.compile(r"Deny inbound (UDP) from (\S+) to (\S+) due to .*?$"),
    "106014": re.compile(r"Deny inbound (icmp) src (\S+) dst (\S+)"),
    "106015": re.compile(r"Deny (TCP) \(no connection\) from (\S+) to (\S+) flags .*? on interface (\S+)"),
    "710003": re.compile(r"(TCP|UDP) access denied by ACL from (\S+) to (\S+)"),
    "302013": re.compile(r"Built (inbound|outbound) (TCP|UDP) connection \d+ for (\S+) \(\S+\) to (\S+) \(\S+\)"),
}
ASA["302015"] = ASA["302013"]
ASA_AUTH = [(re.compile(r"AAA user authentication (Successful|Rejected) : .*?user = (\S+?)(?: : user IP = ([0-9a-fA-F.:]+))?\s*$"), None),
            (re.compile(r"Login (denied|permitted) from (\S+) to \S+ for user \"([^\"]*)\""), None)]


def _asa(sev, mid, text, dev):
    s = 6 if sev is None else int(sev)
    if mid in ("302014", "302016", "302020", "302021"):
        return []
    rx = ASA.get(mid)
    if rx:
        m = rx.search(text)
        if not m:
            return None
        g = m.groups()
        if mid == "106023":
            (i1, s1, p1), (i2, d1, p2) = _ep(g[1]), _ep(g[2])
            return [event("traffic", action="block", proto=g[0], src=s1, sport=p1, dst=d1, dport=p2, iface_in=i1,
                          iface_out=i2, rule=g[3], dir=direction(dev, i1, i2), severity=s, subtype=mid)]
        if mid == "106100":
            return [event("traffic", action=action_of(g[1]), rule=g[0], proto=g[2], src=_ep(g[3])[1], sport=num(g[4]),
                          dst=_ep(g[5])[1], dport=num(g[6]), iface_in=g[3].partition("/")[0],
                          dir=direction(dev, g[3].partition("/")[0]), severity=s, subtype=mid)]
        if mid == "302013" or mid == "302015":
            (i1, a1, p1), (i2, a2, p2) = _ep(g[2]), _ep(g[3])
            # 'inbound': the first endpoint initiated from the lower-security side
            src, sp, dst, dp, ii, io = (a1, p1, a2, p2, i1, i2) if g[0] == "inbound" else (a2, p2, a1, p1, i2, i1)
            return [event("traffic", action="allow", proto=g[1], src=src, sport=sp, dst=dst, dport=dp, iface_in=ii,
                          iface_out=io, dir=direction(dev, ii, io), severity=s, subtype=mid)]
        (i1, a1, p1), (i2, a2, p2) = _ep(g[1]), _ep(g[2])
        iface = g[3] if len(g) > 3 and g[3] else i1
        return [event("traffic", action="block", proto=g[0], src=a1, sport=p1, dst=a2, dport=p2, iface_in=iface,
                      dir=direction(dev, iface), severity=s, subtype=mid)]
    if mid in ("113004", "113005", "113015", "605004", "605005"):
        for r, _ in ASA_AUTH:
            m = r.search(text)
            if m:
                if r.pattern.startswith("Login"):
                    ok, (_, src, _) , user = m.group(1) == "permitted", _ep(m.group(2)), m.group(3)
                else:
                    ok, user, src = m.group(1) == "Successful", m.group(2), ip(m.group(3)) if m.group(3) else None
                return [event("auth", outcome="success" if ok else "failure", user=user, src=src, severity=s, subtype=mid,
                              message=text)]
        return None
    if mid in ("111008", "111010", "111009"):
        u = re.search(r"User '([^']+)'", text)
        a = re.search(r"from IP ([0-9a-fA-F.:]+)", text)
        return [event("config", outcome="change", user=u.group(1) if u else "", src=ip(a.group(1)) if a else None,
                      message=text, severity=s, subtype=mid)]
    if mid in ("411001", "411002", "411003", "411004"):
        m = re.search(r"Interface (\S+?),? changed state to (administratively )?(up|down)", text)
        return [event("interface", outcome=m.group(3) if m else ("up" if mid in ("411001", "411003") else "down"),
                      object=m.group(1) if m else "", message=text, severity=s, subtype=mid)]
    if mid in ("104001", "104002", "104004", "105005", "105008"):
        out = "active" if "ACTIVE" in text else "standby" if "STANDBY" in text else "change"
        return [event("ha", outcome=out, message=text, severity=s, subtype=mid)]
    if mid in ("113019", "713050", "722023", "716002"):
        u = re.search(r"Username = ([^,]+)|User <([^>]+)>", text)
        a = re.search(r"IP = ([0-9a-fA-F.:]+)|peer ([0-9a-fA-F.:]+)|IP <([0-9a-fA-F.:]+)>", text)
        return [event("vpn", outcome="down", user=next((x for x in (u.groups() if u else ()) if x), ""),
                      src=ip(next((x for x in (a.groups() if a else ()) if x), None)), message=text, severity=s, subtype=mid)]
    if mid in ("722022", "713119", "713120", "722051", "716001"):
        u = re.search(r"Username = ([^,]+)|User <([^>]+)>", text)
        a = re.search(r"IP = ([0-9a-fA-F.:]+)|IP <([0-9a-fA-F.:]+)>", text)
        return [event("vpn", outcome="up", user=next((x for x in (u.groups() if u else ()) if x), ""),
                      src=ip(next((x for x in (a.groups() if a else ()) if x), None)), message=text, severity=s, subtype=mid)]
    if mid == "430001":   # FTD intrusion event: 'Key: value, Key: value'
        f = dict(p.split(": ", 1) for p in re.split(r",\s*(?=[A-Z][A-Za-z]+: )", text) if ": " in p)
        prio = num(f.get("Priority"), 3)
        blocked = f.get("InlineResult", "").lower() in ("blocked", "dropped", "would block")
        return [event("ids", action="block" if blocked else "allow", src=ip(f.get("SrcIP")), dst=ip(f.get("DstIP")),
                      sport=num(f.get("SrcPort")), dport=num(f.get("DstPort")), proto=f.get("Protocol", ""),
                      iface_in=f.get("IngressInterface", ""), sig_id=num(f.get("SID")), signature=f.get("Message", ""),
                      threat_class=f.get("Classification", ""), severity=min(max(prio, 1), 4), subtype=mid)]
    if mid in ("430002", "430003"):   # FTD connection events: start (430002) / end (430003)
        if mid == "430002":
            return []
        f = dict(p.split(": ", 1) for p in re.split(r",\s*(?=[A-Z][A-Za-z]+: )", text) if ": " in p)
        act = action_of(f.get("AccessControlRuleAction", ""))
        return [event("traffic", action=act, src=ip(f.get("SrcIP")), dst=ip(f.get("DstIP")), sport=num(f.get("SrcPort")),
                      dport=num(f.get("DstPort")), proto=f.get("Protocol", ""), iface_in=f.get("IngressInterface", ""),
                      iface_out=f.get("EgressInterface", ""), zone_in=f.get("IngressZone", ""), zone_out=f.get("EgressZone", ""),
                      rule=f.get("AccessControlRuleName", ""), bytes=num(f.get("InitiatorBytes")) + num(f.get("ResponderBytes")),
                      dir=direction(dev, f.get("IngressInterface", ""), f.get("EgressInterface", ""),
                                    f.get("IngressZone", ""), f.get("EgressZone", "")), severity=s, subtype=mid)]
    return None


IOS_ACL = re.compile(r"list (\S+) (permitted|denied) (\w+) ([0-9a-fA-F.:]+)(?:\((\d+)\))?(?: \(([^)]*)\))? -> "
                     r"([0-9a-fA-F.:]+)(?:\((\d+)\))?(?: \([^)]*\))?, (\d+) packets?")
IOS_ACL_STD = re.compile(r"list (\S+) (permitted|denied) ([0-9a-fA-F.:]+) (\d+) packets?")


def _ios(fac, sev, mn, text, dev):
    s = int(sev)
    if fac == "SEC" and mn.startswith("IPACCESSLOG"):
        m = IOS_ACL.search(text)
        if m:
            g = m.groups()
            iface = (g[5] or "").split()[0] if g[5] else ""
            return [event("traffic", action=action_of(g[1]), rule=g[0], proto=g[2], src=ip(g[3]), sport=num(g[4]),
                          dst=ip(g[6]), dport=num(g[7]), packets=num(g[8]), iface_in=iface, dir=direction(dev, iface),
                          severity=s, subtype=mn)]
        m = IOS_ACL_STD.search(text)
        if m:
            return [event("traffic", action=action_of(m.group(2)), rule=m.group(1), src=ip(m.group(3)),
                          packets=num(m.group(4)), severity=s, subtype=mn)]
        return None
    if (fac, mn) in (("LINK", "UPDOWN"), ("LINEPROTO", "UPDOWN"), ("LINK", "CHANGED")):
        m = re.search(r"Interface (\S+?), changed state to (administratively down|up|down)", text)
        if not m:
            return None
        return [event("interface", outcome="down" if "down" in m.group(2) else "up", object=m.group(1), message=text,
                      severity=s, subtype=f"{fac}-{mn}")]
    if fac == "SYS" and mn == "CONFIG_I":
        m = re.search(r"Configured from (\S+) by (\S+?)(?: on \S+)?(?: \(([0-9a-fA-F.:]+)\))?$", text)
        return [event("config", outcome="change", user=m.group(2) if m else "", src=ip(m.group(3)) if m and m.group(3) else None,
                      object=m.group(1) if m else "", message=text, severity=s, subtype=mn)]
    if fac == "PARSER" and mn == "CFGLOG_LOGGEDCMD":
        m = re.search(r"User:(\S+)\s+logged command:(.*)$", text)
        return [event("config", outcome="change", user=m.group(1) if m else "", message=(m.group(2) if m else text).strip(),
                      severity=s, subtype=mn)]
    if fac == "SEC_LOGIN" and mn in ("LOGIN_FAILED", "LOGIN_SUCCESS", "QUIET_MODE_ON"):
        u = re.search(r"\[user: ([^\]]*)\]", text)
        a = re.search(r"\[Source: ([^\]]*)\]", text)
        return [event("auth", outcome="success" if mn == "LOGIN_SUCCESS" else "failure", user=u.group(1) if u else "",
                      src=ip(a.group(1)) if a else None, message=text, severity=s, subtype=mn)]
    if fac == "BGP" and mn == "ADJCHANGE":
        m = re.search(r"neighbor (\S+)(?: vpn vrf \S+)? (Up|Down)", text)
        return [event("routing", outcome=m.group(2).lower() if m else "change", object=f"BGP {m.group(1)}" if m else "BGP",
                      message=text, severity=s, subtype=mn)]
    if fac in ("OSPF", "OSPFV3") and mn == "ADJCHG":
        m = re.search(r"Nbr (\S+) on (\S+) from (\S+) to (\S+)", text)
        return [event("routing", outcome=("up" if m.group(4) == "FULL" else "down") if m else "change",
                      object=f"OSPF {m.group(1)} {m.group(2)}" if m else "OSPF", message=text, severity=s, subtype=mn)]
    return None


def parse(raw, app, msg, dev):
    m = RE_ASA.search(raw)
    if m:
        return _asa(m.group(2), m.group(3), m.group(4), dev)
    m = RE_IOS.search(raw)
    if m:
        return _ios(m.group(1), m.group(2), m.group(3), m.group(4), dev)
    return None
