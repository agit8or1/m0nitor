"""Fortinet FortiGate syslog, format 'default' (key=value), as documented in the FortiOS Log Message Reference.

  date=2026-10-31 time=12:00:00 devname="FGT" logid="0000000013" type="traffic" subtype="forward" srcip=..
  srcport=.. srcintf="wan1" srcintfrole="wan" dstip=.. dstport=.. dstintf="lan" proto=6 action="deny" policyid=0 ..
type=traffic: action deny/blocked -> block; accept/close/timeout/client-rst/server-rst -> allow (one line per session end).
type=utm subtype=ips -> IDS; virus/webfilter/dns/app-ctrl/anomaly -> threat. type=event: system/user/vpn/ha.
"""
from . import action_of, event, ip, kv, num, severity_of, ts_parse

IPS_SEV = {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 4}


def _ts(f):
    if f.get("date") and f.get("time"):
        tz = f.get("tz", "")
        if len(tz) == 5 and tz[0] in "+-":
            return ts_parse(f"{f['date']}T{f['time']}{tz[:3]}:{tz[3:]}")
    ev = f.get("eventtime", "")
    if ev.isdigit():   # FortiOS 6.2+: s, ms, us or ns since the epoch depending on version
        v = int(ev)
        while v > 10 ** 11:
            v //= 1000
        return float(v)
    return None


def _dir(f):
    if f.get("srcintfrole") == "wan":
        return "in"
    if f.get("dstintfrole") == "wan":
        return "out"
    return ""


def parse(raw, app, msg, dev):
    if "logid=" not in raw or "type=" not in raw:
        return None
    f = kv(raw[raw.find("date=") if "date=" in raw else 0:])
    t, st = f.get("type", ""), f.get("subtype", "")
    common = dict(ts=_ts(f), src=ip(f.get("srcip")), dst=ip(f.get("dstip")), sport=num(f.get("srcport")),
                  dport=num(f.get("dstport")), proto=f.get("proto", ""), iface_in=f.get("srcintf", ""),
                  iface_out=f.get("dstintf", ""), rule=f.get("policyid", ""), user=f.get("user", "") or f.get("srcuser", ""),
                  severity=severity_of(f.get("level")), subtype=f"{t}/{st}")
    if t == "traffic":
        act = action_of(f.get("action"))
        return [event("traffic", action=act, dir=_dir(f), bytes=num(f.get("sentbyte")) + num(f.get("rcvdbyte")),
                      packets=num(f.get("sentpkt")) + num(f.get("rcvdpkt")), message=f.get("service", ""), **common)]
    if t == "utm" or t == "anomaly":
        a = f.get("action", "")
        if st in ("ips", "anomaly") or t == "anomaly":
            return [event("ids", action="block" if a in ("dropped", "reset", "blocked", "clear_session") else "allow",
                          sig_id=num(f.get("attackid")), signature=f.get("attack", "") or f.get("msg", ""),
                          threat_class=f.get("ref", "") or st, dir=_dir(f),
                          message=f.get("msg", ""), **{**common, "severity": IPS_SEV.get(f.get("severity", "").lower(), 3)})]
        return [event("threat", action=action_of(a), signature=f.get("virus", "") or f.get("catdesc", "") or f.get("msg", ""),
                      threat_class=st, object=f.get("url", "") or f.get("hostname", "") or f.get("qname", ""),
                      message=f.get("msg", ""), **common)]
    if t == "event":
        desc, act, status = f.get("logdesc", ""), f.get("action", ""), f.get("status", "")
        low = (desc + " " + act).lower()
        base = {**common, "message": f.get("msg", "") or desc, "user": f.get("user", "")}
        if st == "vpn" or "tunnel" in low:
            out = "up" if ("up" in act or "tunnel-up" in act or "established" in low) else "down" if "down" in low else ""
            return [event("vpn", outcome=out, object=f.get("vpntunnel", "") or f.get("tunnelid", ""),
                          **{**base, "src": ip(f.get("remip")) or base["src"]})]
        if st == "ha" or "ha " in low or "failover" in low:
            return [event("ha", outcome="change", object=f.get("ha_role", "") or f.get("haname", ""), **base)]
        if act == "login" or "login" in low or "logon" in low:
            ok = status in ("success", "succeeded") or "successful" in low
            src = ip(f.get("srcip")) or ip((f.get("ui", "").partition("(")[2]).rstrip(")"))
            return [event("auth", outcome="success" if ok else "failure", object=f.get("ui", ""), **{**base, "src": src})]
        if f.get("cfgpath") or act in ("Edit", "Add", "Delete", "Move") or "configuration" in low:
            return [event("config", outcome="change", object=f.get("cfgpath", "") or f.get("cfgobj", ""), **base)]
        if "interface" in low and ("down" in low or "up" in low or status in ("up", "down")):
            return [event("interface", outcome=status or ("down" if "down" in low else "up"),
                          object=f.get("interface", "") or f.get("intf", ""), **base)]
        return [event("system", **base)]
    return None
