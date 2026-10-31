"""Juniper Junos / SRX structured syslog (sd-syslog, RFC 5424 structured data) and BSD-style Junos events.

RT_FLOW_SESSION_DENY -> block; RT_FLOW_SESSION_CLOSE -> allow (carries bytes); RT_FLOW_SESSION_CREATE is recognized but
not stored (its CLOSE line describes the same session). RT_IDP_ATTACK_LOG_EVENT / RT_SCREEN_* -> IDS.
UI_LOGIN_EVENT / SSHD_LOGIN_FAILED -> auth; UI_COMMIT* -> config; SNMP_TRAP_LINK_* -> interface;
RPD_BGP_NEIGHBOR_STATE_CHANGED / RPD_OSPF_NBRDOWN|NBRUP -> routing.
"""
import re

from . import direction, event, ip, num

RE_SD = re.compile(r'\[junos@[\d.]+ ((?:[\w-]+="(?:[^"\\]|\\.)*"\s*)*)\]')
RE_PAIR = re.compile(r'([\w-]+)="((?:[^"\\]|\\.)*)"')
RE_TAG = re.compile(r"\b(RT_FLOW_SESSION_(?:DENY|CLOSE|CREATE)|RT_IDP_ATTACK_LOG_EVENT|RT_SCREEN_\w+|UI_LOGIN_EVENT|"
                    r"UI_AUTH_EVENT|SSHD_LOGIN_FAILED|UI_COMMIT\w*|SNMP_TRAP_LINK_(?:UP|DOWN)|RPD_BGP_NEIGHBOR_STATE_CHANGED|"
                    r"RPD_OSPF_NBR(?:UP|DOWN)|LOGIN_FAILED|UI_CHILD_STATUS)\b")


def _grp(rx, text):
    m = re.search(rx, text)
    return next((x for x in m.groups() if x), "") if m else ""


def parse(raw, app, msg, dev):
    t = RE_TAG.search(raw)
    if not t:
        return None
    tag = t.group(1)
    sd = RE_SD.search(raw)
    f = dict(RE_PAIR.findall(sd.group(1))) if sd else {}
    if tag.startswith("RT_FLOW_SESSION"):
        if tag.endswith("CREATE"):
            return []
        if not f:
            return None
        zi, zo = f.get("source-zone-name", ""), f.get("destination-zone-name", "")
        ii = f.get("packet-incoming-interface", "")
        return [event("traffic", action="block" if tag.endswith("DENY") else "allow", src=ip(f.get("source-address")),
                      dst=ip(f.get("destination-address")), sport=num(f.get("source-port")), dport=num(f.get("destination-port")),
                      proto=f.get("protocol-id", ""), rule=f.get("policy-name", ""), zone_in=zi, zone_out=zo, iface_in=ii,
                      user=f.get("username", "") if f.get("username") not in ("N/A", None) else "",
                      bytes=num(f.get("bytes-from-client")) + num(f.get("bytes-from-server")),
                      packets=num(f.get("packets-from-client")) + num(f.get("packets-from-server")),
                      dir=direction(dev, ii, "", zi, zo), message=f.get("reason", ""), subtype=tag)]
    if tag == "RT_IDP_ATTACK_LOG_EVENT" or tag.startswith("RT_SCREEN"):
        act = (f.get("action") or "").lower()
        sev = {"critical": 1, "major": 1, "minor": 2, "warning": 3, "info": 4}.get((f.get("threat-severity") or "").lower(), 2)
        return [event("ids", action="block" if act in ("drop", "drop-packet", "close", "reset-client", "reset-server", "ignore") or
                      tag.startswith("RT_SCREEN") else "allow",
                      src=ip(f.get("source-address")), dst=ip(f.get("destination-address")),
                      sport=num(f.get("source-port")), dport=num(f.get("destination-port")),
                      proto=f.get("protocol-name", "") or f.get("protocol-id", ""), zone_in=f.get("source-zone-name", ""),
                      signature=f.get("attack-name", "") or f.get("message", ""), threat_class=tag, severity=sev, subtype=tag)]
    text = raw[t.end():]
    if tag in ("UI_LOGIN_EVENT", "UI_AUTH_EVENT", "SSHD_LOGIN_FAILED", "LOGIN_FAILED"):
        user = f.get("username") or _grp(r"[Uu]ser '([^']+)'|for user (\S+)|username=(\S+)", text)
        src = f.get("source-address") or f.get("remote-address") or _grp(r"from ([0-9a-fA-F.:]+)", text)
        return [event("auth", outcome="failure" if "FAIL" in tag else "success", user=user, src=ip(src), message=text[:500],
                      subtype=tag)]
    if tag.startswith("UI_COMMIT"):
        u = f.get("username") or _grp(r"User '([^']+)'", text)
        return [event("config", outcome="change", user=u, message=text.strip(" :[]")[:500], subtype=tag)]
    if tag.startswith("SNMP_TRAP_LINK"):
        return [event("interface", outcome="up" if tag.endswith("UP") else "down",
                      object=f.get("interface-name", "") or _grp(r"ifName (\S+?),?\s", text + " "), subtype=tag)]
    if tag.startswith("RPD_"):
        new = (f.get("new-state") or "").lower()
        out = "up" if new == "established" or tag.endswith("UP") else "down"
        return [event("routing", outcome=out, object=f.get("peer-name", "") or text.strip()[:100], message=text[:500], subtype=tag)]
    return None
