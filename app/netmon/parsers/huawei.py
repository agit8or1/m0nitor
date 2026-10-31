"""Huawei VRP / USG information-center logs: '%%01MODULE/<sev>/MNEMONIC(l):text'.

POLICY/POLICYPERMIT|POLICYDENY: 'vsys=public, protocol=6, source-ip=.., source-port=.., destination-ip=..,
  destination-port=.., time=.., source-zone=untrust, destination-zone=trust, rule-name=x.'
SHELL/CMDRECORD -> config; IFNET/LINK_STATE|IF_LINKDOWN|IF_LINKUP -> interface; SSH|TELNET .._LOGIN_FAIL -> auth.
"""
import re

from . import direction, event, ip, num

RE_HW = re.compile(r"%%\d+([A-Z0-9_]+)/(\d)/([A-Z0-9_]+)(?:\([a-z]+\))?(?:\[\d+\])?:\s?(.*)$")
RE_KV = re.compile(r"([A-Za-z][\w-]*)=(\"[^\"]*\"|[^,;)]*)")


def _kv(text):
    return {k.lower(): v.strip().strip('"').rstrip(".") for k, v in RE_KV.findall(text)}


def parse(raw, app, msg, dev):
    m = RE_HW.search(raw)
    if not m:
        return None
    mod, sev, mn, text = m.group(1), int(m.group(2)), m.group(3), m.group(4)
    f = _kv(text)
    if mod in ("POLICY", "SEC") and mn in ("POLICYPERMIT", "POLICYDENY"):
        zi, zo = f.get("source-zone", ""), f.get("destination-zone", "")
        return [event("traffic", action="allow" if mn == "POLICYPERMIT" else "block", proto=f.get("protocol", ""),
                      src=ip(f.get("source-ip")), dst=ip(f.get("destination-ip")), sport=num(f.get("source-port")),
                      dport=num(f.get("destination-port")), zone_in=zi, zone_out=zo, rule=f.get("rule-name", ""),
                      dir=direction(dev, "", "", zi, zo), severity=sev, subtype=f"{mod}/{mn}")]
    if mod == "SHELL" and mn in ("CMDRECORD", "CMDRECORDFAILED"):
        return [event("config", outcome="change" if mn == "CMDRECORD" else "failure", user=f.get("user", ""),
                      src=ip(f.get("ip")), message=f.get("command", text)[:500], severity=sev, subtype=f"{mod}/{mn}")]
    if mod in ("IFNET", "IFPDT") or "LINK" in mn:
        st = "down" if "DOWN" in (mn + text.upper()) else "up" if "UP" in (mn + text.upper()) else "change"
        im = re.search(r"interface (\S+?)[ ,.]", text + " ")
        return [event("interface", outcome=st, object=f.get("interface", "") or (im.group(1) if im else ""), message=text[:500],
                      severity=sev, subtype=f"{mod}/{mn}")]
    if "LOGIN" in mn or mod in ("SSH", "SSHS", "TELNET", "AAA"):
        fail = "FAIL" in mn
        return [event("auth", outcome="failure" if fail else "success", user=f.get("username", "") or f.get("user", ""),
                      src=ip(f.get("ipaddress") or f.get("ip") or f.get("userip")), message=text[:500], severity=sev,
                      subtype=f"{mod}/{mn}")]
    return [event("system", message=text[:500], severity=sev, subtype=f"{mod}/{mn}")]
