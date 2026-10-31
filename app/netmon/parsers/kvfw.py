"""key=value firewalls: SonicWall (SonicOS), Sophos Firewall (SFOS), and Check Point Log Exporter (key:"value";).

SonicWall: 'id=firewall sn=.. time=".." fw=.. pri=6 c=.. m=537 msg="Connection Closed" src=ip:port:X1 dst=ip:port:X0
           proto=tcp/22 sent=.. rcvd=.. [fw_action="drop"]'. Action from fw_action, else from the message text.
           'Connection Opened' (m=98) is recognized but not stored; 'Connection Closed' (m=537) carries the counters.
Sophos:    'device_name="SFW" ... log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" status="Deny"
           src_ip=.. dst_ip=.. protocol="TCP" src_port=.. dst_port=.. fw_rule_id=..' (pre- and post-19.5 field names)
Check Point: '[action:"Drop"; ifdir:"inbound"; ifname:"eth1"; src:".."; dst:".."; proto:"6"; s_port:".."; service:"22";
           product:"VPN-1 & FireWall-1"; rule_name:".."]'
"""
import re

from . import action_of, direction, event, ip, kv, kv_colon, num, severity_of

IDS_SEV = {"critical": 1, "high": 1, "major": 1, "medium": 2, "minor": 3, "low": 3, "info": 4, "informational": 4}


def _sw_ep(v):
    p = (v or "").split(":")
    if len(p) >= 2 and ip(p[0]):
        return ip(p[0]), num(p[1]), p[2] if len(p) > 2 else ""
    return ip(v), 0, ""


def sonicwall(raw, dev):
    f = kv(raw[raw.find("id="):])
    m, text = f.get("m", ""), f.get("msg", "")
    s, sp, si = _sw_ep(f.get("src"))
    d, dp, di = _sw_ep(f.get("dst"))
    pr = (f.get("proto") or "").split("/")[0]
    low = text.lower()
    sev = severity_of(f.get("pri"))
    common = dict(src=s, sport=sp, dst=d, dport=dp, proto=pr, iface_in=si, iface_out=di, severity=sev, subtype=f"m={m}",
                  dir=direction(dev, si, di))
    if "ips detection" in low or "ips prevention" in low or f.get("c") == "IPS":
        return [event("ids", action="block" if "prevention" in low else "allow", signature=text.split(":", 1)[-1].strip(),
                      **{**common, "severity": 2})]
    if "login" in low and ("administrator" in low or "user" in low):
        return [event("auth", outcome="failure" if ("denied" in low or "fail" in low) else "success",
                      user=f.get("usr", "").strip('"'), src=s, message=text, severity=sev, subtype=f"m={m}")]
    if "vpn" in low or "ipsec" in low or "ike" in low:
        out = "up" if ("established" in low or "up" in low.split()) else "down" if ("down" in low or "deleted" in low) else ""
        return [event("vpn", outcome=out, src=s, message=text, severity=sev, subtype=f"m={m}")]
    fa = (f.get("fw_action") or "").strip('"').lower()
    if m == "98" or "connection opened" in low:
        return []
    if fa and fa != "na":
        act = "block" if fa in ("drop", "deny", "reject", "block") else "allow" if fa in ("forward", "allow", "accept") else "unknown"
    elif "dropped" in low or "denied" in low or "blocked" in low:
        act = "block"
    elif "connection closed" in low:
        act = "allow"
    else:
        return [event("system", message=text, severity=sev, subtype=f"m={m}")] if text else None
    return [event("traffic", action=act, bytes=num(f.get("sent")) + num(f.get("rcvd")), message=text, **common)]


def sophos(raw, dev):
    f = kv(raw)
    lt, comp, sub = f.get("log_type", ""), f.get("log_component", ""), f.get("log_subtype", "")
    zin = f.get("src_zone_type", "") or f.get("src_zone", "")
    zout = f.get("dst_zone_type", "") or f.get("dst_zone", "")
    di = "in" if f.get("src_zone_type", "").upper() == "WAN" else "out" if f.get("dst_zone_type", "").upper() == "WAN" else ""
    common = dict(src=ip(f.get("src_ip")), dst=ip(f.get("dst_ip")), sport=num(f.get("src_port")), dport=num(f.get("dst_port")),
                  proto=f.get("protocol", ""), iface_in=f.get("in_interface", "") or f.get("in_display_interface", ""),
                  iface_out=f.get("out_interface", "") or f.get("out_display_interface", ""), zone_in=zin, zone_out=zout,
                  severity=severity_of(f.get("priority") or f.get("severity")), subtype=f"{lt}/{sub}".strip("/"))
    if lt == "Firewall":
        st = (f.get("status") or sub).lower()
        act = "block" if st.startswith("den") or st in ("drop", "reject") else "allow" if st.startswith("allow") else "unknown"
        return [event("traffic", action=act, dir=di, rule=f.get("fw_rule_id", "") or f.get("fw_rule_name", ""),
                      bytes=num(f.get("sent_bytes") or f.get("bytes_sent")) + num(f.get("recv_bytes") or f.get("bytes_received")),
                      user=f.get("user_name", "") or f.get("user", ""), **common)]
    if lt in ("IDP", "IPS"):
        a = (f.get("action") or sub).lower()
        return [event("ids", action="block" if a in ("drop", "reset", "deny") else "allow", dir=di,
                      sig_id=num(f.get("signature_id")), signature=f.get("signature_msg", "") or f.get("message", ""),
                      threat_class=f.get("classification", ""), **{**common, "severity": IDS_SEV.get((f.get("severity") or "").lower(), 2)})]
    if lt in ("Anti-Virus", "Anti-Spam", "Content Filtering", "ATP", "Sandbox", "Application Filter"):
        return [event("threat", action=action_of(f.get("status") or sub), signature=f.get("virus", "") or f.get("category", ""),
                      threat_class=lt, object=f.get("url", "") or f.get("domain", ""), message=f.get("message", ""), **common)]
    msg = f.get("message", "")
    low = (comp + " " + sub + " " + msg).lower()
    base = dict(severity=common["severity"], subtype=common["subtype"], message=msg)
    if "authentication" in low or sub in ("Authentication", "Admin") and "login" in low:
        stt = (f.get("status") or "").lower()
        return [event("auth", outcome="failure" if "fail" in stt or "fail" in low else "success",
                      user=f.get("user_name", "") or f.get("user", ""), src=common["src"], object=comp, **base)]
    if comp in ("IPSec", "SSL VPN", "VPN") or "vpn" in low or "ipsec" in low:
        return [event("vpn", outcome="up" if ("established" in low or "connected" in low) else "down"
                      if ("terminated" in low or "disconnected" in low or "failed" in low) else "", **base)]
    if sub == "Admin" or "changed" in low or "configuration" in low:
        return [event("config", outcome="change", user=f.get("user_name", ""), object=comp, **base)]
    return [event("system", **base)] if lt else None


def checkpoint(raw, dev):
    f = kv_colon(raw)
    if not f:
        return None
    prod = f.get("product", "")
    ifdir = f.get("ifdir", "")
    act = f.get("action", "")
    common = dict(src=ip(f.get("src")), dst=ip(f.get("dst")), sport=num(f.get("s_port")), dport=num(f.get("service")),
                  proto=f.get("proto", ""), iface_in=f.get("ifname", "") if ifdir == "inbound" else "",
                  iface_out=f.get("ifname", "") if ifdir == "outbound" else "", subtype=prod[:64],
                  severity=severity_of(f.get("severity"), 6))
    if prod in ("IPS", "SmartDefense", "IDS"):
        return [event("ids", action="block" if act.lower() in ("drop", "prevent", "reject", "block") else "allow",
                      signature=f.get("protection_name", "") or f.get("attack", ""), threat_class=f.get("protection_type", ""),
                      sig_id=num(f.get("protection_id", "0"), 0) if f.get("protection_id", "").isdigit() else 0,
                      **{**common, "severity": IDS_SEV.get(f.get("severity", "").lower(), 2)})]
    if prod in ("Anti-Bot", "Anti-Virus", "Threat Emulation", "Threat Extraction", "URL Filtering", "Application Control"):
        return [event("threat", action=action_of(act), signature=f.get("malware_action", "") or f.get("protection_name", ""),
                      threat_class=prod, object=f.get("resource", "") or f.get("appi_name", ""), **common)]
    if act in ("Key Install", "Encrypt", "Decrypt") or prod == "VPN" and act:
        return [event("vpn", outcome="up" if act == "Key Install" else "", object=f.get("peer_gateway", ""), message=act,
                      **{k: common[k] for k in ("src", "dst", "severity", "subtype")})]
    if act in ("Accept", "Drop", "Reject", "Block", "Allow"):
        return [event("traffic", action=action_of(act), rule=f.get("rule_name", "") or f.get("rule", ""),
                      dir="in" if ifdir == "inbound" and direction(dev, f.get("ifname", "")) == "in" else
                      direction(dev, common["iface_in"], common["iface_out"]), **common)]
    if "login" in (f.get("operation", "") + act).lower():
        return [event("auth", outcome="failure" if "fail" in (f.get("status", "") + act).lower() else "success",
                      user=f.get("administrator", "") or f.get("user", ""), src=common["src"], subtype=prod[:64])]
    return [event("system", message="; ".join(f"{k}={v}" for k, v in list(f.items())[:12]), subtype=prod[:64])]


def parse(raw, app, msg, dev):
    if "id=firewall" in raw and " m=" in raw:
        return sonicwall(raw, dev)
    if "log_type=" in raw and ("log_component=" in raw or "device_name=" in raw or "device=" in raw):
        return sophos(raw, dev)
    if re.search(r'\baction:"[^"]*";', raw) or 'product:"' in raw:
        return checkpoint(raw, dev)
    return None
