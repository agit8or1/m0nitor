"""Vendor syslog parsers -> normalized events.

Every parser module exposes ``parse(raw, app, msg, dev) -> list[dict] | None``:
  raw  the syslog message without the receipt envelope (PRI and header included; vendors put fields in odd places)
  app  APP-NAME / tag from the header ('' if none), msg the message part after the header
  dev  the owning device dict (vendor, wan_if, ...) or {}
Return None when the line is not recognized (it is then stored unparsed as a system event and counted in parser
coverage), [] when it is recognized but deliberately not stored (e.g. a session-start line whose session-end line
carries the same connection), or a list of events built with ``event()``.

Normalized event (schema version EVENT_SCHEMA): category in vendors.CATEGORIES; action allow | block | unknown for
traffic (only allow/block are firewall decisions; unknown is never counted as a block); outcome for state changes
(up, down, success, failure, change, active, standby). Unknown values stay empty/None, never guessed.
"""
import ipaddress
import re
from datetime import datetime, timezone

EVENT_SCHEMA = 1
BLOCK_WORDS = {"deny", "denied", "drop", "dropped", "reject", "rejected", "block", "blocked", "reset", "reset-both",
               "reset-client", "reset-server", "prevent", "discard", "discarded"}
ALLOW_WORDS = {"allow", "allowed", "accept", "accepted", "permit", "permitted", "pass", "passed", "forward", "close",
               "timeout", "server-rst", "client-rst", "est-allowed"}
SEV_WORDS = {"emergency": 0, "emerg": 0, "alert": 1, "critical": 2, "crit": 2, "error": 3, "err": 3, "high": 3,
             "warning": 4, "warn": 4, "medium": 4, "notice": 5, "low": 5, "information": 6, "informational": 6, "info": 6,
             "debug": 7}
PROTO_NUM = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "58": "ipv6-icmp", "132": "sctp"}

KV = re.compile(r'([A-Za-z_][\w.-]*)=("(?:[^"\\]|\\.)*"|\S*)')
KV_COLON = re.compile(r'([A-Za-z_][\w.-]*):"((?:[^"\\]|\\.)*)"')


def ip(v):
    """IPv6-mapped string for ClickHouse IPv6 columns, or None when absent/invalid (unknown, not 0.0.0.0)."""
    if v is None:
        return None
    v = str(v).strip().strip("[]")
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return None
    return str(a if a.version == 6 else ipaddress.IPv6Address("::ffff:" + str(a)))


def num(v, default=0):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def proto(v):
    v = str(v or "").strip().lower()
    return PROTO_NUM.get(v, v)


def action_of(word):
    w = str(word or "").strip().lower()
    if w in BLOCK_WORDS or w.startswith(("deny", "drop", "reset", "block", "reject")):
        return "block"
    if w in ALLOW_WORDS or w.startswith(("allow", "accept", "permit")):
        return "allow"
    return "unknown"


def severity_of(word, default=6):
    if word is None or word == "":
        return default
    if str(word).isdigit():
        return max(0, min(7, int(word)))
    return SEV_WORDS.get(str(word).strip().lower(), default)


def kv(text):
    """key=value / key="quoted value" pairs (FortiGate, SonicWall, Sophos, Meraki, Huawei)."""
    return {k: (v[1:-1].replace('\\"', '"') if v.startswith('"') and v.endswith('"') and len(v) > 1 else v)
            for k, v in KV.findall(text)}


def kv_colon(text):
    """key:"value"; pairs (Check Point Log Exporter syslog format)."""
    return {k: v.replace('\\"', '"') for k, v in KV_COLON.findall(text)}


def ts_parse(s, fmt=None):
    """Epoch seconds from an ISO / 'YYYY-MM-DD HH:MM:SS' / 'YYYY/MM/DD HH:MM:SS' timestamp, else None.
    A timestamp without zone is taken as UTC only when the caller says so; otherwise None (receipt time is used)."""
    if not s:
        return None
    s = str(s).strip()
    try:
        if fmt:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d.timestamp() if d.tzinfo else None
    except ValueError:
        return None


def event(category, **f):
    """Build a normalized event; unknown fields stay empty."""
    e = {"category": category, "action": f.pop("action", "") or ("unknown" if category == "traffic" else ""),
         "severity": f.pop("severity", 6), "src": f.pop("src", None), "dst": f.pop("dst", None),
         "sport": num(f.pop("sport", 0)), "dport": num(f.pop("dport", 0)), "proto": proto(f.pop("proto", "")),
         "dir": f.pop("dir", ""), "rule": str(f.pop("rule", "") or "")[:200], "zone_in": str(f.pop("zone_in", "") or "")[:64],
         "zone_out": str(f.pop("zone_out", "") or "")[:64], "iface_in": str(f.pop("iface_in", "") or "")[:64],
         "iface_out": str(f.pop("iface_out", "") or "")[:64], "user": str(f.pop("user", "") or "")[:128],
         "object": str(f.pop("object", "") or "")[:200], "outcome": f.pop("outcome", ""), "sig_id": num(f.pop("sig_id", 0)),
         "signature": str(f.pop("signature", "") or "")[:500], "threat_class": str(f.pop("threat_class", "") or "")[:200],
         "bytes": num(f.pop("bytes", 0)), "packets": num(f.pop("packets", 0)), "message": str(f.pop("message", "") or "")[:2000],
         "ts": f.pop("ts", None), "subtype": str(f.pop("subtype", "") or "")[:64]}
    if f:
        raise TypeError(f"unknown event fields: {sorted(f)}")
    return e


def direction(dev, iface_in="", iface_out="", zone_in="", zone_out=""):
    """in/out relative to the device's WAN, only when the WAN interface or zone is known; else '' (unknown)."""
    wan = {x for x in ((dev or {}).get("wan_if"), *((dev or {}).get("wan_zones") or [])) if x}
    if not wan:
        return ""
    if iface_in in wan or zone_in in wan:
        return "in"
    if iface_out in wan or zone_out in wan:
        return "out"
    return ""


def get(name):
    """Parser module for a vendor profile's parser name (None for the built-in OPNsense/pfSense path)."""
    from . import cisco, fortigate, generic, huawei, junos, kvfw, meraki, mikrotik, netfilter, panos, watchguard
    return {"fortigate": fortigate, "panos": panos, "cisco": cisco, "meraki": meraki, "junos": junos,
            "mikrotik": mikrotik, "netfilter": netfilter, "kv": kvfw, "watchguard": watchguard, "huawei": huawei,
            "generic": generic}.get(name)
