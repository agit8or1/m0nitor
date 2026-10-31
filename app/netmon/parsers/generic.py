"""Generic devices: keyword categorization of standard syslog, for state changes only.

Generic logs never yield firewall allow/deny decisions (they are not structured enough to tell a decision from a
description). Lines matched here are stored as normalized events; anything else stays an unparsed system event.
"""
import re

from . import event, ip

RULES = [
    ("interface", re.compile(r"\b(?:interface|port|link)\s+([\w/.:-]+)\b.*?\b(?:changed state to |is |went |link )?(up|down)\b", re.I)),
    ("routing", re.compile(r"\b(BGP|OSPF|IS-IS|RIP)\b.*?\b(?:neighbou?r|peer|nbr|adjacency)\s+(\S+).*?\b(up|down|established|idle|full)\b", re.I)),
    ("auth_fail", re.compile(r"(?:authentication failure|failed (?:login|password)|login (?:failed|failure)|invalid user)\b.*?"
                             r"(?:user[=: ]+'?([\w.@-]+)'?)?.*?(?:from|rhost=|src=)\s*([0-9a-fA-F.:]{3,})?", re.I)),
    ("auth_ok", re.compile(r"(?:accepted password|login success(?:ful)?|logged in)\b.*?(?:user[=: ]+'?([\w.@-]+)'?)?"
                           r".*?(?:from)\s*([0-9a-fA-F.:]{3,})?", re.I)),
    ("config", re.compile(r"\b(?:configuration (?:changed|saved|committed)|config(?:ured)? (?:change|from)|commit (?:complete|succeeded))\b", re.I)),
]


def parse(raw, app, msg, dev):
    text = msg or raw
    for kind, rx in RULES:
        m = rx.search(text)
        if not m:
            continue
        if kind == "interface":
            return [event("interface", outcome=m.group(2).lower(), object=m.group(1), message=text[:500], subtype="generic")]
        if kind == "routing":
            st = m.group(3).lower()
            return [event("routing", outcome="up" if st in ("up", "established", "full") else "down",
                          object=f"{m.group(1)} {m.group(2)}", message=text[:500], subtype="generic")]
        if kind.startswith("auth"):
            return [event("auth", outcome="failure" if kind == "auth_fail" else "success", user=m.group(1) or "",
                          src=ip(m.group(2)), message=text[:500], subtype="generic")]
        return [event("config", outcome="change", message=text[:500], subtype="generic")]
    return None
