"""Investigate → Search: ask in plain English, get a structured, validated, read-only search.

The question becomes a *search spec* (a dict of named filters), never SQL. The spec is validated, shown back as
plain-language filters the user can edit, and run through fixed query templates with typed parameters, a time bound
and a row limit. Interpretation is deterministic (`parse`); AI is optional (`ai_interpret`). With AI, only the
question goes to the model, with internal addresses and device names replaced, after a preview, under the daily
request limit, and the model's answer goes through the same validator. Saved searches can be proposed as scheduled
detections; they only run after an admin reviewed them (`approve`).
"""
import hashlib
import ipaddress
import json
import re
import time
from datetime import datetime, timedelta

SOURCES = {"traffic": "Traffic records", "dns": "DNS lookups", "firewall": "Firewall log", "findings": "Findings"}
RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
MAX_SPAN = {"traffic": 30 * 86400, "dns": 30 * 86400, "firewall": 14 * 86400, "findings": 90 * 86400}
DIRECTIONS = {"any": "any direction", "outgoing": "opened by the device", "incoming": "opened from the internet", "internal": "between internal devices"}
GROUPS = {"none": "individual conversations", "device": "device", "remote": "remote address", "port": "service", "country": "country",
          "asn": "network owner", "domain": "name looked up", "rule": "finding type"}
GROUPS_FOR = {"traffic": {"none", "device", "remote", "port", "country", "asn"}, "dns": {"none", "device", "domain"},
              "firewall": {"none", "device", "remote", "port"}, "findings": {"none", "device", "rule"}}
SEVERITIES = ["low", "medium", "high", "critical"]
MAX_LIMIT = 200
FIELDS = ("source", "range", "from", "to", "sites", "device", "remote", "country", "asn", "org", "port", "proto", "direction",
          "measure", "domain", "action", "severity", "rule", "min_bytes", "group", "limit")
SERVICE_WORDS = {"rdp": ("tcp", 3389), "ssh": ("tcp", 22), "smb": ("tcp", 445), "telnet": ("tcp", 23), "smtp": ("tcp", 25), "http": ("tcp", 80),
                 "https": ("tcp", 443), "dns": ("udp", 53), "ntp": ("udp", 123), "vnc": ("tcp", 5900), "mysql": ("tcp", 3306),
                 "postgres": ("tcp", 5432), "postgresql": ("tcp", 5432), "imap": ("tcp", 143), "imaps": ("tcp", 993), "ldap": ("tcp", 389),
                 "snmp": ("udp", 161), "sip": ("udp", 5060), "ftp": ("tcp", 21), "mssql": ("tcp", 1433), "winrm": ("tcp", 5985)}
EXAMPLES = ["Which devices talked to Russia in the last 7 days?", "Connections to port 3389 from the internet yesterday",
            "Top destinations of 10.0.0.5 by bytes in the last 24 hours", "Which devices looked up example.com this week?",
            "Blocked connections to 10.0.0.5 in the last 24 hours", "High severity findings in the last 30 days",
            "Devices that uploaded more than 1 GB yesterday", "Internal SSH connections today"]


class SpecError(ValueError):
    pass


# ---- the spec ---------------------------------------------------------------------------------------------------
def _net(v, what):
    v = str(v).strip()
    try:
        return str(ipaddress.ip_network(v, strict=False)) if "/" in v else str(ipaddress.ip_address(v))
    except ValueError:
        raise SpecError(f"{what}: not an IP address or range")


def validate(spec, cfg, now=None):
    """Return a clean spec (only known fields, typed, bounded) or raise SpecError with a plain message."""
    now = int(now or time.time())
    s = {k: spec.get(k) for k in FIELDS if spec.get(k) not in (None, "", [])}
    out = {"source": s.get("source", "traffic")}
    if out["source"] not in SOURCES:
        raise SpecError("unknown kind of data")
    src = out["source"]
    if s.get("from") or s.get("to"):
        try:
            t0, t1 = int(s.get("from")), int(s.get("to") or now)
        except (TypeError, ValueError):
            raise SpecError("from/to must be times")
        t1 = min(t1, now)
        if t1 <= t0:
            raise SpecError("the end of the period must be after its start")
        out.update({"range": "custom", "from": t0, "to": t1})
    else:
        rk = s.get("range", "24h")
        if rk not in RANGES:
            raise SpecError("unknown period")
        out["range"] = rk
    span = (out["to"] - out["from"]) if out["range"] == "custom" else RANGES[out["range"]]
    if span > MAX_SPAN[src]:
        raise SpecError(f"{SOURCES[src]} are kept {MAX_SPAN[src] // 86400} days: choose a shorter period")
    ids = {x["id"] for x in cfg.sites}
    sites = s.get("sites") or []
    sites = [sites] if isinstance(sites, str) else list(sites)
    if any(x not in ids for x in sites):
        raise SpecError("unknown firewall")
    if sites:
        out["sites"] = sorted(set(sites))
    if s.get("device"):
        d = _net(s["device"], "device")
        if not cfg.is_internal(str(ipaddress.ip_network(d).network_address)):
            raise SpecError("device must be an internal address")
        out["device"] = d
    if s.get("remote"):
        out["remote"] = _net(s["remote"], "remote address")
    if s.get("country"):
        from .dash import META
        cc = str(s["country"]).upper()[:2]
        if cc not in META:
            raise SpecError("unknown country")
        out["country"] = cc
    if s.get("asn"):
        try:
            a = int(str(s["asn"]).upper().removeprefix("AS"))
        except ValueError:
            raise SpecError("network owner (AS) must be a number")
        if not 0 < a < 2 ** 32:
            raise SpecError("AS number out of range")
        out["asn"] = a
    if s.get("org"):
        org = " ".join(str(s["org"]).split())[:60]
        if len(org) < 2:
            raise SpecError("organization name too short")
        out["org"] = org
    if s.get("port"):
        try:
            p = int(s["port"])
        except (TypeError, ValueError):
            raise SpecError("port must be a number")
        if not 0 < p < 65536:
            raise SpecError("port out of range")
        out["port"] = p
    if s.get("proto"):
        if s["proto"] not in ("tcp", "udp", "icmp"):
            raise SpecError("protocol must be tcp, udp or icmp")
        out["proto"] = s["proto"]
    d = s.get("direction", "any")
    if d not in DIRECTIONS:
        raise SpecError("unknown direction")
    if src == "traffic":
        out["direction"] = d
        m = s.get("measure", "received")
        if m not in ("received", "sent"):
            raise SpecError("measure must be received or sent")
        out["measure"] = m
        if m == "sent" and d == "internal":
            raise SpecError("sent volume is for internet traffic")
    if s.get("domain"):
        dom = str(s["domain"]).strip().lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9*_.-]{2,253}", dom):
            raise SpecError("not a domain name")
        out["domain"] = dom.lstrip("*.")
    if s.get("action"):
        if s["action"] not in ("block", "pass"):
            raise SpecError("action must be block or pass")
        out["action"] = s["action"]
    if s.get("severity"):
        if s["severity"] not in SEVERITIES:
            raise SpecError("unknown severity")
        out["severity"] = s["severity"]
    if s.get("rule"):
        if not re.fullmatch(r"[a-z_]{2,40}", str(s["rule"])):
            raise SpecError("unknown finding type")
        out["rule"] = s["rule"]
    if s.get("min_bytes"):
        try:
            mb = int(s["min_bytes"])
        except (TypeError, ValueError):
            raise SpecError("minimum volume must be a number")
        if mb < 0:
            raise SpecError("minimum volume must be positive")
        out["min_bytes"] = mb
    g = s.get("group", "none")
    if g not in GROUPS_FOR[src]:
        raise SpecError(f"{SOURCES[src]} cannot be grouped by {GROUPS.get(g, g)}")
    out["group"] = g
    try:
        out["limit"] = max(1, min(MAX_LIMIT, int(s.get("limit", 50))))
    except (TypeError, ValueError):
        raise SpecError("limit must be a number")
    # fields that make no sense for the source are dropped with a note (never silently widened)
    allowed = {"traffic": {"device", "remote", "country", "asn", "org", "port", "proto", "min_bytes"},
               "dns": {"device", "domain"}, "firewall": {"device", "remote", "port", "proto", "action"},
               "findings": {"device", "remote", "severity", "rule"}}[src]
    dropped = [k for k in ("device", "remote", "country", "asn", "org", "port", "proto", "domain", "action", "severity", "rule", "min_bytes")
               if k in out and k not in allowed]
    for k in dropped:
        out.pop(k)
    if dropped:
        out["_dropped"] = dropped
    return out


def window(spec, now=None):
    now = int(now or time.time())
    if spec["range"] == "custom":
        return spec["from"], spec["to"]
    return now - RANGES[spec["range"]], now


def describe(spec, cfg, site_tz=None):
    """The interpreted filters, in plain words (shown above the results, and editable in the form)."""
    from .ux import fmt_local
    t0, t1 = window(spec)
    when = (f"from {fmt_local(t0)} to {fmt_local(t1)}" if spec["range"] == "custom" else
            {"1h": "last hour", "6h": "last 6 hours", "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days"}[spec["range"]])
    parts = [SOURCES[spec["source"]], when]
    if spec.get("sites"):
        parts.append("firewall " + ", ".join((cfg.site(x) or {}).get("name", x) for x in spec["sites"]))
    if spec.get("device"):
        parts.append("device " + (cfg.asset_label(spec["device"]) if "/" not in spec["device"] else spec["device"]))
    if spec.get("remote"):
        parts.append("remote " + spec["remote"])
    if spec.get("country"):
        from .dash import META
        parts.append("country " + META[spec["country"]]["name"])
    if spec.get("asn"):
        parts.append(f"network owner AS{spec['asn']}")
    if spec.get("org"):
        parts.append(f"network owner name contains “{spec['org']}”")
    if spec.get("port"):
        parts.append(f"service {spec.get('proto', '')}{'/' if spec.get('proto') else 'port '}{spec['port']}")
    elif spec.get("proto"):
        parts.append(f"protocol {spec['proto']}")
    if spec["source"] == "traffic":
        if spec["direction"] != "any":
            parts.append(DIRECTIONS[spec["direction"]])
        if spec["measure"] == "sent":
            parts.append("volume sent by the device")
    if spec.get("domain"):
        parts.append(f"name {spec['domain']} (and its subdomains)")
    if spec.get("action"):
        parts.append({"block": "blocked", "pass": "passed"}[spec["action"]])
    if spec.get("severity"):
        parts.append(f"severity {spec['severity']} or higher")
    if spec.get("rule"):
        parts.append(f"finding type {spec['rule']}")
    if spec.get("min_bytes"):
        parts.append(f"at least {human(spec['min_bytes'])}")
    parts.append(f"grouped by {GROUPS[spec['group']]}" if spec["group"] != "none" else "individual conversations")
    parts.append(f"top {spec['limit']}")
    return parts


def human(n):
    for u, f in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if n >= f:
            return f"{n / f:.1f} {u}".replace(".0 ", " ")
    return f"{n} B"


# ---- deterministic interpretation -------------------------------------------------------------------------------
UNITS = {"b": 1, "kb": 1e3, "k": 1e3, "mb": 1e6, "m": 1e6, "gb": 1e9, "g": 1e9, "tb": 1e12}
STOP = set("a an the of in on at to from for by with and or is are was were be been any all which what who whose that this these those "
           "show me list find give top most more than over above least last past during since between devices device did do does has have "
           "had talked talk talking connected connect connecting connections connection contacted traffic records record there "
           "bytes volume data servers server my our us we everything anything something get got go went "
           "hosts host machines machine internet my our please how many much".split())


def parse(question, cfg, now=None, tz=None):
    """Plain English -> (spec dict, notes). Deterministic; unknown words are reported, never guessed."""
    from .dash import META
    from .ux import site_tz
    now = int(now or time.time())
    q = " ".join((question or "").split())[:300]
    low = q.lower()
    spec, notes, used = {}, [], set()

    def use(*words):
        used.update(w.lower() for w in words)
    # time ---------------------------------------------------------------------------------------------------------
    tzinfo = tz or site_tz(cfg.sites[0] if cfg.sites else None)
    today0 = int(datetime.fromtimestamp(now, tzinfo).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    m = re.search(r"\b(?:last|past)\s+(\d{1,3})\s*(hours?|h|days?|d|weeks?|minutes?|mins?)\b", low)
    if m:
        n, u = int(m.group(1)), m.group(2)
        secs = n * (3600 if u.startswith("h") else 604800 if u.startswith("w") else 60 if u.startswith("m") else 86400)
        preset = {3600: "1h", 21600: "6h", 86400: "24h", 604800: "7d", 2592000: "30d"}.get(secs)
        spec.update({"range": preset} if preset else {"from": now - secs, "to": now})
        use(*m.group(0).split())
    elif re.search(r"\byesterday\b", low):
        y0 = int((datetime.fromtimestamp(today0, tzinfo) - timedelta(days=1)).timestamp())
        spec.update({"from": y0, "to": today0})
        use("yesterday")
    elif re.search(r"\btoday\b", low):
        spec.update({"from": today0, "to": now})
        use("today")
    elif re.search(r"\b(?:this|last|past)\s+week\b|\bweek\b", low):
        spec["range"] = "7d"
        use("this", "last", "past", "week")
    elif re.search(r"\b(?:this|last|past)\s+month\b|\bmonth\b", low):
        spec["range"] = "30d"
        use("this", "last", "past", "month")
    elif re.search(r"\b(?:last|past)\s+hour\b", low):
        spec["range"] = "1h"
        use("hour")
    # source ---------------------------------------------------------------------------------------------------------
    if re.search(r"\b(?:look(?:ed)?\s*ups?|lookups?|resolved|queried|dns queries|dns lookups?|looked up)\b", low):
        spec["source"] = "dns"
        use("looked", "up", "lookup", "lookups", "resolved", "queried", "queries", "dns", "look")
    if re.search(r"\b(?:blocked|denied|dropped|rejected)\b", low):
        spec["source"], spec["action"] = "firewall", "block"
        use("blocked", "denied", "dropped", "rejected")
    elif re.search(r"\bfirewall log\b|\bpassed\b", low):
        spec["source"] = "firewall"
        if "passed" in low:
            spec["action"] = "pass"
        use("firewall", "log", "passed")
    if re.search(r"\b(?:findings?|alerts?)\b", low):
        spec["source"] = "findings"
        use("finding", "findings", "alert", "alerts")
        for sv in SEVERITIES:
            if re.search(rf"\b{sv}\b", low):
                spec["severity"] = sv
                use(sv, "severity")
        if re.search(r"\bserious\b", low):
            spec["severity"] = "high"
            use("serious")
    # addresses and names ----------------------------------------------------------------------------------------
    for tok in re.findall(r"(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|[0-9a-f]*:[0-9a-f:]+(?:/\d{1,3})?)(?![\w.:])", low):
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            continue
        if cfg.is_internal(str(net.network_address)) and "device" not in spec:
            spec["device"] = tok
        elif "remote" not in spec:
            spec["remote"] = tok
        use(tok)
    names = {a["name"].lower(): ip for ip, a in (cfg.get("assets") or {}).items() if a.get("name")}
    for n in sorted(names, key=len, reverse=True):
        if len(n) >= 3 and re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", low) and "device" not in spec:
            spec["device"] = names[n]
            use(*n.split())
    for tok in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", low):
        if not re.fullmatch(r"[\d.]+", tok):
            spec["domain"] = tok
            if spec.get("source") not in ("dns",):
                spec["source"] = "dns"
            use(tok)
    m = re.search(r"\bas\s?(\d{1,10})\b", low)
    if m:
        spec["asn"] = int(m.group(1))
        use(m.group(0).replace(" ", ""), "as", m.group(1))
    m = re.search(r"\b(?:owned by|organi[sz]ation|network owner|operated by)\s+([a-z0-9][\w .&-]{1,40}?)(?=\s+(?:in|during|over|from|since|last|past|yesterday|today|this|by)\b|[?.!,]|$)", low)
    if m:
        spec["org"] = m.group(1).strip()
        use(*m.group(0).split())
    cnames = {v["name"].lower(): cc for cc, v in META.items()}
    for n in sorted(cnames, key=len, reverse=True):
        if re.search(rf"\b{re.escape(n)}\b", low):
            spec["country"] = cnames[n]
            use(*n.split())
            break
    # services, protocol, direction, volume, grouping --------------------------------------------------------
    m = re.search(r"\bport\s+(\d{1,5})\b", low)
    if m:
        spec["port"] = int(m.group(1))
        use("port", m.group(1))
    for w, (proto, port) in SERVICE_WORDS.items():
        if re.search(rf"\b{w}\b", low) and "port" not in spec and not (w == "dns" and spec.get("source") == "dns"):
            spec.update(port=port, proto=proto)
            use(w)
            break
    for pr in ("tcp", "udp", "icmp"):
        if re.search(rf"\b{pr}\b", low):
            spec["proto"] = pr
            use(pr)
    if re.search(r"\bping\b", low) and "proto" not in spec:
        spec["proto"] = "icmp"
        use("ping")
    if re.search(r"\b(?:internal|lateral|between (?:internal )?devices|east-west)\b", low):
        spec["direction"] = "internal"
        use("internal", "lateral", "between", "east-west")
    elif re.search(r"\b(?:inbound|incoming|from the internet|reached from|exposed|scann?ed|reaching)\b", low):
        spec["direction"] = "incoming"
        use("inbound", "incoming", "from", "the", "internet", "reached", "exposed", "scanned", "scaned", "reaching")
    elif re.search(r"\b(?:outbound|outgoing|to the internet)\b", low):
        spec["direction"] = "outgoing"
        use("outbound", "outgoing", "to", "the", "internet")
    if re.search(r"\b(?:upload(?:ed|s)?|sent|sending|exfiltrat\w*)\b", low):
        spec["measure"] = "sent"
        use("upload", "uploaded", "uploads", "sent", "sending")
    if re.search(r"\b(?:download(?:ed|s)?|received)\b", low):
        use("download", "downloaded", "downloads", "received")
    m = re.search(r"\b(?:more than|over|above|at least|>)\s*(\d+(?:\.\d+)?)\s*(tb|gb|mb|kb|g|m|k|b)\b", low)
    if m:
        spec["min_bytes"] = int(float(m.group(1)) * UNITS[m.group(2)])
        use(*m.group(0).split(), m.group(1), m.group(2))
    groups = [(r"\b(?:which|what|who|top|list)\s+(?:\w+\s+)?(?:devices?|hosts?|machines?|servers?|clients?)\b|\bwho\b", "device"),
              (r"\b(?:which|what|top)\s+(?:\w+\s+)?(?:countries|country)\b", "country"),
              (r"\b(?:which|what|top)\s+(?:\w+\s+)?(?:destinations?|remotes?|addresses|ips?|peers?)\b|\bwhere\b", "remote"),
              (r"\b(?:which|what|top)\s+(?:\w+\s+)?(?:ports?|services?)\b", "port"),
              (r"\b(?:which|what|top)\s+(?:\w+\s+)?(?:organi[sz]ations?|companies|providers|networks|owners|asns?)\b", "asn"),
              (r"\b(?:which|what|top)\s+(?:\w+\s+)?(?:domains?|names?|sites?|websites?)\b", "domain"),
              (r"\b(?:which|what)\s+(?:\w+\s+)?(?:kinds?|types?|rules?)\b", "rule")]
    src = spec.get("source", "traffic")
    for pat, g in groups:
        if re.search(pat, low) and g in GROUPS_FOR[src]:
            spec["group"] = g
            used.update(re.findall(r"\w+", re.search(pat, low).group(0)))
            break
    if "group" not in spec and spec.get("measure") == "sent" and spec.get("min_bytes"):
        spec["group"] = "device"
    if re.search(r"\bdestinations of\b|\bwhere did\b", low):
        spec["group"] = "remote"
    words = [w for w in re.findall(r"[a-z0-9][a-z0-9'-]*", low) if w not in STOP and w not in used and not w.isdigit()]
    words = [w for w in words if not any(w in u for u in used if len(u) > 3)]
    if words:
        notes.append("Not understood (ignored): " + ", ".join(dict.fromkeys(words)))
    return spec, notes


# ---- running ----------------------------------------------------------------------------------------------------
def _sites(cfg, spec):
    return [s for s in cfg.sites if not spec.get("sites") or s["id"] in spec["sites"]]


def _net_cond(col, value, key, p):
    """SQL condition matching an IPv6-mapped address column against an IP or range (typed parameters)."""
    net = ipaddress.ip_network(value, strict=False)
    lo, hi = net.network_address, net.broadcast_address
    if net.version == 4:
        lo, hi = ipaddress.IPv6Address(f"::ffff:{lo}"), ipaddress.IPv6Address(f"::ffff:{hi}")
    p[f"{key}lo"], p[f"{key}hi"] = str(lo), str(hi)
    return f"{col} BETWEEN toIPv6({{{key}lo:String}}) AND toIPv6({{{key}hi:String}})"


IP = "replaceOne(IPv6NumToString({c}), '::ffff:', '')"
PROTO = {"tcp": 6, "udp": 17, "icmp": 1}


def _traffic(cfg, ch, spec, t0, t1):
    from .core import expand_flow_sql, flow_predicates
    sites = _sites(cfg, spec)
    macros, fp = flow_predicates(cfg, sites)
    p = {"exps": [s["exporter"] for s in sites], "t0": int(t0), "t1": int(t1), "lim": spec["limit"], **fp}
    w = ["ExporterName IN {exps:Array(String)}", "TimeReceived >= toDateTime({t0:UInt32})", "TimeReceived < toDateTime({t1:UInt32})"]
    note = ""
    if spec["direction"] == "internal":
        wans = [s["wan_if"] for s in sites]
        p["wans"] = wans
        w += ["InIfName != ''", "NOT has({wans:Array(String)}, InIfName)", "NOT has({wans:Array(String)}, OutIfName)"]
        from .segments import _ranges
        p["ilo"], p["ihi"] = _ranges(cfg)
        w += ["arrayExists((a, z) -> SrcAddr >= a AND SrcAddr <= z, {ilo:Array(IPv6)}, {ihi:Array(IPv6)})",
              "arrayExists((a, z) -> DstAddr >= a AND DstAddr <= z, {ilo:Array(IPv6)}, {ihi:Array(IPv6)})"]
        dev = "if(DstPort <= SrcPort, SrcAddr, DstAddr)"     # the client (inferred from ports)
        rem = "if(DstPort <= SrcPort, DstAddr, SrcAddr)"
        dirx = "'internal'"
    elif spec["measure"] == "sent":
        # sent volume is in the outbound records, which carry the post-NAT address: per device only for 1:1 NAT addresses
        w.append("OUTB")
        dev, rem = "SrcAddr", "DstAddr"
        dirx = "if(DstPort < SrcPort, 'outgoing', 'incoming')"
        note = ("Volume sent is measured on the outbound records, which carry the address after NAT: devices behind a shared address "
                "appear as that shared address.")
    else:
        # inbound records (replies included) name the internal device even behind a shared NAT address
        w += ["INB", "TOLAN"]
        dev, rem = "DstAddr", "SrcAddr"
        dirx = "if(SrcPort < DstPort, 'outgoing', 'incoming')"
        note = "Volume is what the device received (the records that name the device even behind a shared address)."
    if spec.get("device"):
        if spec["measure"] == "sent" and spec["direction"] != "internal":
            ext = list(cfg.binat_ext(spec["device"])) if "/" not in spec["device"] else []
            if not ext:
                raise SpecError("volume sent cannot be tied to this device: it shares its public address with others. "
                                "Search what it received instead.")
            p["dext"] = [f"::ffff:{x}" if ":" not in x else x for x in ext]
            w.append(f"has(arrayMap(x -> toIPv6(x), {{dext:Array(String)}}), {dev})")
        else:
            w.append(_net_cond(dev, spec["device"], "dv", p))
    if spec.get("remote"):
        w.append(_net_cond(rem, spec["remote"], "rm", p))
    remote_cc = "SrcCountry" if rem == "SrcAddr" else "DstCountry"
    remote_as = "SrcAS" if rem == "SrcAddr" else "DstAS"
    if spec.get("country"):
        p["cc"] = spec["country"]
        w.append(f"{remote_cc} = {{cc:String}}")
    if spec.get("asn"):
        p["asn"] = spec["asn"]
        w.append(f"{remote_as} = {{asn:UInt32}}")
    if spec.get("org"):
        p["org"] = spec["org"]
        w.append(f"positionCaseInsensitive(dictGetOrDefault('asns', 'name', toUInt64({remote_as}), ''), {{org:String}}) > 0")
    if spec.get("port"):
        p["port"] = spec["port"]
        w.append("least(SrcPort, DstPort) = {port:UInt16}" if spec["direction"] != "incoming" else
                 f"{'DstPort' if dev == 'DstAddr' else 'SrcPort'} = {{port:UInt16}}")
    if spec.get("proto"):
        p["proto"] = PROTO[spec["proto"]]
        w.append("Proto = {proto:UInt8}")
    if spec["direction"] == "outgoing":
        w.append("SrcPort < DstPort" if dev == "DstAddr" else "DstPort < SrcPort")
    elif spec["direction"] == "incoming":
        w.append("SrcPort > DstPort" if dev == "DstAddr" else "DstPort > SrcPort")
    dims = {"none": [("device", IP.format(c=dev)), ("remote", IP.format(c=rem)), ("proto", "Proto"), ("port", "least(SrcPort, DstPort)"),
                     ("direction", dirx)],
            "device": [("device", IP.format(c=dev))], "remote": [("remote", IP.format(c=rem))],
            "port": [("proto", "Proto"), ("port", "least(SrcPort, DstPort)")], "country": [("country", remote_cc)],
            "asn": [("asn", remote_as)]}[spec["group"]]
    extra = ""
    if spec["group"] in ("asn", "none", "remote"):
        extra = f", any(dictGetOrDefault('asns', 'name', toUInt64({remote_as}), '')) AS org, any({remote_cc}) AS cc"
    having = " HAVING bytes >= {minb:UInt64}" if spec.get("min_bytes") else ""
    if spec.get("min_bytes"):
        p["minb"] = spec["min_bytes"]
    sql = (f"SELECT {', '.join(f'{x} AS {n}' for n, x in dims)}, count() AS records, sum(Bytes * SamplingRate) AS bytes, "
           f"toUInt32(min(TimeReceived)) AS first, toUInt32(max(TimeReceived)) AS last{extra} FROM flows WHERE {' AND '.join(w)} "
           f"GROUP BY {', '.join(n for n, _ in dims)}{having} ORDER BY bytes DESC LIMIT {{lim:UInt32}}")
    return expand_flow_sql(sql, macros), p, note


def _dns(cfg, spec, t0, t1):
    p = {"sites": [s["id"] for s in _sites(cfg, spec)], "t0": int(t0), "t1": int(t1), "lim": spec["limit"]}
    w = ["site IN {sites:Array(String)}", "ts >= toDateTime({t0:UInt32})", "ts < toDateTime({t1:UInt32})"]
    if spec.get("device"):
        w.append(_net_cond("client", spec["device"], "dv", p))
    if spec.get("domain"):
        p["dom"], p["sfx"] = spec["domain"], "." + spec["domain"]
        w.append("(lower(query) = {dom:String} OR endsWith(lower(query), {sfx:String}))")
    dims = {"none": [("device", IP.format(c="client")), ("domain", "lower(query)"), ("qtype", "qtype"), ("rcode", "rcode")],
            "device": [("device", IP.format(c="client"))], "domain": [("domain", "lower(query)")]}[spec["group"]]
    sql = (f"SELECT {', '.join(f'{x} AS {n}' for n, x in dims)}, count() AS records, toUInt32(min(ts)) AS first, toUInt32(max(ts)) AS last "
           f"FROM netmon.dns_events WHERE {' AND '.join(w)} GROUP BY {', '.join(n for n, _ in dims)} ORDER BY records DESC LIMIT {{lim:UInt32}}")
    return sql, p, "From the DNS query log; devices that use another resolver are not in it."


def _fw(cfg, spec, t0, t1):
    p = {"sites": [s["id"] for s in _sites(cfg, spec)], "t0": int(t0), "t1": int(t1), "lim": spec["limit"]}
    w = ["site IN {sites:Array(String)}", "ts >= toDateTime({t0:UInt32})", "ts < toDateTime({t1:UInt32})"]
    if spec.get("action"):
        p["act"] = spec["action"]
        w.append("action = {act:String}")
    if spec.get("device"):
        w.append(f"({_net_cond('src', spec['device'], 'dv', p)} OR {_net_cond('dst', spec['device'], 'dw', p)})")
    if spec.get("remote"):
        w.append(f"({_net_cond('src', spec['remote'], 'rm', p)} OR {_net_cond('dst', spec['remote'], 'rn', p)})")
    if spec.get("port"):
        p["port"] = spec["port"]
        w.append("dport = {port:UInt16}")
    if spec.get("proto"):
        p["proto"] = spec["proto"]
        w.append("lower(proto) = {proto:String}")
    dev = "if(dir = 'out', src, dst)"
    rem = "if(dir = 'out', dst, src)"
    dims = {"none": [("device", IP.format(c=dev)), ("remote", IP.format(c=rem)), ("proto", "lower(proto)"), ("port", "dport"),
                     ("action", "action"), ("iface", "iface")],
            "device": [("device", IP.format(c=dev))], "remote": [("remote", IP.format(c=rem))],
            "port": [("proto", "lower(proto)"), ("port", "dport")]}[spec["group"]]
    sql = (f"SELECT {', '.join(f'{x} AS {n}' for n, x in dims)}, count() AS records, toUInt32(min(ts)) AS first, toUInt32(max(ts)) AS last "
           f"FROM netmon.fw_events WHERE {' AND '.join(w)} GROUP BY {', '.join(n for n, _ in dims)} ORDER BY records DESC LIMIT {{lim:UInt32}}")
    return sql, p, "From the firewall log: only rules with logging enabled are recorded."


def _findings(conn, cfg, spec, t0, t1):
    w, p = ["last_seen >= ?", "first_seen < ?", "test = 0"], [t0, t1]
    if spec.get("sites"):
        w.append(f"site IN ({','.join('?' * len(spec['sites']))})")
        p += spec["sites"]
    if spec.get("severity"):
        sv = SEVERITIES[SEVERITIES.index(spec["severity"]):]
        w.append(f"severity IN ({','.join('?' * len(sv))})")
        p += sv
    if spec.get("rule"):
        w.append("rule = ?")
        p.append(spec["rule"])
    if spec.get("device") and "/" not in spec["device"]:
        w.append("asset = ?")
        p.append(spec["device"])
    if spec.get("remote") and "/" not in spec["remote"]:
        w.append("subject LIKE ?")
        p.append(f"%{spec['remote']}%")
    rows = [dict(r) for r in conn.execute(
        "SELECT id, rule, severity, asset, subject, title, status, first_seen, last_seen, count FROM alerts WHERE "
        f"{' AND '.join(w)} ORDER BY last_seen DESC LIMIT {MAX_LIMIT * 5}", p)]
    for k in ("device", "remote"):
        if spec.get(k) and "/" in spec[k]:
            net = ipaddress.ip_network(spec[k])
            rows = [r for r in rows if _in(r["asset"] if k == "device" else str(r["subject"]).split("|")[-1].split(":")[0], net)]
    if spec["group"] == "none":
        return rows[:spec["limit"]]
    key, name = ("asset", "device") if spec["group"] == "device" else ("rule", "rule")
    agg = {}
    for r in rows:
        a = agg.setdefault(r[key], {name: r[key], "records": 0, "first": r["first_seen"], "last": r["last_seen"], "worst": "low"})
        a["records"] += 1
        a["first"], a["last"] = min(a["first"], r["first_seen"]), max(a["last"], r["last_seen"])
        if r["severity"] in SEVERITIES and SEVERITIES.index(r["severity"]) > SEVERITIES.index(a["worst"]):
            a["worst"] = r["severity"]
    return sorted(agg.values(), key=lambda x: -x["records"])[:spec["limit"]]


def _in(ip, net):
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def run(conn, cfg, ch, spec, now=None):
    """Execute a validated spec (read-only, bounded). Returns {rows, note, sql (for the technical details), ms}."""
    t0, t1 = window(spec, now)
    t = time.time()
    if spec["source"] == "findings":
        rows = _findings(conn, cfg, spec, t0, t1)
        return {"rows": rows, "note": "Findings netmon raised (tests excluded).", "sql": None, "ms": int((time.time() - t) * 1000),
                "t0": t0, "t1": t1}
    if spec["source"] == "traffic":
        sql, p, note = _traffic(cfg, ch, spec, t0, t1)
    elif spec["source"] == "dns":
        sql, p, note = _dns(cfg, spec, t0, t1)
    else:
        sql, p, note = _fw(cfg, spec, t0, t1)
    rows = ch.query(sql, p)   # read-only session; the client bounds execution time and result size
    return {"rows": rows, "note": note, "sql": sql, "params": p, "ms": int((time.time() - t) * 1000), "t0": t0, "t1": t1}


# ---- optional AI interpretation ---------------------------------------------------------------------------------
AI_SYSTEM = ("You translate a network-monitoring question into search filters. Fill only the fields the question asks for and leave "
             "the others null. Never invent addresses, names or numbers that are not in the question. Internal devices appear as "
             "host-N placeholders: copy them unchanged into device. Answer only with the JSON object.")


def _nullable(t, enum=None):
    x = {"type": [t, "null"]}
    if enum:
        x["enum"] = enum + [None]
    return x


AI_SCHEMA = {"type": "object", "additionalProperties": False, "properties": {
    "source": _nullable("string", list(SOURCES)), "range": _nullable("string", list(RANGES)), "device": _nullable("string"),
    "remote": _nullable("string"), "country_code": _nullable("string"), "asn": _nullable("integer"), "org": _nullable("string"),
    "port": _nullable("integer"), "proto": _nullable("string", ["tcp", "udp", "icmp"]), "direction": _nullable("string", list(DIRECTIONS)),
    "measure": _nullable("string", ["received", "sent"]), "domain": _nullable("string"), "action": _nullable("string", ["block", "pass"]),
    "severity": _nullable("string", SEVERITIES), "min_bytes": _nullable("integer"), "group": _nullable("string", list(GROUPS))},
    "required": ["source", "range", "device", "remote", "country_code", "asn", "org", "port", "proto", "direction", "measure", "domain",
                 "action", "severity", "min_bytes", "group"]}


def ai_preview(ai, question):
    """Exactly what would be sent: the question with internal addresses and device names replaced."""
    mapping = {}
    text = ai.pseudo(" ".join((question or "").split())[:300], mapping) if ai.ac.get("pseudonymize_internal", True) else question
    return {"text": text, "mapping": mapping, "model": ai.ac.get("model"), "used_today": ai.used_today(),
            "limit": ai.ac.get("daily_request_limit", 25), "digest": hashlib.sha256(text.encode()).hexdigest()[:16]}


def ai_interpret(ai, user, question, digest):
    """Send the previewed question (and nothing else). The answer is a filter dict for `validate`, never SQL."""
    import httpx

    from . import secretbox
    from .core import audit
    pv = ai_preview(ai, question)
    if pv["digest"] != digest:
        raise SpecError("the question changed after the preview: preview again")
    if not ai.enabled:
        raise SpecError("AI is not configured")
    if pv["used_today"] >= pv["limit"]:
        raise SpecError("the daily AI request limit is reached; use the filters instead")
    key = secretbox.read_file(ai.key_path())
    model = pv["model"]
    req = {"model": model, "max_output_tokens": 1500, "store": False,
           "input": [{"role": "system", "content": AI_SYSTEM}, {"role": "user", "content": pv["text"]}],
           "text": {"format": {"type": "json_schema", "name": "netmon_search", "strict": True, "schema": AI_SCHEMA}}}
    if model.startswith(("gpt-5", "o1", "o3", "o4")):
        req["reasoning"] = {"effort": "minimal" if model.startswith("gpt-5") else "low"}
    audit(ai.conn, user, "ai_request_sent", {"kind": "search", "model": model, "chars": len(pv["text"]), "categories": ["question"],
                                             "digest": pv["digest"], "max_output_tokens": 1500})
    r = httpx.post("https://api.openai.com/v1/responses", json=req, timeout=60, headers={"Authorization": f"Bearer {key}"})
    if r.status_code != 200:
        audit(ai.conn, user, "ai_request_failed", {"status": r.status_code})
        raise SpecError(f"the AI service returned HTTP {r.status_code}; use the filters instead")
    data = r.json()
    text = "".join(c.get("text", "") for it in data.get("output", []) if it.get("type") == "message" for c in it.get("content", [])
                   if c.get("type") == "output_text")
    try:
        got = json.loads(text)
    except ValueError:
        raise SpecError("the AI answer was not usable; use the filters instead")
    audit(ai.conn, user, "ai_response", {"digest": pv["digest"], "usage": data.get("usage", {})})
    return from_ai(got, pv["mapping"])


def from_ai(got, mapping):
    """Model output -> spec fields; pseudonyms are mapped back locally, anything unknown is dropped."""
    rev = {v: k for k, v in mapping.items()}
    spec = {k: v for k, v in got.items() if v not in (None, "") and k in FIELDS}
    if got.get("country_code"):
        spec["country"] = got["country_code"]
    for k in ("device", "remote"):
        if isinstance(spec.get(k), str) and re.fullmatch(r"host-\d+", spec[k]):
            if spec[k] not in rev:
                spec.pop(k)
            else:
                spec[k] = rev[spec[k]]
    return spec


# ---- saved searches and reviewed detections ---------------------------------------------------------------------
DETECT_INTERVALS = (900, 86400)
MAX_DETECTIONS = 20


def save(conn, owner, name, question, spec, shared=False):
    from .core import audit
    name = " ".join((name or "").split())[:80]
    if not name:
        raise SpecError("give the search a name")
    sid = conn.execute("INSERT INTO saved_searches(owner, name, question, spec, shared, created_at) VALUES (?,?,?,?,?,?)",
                       (owner, name, (question or "")[:300], json.dumps({k: v for k, v in spec.items() if not k.startswith("_")}),
                        1 if shared else 0, time.time())).lastrowid
    conn.commit()
    audit(conn, owner, "search_saved", {"id": sid, "name": name, "shared": bool(shared)})
    return sid


def visible(conn, user):
    return [dict(r) for r in conn.execute("SELECT * FROM saved_searches WHERE owner=? OR shared=1 ORDER BY name", (user,))]


def get(conn, sid):
    r = conn.execute("SELECT * FROM saved_searches WHERE id=?", (sid,)).fetchone()
    if not r:
        raise SpecError("no such saved search")
    return dict(r)


def can_see(row, user):
    return row["owner"] == user or row["shared"]


def delete(conn, sid, user, admin=False):
    from .core import audit
    row = get(conn, sid)
    if row["owner"] != user and not admin:
        raise PermissionError("only the owner or an admin can delete it")
    conn.execute("DELETE FROM saved_searches WHERE id=?", (sid,))
    conn.commit()
    audit(conn, user, "search_deleted", {"id": sid})


def propose(conn, sid, user, interval_s, threshold, severity):
    """Ask for a saved search to run as a detection. It does nothing until an admin approves it."""
    from .core import audit
    row = get(conn, sid)
    spec = json.loads(row["spec"])
    if spec["source"] == "findings":
        raise SpecError("a search over findings cannot itself raise findings")
    interval_s, threshold = int(interval_s), int(threshold)
    if not DETECT_INTERVALS[0] <= interval_s <= DETECT_INTERVALS[1]:
        raise SpecError("run it every 15 minutes to 24 hours")
    if not 1 <= threshold <= 100000:
        raise SpecError("the threshold must be 1 or more results")
    if severity not in SEVERITIES[:3]:
        raise SpecError("severity must be low, medium or high")
    conn.execute("UPDATE saved_searches SET detect='proposed', detect_interval_s=?, detect_threshold=?, detect_severity=?, proposed_by=?, "
                 "proposed_at=?, reviewed_by=NULL, reviewed_at=NULL, review_note=NULL WHERE id=?",
                 (interval_s, threshold, severity, user, time.time(), sid))
    conn.commit()
    audit(conn, user, "detection_proposed", {"search": sid, "interval_s": interval_s, "threshold": threshold, "severity": severity})


def review_preview(conn, cfg, ch, row, now=None, days=7, samples=24):
    """How often the proposed detection would have fired: `samples` windows of its interval spread over the last days.
    Estimate per day = share of sampled windows that fire × windows per day."""
    now = int(now or time.time())
    spec = json.loads(row["spec"])
    iv = row["detect_interval_s"]
    step = max(iv, (days * 86400) // samples)
    out, t = [], now - days * 86400
    while t + iv <= now and len(out) < samples:
        s = dict(spec, range="custom", **{"from": t, "to": t + iv})
        try:
            n = len(run(conn, cfg, ch, validate(s, cfg, now), now)["rows"])
        except Exception:
            n = None
        out.append({"t": t, "n": n, "fires": n is not None and n >= row["detect_threshold"]})
        t += step
    ok = [x for x in out if x["n"] is not None]
    fires = sum(1 for x in ok if x["fires"])
    return {"samples": out, "sampled": len(out), "failed": len(out) - len(ok), "fires": fires,
            "per_day": (fires / len(ok)) * (86400 / iv) if ok else 0}


def approve(conn, sid, admin_user, note=""):
    from .core import audit
    row = get(conn, sid)
    if row["detect"] != "proposed":
        raise SpecError("only a proposed detection can be approved")
    if row["proposed_by"] == admin_user and conn.execute("SELECT count(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0] > 1:
        raise SpecError("another admin must review a detection you proposed")
    if conn.execute("SELECT count(*) FROM saved_searches WHERE detect='approved'").fetchone()[0] >= MAX_DETECTIONS:
        raise SpecError(f"at most {MAX_DETECTIONS} search detections")
    conn.execute("UPDATE saved_searches SET detect='approved', reviewed_by=?, reviewed_at=?, review_note=? WHERE id=?",
                 (admin_user, time.time(), note[:200], sid))
    conn.commit()
    audit(conn, admin_user, "detection_approved", {"search": sid, "note": note[:200]})


def reject(conn, sid, admin_user, note=""):
    from .core import audit
    conn.execute("UPDATE saved_searches SET detect='none', reviewed_by=?, reviewed_at=?, review_note=? WHERE id=?",
                 (admin_user, time.time(), (note or "stopped")[:200], sid))
    conn.commit()
    audit(conn, admin_user, "detection_stopped", {"search": sid, "note": note[:200]})


def due_detections(conn, now):
    return [dict(r) for r in conn.execute("SELECT * FROM saved_searches WHERE detect='approved' AND "
                                          "(last_detect IS NULL OR last_detect + detect_interval_s <= ?)", (now,))]


def detection_findings(conn, cfg, ch, site, now):
    """Detector hook: approved search detections for this firewall, each over its own interval."""
    out = []
    for row in due_detections(conn, now):
        spec = json.loads(row["spec"])
        if spec.get("sites") and site["id"] not in spec["sites"]:
            continue
        s = dict(spec, sites=[site["id"]], range="custom", **{"from": int(now - row["detect_interval_s"]), "to": int(now)})
        res = run(conn, cfg, ch, validate(s, cfg, now), now)
        if site["id"] == (spec.get("sites") or [cfg.sites[-1]["id"]])[-1]:
            conn.execute("UPDATE saved_searches SET last_detect=? WHERE id=?", (now, row["id"]))
            conn.commit()
        n = len(res["rows"])
        if n < row["detect_threshold"]:
            continue
        top = res["rows"][0]
        asset = top.get("device") or ""
        out.append(dict(
            rule="search_detection", severity=row["detect_severity"], confidence="medium", asset=asset, subject=f"search:{row['id']}",
            title=f"Saved search “{row['name']}” matched {n} result{'s' if n != 1 else ''}",
            window=(now - row["detect_interval_s"], now), evidence=res["rows"][:20],
            query=("nlsearch", {k: v for k, v in s.items()}),
            baseline=(f"A reviewed saved search (approved by {row['reviewed_by']}) that fires at {row['detect_threshold']} or more results "
                      f"per {row['detect_interval_s'] // 60} min."),
            alternatives=["The search is broader than intended", "A legitimate change matches it"],
            next_steps=[f"Open the saved search (#{row['id']}) to see the results", "Narrow the search or change the threshold if this is expected"]))
    return out
