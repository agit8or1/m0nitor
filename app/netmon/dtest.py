"""Investigate → Test detections: synthetic scenarios and replay of retained data. Nothing here records findings,
notifies or blocks.

Synthetic scenarios run the *real* detector rules against made-up records that exist only inside the query: every
table the rules read (`flows`, `netmon.*_events`) is replaced by a common table expression built with the `values()`
table function, and any other table reference is refused (`Isolated`). The ClickHouse session stays read-only. Each
scenario says what it expects, and the result shows expected vs actual, why a rule triggered (its own explanation)
or the likely reason it did not (thresholds, monitoring choices, learning, exceptions, expected devices).

Replay ("Preview rule changes") runs the current and the proposed rule settings over sampled windows of retained
data, in a background job with limits and cancellation, and compares how many findings each would have raised.
"""
import copy
import ipaddress
import re
import threading
import time

from .detect import Detector

MAX_ROWS = 20000
SCENARIO_RUNTIME = 60
REPLAY_MAX_WINDOWS = 48
REPLAY_MAX_RUNTIME = 600
REPLAY_SPANS = {"24h": 86400, "3d": 3 * 86400, "7d": 7 * 86400}
REPLAYABLE = {"new_dest_country": "flows", "new_dest_asn": "flows", "unexpected_inbound": "flows", "outbound_volume": "flows",
              "fanout": "flows", "beaconing": "flows", "ids_alert": "ids", "fw_blocked_outbound": "syslog", "fw_blocked_scan": "syslog"}
NOT_REPLAYABLE = {"exporter_silence": "depends on live source state", "syslog_silence": "depends on live source state",
                  "disk_usage": "depends on the current disk"}


class Isolated(RuntimeError):
    """A sandboxed query tried to read something other than the synthetic tables."""


# ---- synthetic tables --------------------------------------------------------------------------------------------
FLOW_COLS = [("TimeReceived", "DateTime"), ("ExporterName", "String"), ("ExporterAddress", "IPv6"), ("InIfName", "String"),
             ("OutIfName", "String"), ("SrcAddr", "IPv6"), ("DstAddr", "IPv6"), ("SrcPort", "UInt16"), ("DstPort", "UInt16"),
             ("Proto", "UInt8"), ("Bytes", "UInt64"), ("Packets", "UInt64"), ("SamplingRate", "UInt64"), ("SrcAS", "UInt32"),
             ("DstAS", "UInt32"), ("SrcCountry", "String"), ("DstCountry", "String"), ("ForwardingStatus", "UInt32"), ("TCPFlags", "UInt16"),
             ("EType", "UInt32")]


def _event_cols():
    from .schema import TABLES
    out = {}
    for name in ("fw_events", "ids_events", "sys_events", "dns_events", "auth_events", "events"):
        ddl = TABLES[name].split("ENGINE")[0]
        cols = re.findall(r"`(\w+)` ((?:LowCardinality\()?[A-Za-z0-9]+(?:\((?:[^()]|\([^()]*\))*\))?\)?)", ddl)
        cols = [(c, re.sub(r"^LowCardinality\((.*)\)$", r"\1", t)) for c, t in cols]
        if name in ("fw_events", "ids_events", "sys_events", "auth_events"):
            cols += [(c, "String") for c in ("device", "vendor") if c not in dict(cols)]
        out[name] = cols
    return out


def _lit(v, t):
    if t.startswith("Array("):
        inner = t[6:-1]
        return "[" + ",".join(_lit(x, inner) for x in (v or [])) + "]"
    if t == "IPv6":
        ip = ipaddress.ip_address(v or "::")
        return f"toIPv6('{('::ffff:' + str(ip)) if ip.version == 4 else str(ip)}')"
    if t.startswith("DateTime64"):
        return f"toDateTime64({float(v or 0):.3f}, 3, 'UTC')"
    if t.startswith("DateTime"):
        return f"toDateTime({int(v or 0)}, 'UTC')"
    if t.startswith(("UInt", "Int", "Float")):
        return str(int(v or 0)) if not t.startswith("Float") else repr(float(v or 0))
    s = str(v if v is not None else "")
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def cte(name, cols, rows):
    struct = ", ".join(f"{c} {t}" for c, t in cols).replace("'", "\\'")
    if rows:
        body = ", ".join("(" + ", ".join(_lit(r.get(c), t) for c, t in cols) + ")" for r in rows)
        return f"__syn_{name} AS (SELECT * FROM values('{struct}', {body}))"
    dummy = "(" + ", ".join(_lit(None, t) for _, t in cols) + ")"
    return f"__syn_{name} AS (SELECT * FROM values('{struct}', {dummy}) WHERE 0)"


TABLE_REF = re.compile(r"\b(FROM|JOIN)\s+(netmon\.([a-z_]+)|flows(?:_[0-9a-z]+)?)\b(?!\s*\()", re.I)
ANY_REF = re.compile(r"\b(?:FROM|JOIN)\s+([A-Za-z_][\w.]*)\s*(\()?", re.I)
CTE_NAME = re.compile(r"(?:\bWITH|,)\s*([A-Za-z_]\w*)\s+AS\s*\(", re.I)
COMMENT = re.compile(r"--[^\n]*")
STRING = re.compile(r"'(?:[^'\\]|\\.)*'")


class SyntheticCH:
    """ClickHouse stand-in for sandboxed rules: same read-only client, synthetic tables only."""

    def __init__(self, ch, tables):
        self.ch, self.tables = ch, tables
        self.cols = {"flows": FLOW_COLS, **_event_cols()}
        if sum(len(v) for v in tables.values()) > MAX_ROWS:
            raise ValueError(f"at most {MAX_ROWS} synthetic records")
        self.sql = []

    def rewrite(self, sql):
        used = set()

        def rep(m):
            t = m.group(3) or "flows"            # aggregated flow tables read the same synthetic flows
            if t.lower() not in self.cols:
                raise Isolated(f"sandboxed query read table {m.group(2)}, which has no synthetic stand-in")
            used.add(t.lower())
            return f"{m.group(1)} __syn_{t.lower()}"
        out = TABLE_REF.sub(rep, COMMENT.sub("", sql))
        bare = STRING.sub("''", out)            # names inside string literals are not table references
        ctes = set(CTE_NAME.findall(bare)) | {f"__syn_{t}" for t in self.cols}
        for name, fn in ANY_REF.findall(bare):
            if fn or name not in ctes:
                raise Isolated(f"sandboxed query referenced {name}{'()' if fn else ''}")
        defs = ", ".join(cte(t, self.cols[t], self.tables.get(t, [])) for t in sorted(used))
        if not defs:
            return out
        s = out.lstrip()
        return ("WITH " + defs + ", " + s[4:].lstrip()) if s[:4].upper() == "WITH" else f"WITH {defs} {s}"

    def query(self, sql, params=None):
        q = self.rewrite(sql)
        self.sql.append(q)
        return self.ch.query(q, params or {})


class SandboxDetector(Detector):
    """The real rules, never recording, never notifying."""

    def __init__(self, cfg, ch, conn):
        super().__init__(cfg, ch, conn, notifier=None)

    def record(self, f, now):
        raise RuntimeError("the sandbox never records findings")


RULE_FN = {
    "new_dest_country": lambda d, now, days: d.rule_new_dest(now, days, "country"),
    "new_dest_asn": lambda d, now, days: d.rule_new_dest(now, days, "asn"),
    "unexpected_inbound": lambda d, now, days: d.rule_unexpected_inbound(now, days),
    "outbound_volume": lambda d, now, days: d.rule_outbound_volume(now, days),
    "fanout": lambda d, now, days: d.rule_fanout(now, days),
    "beaconing": lambda d, now, days: d.rule_beaconing(now, days),
    "ids_alert": lambda d, now, days: d.rule_ids(now),
    "fw_blocked_outbound": lambda d, now, days: [f for f in d.rule_fw_blocks(now) if f["rule"] == "fw_blocked_outbound"],
    "fw_blocked_scan": lambda d, now, days: [f for f in d.rule_fw_blocks(now) if f["rule"] == "fw_blocked_scan"],
}


def dry_exception(conn, f, now, site):
    from .baselines import exception_applies
    for x in conn.execute("SELECT * FROM exceptions WHERE enabled=1 ORDER BY id").fetchall():
        if exception_applies(x, f, now, site):
            return x
    return None


def evaluate(det, rules, now, days=None):
    """Run rules like run_site does, then the record-time checks without recording. Returns (kept, hidden, errors)."""
    from .core import expected_devices, expected_match
    from .ux import monitored
    days = det.learning() if days is None else days
    raw, errors = [], []
    for name in rules:
        if not monitored(det.site, REPLAYABLE.get(name, "flows")):
            errors.append(f"{name}: not monitored on this firewall (your choice)")
            continue
        try:
            raw += [dict(f, _rule_group=name) for f in RULE_FN[name](det, now, days)]
        except Isolated:
            raise
        except Exception as ex:
            errors.append(f"{name}: {type(ex).__name__}: {str(ex)[:200]}")
    kept, hidden = [], []
    exp = expected_devices(det.conn, now)
    for f in raw:
        try:
            f.update(det.verify_direction(f))
        except Isolated:
            raise
        except Exception as ex:
            f.update(direction=None, direction_verified=0, direction_basis=f"direction check failed: {ex}")
        if f["rule"] == "unexpected_inbound" and f.get("direction") == "outbound" and f.get("direction_verified"):
            hidden.append((f, "the firewall shows the device opened this connection: reply traffic, not exposure"))
            continue
        if f["rule"] != "fanout" and det.expected_only(f):
            hidden.append((f, "the traffic belongs to expected devices"))
            continue
        x = dry_exception(det.conn, f, now, det.site)
        if x:
            from .baselines import describe
            try:
                why = describe(x)
            except Exception:
                why = f"exception #{x['id']}"
            hidden.append((f, f"hidden by exception #{x['id']}: {why}"))
            continue
        if exp and (expected_match(exp, f["asset"]) or expected_match(exp, str(f["subject"]).split("|")[-1].split(":")[0])):
            hidden.append((f, "the device (or its peer) is an expected device"))
            continue
        kept.append(f)
    return kept, hidden, errors, days


def with_rules(cfg, rules_ov=None, det_ov=None):
    """A copy of the configuration with proposed settings. Like saved overrides, they apply on top of config.yaml
    (cfg._base), so a value set back to its default really goes back. The live configuration is untouched."""
    c = copy.copy(cfg)
    c.raw = copy.deepcopy(cfg.raw)
    base = getattr(cfg, "_base", None) or {"rules": cfg.raw["rules"], "detector": cfg.raw["detector"]}
    c.raw["rules"] = copy.deepcopy(base["rules"])
    c.raw["detector"] = copy.deepcopy(base["detector"])
    for name, ov in (rules_ov or {}).items():
        c.raw["rules"].setdefault(name, {}).update(ov)
    c.raw["detector"].update(det_ov or {})
    return c


# ---- scenarios ---------------------------------------------------------------------------------------------------
def _remotes(cfg, n, start=10):
    out = []
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/16"):
        for a in list(ipaddress.ip_network(net).hosts())[start:]:
            s = str(a)
            if not cfg.is_internal(s) and not cfg.is_ours(s):
                out.append(s)
                if len(out) >= n:
                    return out
    return out


class Rec:
    def __init__(self, cfg, site):
        self.cfg, self.site = cfg, site
        self.routed = site.get("flow_mode", "routed") == "routed"
        self.wan, self.lan = site["wan_if"], site.get("lan_if") or "lan"

    def inb(self, t, remote, device, rport, lport, proto=6, b=1500, cc="", asn=64500):
        """Internet -> device (replies included), delivered to the LAN: names the device even behind NAT."""
        return {"TimeReceived": t, "ExporterName": self.site["exporter"], "ExporterAddress": self.site.get("exporter_ip") or "::",
                "InIfName": self.wan, "OutIfName": self.lan if self.routed else "", "SrcAddr": remote, "DstAddr": device, "SrcPort": rport,
                "DstPort": lport, "Proto": proto, "Bytes": b, "Packets": max(1, b // 1200), "SamplingRate": 1, "SrcAS": asn, "DstAS": 0,
                "SrcCountry": cc, "DstCountry": ""}

    def outb(self, t, src, remote, sport, dport, proto=6, b=1500, cc="", asn=64500):
        """Device -> internet, after NAT (src is the public address)."""
        return {"TimeReceived": t, "ExporterName": self.site["exporter"], "ExporterAddress": self.site.get("exporter_ip") or "::",
                "InIfName": self.lan if self.routed else self.wan, "OutIfName": self.wan if self.routed else "", "SrcAddr": src,
                "DstAddr": remote, "SrcPort": sport, "DstPort": dport, "Proto": proto, "Bytes": b, "Packets": max(1, b // 1200),
                "SamplingRate": 1, "SrcAS": 0, "DstAS": asn, "SrcCountry": "", "DstCountry": cc}


def public_of(cfg, site, device):
    ext = cfg.binat_ext(device)
    if ext:
        return ext[0]
    nat = site.get("outbound_nat_ips") or cfg.get("outbound_nat_ips") or []
    return nat[0] if nat else device


def _window(cfg, now):
    d = cfg["detector"]
    we = int(now - d["ingest_delay_seconds"])
    return we - d["window_minutes"] * 60, we


def _baseline_country(r, now, device, remote, days=7, cc="DE"):
    out = []
    for h in range(days * 24, 1, -1):
        out.append(r.inb(now - h * 3600, remote, device, 443, 50000 + h % 1000, b=40000, cc=cc))
    return out


def sc_new_country(cfg, site, now, p):
    r, dev = Rec(cfg, site), p["device"]
    rem_old, rem_new = _remotes(cfg, 2)
    ws, we = _window(cfg, now)
    rows = _baseline_country(r, now, dev, rem_old)
    rows += [r.inb(we - 300 - i * 30, rem_new, dev, 443, 51000 + i, b=6000, cc=p["country"]) for i in range(p["records"])]
    return {"flows": rows}, [{"rule": "new_dest_country", "asset": dev, "subject": p["country"]}]


def sc_normal(cfg, site, now, p):
    r, dev = Rec(cfg, site), p["device"]
    rem = _remotes(cfg, 1)[0]
    ws, we = _window(cfg, now)
    rows = _baseline_country(r, now, dev, rem)
    rows += [r.inb(we - 300 - i * 60, rem, dev, 443, 52000 + i, b=40000, cc="DE") for i in range(3)]
    return {"flows": rows}, []


def sc_large_upload(cfg, site, now, p):
    r, dev = Rec(cfg, site), p["device"]
    src = public_of(cfg, site, dev)
    rem = _remotes(cfg, 1)[0]
    ws, we = _window(cfg, now)
    rows = [r.outb(now - h * 3600 - 600, src, rem, 40000 + h % 2000, 443, b=10_000_000) for h in range(7 * 24, 1, -1)]
    n = 30
    rows += [r.outb(we - 60 - i * ((we - ws - 120) // n), src, rem, 45000 + i, 443, b=p["volume"] // n) for i in range(n)]
    return {"flows": rows}, [{"rule": "outbound_volume", "asset": "*", "subject": src}]


def sc_exposed_port(cfg, site, now, p):
    r, dev = Rec(cfg, site), p["device"]
    ws, we = _window(cfg, now)
    rows = [r.inb(we - 120 - i * 20, x, dev, 40000 + i, p["port"], b=900, cc="US") for i, x in enumerate(_remotes(cfg, p["peers"], 40))]
    return {"flows": rows}, [{"rule": "unexpected_inbound", "asset": dev, "subject": f"tcp/{p['port']}"}]


def sc_port_scan(cfg, site, now, p):
    r, dev = Rec(cfg, site), p["device"]
    src = public_of(cfg, site, dev)
    we = int(now - cfg["detector"]["ingest_delay_seconds"])
    span = cfg["rules"]["fanout"]["window_minutes"] * 60
    rows = [r.outb(we - 30 - (i * (span - 60)) // max(1, p["destinations"]), src, x, 50000 + i % 10000, 445, b=120)
            for i, x in enumerate(_remotes(cfg, p["destinations"], 20))]
    return {"flows": rows}, [{"rule": "fanout", "asset": src, "subject": "horizontal"}]


def sc_beaconing(cfg, site, now, p):
    r, dev = Rec(cfg, site), p["device"]
    rem = _remotes(cfg, 1, 77)[0]
    we = int(now - cfg["detector"]["ingest_delay_seconds"])
    hours = cfg["rules"]["beaconing"]["hours"]
    n = min(1500, int(hours * 3600 / p["interval"]) - 1)
    rows = [r.inb(we - 30 - i * p["interval"], rem, dev, p["port"], 53000 + i % 1000, b=700, cc="NL") for i in range(n)]
    return {"flows": rows}, [{"rule": "beaconing", "asset": dev, "subject": f"{rem}:{p['port']}"}]


SCENARIOS = {
    "new_country": {"name": "Device contacts a new country", "fn": sc_new_country, "rules": ["new_dest_country"],
                    "text": "7 days of traffic from the device to one country, then a few connections to another country.",
                    "params": {"country": ("Country code", "str", "BR"), "records": ("Records in the last window", "int", 5, 1, 200)}},
    "large_upload": {"name": "Unusually large upload", "fn": sc_large_upload, "rules": ["outbound_volume"],
                     "text": "7 days of about 10 MB per hour to the internet, then a large upload in the last window.",
                     "params": {"volume": ("Upload in the last window (bytes)", "int", 3_000_000_000, 1, 10 ** 13)}},
    "exposed_port": {"name": "Internet reaches a port with no port forward", "fn": sc_exposed_port, "rules": ["unexpected_inbound"],
                     "text": "Connections from many internet addresses to one port of the device.",
                     "params": {"port": ("Port", "int", 3389, 1, 65535), "peers": ("Internet addresses", "int", 20, 1, 500)}},
    "port_scan": {"name": "Device scans many internet addresses", "fn": sc_port_scan, "rules": ["fanout"],
                  "text": "Connections from the device to many internet addresses on one port within the fan-out window.",
                  "params": {"destinations": ("Destinations", "int", 200, 1, 2000)}},
    "beaconing": {"name": "Regular check-ins to one server (beaconing)", "fn": sc_beaconing, "rules": ["beaconing"],
                  "text": "The device connects to one internet server at a fixed interval for the beaconing window.",
                  "params": {"interval": ("Interval (seconds)", "int", 300, 10, 3600), "port": ("Server port", "int", 443, 1, 65535)}},
    "normal": {"name": "Normal day (nothing expected)", "fn": sc_normal, "rules": ["new_dest_country", "outbound_volume"],
               "text": "The device keeps its usual traffic to its usual country: a good detection stays quiet.", "params": {}},
}


def scenario_params(key, form, cfg):
    sc = SCENARIOS[key]
    out = {}
    dev = str(form.get("device") or "").strip() or default_device(cfg)
    try:
        dev = str(ipaddress.ip_address(dev))
    except ValueError:
        raise ValueError("the device must be an IP address")
    if not cfg.is_internal(dev):
        raise ValueError("the device must be an internal address")
    out["device"] = dev
    for k, spec in sc["params"].items():
        label, typ, default = spec[:3]
        v = form.get(k, default)
        if typ == "int":
            try:
                v = int(float(v))
            except (TypeError, ValueError):
                raise ValueError(f"{label}: a number")
            lo, hi = spec[3], spec[4]
            if not lo <= v <= hi:
                raise ValueError(f"{label}: {lo} to {hi}")
        else:
            from .dash import META
            v = str(v).upper()[:2]
            if v not in META:
                raise ValueError(f"{label}: unknown country")
        out[k] = v
    return out


def default_device(cfg):
    """An internal device that is not a firewall (its own address is not device traffic)."""
    fw = {x.get("exporter_ip") for x in cfg.sites} | {x.get("syslog_source") for x in cfg.sites}
    for ip, a in (cfg.get("assets") or {}).items():
        try:
            if cfg.is_internal(ip) and ip not in fw and a.get("role") != "firewall":
                return ip
        except ValueError:
            continue
    net = ipaddress.ip_network(str(cfg.internal_nets[0]))
    return str(net.network_address + min(200, net.num_addresses - 2))


def why_not(cfg, site, exp, params, days, errors):
    """Likely reasons an expected finding did not appear (from the settings the rule uses)."""
    from .ux import monitored
    rule = exp["rule"]
    rc = cfg["rules"].get(rule, {})
    d = cfg["detector"]
    out = [e for e in errors if e.startswith(rule)]
    if rc and not rc.get("enabled", True):
        out.append("the rule is switched off (Settings → Alert rules)")
    if not monitored(site, REPLAYABLE.get(rule, "flows")):
        out.append("this kind of data is not monitored on this firewall (Firewalls & sites → What to monitor)")
    if rule.startswith("new_dest") and days < d["min_learning_days"]:
        out.append(f"still learning: {days:.1f} days of data, the rule waits for {d['min_learning_days']}")
    if rule == "new_dest_country" and params.get("records", 0) < rc.get("min_flows", 0):
        out.append(f"{params['records']} record(s) in the window; the rule needs at least {rc['min_flows']}")
    if rule == "outbound_volume":
        if params["volume"] < rc.get("min_bytes", 0):
            out.append(f"the upload is below the minimum the rule looks at ({rc['min_bytes']:,} bytes)")
        upper = 10_000_000 * d["window_minutes"] / 60
        if params["volume"] < rc.get("factor", 0) * upper:
            out.append(f"the upload is less than {rc['factor']} × the usual volume (about {upper / 1e6:.0f} MB per window)")
    if rule == "unexpected_inbound":
        if params["port"] >= rc.get("ephemeral_floor", 65536):
            out.append(f"port {params['port']} is at or above the ephemeral floor ({rc['ephemeral_floor']}), where replies cannot be told apart")
        if cfg.exposed(params["device"], "tcp", params["port"]):
            out.append(f"a port forward exists for tcp/{params['port']} on this device, so this exposure is intended")
    if rule == "fanout" and params["destinations"] < rc.get("min_peers", 0):
        out.append(f"{params['destinations']} destinations; the rule needs {rc['min_peers']} within {rc['window_minutes']} min")
    if rule == "beaconing":
        n = int(rc["hours"] * 3600 / params["interval"]) - 1
        if n < rc["min_events"]:
            out.append(f"{n} check-ins in {rc['hours']} h; the rule needs {rc['min_events']}")
        if not rc["min_interval_s"] <= params["interval"] <= rc["max_interval_s"]:
            out.append(f"the interval is outside {rc['min_interval_s']}–{rc['max_interval_s']} s")
        if params["port"] in rc.get("ignore_ports", []):
            out.append(f"port {params['port']} is ignored by this rule")
        at = site.get("active_timeout") or 0
        if at and abs(params["interval"] - at) <= at * 0.05:
            out.append(f"the interval matches the firewall's flow export timeout ({at} s), which looks like one long connection")
        if params["port"] >= 1024 and params["port"] not in cfg["service_ports"]:
            out.append(f"port {params['port']} is not a service port, so netmon cannot tell the device opened the connections")
    return out or ["no single setting explains it; see the technical details"]


def _matches(f, exp):
    return f["rule"] == exp["rule"] and exp["asset"] in ("*", f["asset"]) and exp.get("subject") in (None, "*", str(f["subject"]))


def run_scenario(conn, cfg, ch, site, key, params, rules_ov=None, det_ov=None, now=None):
    """One synthetic scenario against the real rules (current settings, or proposed ones). Never records anything."""
    now = int(now or time.time())
    sc = SCENARIOS[key]
    c = with_rules(cfg, rules_ov, det_ov) if (rules_ov or det_ov) else cfg
    tables, expected = sc["fn"](c, site, now, params)
    sch = SyntheticCH(ch, tables)
    det = SandboxDetector(c, sch, conn)
    det.site = site
    t = time.time()
    kept, hidden, errors, days = evaluate(det, sc["rules"], now)
    rows = []
    for exp in expected:
        got = [f for f in kept if _matches(f, exp)]
        hid = [(f, why) for f, why in hidden if _matches(f, exp)]
        if got:
            rows.append({"expected": exp, "ok": True, "finding": got[0], "why": [got[0].get("baseline") or ""]})
        elif hid:
            rows.append({"expected": exp, "ok": False, "finding": hid[0][0], "why": [f"raised by the rule but {hid[0][1]}"]})
        else:
            rows.append({"expected": exp, "ok": False, "finding": None, "why": why_not(c, site, exp, params, days, errors)})
    unexpected = [f for f in kept if not any(_matches(f, x) for x in expected)]
    return {"scenario": key, "name": sc["name"], "params": params, "expected": rows, "unexpected": unexpected,
            "hidden": [(f, w) for f, w in hidden if not any(_matches(f, x) for x in expected)], "errors": errors,
            "records": sum(len(v) for v in tables.values()), "queries": len(sch.sql), "ms": int((time.time() - t) * 1000),
            "passed": all(r["ok"] for r in rows) and not unexpected, "sql": sch.sql[:3]}


# ---- replay of retained data ---------------------------------------------------------------------------------------
_jobs = {}
_lock = threading.Lock()


def changes(cfg, rules_ov, det_ov):
    """[(rule or 'detector', setting, current, proposed)] between the effective and the proposed settings."""
    new = with_rules(cfg, rules_ov, det_ov)
    out = []
    for n in sorted(set(cfg["rules"]) | set(new["rules"])):
        a, b = cfg["rules"].get(n, {}), new["rules"].get(n, {})
        out += [(n, k, a.get(k), b.get(k)) for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    a, b = cfg["detector"], new["detector"]
    out += [("detector", k, a.get(k), b.get(k)) for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    return out


def changed_rules(cfg, rules_ov, det_ov):
    """Rules whose behaviour the proposed settings change (detector-wide settings change all flow rules)."""
    ch = changes(cfg, rules_ov, det_ov)
    names = {n for n, *_ in ch if n != "detector"}
    if any(n == "detector" for n, *_ in ch):
        names |= {n for n, src in REPLAYABLE.items() if src == "flows"}
    return sorted(names)


class Replay(threading.Thread):
    def __init__(self, cfg, ch, connect, site, rules_ov, det_ov, span, user):
        super().__init__(daemon=True, name="detection-replay")
        self.cfg, self.ch, self.connect, self.site, self.span, self.user = cfg, ch, connect, site, span, user
        self.rules_ov, self.det_ov = rules_ov or {}, det_ov or {}
        self.cancel = threading.Event()
        self.state = {"status": "queued", "done": 0, "total": 0, "started": time.time(), "user": user, "site": site["id"],
                      "span": span, "rules": changed_rules(cfg, rules_ov, det_ov), "changes": {"rules": rules_ov, "detector": det_ov}}

    def run(self):
        conn = self.connect()
        rules = [r for r in self.state["rules"] if r in REPLAYABLE]
        self.state["skipped"] = [r for r in self.state["rules"] if r not in REPLAYABLE]
        if not rules:
            self.state.update(status="done", result={}, finished=time.time())
            return
        cur_cfg, new_cfg = self.cfg, with_rules(self.cfg, self.rules_ov, self.det_ov)
        now = int(time.time())
        step = max(cur_cfg["detector"]["window_minutes"] * 60, self.span // REPLAY_MAX_WINDOWS)
        ends = list(range(now - self.span + step, now + 1, step))[-REPLAY_MAX_WINDOWS:]
        self.state.update(status="running", total=len(ends), windows=len(ends), step=step)
        res = {r: {"current": {}, "proposed": {}} for r in rules}
        errors = []
        for i, t in enumerate(ends):
            if self.cancel.is_set():
                self.state.update(status="cancelled", finished=time.time())
                break
            if time.time() - self.state["started"] > REPLAY_MAX_RUNTIME:
                self.state.update(status="stopped", note=f"time limit ({REPLAY_MAX_RUNTIME // 60} min) reached", finished=time.time())
                break
            for label, c in (("current", cur_cfg), ("proposed", new_cfg)):
                det = SandboxDetector(c, self.ch, conn)
                det.site = self.site
                try:
                    kept, _, errs, _ = evaluate(det, rules, t)
                except Exception as ex:
                    errs, kept = [f"{type(ex).__name__}: {ex}"], []
                errors += [f"{label}: {x}" for x in errs]
                for f in kept:
                    key = f"{f['rule']}|{f['asset']}|{f['subject']}"
                    res[f["_rule_group"]][label].setdefault(key, {"title": f["title"], "first": t, "windows": 0, "severity": f["severity"]})
                    res[f["_rule_group"]][label][key]["windows"] += 1
            self.state["done"] = i + 1
        out = {}
        for r, v in res.items():
            cur, new = v["current"], v["proposed"]
            out[r] = {"current": len(cur), "proposed": len(new), "added": [dict(x, key=k) for k, x in new.items() if k not in cur][:20],
                      "removed": [dict(x, key=k) for k, x in cur.items() if k not in new][:20]}
        self.state.update(result=out, errors=errors[:20])
        if self.state["status"] == "running":
            self.state.update(status="done", finished=time.time())
        from .core import audit, set_state
        set_state(conn, f"dtest:replay:{self.site['id']}", {k: v for k, v in self.state.items()})
        audit(conn, self.user, "rules_replayed", {"site": self.site["id"], "rules": rules, "windows": self.state["done"],
                                                  "status": self.state["status"]})


def start_replay(cfg, ch, connect, site, rules_ov, det_ov, span, user):
    with _lock:
        if any(j.is_alive() for j in _jobs.values()):
            raise ValueError("a replay is already running; wait for it or cancel it")
        if span not in REPLAY_SPANS.values():
            raise ValueError("unknown period")
        job = Replay(cfg, ch, connect, site, rules_ov, det_ov, span, user)
        jid = f"r{int(time.time() * 1000)}"
        _jobs.clear()
        _jobs[jid] = job
        job.start()
        return jid


def job(jid):
    return _jobs.get(jid)
