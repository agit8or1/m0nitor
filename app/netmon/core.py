"""Config, ClickHouse access (read-only, parameterized), SQLite state."""
import ipaddress
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field

import httpx
import yaml

CONFIG_PATH = os.environ.get("NETMON_CONFIG", "/app/config.yaml")
DB_PATH = os.environ.get("NETMON_DB", "/data/netmon.db")
DATA_DIR = os.path.dirname(DB_PATH)


@dataclass
class Exposure:
    ip: str
    proto: str
    lo: int
    hi: int
    public_ip: str

    def matches(self, ip: str, proto: str, port: int) -> bool:
        return self.ip == ip and self.proto == proto and self.lo <= port <= self.hi


@dataclass
class Config:
    raw: dict
    internal_nets: list = field(default_factory=list)
    public_nets: list = field(default_factory=list)
    exposures: list = field(default_factory=list)

    def __getitem__(self, k):
        return self.raw[k]

    def get(self, k, d=None):
        return self.raw.get(k, d)

    @property
    def sites(self) -> list:
        return self.raw["sites"]

    def site(self, sid: str):
        return next((x for x in self.raw["sites"] if x["id"] == sid), None)

    def site_ours(self, s: dict) -> list:
        """CIDRs that are 'ours' for an address-based (capture) site."""
        return [str(n) for n in s.get("internal_nets", []) + s.get("public_nets", [])] or \
            [str(n) for n in self.internal_nets + self.public_nets]

    def is_internal(self, ip: str) -> bool:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in self.internal_nets)

    def is_ours(self, ip: str) -> bool:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in self.internal_nets + self.public_nets)

    def asset(self, ip: str) -> dict:
        a = self.raw.get("assets", {}).get(ip)
        return a or {"name": ip, "role": "unknown", "sensitive": False}

    def asset_label(self, ip: str) -> str:
        if ip in self.raw.get("outbound_nat_ips", []):
            return f"Shared NAT {ip} (many LAN hosts; see the LAN host attribution)"
        a = self.raw.get("assets", {}).get(ip) or self.raw.get("labels", {}).get(ip)
        if not a and ip in self.binat:     # 1:1 NAT public address: name it after the one internal server behind it
            inner = self.raw.get("assets", {}).get(self.binat[ip])
            return f"{inner['name'] if inner else self.binat[ip]} via 1:1 NAT ({ip})"
        return f"{a['name']} ({ip})" if a else ip

    def label(self, ip: str) -> str:
        """Operator-given name for any address (internal servers first, then external labels)."""
        a = self.raw.get("assets", {}).get(ip) or self.raw.get("labels", {}).get(ip)
        return a["name"] if a else ""

    @property
    def binat(self) -> dict:
        """1:1 NAT (OPNsense binat) public address -> internal address, from the firewall (setting nat11:db)."""
        return {x["external"]: x["internal"] for x in self.raw.get("binat", [])}

    def binat_ext(self, internal: str) -> list:
        return [x["external"] for x in self.raw.get("binat", []) if x["internal"] == internal]

    def exposed(self, ip, proto, port) -> bool:
        return any(e.matches(ip, proto, port) for e in self.exposures)

    def attribute_public(self, ip: str, port: int, proto: str):
        """Map a post-NAT public source (ip, port) back to an internal host.

        Only deterministic for replies from port-forwarded services. Returns
        (internal_ip or None, confidence, explanation)."""
        if ip in self.raw.get("outbound_nat_ips", []):
            return None, "none", f"{ip} is the shared outbound NAT address (any LAN host)"
        if ip in self.binat:
            return self.binat[ip], "high", f"{ip} is 1:1 NAT for {self.binat[ip]} (every port, both directions)"
        hits = {e.ip for e in self.exposures
                if e.public_ip == ip and e.proto == proto and e.lo <= port <= e.hi}
        if len(hits) == 1:
            h = hits.pop()
            return h, "high", f"{ip}:{port}/{proto} is a port forward to {h}"
        return None, "low", f"no unique port-forward mapping for {ip}:{port}/{proto}"


def parse_exposure(s: str) -> Exposure:
    ip, proto, ports, pub = s.split()
    lo, _, hi = ports.partition("-")
    return Exposure(ip, proto, int(lo), int(hi or lo), pub)


# How each vendor's NetFlow exporter reports interfaces.
#   routed : OPNsense ng_netflow — real input/output ifindex per flow; WAN/LAN split by interface.
#   capture: pfSense softflowd — pcap on one interface, input = output = that ifindex (softflowd
#            compat/netflow9.c), so direction comes from addresses; capture on WAN only.
VENDORS = {"opnsense": {"label": "OPNsense", "flow_mode": "routed"},
           "pfsense": {"label": "pfSense", "flow_mode": "capture"}}
SITE_ID = r"^[a-z0-9][a-z0-9-]{0,23}$"
IFNAME = r"^[A-Za-z0-9_.-]{1,15}$"


def normalize_site(s: dict, raw: dict, first: bool) -> dict:
    """Fill per-site defaults. The first site inherits the legacy top-level settings."""
    s = dict(s)
    s.setdefault("vendor", "opnsense")
    s.setdefault("flow_mode", VENDORS.get(s["vendor"], VENDORS["opnsense"])["flow_mode"])
    s.setdefault("lan_if", "")
    s.setdefault("exporter_ip", s.get("syslog_source", ""))
    s.setdefault("syslog_source", s.get("exporter_ip", ""))
    s.setdefault("active_timeout", raw.get("exporter_active_timeout", 1800) if first else 1800)
    for k in ("internal_nets", "public_nets", "outbound_nat_ips"):
        s.setdefault(k, list(raw.get(k, [])) if first else [])
    if first and "block" not in s and raw.get("opnsense"):
        oc = raw["opnsense"]
        s["block"] = {k: oc[k] for k in ("base_url", "tls_server_name", "block_alias", "key_file") if k in oc}
    s.setdefault("block", {})
    cap = s.get("wan_capacity_mbps")
    s.setdefault("wan_down_mbps", cap)
    s.setdefault("wan_up_mbps", cap)
    s.setdefault("location", {})
    return s


def rebuild_sites(cfg, sites: list) -> None:
    """Install a normalized site list and recompute the address sets that span all sites."""
    raw = cfg.raw
    cfg.raw["sites"] = [normalize_site(x, raw, i == 0) for i, x in enumerate(sites)]
    def nets(k):
        out = {ipaddress.ip_network(n) for n in raw.get(k, [])}
        for x in cfg.raw["sites"]:
            out |= {ipaddress.ip_network(n) for n in x.get(k, [])}
        return sorted(out, key=lambda n: (n.version, n))
    cfg.internal_nets, cfg.public_nets = nets("internal_nets"), nets("public_nets")
    nat = list(raw.get("outbound_nat_ips", []))
    for x in cfg.raw["sites"]:
        nat += [n for n in x.get("outbound_nat_ips", []) if n not in nat]
    cfg.raw["outbound_nat_ips"] = nat
    # legacy single-site keys keep pointing at the first site
    if cfg.raw["sites"]:
        f = cfg.raw["sites"][0]
        cfg.raw.update(exporter=f["exporter"], wan_if=f["wan_if"], lan_if=f["lan_if"],
                       exporter_active_timeout=f["active_timeout"])


def load_config(path: str = CONFIG_PATH) -> Config:
    with open(path) as f:
        raw = yaml.safe_load(f)
    if not raw.get("sites"):
        raw["sites"] = [{"id": "site1", "name": raw.get("exporter", "firewall"), "exporter": raw.get("exporter", ""),
                         "wan_if": raw.get("wan_if", ""), "lan_if": raw.get("lan_if", "")}]
    cfg = Config(raw=raw, exposures=[parse_exposure(s) for s in raw.get("exposures", [])])
    cfg._sites_yaml = [dict(x) for x in raw["sites"]]
    cfg._assets_yaml = {str(k): dict(v) for k, v in (raw.get("assets") or {}).items()}
    raw.setdefault("assets", {})
    raw.setdefault("labels", {})
    rebuild_sites(cfg, raw["sites"])
    return cfg


def apply_sites(cfg, conn) -> None:
    """Firewalls live in the app DB (setting sites:db). config.yaml `sites:` only seeds a fresh DB; earlier UI
    edits (override:sites) and UI-added sites (sites:added) are folded in once at that migration."""
    import copy
    sites = get_setting(conn, "sites:db", None)
    if sites is None:
        ov = get_setting(conn, "override:sites", {}) or {}
        sites = copy.deepcopy(cfg._sites_yaml)
        for x in sites:
            x.update({k: v for k, v in (ov.get(x["id"]) or {}).items() if k != "wan_capacity_mbps" or "wan_down_mbps" not in ov.get(x["id"], {})})
        ids = {x["id"] for x in sites}
        sites += [x for x in (get_setting(conn, "sites:added", []) or []) if x.get("id") not in ids]
        sites = [{k: v for k, v in normalize_site(x, cfg.raw, i == 0).items() if k != "source"} for i, x in enumerate(sites)]
        put_setting(conn, "sites:db", sites, "migration")
    rebuild_sites(cfg, copy.deepcopy(sites))


def apply_assets(cfg, conn) -> None:
    """Server names/roles (assets:db) and external address labels (labels:db) live in the app DB;
    config.yaml `assets:` only seeds a fresh DB."""
    import copy
    assets = get_setting(conn, "assets:db", None)
    if assets is None:
        assets = {ip: {"name": str(a.get("name") or ip), "role": str(a.get("role") or ""), "sensitive": bool(a.get("sensitive")),
                       "notes": str(a.get("notes") or "")} for ip, a in getattr(cfg, "_assets_yaml", {}).items()}
        put_setting(conn, "assets:db", assets, "migration")
    cfg.raw["assets"] = copy.deepcopy(assets)
    cfg.raw["labels"] = copy.deepcopy(get_setting(conn, "labels:db", {}) or {})
    cfg.raw["binat"] = [x for rules in (get_setting(conn, "nat11:db", {}) or {}).values() for x in rules]


PROTO = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}

_IPSTR = "replaceOne(IPv6NumToString({c}), '::ffff:', '')"


def flow_predicates(cfg, sites) -> tuple[dict, dict]:
    """SQL macros for the WAN accounting boundary of `sites`, plus their query parameters.

    INB   Internet -> us        OUTB  us -> Internet        TOLAN  inbound and delivered to a LAN host
    FWORIG flow originated by the firewall itself (routed exporters only)
    Routed exporters are split by interface; capture exporters (one WAN interface) by address."""
    routed = [x for x in sites if x["flow_mode"] == "routed"]
    cap = [x for x in sites if x["flow_mode"] == "capture"]
    p = {"fd_wan": [(x["exporter"], x["wan_if"]) for x in routed],
         "fd_lan": [(x["exporter"], x["lan_if"]) for x in routed if x.get("lan_if")],
         "fd_rexp": [x["exporter"] for x in routed]}
    inb = ["has({fd_wan:Array(Tuple(String, String))}, (ExporterName, InIfName))"]
    outb = ["has({fd_wan:Array(Tuple(String, String))}, (ExporterName, OutIfName))"]
    tolan = ["has({fd_lan:Array(Tuple(String, String))}, (ExporterName, OutIfName))"]
    for i, x in enumerate(cap):
        p[f"fd_c{i}"], p[f"fd_ci{i}"], p[f"fd_cn{i}"] = x["exporter"], x["wan_if"], cfg.site_ours(x)
        ours = lambda c: f"arrayExists(n -> isIPAddressInRange({_IPSTR.format(c=c)}, n), {{fd_cn{i}:Array(String)}})"  # noqa: E731
        base = f"ExporterName = {{fd_c{i}:String}} AND InIfName = {{fd_ci{i}:String}}"
        inb.append(f"({base} AND {ours('DstAddr')} AND NOT {ours('SrcAddr')})")
        outb.append(f"({base} AND {ours('SrcAddr')} AND NOT {ours('DstAddr')})")
        tolan.append(inb[-1])  # the local side is visible only as the address on the WAN
    m = {"INB": "(" + " OR ".join(inb) + ")", "OUTB": "(" + " OR ".join(outb) + ")",
         "TOLAN": "(" + " OR ".join(tolan) + ")",
         "FWORIG": "(InIfName = '' AND has({fd_rexp:Array(String)}, ExporterName))"}
    return m, p


def expand_flow_sql(sql: str, macros: dict) -> str:
    for k in ("FWORIG", "TOLAN", "OUTB", "INB"):
        sql = sql.replace(k, macros[k])
    return sql


def ch_literal(v) -> str:
    """Serialize a query-parameter value in ClickHouse text format (strings single-quoted inside arrays)."""
    if isinstance(v, (list, tuple)):
        inner = ",".join(ch_literal(x) if not isinstance(x, str) else "'" + x.replace("\\", "\\\\").replace("'", "\\'") + "'"
                         for x in v)
        return f"[{inner}]" if isinstance(v, list) else f"({inner})"
    if isinstance(v, bool):
        return "1" if v else "0"
    return str(v)


class ClickHouse:
    """Read-only access. Values are always passed as typed query parameters."""

    def __init__(self, url: str):
        self.url = url
        self.client = httpx.Client(timeout=60)

    def query(self, sql: str, params: dict | None = None) -> list[dict]:
        q = {"default_format": "JSONEachRow", "readonly": "1",
             "max_execution_time": "45", "max_result_rows": "200000",
             "result_overflow_mode": "throw"}
        for k, v in (params or {}).items():
            q[f"param_{k}"] = v if isinstance(v, str) else ch_literal(v)
        r = self.client.post(self.url, params=q, content=sql.encode())
        if r.status_code != 200:
            raise RuntimeError(f"ClickHouse {r.status_code}: {r.text[:500]}")
        return [json.loads(line) for line in r.text.splitlines() if line.strip()]


SCHEMA = [
    # v1
    """
    CREATE TABLE alerts (
      id INTEGER PRIMARY KEY, key TEXT NOT NULL, rule TEXT NOT NULL,
      severity TEXT NOT NULL, confidence TEXT NOT NULL, asset TEXT, subject TEXT,
      title TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
      window_start REAL, window_end REAL, count INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'open', evidence TEXT, query TEXT, baseline TEXT,
      alternatives TEXT, next_steps TEXT, akvorado_filter TEXT,
      acked_by TEXT, acked_at REAL, notify_status TEXT, test INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX alerts_key ON alerts(key, status);
    CREATE TABLE exceptions (
      id INTEGER PRIMARY KEY, rule TEXT NOT NULL, asset TEXT NOT NULL, subject TEXT NOT NULL,
      owner TEXT NOT NULL, reason TEXT NOT NULL, created_by TEXT NOT NULL,
      created_at REAL NOT NULL, expires_at REAL, enabled INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE blocks (
      id INTEGER PRIMARY KEY, address TEXT NOT NULL, alias TEXT NOT NULL, reason TEXT NOT NULL,
      alert_id INTEGER, requested_by TEXT NOT NULL, requested_at REAL NOT NULL,
      status TEXT NOT NULL, approved_by TEXT, applied_at REAL, result TEXT,
      removed_by TEXT, removed_at REAL, impact TEXT);
    CREATE TABLE audit (
      id INTEGER PRIMARY KEY, ts REAL NOT NULL, user TEXT NOT NULL, action TEXT NOT NULL,
      detail TEXT);
    CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
      BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
    CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
      BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
    CREATE TABLE state (k TEXT PRIMARY KEY, v TEXT, ts REAL);
    """,
    # v2: UI-managed settings, notification channels, deliveries, maintenance windows
    """
    CREATE TABLE settings (k TEXT PRIMARY KEY, v TEXT NOT NULL, updated_by TEXT, ts REAL);
    CREATE TABLE channels (
      id INTEGER PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, config TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
      min_severity TEXT NOT NULL DEFAULT 'medium', categories TEXT NOT NULL DEFAULT '["security","health"]',
      quiet_start INTEGER, quiet_end INTEGER, quiet_allow_high INTEGER NOT NULL DEFAULT 1, summary_daily INTEGER NOT NULL DEFAULT 0,
      max_per_hour INTEGER NOT NULL DEFAULT 20, created_by TEXT, created_at REAL);
    CREATE TABLE deliveries (
      id INTEGER PRIMARY KEY, ts REAL NOT NULL, channel_id INTEGER, channel TEXT, alert_id INTEGER, kind TEXT NOT NULL,
      status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, detail TEXT);
    CREATE INDEX deliveries_ts ON deliveries(ts);
    CREATE TABLE maintenance (
      id INTEGER PRIMARY KEY, start_ts REAL NOT NULL, end_ts REAL NOT NULL, asset TEXT NOT NULL DEFAULT '*',
      rule TEXT NOT NULL DEFAULT '*', reason TEXT NOT NULL, created_by TEXT, created_at REAL, enabled INTEGER NOT NULL DEFAULT 1);
    ALTER TABLE alerts ADD COLUMN maintenance INTEGER NOT NULL DEFAULT 0;
    """,
    # v-next: who opened the connection, and the evidence for it
    """
    ALTER TABLE alerts ADD COLUMN direction TEXT;
    ALTER TABLE alerts ADD COLUMN direction_verified INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE alerts ADD COLUMN direction_basis TEXT;
    """,
    # multiple firewalls: alerts and block requests belong to a site
    """
    ALTER TABLE alerts ADD COLUMN site TEXT;
    ALTER TABLE blocks ADD COLUMN site TEXT;
    """,
    # auto-response: automatic blocks expire; every decision (block, dry run, skip) is logged with its evidence
    """
    ALTER TABLE blocks ADD COLUMN auto INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE blocks ADD COLUMN trigger TEXT;
    ALTER TABLE blocks ADD COLUMN expires_at REAL;
    CREATE TABLE response_log (
      id INTEGER PRIMARY KEY, ts REAL NOT NULL, site TEXT NOT NULL, address TEXT NOT NULL, trigger TEXT NOT NULL,
      decision TEXT NOT NULL, reason TEXT NOT NULL, evidence TEXT, block_id INTEGER, alert_id INTEGER);
    CREATE INDEX response_log_ts ON response_log(ts);
    CREATE INDEX response_log_addr ON response_log(address, trigger);
    """,
]


def SITE_FIRST() -> str:
    try:
        with open(CONFIG_PATH) as f:
            return (yaml.safe_load(f).get("sites") or [{"id": "site1"}])[0]["id"]
    except OSError:
        return "site1"


def db_connect(path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    ver = conn.execute("PRAGMA user_version").fetchone()[0]
    for i, ddl in enumerate(SCHEMA[ver:], start=ver + 1):
        conn.executescript(ddl)
        conn.execute(f"PRAGMA user_version={i}")
        if "ADD COLUMN site" in ddl:  # existing rows came from the only (first) site
            first = SITE_FIRST()
            conn.execute("UPDATE alerts SET site=?, key=?||'|'||key WHERE site IS NULL", (first, first))
            conn.execute("UPDATE blocks SET site=? WHERE site IS NULL", (first,))
    conn.commit()
    return conn


class ThreadLocalDB:
    """One SQLite connection per thread (sqlite3 connections must not be used concurrently)."""

    def __init__(self, path: str = DB_PATH):
        self._path, self._local = path, threading.local()
        db_connect(path).close()  # run migrations once

    def _c(self):
        c = getattr(self._local, "c", None)
        if c is None:
            c = self._local.c = db_connect(self._path)
        return c

    def __getattr__(self, name):
        return getattr(self._c(), name)


def audit(conn, user: str, action: str, detail) -> None:
    conn.execute("INSERT INTO audit(ts,user,action,detail) VALUES (?,?,?,?)",
                 (time.time(), user, action, json.dumps(detail, default=str)))
    conn.commit()


def set_state(conn, k: str, v) -> None:
    conn.execute("INSERT INTO state(k,v,ts) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, ts=excluded.ts",
                 (k, json.dumps(v, default=str), time.time()))
    conn.commit()


def get_setting(conn, k: str, default=None):
    r = conn.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return json.loads(r["v"]) if r else default


EXPECTED_KEY = "expected:db"


def expected_devices(conn, now=None):
    """Devices whose traffic is known and legitimate (e.g. crawlers): {target: {reason, owner, by, ts, expires_at}}.
    Expired entries are left out. Targets are IPs or CIDRs, internal or external."""
    now = now or time.time()
    return {k: v for k, v in (get_setting(conn, EXPECTED_KEY, {}) or {}).items() if not v.get("expires_at") or v["expires_at"] > now}


def expected_match(entries, ip):
    """The expected-device target covering ip, or None."""
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    for t in entries:
        try:
            if a in ipaddress.ip_network(t, strict=False):
                return t
        except ValueError:
            continue
    return None


def put_setting(conn, k: str, v, user: str):
    conn.execute("INSERT INTO settings(k,v,updated_by,ts) VALUES(?,?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, "
                 "updated_by=excluded.updated_by, ts=excluded.ts", (k, json.dumps(v), user, time.time()))
    conn.commit()


def apply_overrides(cfg, conn):
    """Merge UI overrides into cfg.raw in place (keeps the config.yaml baseline in cfg._base)."""
    import copy
    if hasattr(cfg, "_sites_yaml"):
        apply_sites(cfg, conn)
        apply_assets(cfg, conn)
    if not hasattr(cfg, "_base"):
        cfg._base = copy.deepcopy({k: cfg.raw[k] for k in ("detector", "rules")})
    for sect in ("detector", "rules"):
        merged = copy.deepcopy(cfg._base[sect])
        for k, v in (get_setting(conn, f"override:{sect}", {}) or {}).items():
            if isinstance(v, dict) and isinstance(merged.get(k), dict):
                merged[k].update(v)
            else:
                merged[k] = v
        cfg.raw[sect] = merged


def effective(cfg, conn):
    """config.yaml merged with UI overrides for detector/rules (overrides win)."""
    import copy
    raw = copy.deepcopy(cfg.raw)
    for sect in ("detector", "rules"):
        ov = get_setting(conn, f"override:{sect}", {}) or {}
        for k, v in ov.items():
            if isinstance(v, dict) and isinstance(raw[sect].get(k), dict):
                raw[sect][k].update(v)
            else:
                raw[sect][k] = v
    return raw


def get_state(conn, k: str, default=None):
    r = conn.execute("SELECT v, ts FROM state WHERE k=?", (k,)).fetchone()
    return (json.loads(r["v"]), r["ts"]) if r else (default, None)
