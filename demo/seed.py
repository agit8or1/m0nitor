"""Synthetic data for the m0nitor demo. Nothing here comes from a real network.

Addresses: LAN 10.40.0.0/24, own public 203.0.113.176/28, "the Internet" = the rest of the RFC 5737 documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) split into /28s, each given a country and a documentation ASN
(RFC 5398) through a CSV the app reads instead of a GeoIP database. Names use example.com/.net/.org.

    python seed.py init      schema, lookup tables, GeoIP CSV, admin password, DEMO_DAYS of history
    python seed.py feed      append the last minute every 60 s (keeps the demo "live")

Records follow the OPNsense routed-export semantics the app expects: WAN->LAN records carry the real internal host,
LAN->WAN records carry the post-NAT source (shared NAT 203.0.113.179, 1:1 NAT for crm-1 and backup-1).
Scenarios (so the real detector has something to find): a workstation scanning (fan-out behind the shared NAT),
a workstation beaconing, a nightly backup plus one large upload, a blocked port scan, IDS alerts, SSH password
guessing on web-1, an NXDOMAIN/random-label burst and firewall configuration changes.
Additional devices (Settings -> Devices): a FortiGate and a PAN-OS firewall whose synthetic log lines go through the
app's real parsers, and a generic switch sending sFlow-style samples and an interface flap.
"""
import ipaddress
import json
import os
import random
import secrets
import sys
import time

import httpx

CH = os.environ.get("DEMO_CLICKHOUSE", "http://clickhouse:8123")
DATA = os.environ.get("DEMO_DATA", "/demo-data")
SECRETS = os.environ.get("DEMO_SECRETS", "/run/demo")
DAYS = float(os.environ.get("DEMO_DAYS", "4"))
SITE, EXPORTER, FW = "demo-a", "fw-demo", "10.40.0.1"
WAN, LAN = "ix0", "bridge0"
NAT, CRM_PUB, BACKUP_PUB = "203.0.113.179", "203.0.113.181", "203.0.113.183"
PROXY, MAIL, WEB, CRM, BACKUP = "10.40.0.250", "10.40.0.240", "10.40.0.20", "10.40.0.74", "10.40.0.8"
PUB = {PROXY: "203.0.113.180", MAIL: "203.0.113.182", WEB: "203.0.113.184"}
WORKSTATIONS = [f"10.40.0.{i}" for i in range(120, 136)]
SCANNER_HOST, BEACON_HOST = "10.40.0.131", "10.40.0.127"
GEO_RULE = "00000000-0000-4000-8000-0000000000a1"

# 47 /28 blocks of documentation space -> (country, ASN, AS name). Order is fixed so runs are reproducible.
COUNTRIES = ["US", "US", "US", "NL", "DE", "DE", "IE", "GB", "FR", "SE", "JP", "SG", "AU", "CA", "BR", "IN",
             "CN", "CN", "RU", "RU", "KR", "VN", "UA", "IR", "ZA", "NG", "MX", "AR", "TR", "PL", "IT", "ES",
             "CH", "HK", "ID", "TW", "FI", "NO", "DK", "AT", "BE", "CZ", "RO", "TH", "MY", "PH", "KP"]
ASNS = list(range(64496, 64512)) + list(range(65536, 65552))
AS_NAMES = ["Example Cloud", "Example CDN", "Demo Transit", "Sample Hosting", "Example Mail Services", "Example ISP",
            "Demo Broadband", "Sample Datacenter", "Example Telecom", "Demo Mobile", "Example Research Net",
            "Sample VPS", "Example Edge", "Demo Backbone", "Example Fiber", "Sample Cable"]


def blocks():
    out = []
    own = ipaddress.ip_network("203.0.113.176/28")
    for base in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
        for n in ipaddress.ip_network(base).subnets(new_prefix=28):
            if n != own:
                out.append(n)
    rows = []
    for i, n in enumerate(out):
        asn = ASNS[i % len(ASNS)]
        rows.append({"net": n, "cc": COUNTRIES[i % len(COUNTRIES)], "asn": asn,
                     "asname": f"{AS_NAMES[i % len(AS_NAMES)]} {chr(65 + i % 26)} (AS{asn}, documentation)"})
    return rows


BLOCKS = blocks()


def hosts(*ccs):
    return [(str(h), b) for b in BLOCKS if b["cc"] in ccs for h in list(b["net"].hosts())[1:12]]


SERVICES = hosts("US", "NL", "DE", "IE", "GB", "FR", "SE")          # what the office talks to
CLIENTS = hosts("US", "CA", "GB", "DE", "FR", "NL", "AU", "JP", "BR", "IN", "ES", "IT", "PL", "SE", "CH")
SCANNERS = hosts("CN", "RU", "BR", "VN", "IN", "KR", "UA", "TR", "ID", "KP", "IR")
MAILERS = hosts("US", "DE", "IE", "NL", "FI")
SCAN_TARGETS = [(str(h), b) for b in BLOCKS for h in list(b["net"].hosts())[:14]]
CLOUD_BACKUP = next(x for x in SERVICES if x[1]["cc"] == "NL")
BEACON_PEER = next(x for x in hosts("SG"))
NEW_COUNTRY_PEER = next(x for x in hosts("TH"))        # contacted by mail-1 only in the last hours
BRUTE = next(x for x in hosts("VN"))
PORT_SCANNER = next(x for x in hosts("RU"))


def v6(ip):
    return "::ffff:" + ip if ":" not in ip else ip


def ch(sql, data=None):
    r = httpx.post(CH, params={"query": sql, "date_time_input_format": "best_effort"}, content=data, timeout=120)
    if r.status_code != 200:
        raise RuntimeError(f"{sql[:80]}: {r.text[:300]}")
    return r.text


def insert(table, rows):
    for i in range(0, len(rows), 50000):
        ch(f"INSERT INTO {table} FORMAT JSONEachRow", "\n".join(json.dumps(x) for x in rows[i:i + 50000]).encode())


# ---------------------------------------------------------------- schema
FLOWS = """CREATE TABLE IF NOT EXISTS default.flows (
  TimeReceived DateTime, SamplingRate UInt64, ExporterAddress IPv6, ExporterName LowCardinality(String),
  SrcAddr IPv6, DstAddr IPv6, SrcAS UInt32, DstAS UInt32, SrcCountry FixedString(2), DstCountry FixedString(2),
  InIfName LowCardinality(String), OutIfName LowCardinality(String), InIfDescription LowCardinality(String),
  OutIfDescription LowCardinality(String), InIfSpeed UInt32, OutIfSpeed UInt32,
  InIfBoundary Enum8('undefined' = 0, 'external' = 1, 'internal' = 2), OutIfBoundary Enum8('undefined' = 0, 'external' = 1, 'internal' = 2),
  EType UInt32, FlowDirection Enum8('undefined' = 0, 'ingress' = 1, 'egress' = 2), Proto UInt32, SrcPort UInt16, DstPort UInt16, Bytes UInt64, Packets UInt64, ForwardingStatus UInt32, TCPFlags UInt16)
ENGINE = MergeTree PARTITION BY toDate(TimeReceived) ORDER BY (toStartOfFiveMinutes(TimeReceived), ExporterName, InIfName, OutIfName)
TTL TimeReceived + INTERVAL 30 DAY"""
# Akvorado keeps pre-aggregated tables; in the demo they are views with the same names and time buckets.
VIEWS = {"flows_1m0s": "toStartOfMinute", "flows_5m0s": "toStartOfFiveMinutes", "flows_1h0m0s": "toStartOfHour"}
PORTS = {"tcp": {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 110: "pop3", 143: "imap", 443: "https",
                 445: "microsoft-ds", 465: "submissions", 587: "submission", 853: "domain-s", 993: "imaps", 995: "pop3s",
                 1433: "ms-sql-s", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 8080: "http-alt", 8443: "https-alt"},
         "udp": {53: "domain", 123: "ntp", 443: "https", 500: "isakmp", 1194: "openvpn", 51820: "wireguard"}}


def schema():
    sys.path.insert(0, "/app")
    from netmon import schema as nschema
    ch(FLOWS)
    for name, fn in VIEWS.items():
        ch(f"CREATE VIEW IF NOT EXISTS default.{name} AS SELECT * REPLACE ({fn}(TimeReceived) AS TimeReceived) FROM default.flows")
    ch("CREATE TABLE IF NOT EXISTS default.demo_asns (asn UInt32, name String) ENGINE = MergeTree ORDER BY asn")
    ch("TRUNCATE TABLE default.demo_asns")
    insert("default.demo_asns", [{"asn": b["asn"], "name": b["asname"].split(" (")[0]} for b in {b["asn"]: b for b in BLOCKS}.values()])
    ch("CREATE DICTIONARY IF NOT EXISTS default.asns (asn UInt32, name String) PRIMARY KEY asn "
       "SOURCE(CLICKHOUSE(TABLE 'demo_asns' DB 'default')) LIFETIME(MIN 0 MAX 300) LAYOUT(HASHED())")
    for proto, names in PORTS.items():
        ch(f"CREATE TABLE IF NOT EXISTS default.demo_{proto} (port UInt16, name String) ENGINE = MergeTree ORDER BY port")
        ch(f"TRUNCATE TABLE default.demo_{proto}")
        insert(f"default.demo_{proto}", [{"port": p, "name": n} for p, n in names.items()])
        ch(f"CREATE DICTIONARY IF NOT EXISTS default.{proto} (port UInt16, name String) PRIMARY KEY port "
           f"SOURCE(CLICKHOUSE(TABLE 'demo_{proto}' DB 'default')) LIFETIME(MIN 0 MAX 300) LAYOUT(HASHED())")
    for stmt in nschema.statements(7):
        ch(stmt)


# ---------------------------------------------------------------- flow records
def flow(t, src, dst, sport, dport, proto, nbytes, inif, outif, flags=27, packets=None):
    sb, db = geo(src), geo(dst)
    return {"TimeReceived": int(t), "SamplingRate": 1, "ExporterAddress": v6(FW), "ExporterName": EXPORTER,
            "SrcAddr": v6(src), "DstAddr": v6(dst), "SrcAS": sb["asn"] if sb else 0, "DstAS": db["asn"] if db else 0,
            "SrcCountry": sb["cc"] if sb else "", "DstCountry": db["cc"] if db else "",
            "InIfName": inif, "OutIfName": outif, "InIfDescription": "WAN" if inif == WAN else "LAN bridge" if inif else "",
            "OutIfDescription": "WAN" if outif == WAN else "LAN bridge", "InIfSpeed": 10000, "OutIfSpeed": 10000,
            "InIfBoundary": "external" if inif == WAN else "internal" if inif else "undefined",
            "OutIfBoundary": "external" if outif == WAN else "internal", "EType": 2048, "Proto": proto,
            "SrcPort": sport, "DstPort": dport, "Bytes": int(nbytes), "Packets": packets or max(1, int(nbytes) // 900),
            "ForwardingStatus": 64, "TCPFlags": flags if proto == 6 else 0}


_GEO = {}


def geo(ip):
    if ip not in _GEO:
        a = ipaddress.ip_address(ip)
        _GEO[ip] = next((b for b in BLOCKS if a in b["net"]), None)
    return _GEO[ip]


def eph(rng):
    return rng.randint(40000, 60999)


def office_factor(t):
    h = time.gmtime(t).tm_hour
    return 1.0 if 13 <= h <= 21 else 0.45 if 11 <= h <= 23 else 0.12     # a US business day in UTC


def client_conn(rng, t, host, pub, remote, port, up, down, proto=6):
    """One outbound connection: post-NAT egress record + the reply delivered to the real host (return path)."""
    sp = eph(rng)
    return [flow(t, pub, remote, sp, port, proto, up, LAN, WAN), flow(t + rng.randint(0, 2), remote, host, port, sp, proto, down, WAN, LAN)]


def server_conn(rng, t, server, port, remote, up, down):
    """One inbound connection to a published service: request delivered to the server + reply from its public address."""
    sp = eph(rng)
    return [flow(t, remote, server, sp, port, 6, up, WAN, LAN), flow(t + 1, PUB.get(server, NAT), remote, port, sp, 6, down, LAN, WAN)]


def minute(t, rng, live_from):
    """All flow records for the minute starting at t. live_from: start of the scenario window (last hours)."""
    rows, f = [], office_factor(t)
    for host in WORKSTATIONS:
        for _ in range(rng.choices([0, 1, 2, 3], [1 - f, f * 0.4, f * 0.4, f * 0.2])[0]):
            remote = rng.choice(SERVICES)[0]
            port = rng.choices([443, 80, 443], [0.8, 0.1, 0.1])[0]
            proto = 17 if port == 443 and rng.random() < 0.15 else 6
            rows += client_conn(rng, t + rng.randint(0, 50), host, NAT, remote, port, rng.randint(2_000, 120_000),
                                rng.randint(20_000, 4_000_000), proto)
    for _ in range(rng.randint(2, 6)):                                        # visitors of the reverse proxy
        rows += server_conn(rng, t + rng.randint(0, 55), PROXY, rng.choice([443, 443, 80]), rng.choice(CLIENTS)[0],
                            rng.randint(800, 20_000), rng.randint(5_000, 900_000))
    if rng.random() < 0.6:                                                    # inbound mail
        rows += server_conn(rng, t + rng.randint(0, 55), MAIL, 25, rng.choice(MAILERS)[0], rng.randint(3_000, 80_000), rng.randint(400, 2_000))
    if rng.random() < 0.3:                                                    # outbound mail
        rows += client_conn(rng, t + rng.randint(0, 55), MAIL, PUB[MAIL], rng.choice(MAILERS)[0], 25, rng.randint(3_000, 60_000), 1_200)
    if rng.random() < 0.5:                                                    # crm-1 (1:1 NAT) calling APIs
        rows += client_conn(rng, t + rng.randint(0, 55), CRM, CRM_PUB, rng.choice(SERVICES)[0], 443, rng.randint(1_000, 30_000), rng.randint(2_000, 200_000))
    for _ in range(rng.randint(1, 3)):                                        # the firewall's own resolver
        r = rng.choice(SERVICES[:6])[0]
        rows.append(flow(t + rng.randint(0, 55), NAT, r, eph(rng), 53, 17, rng.randint(70, 200), "", WAN))
    h = time.gmtime(t).tm_hour
    if h == 2 and int(t) % 120 < 60:                                          # nightly backup, ~400 MB, one long flow
        rows += [flow(t + 5, BACKUP_PUB, CLOUD_BACKUP[0], 47_000, 443, 6, 13_200_000, LAN, WAN),
                 flow(t + 5, CLOUD_BACKUP[0], BACKUP, 443, 47_000, 6, 180_000, WAN, LAN)]
    if t >= live_from:
        rows += scenarios(t, rng, live_from)
    return rows


def scenarios(t, rng, live_from):
    rows = []
    if int(t) % 300 < 60:                                                     # beacon: every 5 min, tiny and regular
        rows += client_conn(rng, t + 7, BEACON_HOST, NAT, BEACON_PEER[0], 443, 1_150 + rng.randint(-20, 20), 3_400)
    if t >= time.time() - 3600:                                               # workstation scanning (last hour)
        for _ in range(45):
            dst = rng.choice(SCAN_TARGETS)[0]
            port = rng.choice([445, 3389, 22, 23, 5900, 1433])
            sp = eph(rng)
            rows.append(flow(t + rng.randint(0, 58), NAT, dst, sp, port, 6, 60, LAN, WAN, flags=2, packets=1))
            if rng.random() < 0.25:                                           # some targets answer (RST/ACK)
                rows.append(flow(t + rng.randint(0, 59), dst, SCANNER_HOST, port, sp, 6, 54, WAN, LAN, flags=20, packets=1))
    if t >= time.time() - 5400 and rng.random() < 0.15:                       # mail-1 starts talking to a new country
        rows += client_conn(rng, t + 3, MAIL, PUB[MAIL], NEW_COUNTRY_PEER[0], 443, 25_000, 6_000)
    if time.time() - 2400 <= t < time.time() - 1200 and int(t) % 120 < 60:   # one long ~3 GB upload from backup-1, exported
        sp = 47_001                                                           # every active timeout (120 s) like a real flow
        rows += [flow(t + 9, BACKUP_PUB, CLOUD_BACKUP[0], sp, 443, 6, 300_000_000, LAN, WAN),
                 flow(t + 9, CLOUD_BACKUP[0], BACKUP, 443, sp, 6, 800_000, WAN, LAN)]
    return rows


# ---------------------------------------------------------------- logs
def ts64(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}"


def fw_minute(t, rng):
    rows = []
    for _ in range(rng.randint(8, 20)):                                       # background noise on the WAN, default deny
        src = rng.choice(SCANNERS + CLIENTS[:40])
        rid = GEO_RULE if src[1]["cc"] in ("KP", "IR", "RU") else "default"
        rows.append(fw(t + rng.uniform(0, 59), src[0], rng.choice(["203.0.113.179", "203.0.113.185", "203.0.113.190"]),
                       rng.choice([22, 23, 80, 443, 445, 1433, 3389, 5900, 8080]), rid))
    if time.time() - 1500 <= t < time.time() - 600:                           # a vertical port scan from one address
        for _ in range(40):
            rows.append(fw(t + rng.uniform(0, 59), PORT_SCANNER[0], NAT, rng.randint(1, 1024), GEO_RULE))
    return rows


def fw(t, src, dst, dport, rid):
    return {"ts": ts64(t), "received": int(t) + 1, "site": SITE, "rulenr": 5 if rid == GEO_RULE else 2, "rid": rid, "iface": WAN,
            "reason": "match", "action": "block", "dir": "in", "ipver": 4, "proto": "tcp", "src": v6(src), "dst": v6(dst),
            "sport": random.randint(30000, 65000), "dport": dport, "length": 60, "tcpflags": "S"}


SIGS = [(2001219, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2),
        (2010935, "ET SCAN Suspicious inbound to MSSQL port 1433", "Potentially Bad Traffic", 2),
        (2024364, "ET SCAN Possible Nmap User-Agent Observed", "Web Application Attack", 1),
        (2100498, "GPL ATTACK_RESPONSE id check returned root", "Potentially Bad Traffic", 2)]


def ids_minute(t, rng):
    rows = []
    if rng.random() < 0.08:
        sid, sig, cat, sev = rng.choice(SIGS[:2])
        rows.append(ids(t + rng.uniform(0, 59), sid, sig, cat, sev, rng.choice(SCANNERS)[0], PROXY, 443))
    if time.time() - 1800 <= t and rng.random() < 0.3:                        # web scanner against the proxy (priority 1)
        sid, sig, cat, sev = SIGS[2]
        rows.append(ids(t + rng.uniform(0, 59), sid, sig, cat, sev, PORT_SCANNER[0], PROXY, 443))
    return rows


def ids(t, sid, sig, cat, sev, src, dst, dport):
    return {"ts": ts64(t), "received": int(t) + 1, "site": SITE, "sensor": "suricata", "sig_id": sid, "gid": 1, "rev": 3,
            "signature": sig, "category": cat, "severity": sev, "action": "allowed", "proto": "TCP", "src": v6(src), "dst": v6(dst),
            "sport": random.randint(30000, 65000), "dport": dport, "iface": WAN, "event_type": "alert",
            "flow_id": random.randint(1, 2**52), "raw": json.dumps({"demo": True, "signature": sig})}


NAMES = ["www.example.com", "cdn.example.net", "api.example.org", "mail.example.com", "updates.example.net",
         "login.example.org", "static.example.com", "chat.example.net", "files.example.org", "time.example.com"]


def dns_minute(t, rng):
    rows = []
    for host in rng.sample(WORKSTATIONS, rng.randint(1, 6)):
        q = rng.choice(NAMES)
        rows.append(dns(t + rng.uniform(0, 59), host, q, "NOERROR"))
    if t >= time.time() - 2700:                                               # random-label NXDOMAIN burst from one host
        for _ in range(rng.randint(4, 9)):
            label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(30))
            rows.append(dns(t + rng.uniform(0, 59), SCANNER_HOST, f"{label}.example.org", "NXDOMAIN"))
    return rows


def dns(t, client, q, rcode):
    return {"ts": ts64(t), "received": int(t) + 1, "site": SITE, "sensor": "", "source": "unbound", "client": v6(client), "query": q,
            "qtype": "A", "rcode": rcode, "answers": [], "ttls": [], "resolver": v6(FW), "uid": ""}


def auth_minute(t, rng):
    rows = []
    if t >= time.time() - 3000 and rng.random() < 0.7:                        # password guessing against web-1
        for _ in range(rng.randint(3, 10)):
            user = rng.choice(["root", "admin", "test", "ubuntu", "oracle", "git"])
            rows.append({"ts": ts64(t + rng.uniform(0, 59)), "received": int(t) + 1, "site": SITE, "host": "web-1", "sender": v6(WEB),
                         "app": "sshd", "event": "login_failed", "user": user, "src": v6(BRUTE[0]), "method": "password",
                         "message": f"Failed password for invalid user {user} from {BRUTE[0]} port {eph(rng)} ssh2"})
            rows.append(fw(t + rng.uniform(0, 59), BRUTE[0], PUB[WEB], 22, "default") | {"action": "pass"})
    return rows


def sys_events(t0, rng):
    rows = []
    for i, (what, path) in enumerate([("firewall rule changed", "/api/firewall/filter/set_rule"),
                                      ("alias updated", "/api/firewall/alias/set_item"),
                                      ("NetFlow settings saved", "/api/diagnostics/netflow/set")]):
        t = t0 + (i + 1) * 20000
        rows.append({"ts": ts64(t), "received": int(t), "site": SITE, "app": "audit", "severity": 5, "kind": "config",
                     "message": f"user demo-admin changed configuration ({what}) in {path}"})
    return rows


# ---------------------------------------------------------------- additional devices (multi-vendor)
# Synthetic log lines in each vendor's documented format, run through the app's real parsers (netmon.logingest):
# what the demo shows for these devices is exactly what the parsers make of such lines.
DEVICES = [
    {"id": "fgt-branch", "site": SITE, "name": "Branch FortiGate", "vendor": "fortigate", "model": "FortiGate 60F",
     "firmware": "7.4", "exporter_ip": None, "syslog_source": "10.40.0.2", "syslog_transport": "tcp", "flows": [],
     "wan_if": "wan1", "wan_zones": [], "snmp": {}, "device_tz_utc": True},
    {"id": "pa-dmz", "site": SITE, "name": "DMZ PA-440", "vendor": "panos", "model": "PA-440", "firmware": "11.1",
     "exporter_ip": None, "syslog_source": "10.40.0.3", "syslog_transport": "tcp", "flows": [], "wan_if": "ethernet1/1",
     "wan_zones": ["untrust"], "snmp": {}},
    {"id": "core-sw", "site": SITE, "name": "Core switch", "vendor": "aruba", "model": "CX 6100", "firmware": "",
     "exporter_ip": "10.40.0.4", "syslog_source": "10.40.0.4", "syslog_transport": "udp", "flows": ["sflow"], "wan_if": "",
     "wan_zones": [], "snmp": {}},
]
BY_SENDER = {d["syslog_source"]: d for d in DEVICES}


def vendor_lines(t, rng):
    """(receipt epoch, sender, raw syslog) for one minute."""
    out = []
    iso = lambda x: time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(x))  # noqa: E731
    for _ in range(rng.randint(2, 6)):                                     # FortiGate: denied inbound background noise
        x = t + rng.uniform(0, 59)
        src = rng.choice(SCANNERS)[0]
        d, tm = iso(x).split(" ")
        out.append((int(x) + 1, "10.40.0.2", f'<189>date={d} time={tm} devname="FGT60F-DEMO" logid="0000000013" tz="+0000" '
                    f'type="traffic" subtype="forward" level="notice" srcip={src} srcport={eph(rng)} srcintf="wan1" srcintfrole="wan" '
                    f'dstip=203.0.113.186 dstport={rng.choice([22, 23, 445, 3389, 8443])} dstintf="internal" dstintfrole="lan" '
                    f'proto=6 action="deny" policyid=0 sentbyte=0 rcvdbyte=0'))
    if rng.random() < 0.05:                                                 # occasional IPS alert
        x = t + rng.uniform(0, 59)
        d, tm = iso(x).split(" ")
        out.append((int(x) + 1, "10.40.0.2", f'<185>date={d} time={tm} tz="+0000" logid="0419016384" type="utm" subtype="ips" '
                    f'level="alert" severity="high" srcip={rng.choice(SCANNERS)[0]} dstip=203.0.113.186 srcport={eph(rng)} '
                    f'dstport=443 proto=6 action="dropped" attack="Demo.Web.Exploit.Attempt" attackid=10001 srcintf="wan1" srcintfrole="wan"'))
    if time.time() - 2400 <= t < time.time() - 1800:                        # admin password guessing on the branch firewall
        for _ in range(3):
            x = t + rng.uniform(0, 59)
            d, tm = iso(x).split(" ")
            out.append((int(x) + 1, "10.40.0.2", f'<190>date={d} time={tm} tz="+0000" logid="0100032002" type="event" subtype="system" '
                        f'level="alert" logdesc="Admin login failed" user="admin" ui="https({BRUTE[0]})" action="login" status="failed"'))
    if int(t) % 21600 == 0:                                                 # every 6 h a branch VPN flap
        d, tm = iso(t).split(" ")
        out.append((int(t) + 1, "10.40.0.2", f'<189>date={d} time={tm} tz="+0000" logid="0101037138" type="event" subtype="vpn" '
                    f'level="notice" action="tunnel-down" remip=198.51.100.200 vpntunnel="hq-branch" logdesc="IPsec tunnel down"'))
        d, tm = iso(t + 240).split(" ")
        out.append((int(t) + 241, "10.40.0.2", f'<189>date={d} time={tm} tz="+0000" logid="0101037139" type="event" subtype="vpn" '
                    f'level="notice" action="tunnel-up" remip=198.51.100.200 vpntunnel="hq-branch" logdesc="IPsec tunnel up"'))
    for _ in range(rng.randint(1, 4)):                                     # PAN-OS: denied and allowed sessions (end lines)
        x = t + rng.uniform(0, 59)
        allow = rng.random() < 0.4
        src = rng.choice(CLIENTS if allow else SCANNERS)[0]
        f = ["1", time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(x)), "007200000000", "TRAFFIC", "end", "2561",
             time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(x)), src, "10.40.0.20", "", "", "allow-web" if allow else "interzone-default",
             "", "", "web-browsing" if allow else "incomplete", "vsys1", "untrust", "dmz", "ethernet1/1", "ethernet1/2", "fwd", "",
             str(rng.randint(1, 99999)), "1", str(eph(rng)), "443" if allow else str(rng.choice([22, 3389, 5900])), "0", "0", "0x0",
             "tcp", "allow" if allow else "deny", str(rng.randint(2000, 90000) if allow else 0), "0", "0", "4"]
        out.append((int(x) + 1, "10.40.0.3", "<14>" + time.strftime("%b %d %H:%M:%S", time.gmtime(x)) + " PA-440-DEMO " + ",".join(f)))
    if int(t) % 43200 == 3600:                                              # twice a day a configuration commit
        f = ["1", time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(t)), "007200000000", "CONFIG", "0", "2561",
             time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(t)), "10.40.0.210", "vsys1", "edit", "demo-admin", "Web", "Succeeded",
             "vsys vsys1 rulebase security rules allow-web"]
        out.append((int(t) + 1, "10.40.0.3", "<14>" + time.strftime("%b %d %H:%M:%S", time.gmtime(t)) + " PA-440-DEMO " + ",".join(f)))
    if int(t) % 14400 == 600:                                               # switch: an access port flaps
        for i, st in ((0, "down"), (90, "up")):
            out.append((int(t) + i, "10.40.0.4", "<187>" + time.strftime("%b %d %H:%M:%S", time.gmtime(t + i)) +
                        f" core-sw lldpd: Port 1/1/12 changed state to {st}"))
    return out


def vendor_rows(t0, t1, rng):
    sys.path.insert(0, "/app")
    from netmon.logingest import parse_line
    tables = {}
    t = t0 - t0 % 60
    while t < t1:
        for recv, sender, raw in vendor_lines(t, rng):
            kind, row = parse_line(f"{recv} {sender} {raw}", lambda ip: SITE, BY_SENDER.get)
            for tb, r in (row if kind == "multi" else [(kind, row)] if kind not in (None, "skip") else []):
                r = dict(r)
                r["ts"] = ts64(r["ts"])
                tables.setdefault(tb, []).append(r)
        t += 60
    for tb, rows in tables.items():
        insert(f"netmon.{tb}", rows)


def switch_flows(t0, t1, rng):
    """sFlow-style samples from the core switch: LAN to LAN (never part of the site's WAN totals)."""
    rows, t = [], t0 - t0 % 60
    while t < t1:
        for _ in range(rng.randint(3, 8)):
            a, b = rng.choice(WORKSTATIONS), rng.choice([BACKUP, CRM, WEB, MAIL])
            rows.append({"TimeReceived": int(t + rng.uniform(0, 59)), "SamplingRate": 512, "ExporterAddress": v6("10.40.0.4"),
                         "ExporterName": "core-sw", "SrcAddr": v6(a), "DstAddr": v6(b), "SrcAS": 0, "DstAS": 0, "SrcCountry": "",
                         "DstCountry": "", "InIfName": "1/1/12", "OutIfName": "1/1/49", "InIfDescription": "", "OutIfDescription": "",
                         "InIfSpeed": 1000, "OutIfSpeed": 10000, "InIfBoundary": "internal", "OutIfBoundary": "internal",
                         "EType": 2048, "Proto": 6, "SrcPort": eph(rng), "DstPort": rng.choice([443, 445, 8007]),
                         "Bytes": rng.randint(200, 1500), "Packets": 1, "ForwardingStatus": 64, "TCPFlags": 16})
        t += 60
    insert("default.flows", rows)


# ---------------------------------------------------------------- driver
def generate(t0, t1, rng, live_from):
    flows, fws, idss, dnss, auths = [], [], [], [], []
    t = t0 - t0 % 60
    while t < t1:
        flows += minute(t, rng, live_from)
        fws += fw_minute(t, rng)
        idss += ids_minute(t, rng)
        dnss += dns_minute(t, rng)
        auths += auth_minute(t, rng)
        t += 60
    insert("default.flows", flows)
    insert("netmon.fw_events", fws)
    insert("netmon.ids_events", idss)
    insert("netmon.dns_events", dnss)
    insert("netmon.auth_events", [a for a in auths if "app" in a and a.get("event")])
    insert("netmon.fw_events", [a for a in auths if "rid" in a])
    vendor_rows(t0, t1, rng)
    switch_flows(t0, t1, rng)
    return len(flows)


def write_files():
    os.makedirs(DATA, exist_ok=True)
    with open(os.path.join(DATA, "geoip.csv"), "w") as fh:
        fh.write("# synthetic: documentation ranges only\n")
        for b in BLOCKS:
            fh.write(f"{b['net']},{b['cc']}\n")
    os.makedirs(SECRETS, exist_ok=True)
    pw_file = os.path.join(SECRETS, "admin_password")
    if not os.path.exists(pw_file):
        with open(pw_file, "w") as fh:
            fh.write(secrets.token_urlsafe(18))
        os.chmod(pw_file, 0o640)


def seed_db():
    """1:1 NAT and DNS settings the firewall would normally provide (read by the app at start)."""
    sys.path.insert(0, "/app")
    from netmon.core import db_connect, put_setting
    conn = db_connect(os.environ.get("NETMON_DB", "/data/netmon.db"))
    put_setting(conn, "nat11:db", {SITE: [{"external": CRM_PUB, "internal": CRM, "description": "crm-1"},
                                          {"external": BACKUP_PUB, "internal": BACKUP, "description": "backup-1"}]}, "demo-seed")
    put_setting(conn, "dns", {"enabled": True, "retention_days": 7}, "demo-seed")
    put_setting(conn, "devices:db", DEVICES, "demo-seed")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "init"
    for _ in range(60):
        try:
            ch("SELECT 1")
            break
        except Exception:
            time.sleep(2)
    if cmd == "init":
        schema()
        write_files()
        seed_db()
        if int(ch("SELECT count() FROM default.flows").strip() or 0) == 0:
            now = time.time()
            rng = random.Random(42)
            n = generate(now - DAYS * 86400, now - 60, rng, now - 8 * 3600)
            insert("netmon.sys_events", sys_events(now - DAYS * 86400, rng))
            print(f"seeded {n:,} flow records over {DAYS} days", flush=True)
        else:
            print("demo data already present; not re-seeding", flush=True)
        if os.geteuid() == 0:                       # fresh named volumes are root-owned; the app runs as uid 10001
            for d in (DATA, SECRETS, os.path.dirname(os.environ.get("NETMON_DB", "/data/netmon.db"))):
                for root, dirs, files in os.walk(d):
                    for x in [root] + [os.path.join(root, f) for f in files]:
                        os.chown(x, 10001, 10001)
        print(f"admin password: {open(os.path.join(SECRETS, 'admin_password')).read()}  (user admin)", flush=True)
    elif cmd == "feed":
        rng = random.Random()
        last = int(time.time()) - 60
        while True:
            now = int(time.time())
            if now - last >= 60:
                generate(last, now - now % 60, rng, 0)
                last = now - now % 60
            time.sleep(10)


if __name__ == "__main__":
    main()
