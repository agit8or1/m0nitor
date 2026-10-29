"""OPNsense / pfSense syslog ingestion (rsyslog → /var/log/netmon/opnsense-YYYYMMDD.log → ClickHouse netmon.*).

Line format written by rsyslog: "<receipt-epoch> <sender-ip> <raw syslog message>".
filterlog CSV layout follows OPNsense's own parser (/usr/local/opnsense/scripts/filter/read_log.py, 26.7.7); pfSense
writes the same field order (its 4th field is a tracker id where OPNsense has a rule hash). pfSense sends BSD syslog
over UDP without a hostname ("<134>Oct 29 18:00:00 filterlog[123]: ...") unless RFC 5424 is selected.
Suricata: EVE JSON via syslog ("syslog_eve") or classic alert lines ("syslog"). With both enabled every alert
arrives twice; once a sensor has sent EVE alerts, its classic lines are dropped (EVE carries flow_id and timestamps).
The rsyslog files are the disk buffer: offsets are persisted, so lines received while this
process is down are ingested when it restarts.
"""
import glob
import ipaddress
import json
import os
import re
import threading
import time
from datetime import datetime, timezone

import httpx

from .core import get_setting, get_state, set_state, ThreadLocalDB

LOG_DIR = os.environ.get("NETMON_SYSLOG_DIR", "/var/log/netmon")
F_GEN = "rulenr,subrulenr,anchorname,rid,interface,reason,action,dir,ipversion".split(",")
F_V4 = F_GEN + "tos,ecn,ttl,id,offset,ipflags,protonum,protoname,length,src,dst".split(",")
F_V6 = F_GEN + "class,flow,hoplimit,protoname,protonum,length,src,dst".split(",")
F_UDP = "srcport,dstport,datalen".split(",")
F_TCP = "srcport,dstport,datalen,tcpflags,seq,ack,urp,tcpopts".split(",")
RE_5424 = re.compile(r"^<(\d+)>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(.*)$")
RE_3164_NOHOST = re.compile(r"^<(\d+)>(\w{3} +\d+ \d\d:\d\d:\d\d) ([A-Za-z][\w.-]*)(?:\[\d+\])?: ?(.*)$")
RE_3164 = re.compile(r"^<(\d+)>(\w{3} +\d+ \d\d:\d\d:\d\d) (\S+) ([^:\[\s]+)(?:\[\d+\])?: ?(.*)$")
RE_SURI = re.compile(r"\[(\d+):(\d+):(\d+)\] (.*?) \[Classification: (.*?)\] \[Priority: (\d+)\] \{(\w+)\} (\S+) -> (\S+)")
KIND = {"dpinger": "gateway", "wireguard": "vpn", "openvpn": "vpn", "charon": "vpn", "audit": "auth/config",
        "configd.py": "config", "kernel": "system", "firewall": "firewall-service"}


def v6(ip):
    try:
        a = ipaddress.ip_address(ip.strip("[]"))
        return str(a if a.version == 6 else ipaddress.IPv6Address("::ffff:" + str(a)))
    except ValueError:
        return "::"


def parse_header(raw):
    m = RE_5424.match(raw)
    if m:
        pri, ts, host, app, _pid, _mid, _sd, msg = m.groups()
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
        except ValueError:
            t = None
        return int(pri), t, host, app, msg, "rfc5424"
    m = RE_3164_NOHOST.match(raw)  # tried first: a hostname is never directly followed by ':'
    if m:
        pri, _ts, app, msg = m.groups()
        return int(pri), None, "", app, msg, "rfc3164"
    m = RE_3164.match(raw)
    if m:
        pri, _ts, host, app, msg = m.groups()
        return int(pri), None, host, app, msg, "rfc3164"  # no year/zone: use receipt time
    return None


def parse_filterlog(msg):
    f = msg.split(",")
    r = dict(zip(F_GEN, f))
    if r.get("ipversion") == "4":
        names = F_V4
    elif r.get("ipversion") == "6":
        names = F_V6
    else:
        return None
    r = dict(zip(names, f))
    rest = f[len(names):]
    if r.get("protonum") == "6":
        r.update(zip(F_TCP, rest))
    elif r.get("protonum") == "17":
        r.update(zip(F_UDP, rest))
    num = lambda k: int(r[k]) if r.get(k, "").isdigit() else 0  # noqa: E731
    if "src" not in r or "dst" not in r:
        return None
    return {"rulenr": num("rulenr"), "rid": r.get("rid", ""), "iface": r.get("interface", ""), "reason": r.get("reason", ""),
            "action": r.get("action", ""), "dir": r.get("dir", ""), "ipver": num("ipversion"), "proto": r.get("protoname", ""),
            "src": v6(r["src"]), "dst": v6(r["dst"]), "sport": num("srcport"), "dport": num("dstport"),
            "length": num("length"), "tcpflags": r.get("tcpflags", "")}


def parse_suricata(msg):
    if msg.lstrip().startswith("{"):
        try:
            e = json.loads(msg)
        except ValueError:
            return None
        a = e.get("alert") or {}
        if e.get("event_type") != "alert":
            return None
        try:
            ts = datetime.fromisoformat(e.get("timestamp", "").replace("Z", "+00:00")).timestamp()
        except ValueError:
            ts = None
        return {"_ts": ts, "sig_id": int(a.get("signature_id") or 0), "gid": int(a.get("gid") or 0), "rev": int(a.get("rev") or 0),
                "signature": str(a.get("signature", ""))[:500], "category": str(a.get("category", ""))[:200],
                "severity": int(a.get("severity") or 3), "action": str(a.get("action", "")), "proto": str(e.get("proto", "")),
                "src": v6(str(e.get("src_ip", ""))), "dst": v6(str(e.get("dest_ip", ""))), "sport": int(e.get("src_port") or 0),
                "dport": int(e.get("dest_port") or 0), "iface": str(e.get("in_iface", "")), "event_type": "alert",
                "flow_id": int(e.get("flow_id") or 0) & 0xFFFFFFFFFFFFFFFF, "raw": msg[:4000]}
    m = RE_SURI.search(msg)
    if not m:
        return None
    gid, sid, rev, sig, cls, prio, proto, s_ep, d_ep = m.groups()

    def ep(x):  # "1.2.3.4:80", "[2001:db8::1]:80" or "2001:db8::1:80" -> (addr, port)
        a, _, p = x.rpartition(":")
        return (a, p) if p.isdigit() and a else (x, "")
    (src, sp), (dst, dp) = ep(s_ep), ep(d_ep)
    return {"_ts": None, "sig_id": int(sid), "gid": int(gid), "rev": int(rev), "signature": sig[:500], "category": cls[:200],
            "severity": int(prio), "action": "blocked" if "Drop" in msg[:40] else "allowed", "proto": proto,
            "src": v6(src), "dst": v6(dst), "sport": int(sp or 0), "dport": int(dp or 0), "iface": "", "event_type": "alert",
            "flow_id": 0, "raw": msg[:4000]}


# Unbound (OPNsense: Services -> Unbound DNS -> Advanced -> Log queries / Log replies).
# log-queries: "info: 192.0.2.10 example.com. A IN"
# log-replies: "info: 192.0.2.10 example.com. A IN NOERROR 0.000026 0 59"  (rcode, time, cached, size; no answers)
UNBOUND = re.compile(r"info: (\S+) (\S+) (\S+) (\S+)(?: (\S+) [\d.]+ (\d) \d+)?\s*$")


def parse_unbound(msg):
    m = UNBOUND.search(msg)
    if not m or v6(m.group(1)) == "::":
        return None
    name = m.group(2).rstrip(".").lower() or "."
    return {"client": v6(m.group(1)), "query": name[:255], "qtype": m.group(3), "rcode": m.group(5) or "",
            "answers": [], "ttls": [], "resolver": "::", "uid": "", "sensor": "unbound",
            "source": "unbound-reply" if m.group(5) else "unbound-query"}


# Actual authentication / privilege events from servers' own logs (never inferred from flows)
AUTH = [
    ("sshd", re.compile(r"Failed (\S+) for (?:invalid user )?(\S+) from (\S+)"), "login_failed", (2, 3, 1)),
    ("sshd", re.compile(r"Accepted (\S+) for (\S+) from (\S+)"), "login_ok", (2, 3, 1)),
    ("sshd", re.compile(r"Invalid user (\S*) from (\S+)"), "invalid_user", (1, 2, None)),
    ("sudo", re.compile(r"^\s*(\S+) : (?:\d+ incorrect password attempts?)"), "sudo_failed", (1, None, None)),
    ("sudo", re.compile(r"^\s*(\S+) : .*COMMAND="), "sudo", (1, None, None)),
    ("su", re.compile(r"(?:FAILED su|authentication failure).*?(?:for|user=)\s*(\S+)"), "su_failed", (1, None, None)),
    ("su", re.compile(r"(?:Successful su|session opened) for (?:user )?(\S+)"), "su", (1, None, None)),
    ("audit", re.compile(r"user (\S+) authenticated successfully.*?@ ?(\S+)?"), "login_ok", (1, 2, None)),
    ("audit", re.compile(r"(?:failed to authenticate|authentication failed).*?user[\s:]+'?([^\s']+)'?.*?(?:@|from) ?(\S+)?"), "login_failed", (1, 2, None)),
]


def parse_auth(app, msg):
    base = app.split("[")[0]
    for a, rx, event, (ui, si, mi) in AUTH:
        if base != a:
            continue
        m = rx.search(msg)
        if m:
            src = v6(m.group(si).strip("()[],")) if si and m.group(si) else None
            return {"app": base, "event": event, "user": (m.group(ui) or "")[:64] if ui else "", "src": src or "::",
                    "method": (m.group(mi) or "")[:32] if mi else "", "message": msg[:500]}
    return None


def parse_line(line, site_of):
    """Return (table, row) or (None, reason)."""
    parts = line.rstrip("\n").split(" ", 2)
    if len(parts) < 3 or not parts[0].isdigit():
        return None, "bad envelope"
    recv, sender, raw = int(parts[0]), parts[1], parts[2]
    h = parse_header(raw)
    if not h:
        return None, "unparsed header"
    pri, ts, host, app, msg, fmt = h
    t = ts or recv
    base = {"received": recv, "site": site_of(sender)}
    if app == "filterlog":
        r = parse_filterlog(msg)
        return ("fw_events", {**base, "ts": t, **r}) if r else (None, "bad filterlog")
    if app == "suricata":
        r = parse_suricata(msg)
        if not r:
            return None, "suricata non-alert"
        st = r.pop("_ts") or t
        return "ids_events", {**base, "ts": st, "sensor": host, **r}
    if app == "unbound":
        r = parse_unbound(msg)
        if r:
            return "dns_events", {**base, "ts": t, **r}
    au = parse_auth(app, msg)
    if au:
        row = ("auth_events", {**base, "ts": t, "host": host or sender, "sender": v6(sender) or "::", **au})
        if app != "audit":
            return row
        # firewall audit lines are kept in sys_events too (config-change history)
        return "multi", [row, ("sys_events", {**base, "ts": t, "app": app, "severity": pri & 7, "kind": KIND.get(app, "other"), "message": msg[:2000]})]
    return "sys_events", {**base, "ts": t, "app": app, "severity": pri & 7, "kind": KIND.get(app, "other"), "message": msg[:2000]}


class Ingest:
    def __init__(self, cfg, url):
        self.cfg, self.url = cfg, url
        self.http = httpx.Client(timeout=30)
        self.eve_seen = {}  # sensor -> last receipt epoch of an EVE alert

    def dedupe_ids(self, rows, stats):
        """Drop classic alert lines from sensors that also send EVE JSON (same alert, less detail)."""
        for r in rows:
            if r["flow_id"] or r["raw"].lstrip().startswith("{"):
                self.eve_seen[r["sensor"]] = max(self.eve_seen.get(r["sensor"], 0), r["received"])
        keep = []
        for r in rows:
            classic = not (r["flow_id"] or r["raw"].lstrip().startswith("{"))
            if classic and r["received"] - self.eve_seen.get(r["sensor"], -10 ** 9) < 86400:
                stats["unparsed"]["suricata classic (EVE preferred)"] = stats["unparsed"].get("suricata classic (EVE preferred)", 0) + 1
                continue
            keep.append(r)
        return keep

    def site_of(self, ip):
        # read per line: sites added in the UI take effect without a restart
        return next((s["id"] for s in self.cfg["sites"] if s.get("syslog_source") == ip), ip)

    def insert(self, table, rows):
        if not rows:
            return
        for r in rows:
            r["ts"] = datetime.fromtimestamp(r["ts"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        body = "\n".join(json.dumps(r) for r in rows).encode()
        q = f"INSERT INTO netmon.{table} SETTINGS date_time_input_format='best_effort' FORMAT JSONEachRow"
        r = self.http.post(self.url, params={"query": q}, content=body)
        if r.status_code != 200:
            raise RuntimeError(f"ClickHouse insert {table}: {r.status_code} {r.text[:200]}")

    def run(self):
        conn = ThreadLocalDB()
        stats = {"lines": 0, "fw": 0, "ids": 0, "sys": 0, "errors": 0, "unparsed": {}, "last_line": None, "error": None}
        st, _ = get_state(conn, "ingest:offset", {})
        cur_file, offset = (st or {}).get("file"), (st or {}).get("offset", 0)  # noqa: F841
        while True:
            try:
                files = sorted(glob.glob(os.path.join(LOG_DIR, "opnsense-*.log")))
                if not files:
                    stats["error"] = None
                    set_state(conn, "ingest", {**stats, "files": 0})
                    time.sleep(5)
                    continue
                if cur_file not in files:  # first start, or our file was pruned: continue with the next newer one
                    cur_file = files[0] if cur_file is None else next((f for f in files if f > cur_file), files[-1])
                    offset = 0
                if os.path.getsize(cur_file) < offset:  # truncated/replaced
                    offset = 0
                batch = {"fw_events": [], "ids_events": [], "sys_events": [], "dns_events": [], "auth_events": []}
                dns_on = (get_setting(conn, "dns", {}) or {}).get("enabled", True)
                with open(cur_file, "r", errors="replace") as fh:
                    fh.seek(offset)
                    for _ in range(20000):
                        line = fh.readline()
                        if not line or not line.endswith("\n"):
                            break
                        offset = fh.tell()
                        stats["lines"] += 1
                        table, row = parse_line(line, self.site_of)
                        if table == "dns_events" and not dns_on:
                            stats["unparsed"]["dns (collection disabled)"] = stats["unparsed"].get("dns (collection disabled)", 0) + 1
                            continue
                        if table == "multi":
                            for t2, r2 in row:
                                batch[t2].append(r2)
                            stats["last_line"] = time.time()
                        elif table:
                            batch[table].append(row)
                            stats["last_line"] = time.time()
                        else:
                            stats["unparsed"][row] = stats["unparsed"].get(row, 0) + 1
                batch["ids_events"] = self.dedupe_ids(batch["ids_events"], stats)
                for t, rows in batch.items():
                    self.insert(t, rows)
                stats["fw"] += len(batch["fw_events"])
                stats["ids"] += len(batch["ids_events"])
                stats["sys"] += len(batch["sys_events"])
                stats["dns"] = stats.get("dns", 0) + len(batch["dns_events"])
                stats["auth"] = stats.get("auth", 0) + len(batch["auth_events"])
                stats["error"] = None
                set_state(conn, "ingest:offset", {"file": cur_file, "offset": offset})
                idx = files.index(cur_file)
                moved = sum(len(v) for v in batch.values())
                if not moved and idx < len(files) - 1 and offset >= os.path.getsize(cur_file):
                    cur_file, offset = files[idx + 1], 0   # finished an older day's file
                set_state(conn, "ingest", {**stats, "files": len(files), "file": os.path.basename(cur_file)})
                if not moved:
                    time.sleep(2)
            except Exception as ex:
                stats["errors"] += 1
                stats["error"] = str(ex)[:300]
                set_state(conn, "ingest", stats)
                time.sleep(10)

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
