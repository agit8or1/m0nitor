"""Optional Zeek sensor ingestion (read-only): tails Zeek JSON logs from a mounted directory into ClickHouse.

Expected layout: <dir>/<sensor>/{conn,dns,ssl,http,notice,capture_loss,stats}.log written by Zeek with
`redef LogAscii::use_json = T;` (see docs/zeek.md). Files are only read; offsets and inodes are kept in the
state table so rotation and restarts neither skip nor re-read lines. With no directory or no files the
source shows "Awaiting traffic feed" - nothing here assumes a sensor exists.

What Zeek can and cannot add: connection records for traffic the sensor's mirror/TAP actually sees
(including LAN<->LAN), DNS queries with answers and TTLs, TLS SNI/version (not decrypted content), and HTTP
request lines for cleartext HTTP only. No TLS interception is configured or supported.
"""
import glob
import ipaddress
import json
import os
import threading
import time
from datetime import datetime, timezone

import httpx

from .core import get_state, set_state, ThreadLocalDB

ZEEK_DIR = os.environ.get("NETMON_ZEEK_DIR", "/var/log/zeek")
LOGS = ("conn", "dns", "ssl", "http", "notice", "capture_loss", "stats")


def v6(ip):
    try:
        a = ipaddress.ip_address(str(ip))
        return str(a if a.version == 6 else ipaddress.IPv6Address("::ffff:" + str(a)))
    except ValueError:
        return "::"


def ts64(t):
    return datetime.fromtimestamp(float(t), timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def convert(kind, r, site, sensor, received):
    """One Zeek JSON record -> (table, row) or (None, None)."""
    base = {"ts": ts64(r.get("ts", received)), "received": int(received), "site": site, "sensor": sensor}
    if kind == "conn":
        return "zeek_conn", {**base, "uid": r.get("uid", ""), "proto": r.get("proto", ""), "service": r.get("service") or "",
                             "orig_h": v6(r.get("id.orig_h")), "orig_p": int(r.get("id.orig_p") or 0), "resp_h": v6(r.get("id.resp_h")),
                             "resp_p": int(r.get("id.resp_p") or 0), "duration": float(r.get("duration") or 0),
                             "orig_bytes": int(r.get("orig_bytes") or 0), "resp_bytes": int(r.get("resp_bytes") or 0),
                             "conn_state": r.get("conn_state", ""), "local_orig": int(bool(r.get("local_orig"))),
                             "local_resp": int(bool(r.get("local_resp"))), "missed_bytes": int(r.get("missed_bytes") or 0),
                             "history": (r.get("history") or "")[:32]}
    if kind == "dns":
        if not r.get("query"):
            return None, None
        return "dns_events", {**base, "source": "zeek", "client": v6(r.get("id.orig_h")), "query": str(r["query"]).lower()[:255],
                              "qtype": r.get("qtype_name") or str(r.get("qtype", "")), "rcode": r.get("rcode_name") or "",
                              "answers": [str(a)[:255] for a in (r.get("answers") or [])][:16],
                              "ttls": [int(float(x)) for x in (r.get("TTLs") or [])][:16], "resolver": v6(r.get("id.resp_h")),
                              "uid": r.get("uid", "")}
    if kind == "ssl":
        return "zeek_tls", {**base, "uid": r.get("uid", ""), "orig_h": v6(r.get("id.orig_h")), "resp_h": v6(r.get("id.resp_h")),
                            "resp_p": int(r.get("id.resp_p") or 0), "version": r.get("version") or "",
                            "server_name": (r.get("server_name") or "")[:255], "established": int(bool(r.get("established"))),
                            "validation_status": (r.get("validation_status") or "")[:64]}
    if kind == "http":
        return "zeek_http", {**base, "uid": r.get("uid", ""), "orig_h": v6(r.get("id.orig_h")), "resp_h": v6(r.get("id.resp_h")),
                             "resp_p": int(r.get("id.resp_p") or 0), "method": r.get("method") or "", "host": (r.get("host") or "")[:255],
                             "uri": (r.get("uri") or "")[:512], "status_code": int(r.get("status_code") or 0),
                             "user_agent": (r.get("user_agent") or "")[:255]}
    if kind == "notice":
        return "zeek_notice", {**base, "note": r.get("note") or "", "msg": (r.get("msg") or "")[:500], "src": v6(r.get("src") or "::"),
                               "dst": v6(r.get("dst") or "::"), "p": int(r.get("p") or 0)}
    if kind == "capture_loss":
        return "zeek_stats", {**base, "kind": "capture_loss", "percent_lost": float(r.get("percent_lost") or 0),
                              "gaps": int(r.get("gaps") or 0), "acks": int(r.get("acks") or 0), "pkts_proc": 0, "pkts_dropped": 0}
    if kind == "stats":
        return "zeek_stats", {**base, "kind": "stats", "percent_lost": 0.0, "gaps": 0, "acks": 0,
                              "pkts_proc": int(r.get("pkts_proc") or 0), "pkts_dropped": int(r.get("pkts_dropped") or 0)}
    return None, None


class ZeekIngest:
    def __init__(self, cfg, url, root=ZEEK_DIR):
        self.cfg, self.url, self.root = cfg, url, root
        self.http = httpx.Client(timeout=30)
        z = cfg.get("zeek") or {}
        self.site = z.get("site") or cfg.sites[0]["id"]

    def files(self):
        out = []
        for path in glob.glob(os.path.join(self.root, "*", "*.log")):
            kind = os.path.basename(path)[:-4]
            if kind in LOGS:
                out.append((os.path.basename(os.path.dirname(path)), kind, path))
        return sorted(out)

    def insert(self, table, rows):
        if not rows:
            return
        q = f"INSERT INTO netmon.{table} SETTINGS date_time_input_format='best_effort' FORMAT JSONEachRow"
        r = self.http.post(self.url, params={"query": q}, content="\n".join(json.dumps(x) for x in rows).encode())
        if r.status_code != 200:
            raise RuntimeError(f"ClickHouse insert {table}: {r.status_code} {r.text[:200]}")

    def run_once(self, conn, stats):
        moved = 0
        for sensor, kind, path in self.files():
            key = f"zeek:offset:{sensor}:{kind}"
            st, _ = get_state(conn, key, {})
            st = st or {}
            ino, size = os.stat(path).st_ino, os.path.getsize(path)
            off = st.get("offset", 0) if st.get("inode") == ino and size >= st.get("offset", 0) else 0  # rotated/truncated -> start over
            batch = {}
            with open(path, "r", errors="replace") as fh:
                fh.seek(off)
                for _ in range(20000):
                    line = fh.readline()
                    if not line or not line.endswith("\n"):
                        break
                    off = fh.tell()
                    if line.startswith("#"):
                        continue
                    try:
                        table, row = convert(kind, json.loads(line), self.site, sensor, time.time())
                    except (ValueError, TypeError):
                        stats["bad"] = stats.get("bad", 0) + 1
                        continue
                    if table:
                        batch.setdefault(table, []).append(row)
            for t, rows in batch.items():
                self.insert(t, rows)
                moved += len(rows)
            set_state(conn, key, {"inode": ino, "offset": off})
        return moved

    def run(self):
        conn = ThreadLocalDB()
        stats = {"lines": 0, "bad": 0, "error": None}
        while True:
            try:
                n = self.run_once(conn, stats)
                stats["lines"] += n
                stats["error"], stats["files"], stats["ts"] = None, len(self.files()), time.time()
                set_state(conn, "zeek", stats)
                time.sleep(2 if n else 10)
            except Exception as ex:
                stats["error"] = str(ex)[:300]
                set_state(conn, "zeek", stats)
                time.sleep(30)

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
