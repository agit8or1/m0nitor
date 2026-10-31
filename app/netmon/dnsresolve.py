"""Names (FQDNs) for remote addresses, from the firewall's DNS query log.

Unbound's query log says which client asked for which name, never the answer. For every A/AAAA name a client looked
up, netmon asks the same resolver - by default the firewall that sends the log - and records the answer. A caching
resolver normally hands back the very answer the client got, so a connection to one of those addresses shortly
after the lookup is labelled with the name. Basis shown per match: "this host looked it up" or only "another host
did" (shared CDN/hosting addresses can carry several names; up to three are listed).
Rows go to netmon.dns_resolved (7 days). Per-site settings: on/off and the resolver address (blank = automatic).
Also kept here: the operator's note of how the firewall side was set up (query log mode, who, when).
"""
import ipaddress
import json
import os
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

from .core import get_setting, get_state, put_setting, set_state, ThreadLocalDB

SETTING = "dnsnames"
DEFAULTS = {"enabled": True, "resolver": "", "fw_mode": "", "fw_note": "", "noted_by": "", "noted_at": None}
FW_MODES = {"": "not recorded", "off": "off", "queries": "queries only", "queries+replies": "queries and replies"}
QTYPES = {"A": 1, "AAAA": 28, "PTR": 12}
IPS = "replaceOne(IPv6NumToString({c}), '::ffff:', '')"


def settings(conn, site_id):
    return {**DEFAULTS, **((get_setting(conn, SETTING, {}) or {}).get(site_id) or {})}


def save_settings(conn, site_id, values, user):
    allv = get_setting(conn, SETTING, {}) or {}
    s = {**DEFAULTS, **(allv.get(site_id) or {})}
    if "resolver" in values:
        r = (values["resolver"] or "").strip()
        if r:
            r = str(ipaddress.ip_address(r))     # ValueError for anything that is not an address
        s["resolver"] = r
    if "enabled" in values:
        s["enabled"] = bool(values["enabled"])
    if "fw_mode" in values:
        if values["fw_mode"] not in FW_MODES:
            raise ValueError("unknown query log mode")
        note = " ".join((values.get("fw_note") or "").split())[:300].replace("<", "‹").replace(">", "›")
        if (values["fw_mode"], note) != (s["fw_mode"], s["fw_note"]):
            s.update({"fw_mode": values["fw_mode"], "fw_note": note, "noted_by": user, "noted_at": time.time()})
    allv[site_id] = s
    put_setting(conn, SETTING, allv, user)
    return s


def resolver_for(site, s):
    """Configured resolver, else the firewall itself (its syslog source or exporter address: it runs the resolver)."""
    if s.get("resolver"):
        return s["resolver"], "configured"
    auto = site.get("syslog_source") or site.get("exporter_ip") or ""
    return auto, ("automatic: the firewall that sends the query log" if auto else "none (set one)")


# ---- minimal DNS client (stdlib) ---------------------------------------------------------------------------------
def _name(buf, off):
    """Decode a (possibly compressed) name at off -> (name, offset after it in the original position)."""
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated name")
        n = buf[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("truncated pointer")
            if not jumped:
                end = off + 2
            off, jumped, hops = ((n & 0x3F) << 8) | buf[off + 1], True, hops + 1
            if hops > 30:
                raise ValueError("pointer loop")
            continue
        if n == 0:
            return ".".join(labels), (end if jumped else off + 1)
        labels.append(buf[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n


def query(name, qtype, server, timeout=2.0, port=53):
    """[(address or PTR name, ttl)] for name/qtype ('A', 'AAAA' or 'PTR') from server; [] for NXDOMAIN/no data. Raises on timeout."""
    qid = int.from_bytes(os.urandom(2), "big")
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)   # recursion desired
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        if not 0 < len(raw) < 64:
            raise ValueError("bad label")
        q += bytes([len(raw)]) + raw
    q += b"\x00" + struct.pack(">HH", QTYPES[qtype], 1)
    fam = socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, (server, port))
        while True:
            buf, _ = s.recvfrom(4096)
            if len(buf) >= 12 and struct.unpack(">H", buf[:2])[0] == qid:
                break
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", buf[:12])
    if flags & 0x000F:            # rcode != NOERROR (NXDOMAIN, SERVFAIL, ...)
        return []
    off = 12
    for _ in range(qd):
        _, off = _name(buf, off)
        off += 4
    out = []
    for _ in range(an):
        _, off = _name(buf, off)
        rtype, _, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        rdata, rd_off = buf[off:off + rdlen], off
        off += rdlen
        if rtype == 1 and rdlen == 4:
            out.append((str(ipaddress.IPv4Address(rdata)), ttl))
        elif rtype == 28 and rdlen == 16:
            out.append((str(ipaddress.IPv6Address(rdata)), ttl))
        elif rtype == 12 and qtype == "PTR":
            out.append((_name(buf, rd_off)[0], ttl))
    return out


# ---- background resolver ------------------------------------------------------------------------------------------
class NameResolver:
    """Every 30 s: new A/AAAA names from each site's query log -> resolve on the site's resolver -> dns_resolved."""
    BATCH, WORKERS, TIMEOUT = 3000, 16, 2.0

    def __init__(self, cfg, ch, url):
        self.cfg, self.ch, self.url = cfg, ch, url
        self.http = httpx.Client(timeout=30)
        self.fresh = {}            # (resolver, name, qtype) -> answer valid until

    def insert(self, rows):
        if rows:
            q = "INSERT INTO netmon.dns_resolved FORMAT JSONEachRow"
            r = self.http.post(self.url, params={"query": q}, content="\n".join(json.dumps(x) for x in rows).encode())
            if r.status_code != 200:
                raise RuntimeError(f"ClickHouse insert: {r.status_code} {r.text[:200]}")

    def run_site(self, conn, site):
        s = settings(conn, site["id"])
        server, _ = resolver_for(site, s)
        st = {"ts": time.time(), "resolver": server, "names": 0, "addresses": 0, "failed": 0, "error": ""}
        if not s["enabled"] or not server:
            st["error"] = "" if not s["enabled"] else "no resolver"
            return st
        key = f"dnsnames:mark:{site['id']}"
        mark, _ = get_state(conn, key, None)
        mark = mark or int(time.time()) - 600
        rows = self.ch.query("""
            SELECT query, qtype, groupUniqArray(5)(client) AS clients, toUInt32(min(ts)) AS t, toUInt32(max(received)) AS r
            FROM netmon.dns_events WHERE site = {site:String} AND received > toDateTime({m:UInt32})
              AND received <= now() - 2 AND qtype IN ('A', 'AAAA') AND startsWith(source, 'unbound')
            GROUP BY query, qtype ORDER BY r LIMIT {n:UInt32}""", {"site": site["id"], "m": int(mark), "n": self.BATCH})
        now = time.time()
        todo = [x for x in rows if self.fresh.get((server, x["query"], x["qtype"]), 0) < now]
        if len(self.fresh) > 100000:
            self.fresh = {k: v for k, v in self.fresh.items() if v >= now}

        def one(x):
            try:
                return x, query(x["query"], x["qtype"], server, self.TIMEOUT), None
            except (OSError, ValueError) as ex:
                return x, [], ex
        out = []
        with ThreadPoolExecutor(self.WORKERS) as pool:
            for x, answers, err in pool.map(one, todo):
                if err:
                    st["failed"] += 1
                    st["error"] = f"{type(err).__name__}: {str(err)[:120]}"
                    continue
                st["names"] += 1
                ttl = min([a[1] for a in answers] or [300])
                self.fresh[(server, x["query"], x["qtype"])] = now + max(60, min(ttl, 3600))
                for addr, attl in answers:
                    out.append({"ts": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(x["t"])), "site": site["id"], "query": x["query"].rstrip(".").lower(), "qtype": x["qtype"],
                                "addr": _v6(addr), "ttl": attl, "clients": x["clients"], "resolver": server})
        self.insert(out)
        st["addresses"] = len(out)
        if rows:
            set_state(conn, key, int(rows[-1]["r"]) if len(rows) >= self.BATCH else max(int(r["r"]) for r in rows))
        return st

    def run(self):
        conn = ThreadLocalDB()
        time.sleep(60)
        while True:
            status = {}
            for site in self.cfg.sites:
                try:
                    status[site["id"]] = self.run_site(conn, site)
                except Exception as ex:
                    status[site["id"]] = {"ts": time.time(), "error": f"{type(ex).__name__}: {str(ex)[:200]}"}
            prev, _ = get_state(conn, "dnsnames:status", None)
            for sid, st in status.items():   # running totals for the last hour, per site
                p = (prev or {}).get(sid) or {}
                hour = [h for h in p.get("hour", []) if h[0] > time.time() - 3600] + [[st["ts"], st.get("names", 0), st.get("addresses", 0), st.get("failed", 0)]]
                st["hour"] = hour
            set_state(conn, "dnsnames:status", status)
            time.sleep(30)

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()


# ---- lookup for the UI ----------------------------------------------------------------------------------------------
def names_for(ch, site_ids, pairs, t0, t1, lookback=86400):
    """{(client, remote): {"name", "names", "mine", "basis"}} for (internal client, remote address) pairs seen t0..t1.
    A name counts when it was looked up from t0 - lookback until t1 and resolved to the remote address."""
    remotes = sorted({r for _, r in pairs})
    if not remotes:
        return {}
    rows = ch.query(f"""
        SELECT {IPS.format(c='addr')} AS ip, query, toUInt32(max(ts)) AS t,
               arrayDistinct(arrayMap(x -> {IPS.format(c='x')}, groupArrayArray(clients))) AS clients
        FROM netmon.dns_resolved WHERE has({{sites:Array(String)}}, site)
          AND addr IN (SELECT arrayJoin(arrayMap(x -> toIPv6(x), {{ips:Array(String)}})))
          AND ts >= toDateTime64({{t0:UInt32}}, 3) AND ts <= toDateTime64({{t1:UInt32}}, 3)
        GROUP BY ip, query ORDER BY t DESC LIMIT 5000""",
                    {"sites": site_ids, "ips": [_v6(r) for r in remotes], "t0": int(t0 - lookback), "t1": int(t1)})
    by_ip = {}
    for r in rows:
        by_ip.setdefault(r["ip"], []).append(r)
    out = {}
    for client, remote in pairs:
        cands = by_ip.get(remote)
        if not cands:
            continue
        mine = [c for c in cands if client in c["clients"]]
        pick = mine or cands
        names = [c["query"] for c in pick][:3]
        out[(client, remote)] = {
            "name": names[0], "names": names, "more": max(0, len(pick) - 3), "mine": bool(mine),
            "basis": ("this host looked the name up (Unbound query log), resolved by netmon on the same resolver" if mine else
                      "another host looked the name up; this host may have used a cached answer or a different name")
                     + ("; the address carries several names (shared hosting/CDN)" if len(pick) > 1 else "")}
    return out


def _v6(ip):
    a = ipaddress.ip_address(ip)
    return str(a if a.version == 6 else ipaddress.IPv6Address("::ffff:" + str(a)))
