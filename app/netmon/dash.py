"""Scoped, read-only aggregation for the operator UI.

Accounting boundary: the WAN interface of each site.
  inbound  = flow records with InIfName  = site WAN  (Internet -> us)
  outbound = flow records with OutIfName = site WAN  (us -> Internet, post-NAT source)
Each packet crossing the WAN appears in exactly one of these sets (validated
2026-10-29), so in + out is not double counted. LAN-side records are never added.
Every query in this module uses the same Scope clause, so cards, chart, map
and tables reconcile for the same scope.
"""
import ipaddress
import json
import os
import threading
import time
from dataclasses import dataclass, field

from .core import PROTO, expand_flow_sql, flow_predicates

IPS = "replaceOne(IPv6NumToString({c}), '::ffff:', '')"
REMOTE_IP = IPS.format(c="if(INB, SrcAddr, DstAddr)")
LOCAL_IP = IPS.format(c="if(INB, DstAddr, SrcAddr)")
PUBS = "(SELECT arrayJoin(arrayMap(x -> toIPv6(concat('::ffff:', x)), {pubs:Array(String)})))"
PRESETS = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
MAX_SPAN = 31 * 86400
MGMT_PORTS = {21, 22, 23, 3389, 5900, 8006, 8007, 10000, 2222, 9090}
META = json.load(open(os.path.join(os.path.dirname(__file__), "static", "countries-meta.json")))


def cname(cc):
    return META.get(cc, {}).get("name") or ("Unknown" if cc in ("", "??") else cc)


def pick_bucket(span):
    for limit, b in ((1500, 30), (7200, 60), (28800, 300), (2 * 86400, 900), (8 * 86400, 3600)):
        if span <= limit:
            return b
    return 4 * 3600


@dataclass
class Scope:
    sites: list
    start: int
    end: int
    range_key: str = "15m"
    cc: str = ""
    host: str = ""
    asn: int = 0
    port: int = 0
    rip: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def span(self):
        return max(1, self.end - self.start)

    @property
    def bucket(self):
        return pick_bucket(self.span)

    @property
    def ip_level(self):
        return bool(self.host or self.port or self.rip)

    def describe(self):
        parts = [", ".join(s["name"] for s in self.sites)]
        if self.cc:
            parts.append(f"country {cname(self.cc)}")
        if self.host:
            parts.append(f"server {self.host}")
        if self.asn:
            parts.append(f"AS{self.asn}")
        if self.port:
            parts.append(f"port {self.port}")
        if self.rip:
            parts.append(f"remote {self.rip}")
        return " · ".join(parts)


def tuples(pairs):
    return "[" + ",".join(f"('{a}',{b})" if isinstance(b, int) else f"('{a}','{b}')" for a, b in pairs) + "]"


def merge_pairs(ps, n=5):
    """LAN hosts behind one NAT address show as the same public pair: add them up, keep the busiest n per direction."""
    agg = {}
    for p in ps:
        k = (p["src"], p["dst"], p["dir"])
        if k in agg:
            agg[k]["b"] += p["b"]
            agg[k]["flows"] += p["flows"]
            for side in ("src", "dst"):
                agg[k][f"{side}_inner"] += [x for x in p.get(f"{side}_inner", []) if x not in agg[k][f"{side}_inner"]]
        else:
            agg[k] = {**p, "src_inner": list(p.get("src_inner", [])), "dst_inner": list(p.get("dst_inner", []))}
    out = sorted(agg.values(), key=lambda p: -p["b"])
    return [p for d in ("in", "out") for p in [x for x in out if x["dir"] == d][:n]]


class Dash:
    def __init__(self, cfg, ch):
        self.cfg, self.ch = cfg, ch
        self._cache, self._lock = {}, threading.Lock()
        from .rdns import RDNS
        self.rdns = RDNS(cfg)          # reverse DNS names for tooltips and endpoint tables

    # ---- scope -------------------------------------------------------------
    def scope(self, site="all", range_key="15m", start=None, end=None, cc="", host="", asn="", port="", rip=""):
        sites = [s for s in self.cfg["sites"] if site in ("all", "", s["id"])] or self.cfg["sites"]
        now = int(time.time()) // 10 * 10   # quantized so concurrent viewers share the query cache
        if range_key == "custom" and start and end:
            start, end = int(start), int(end)
            end = min(end, now)
            if end <= start:
                raise ValueError("custom range end must be after start")
            start = max(start, end - MAX_SPAN)
        else:
            range_key = range_key if range_key in PRESETS else "15m"
            end, start = now, now - PRESETS[range_key]
        cc = cc.upper()[:2] if cc and (cc.upper() in META or cc == "??") else ""
        if host:
            host = str(ipaddress.ip_address(host))
            if not self.cfg.is_internal(host):
                raise ValueError("server filter must be an internal address")
        if rip:
            rip = str(ipaddress.ip_address(rip))
        return Scope(sites, start, end, range_key, cc, host, int(asn or 0), int(port or 0), rip)

    def params(self, sc: Scope):
        hexp = [(e.public_ip, p) for e in self.cfg.exposures if e.ip == sc.host for p in range(e.lo, e.hi + 1)]
        return {"exps": [s["exporter"] for s in sc.sites], "hbin": self.cfg.binat_ext(sc.host) if sc.host else [],
                "t0": sc.start, "t1": sc.end, "cc": sc.cc if sc.cc != "??" else "", "host": sc.host,
                "hexp": tuples(hexp) if hexp else "[]", "asn": sc.asn, "port": sc.port, "rip": sc.rip,
                "svc": self.cfg["service_ports"], "pubs": self.public_ips()}

    def public_ips(self):
        return sorted({e.public_ip for e in self.cfg.exposures})

    def where(self, sc: Scope, table="flows"):
        """WHERE clause for the WAN accounting boundary + scope filters."""
        w = ["has({exps:Array(String)}, ExporterName)",
             "TimeReceived >= toDateTime({t0:UInt32}) AND TimeReceived < toDateTime({t1:UInt32})",
             "(INB OR OUTB)"]
        if sc.cc:
            w.append("if(INB, SrcCountry, DstCountry) = {cc:String}")
        if sc.asn:
            w.append("if(INB, SrcAS, DstAS) = {asn:UInt32}")
        if table == "flows":
            if sc.host:
                # exact for inbound; outbound only where a port-forward reply maps uniquely to this host
                # outbound is exact for a 1:1 NAT address (every port is this host's)
                w.append(f"((INB AND TOLAN AND {IPS.format(c='DstAddr')} = {{host:String}}) OR "
                         f"(OUTB AND has({{hbin:Array(String)}}, {IPS.format(c='SrcAddr')})) OR "
                         f"(OUTB AND SrcAddr IN {PUBS} AND has({{hexp:Array(Tuple(String, UInt16))}}, ({IPS.format(c='SrcAddr')}, SrcPort))))")
            if sc.port:
                w.append("(SrcPort = {port:UInt16} OR DstPort = {port:UInt16})")
            if sc.rip:
                w.append(f"{REMOTE_IP} = {{rip:String}}")
        return " AND ".join(w)

    def _fqdns(self, rows, sc):
        """r["fqdn"]: the name the server (or its LAN host behind 1:1 NAT) looked up for this remote, from the DNS query log."""
        from .dnsresolve import names_for
        pairs = {(self.cfg.binat.get(r["server"], r["server"]), r["remote"]) for r in rows}
        try:
            got = names_for(self.ch, [s["id"] for s in sc.sites], pairs, sc.start, sc.end)
        except Exception:   # names are context only: no DNS table / ClickHouse hiccup -> no names
            got = {}
        for r in rows:
            r["fqdn"] = got.get((self.cfg.binat.get(r["server"], r["server"]), r["remote"]))

    def q(self, sc: Scope, s: str, extra=None, ttl=10):
        macros, fp = flow_predicates(self.cfg, sc.sites)
        sql = expand_flow_sql(s, macros)
        p = {**self.params(sc), **fp, **(extra or {})}
        key = (sql, json.dumps(p, sort_keys=True, default=str))
        now = time.time()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < ttl:
                return hit[1]
        rows = self.ch.query(sql, p)
        with self._lock:
            if len(self._cache) > 500:
                self._cache.clear()
            self._cache[key] = (now, rows)
        return rows

    def table_for(self, sc: Scope):
        if sc.ip_level or sc.bucket < 300:
            return "flows"
        return "flows_1h0m0s" if sc.bucket >= 3600 else "flows_5m0s"

    # ---- collection state -------------------------------------------------------
    def collection(self, sc: Scope):
        r = self.q(sc, "SELECT toUInt32(min(TimeReceived)) AS first, toUInt32(max(TimeReceived)) AS last, "
                       "countIf(TimeReceived > now() - 300) AS f5 FROM flows WHERE has({exps:Array(String)}, ExporterName)", ttl=5)[0]
        last = r["last"] or None
        return {"first": r["first"] or None, "last": last, "age": (time.time() - last) if last else None,
                "flows_5m": int(r["f5"])}

    # ---- summary -------------------------------------------------------------------
    def summary(self, sc: Scope):
        t = self.table_for(sc) if not (sc.ip_level) else "flows"
        r = self.q(sc, f"""
            SELECT sumIf(Bytes * SamplingRate, INB) AS in_b, sumIf(Bytes * SamplingRate, OUTB) AS out_b
            FROM {t} WHERE {self.where(sc, t)}""")[0]
        r2 = self.q(sc, f"""
            SELECT count() AS flows,
                   uniqExactIf(DstAddr, INB AND TOLAN) AS servers,
                   uniq(if(INB, SrcAddr, DstAddr)) AS peers,
                   uniqIf(if(INB, SrcCountry, DstCountry), if(INB, SrcCountry, DstCountry) != '') AS countries
            FROM flows WHERE {self.where(sc)}""")[0]
        out = {"in_b": int(r["in_b"]), "out_b": int(r["out_b"]), **{k: int(v) for k, v in r2.items()}}
        out["in_avg_bps"], out["out_avg_bps"] = out["in_b"] * 8 / sc.span, out["out_b"] * 8 / sc.span
        return out

    def flow_series(self, sc: Scope, coll):
        t, b = self.table_for(sc), sc.bucket
        rows = self.q(sc, f"""
            SELECT toUInt32(toStartOfInterval(TimeReceived, INTERVAL {{b:UInt32}} SECOND)) AS ts,
                   sumIf(Bytes * SamplingRate, INB) AS in_b, sumIf(Bytes * SamplingRate, OUTB) AS out_b, count() AS n
            FROM {t} WHERE {self.where(sc, t)} GROUP BY ts ORDER BY ts""", {"b": b})
        by = {r["ts"]: r for r in rows}
        first, last = coll["first"] or sc.end, coll["last"] or 0
        pts, peak_in, peak_out = [], 0, 0
        for ts in range(sc.start // b * b, sc.end + 1, b):
            r = by.get(ts)
            if ts + b <= first or ts > last:     # before collection started / after newest data: unavailable
                pts.append({"t": ts, "in_bps": None, "out_bps": None})
            elif r is None:                       # collection running but no records: gap, not zero
                pts.append({"t": ts, "in_bps": None, "out_bps": None})
            else:
                i, o = int(r["in_b"]) * 8 / b, int(r["out_b"]) * 8 / b
                peak_in, peak_out = max(peak_in, i), max(peak_out, o)
                pts.append({"t": ts, "in_bps": i, "out_bps": o})
        return {"bucket": b, "points": pts, "peak_in_bps": peak_in, "peak_out_bps": peak_out,
                "source": "flow-estimated", "table": t}

    # ---- countries / map ----------------------------------------------------------------
    def countries(self, sc: Scope, limit=250):
        t = self.table_for(sc)
        rows = self.q(sc, f"""
            SELECT if(INB, SrcCountry, DstCountry) AS cc,
                   sumIf(Bytes * SamplingRate, INB) AS in_b, sumIf(Bytes * SamplingRate, OUTB) AS out_b,
                   sum(Packets) AS packets, topK(1)(if(INB, SrcAS, DstAS)) AS top_as
            FROM {t} WHERE {self.where(sc, t)} GROUP BY cc ORDER BY in_b + out_b DESC LIMIT {{l:UInt32}}""", {"l": limit})
        extra = {(r["cc"] or "").strip("\x00"): r for r in self.q(sc, f"""
            SELECT if(INB, SrcCountry, DstCountry) AS cc, count() AS flows,
                   uniqExactIf(DstAddr, INB AND TOLAN) AS servers, uniq(if(INB, SrcAddr, DstAddr)) AS peers
            FROM flows WHERE {self.where(sc)} GROUP BY cc""")}
        out = []
        for r in rows:
            cc = (r["cc"] or "").strip("\x00")   # FixedString(2): no GeoIP country = NUL bytes
            e = extra.get(cc, {})
            cc = cc or "??"
            out.append({"cc": cc, "name": cname(cc), "in_b": int(r["in_b"]), "out_b": int(r["out_b"]),
                        "flows": int(e.get("flows", 0)), "servers": int(e.get("servers", 0)), "peers": int(e.get("peers", 0)),
                        "top_asn": int(r["top_as"][0]) if r["top_as"] else 0,
                        "ll": META.get(cc, {}).get("ll")})
        self._names(out, "top_asn", "top_asname", sc)
        pairs = {}
        for r in self.q(sc, f"""
            SELECT if(INB, SrcCountry, DstCountry) AS cc, toUInt8(INB) AS inb, {IPS.format(c='SrcAddr')} AS src, {IPS.format(c='DstAddr')} AS dst,
                   sum(Bytes * SamplingRate) AS b, count() AS flows
            FROM flows WHERE {self.where(sc)} GROUP BY cc, inb, src, dst ORDER BY b DESC LIMIT 25 BY cc, inb""", ttl=30):
            pairs.setdefault((r["cc"] or "").strip("\x00") or "??", []).append(self.pair(r["src"], r["dst"], r["b"], r["flows"], "in" if r["inb"] else "out"))
        for c in out:
            c["pairs"] = merge_pairs(pairs.get(c["cc"], []))
        return out

    def pair(self, src, dst, b, flows, dir):
        """One source -> destination address pair for map tooltips, with operator names where known."""
        out = {"b": int(b), "flows": int(flows), "dir": dir}
        for side, ip in (("src", src), ("dst", dst)):
            # the public side of the firewall: an internal address is shown as the WAN address or WAN alias it is
            # reached on (its 1:1 NAT address, else the site's outbound NAT / WAN address), never as the LAN address
            pub = self.cfg.public_of(ip)
            fw = self.cfg.fw_label(pub) or ("WAN" if pub != ip else "")
            out[side], out[f"{side}_fw"] = pub, fw
            out[f"{side}_name"] = "" if fw else self.cfg.label(ip)
            # the internal server(s) behind that public address (a name, else the LAN address)
            inner = self.cfg.binat.get(ip) or (ip if pub != ip else "")
            out[f"{side}_inner"] = [self.cfg.label(inner) or inner] if inner else []
            out[f"{side}_rdns"] = self.rdns.get(pub)
        return out

    def top_remotes(self, sc: Scope, cc: str, limit=500):
        """The busiest remote endpoints in one country (for placing that country's traffic by region on the map)."""
        rows = self.q(sc, f"""
            SELECT {REMOTE_IP} AS ip, sumIf(Bytes * SamplingRate, INB) AS in_b, sumIf(Bytes * SamplingRate, OUTB) AS out_b, count() AS flows,
                   topKWeighted(1)({LOCAL_IP}, toUInt64(Bytes * SamplingRate)) AS loc
            FROM flows WHERE {self.where(sc)} AND if(INB, SrcCountry, DstCountry) = {{cc:String}}
            GROUP BY ip ORDER BY in_b + out_b DESC LIMIT {{l:UInt32}}""", {"cc": cc, "l": limit}, ttl=60)
        return [{"ip": r["ip"], "cc": cc, "in_b": int(r["in_b"]), "out_b": int(r["out_b"]), "flows": int(r["flows"]),
                 "pair": self._rpair(r["ip"], r["loc"], r["in_b"], r["out_b"], r["flows"])} for r in rows]

    def _rpair(self, remote, loc, in_b, out_b, flows):
        """A remote endpoint's busiest local partner, as source -> destination in its dominant direction."""
        if not loc:
            return None
        return self.pair(remote, loc[0], in_b + out_b, flows, "in") if in_b >= out_b else self.pair(loc[0], remote, in_b + out_b, flows, "out")

    def finding_traffic(self, sc: Scope, subject: str, peers: list[str]):
        """WAN-boundary traffic behind one finding: flows whose local side is the finding's subject address,
        plus any flow with a remote peer the finding names. Per remote, per country (map) and per destination port."""
        cond = [f"if(INB, {IPS.format(c='DstAddr')}, {IPS.format(c='SrcAddr')}) = {{subj:String}}"] if subject else []
        if peers:
            cond.append(f"has({{peers:Array(String)}}, {REMOTE_IP})")
        if not cond:
            return {"remotes": [], "countries": [], "ports": []}
        w = f"{self.where(sc)} AND ({' OR '.join(cond)})"
        x = {"subj": subject or "", "peers": peers}
        remotes = self.q(sc, f"""
            SELECT {REMOTE_IP} AS ip, any(if(INB, SrcCountry, DstCountry)) AS cc, any(if(INB, SrcAS, DstAS)) AS asn,
                   sumIf(Bytes * SamplingRate, INB) AS in_b, sumIf(Bytes * SamplingRate, OUTB) AS out_b, count() AS flows,
                   topK(8)(DstPort) AS ports, any(Proto) AS proto, topKWeighted(1)({LOCAL_IP}, toUInt64(Bytes * SamplingRate)) AS loc,
                   min(toUnixTimestamp(TimeReceived)) AS first, max(toUnixTimestamp(TimeReceived)) AS last
            FROM flows WHERE {w} GROUP BY ip ORDER BY has({{peers:Array(String)}}, ip) DESC, in_b + out_b DESC LIMIT 40""", x, ttl=60)   # named peers first, never cut off
        ports = self.q(sc, f"""
            SELECT DstPort AS port, Proto AS proto, count() AS flows, uniqExact({REMOTE_IP}) AS remotes,
                   sum(Bytes * SamplingRate) AS b, countIf(INB) AS in_flows, countIf(OUTB) AS out_flows,
                   if(Proto = 6, dictGetOrDefault('tcp', 'name', toUInt64(DstPort), ''),
                      if(Proto = 17, dictGetOrDefault('udp', 'name', toUInt64(DstPort), ''), '')) AS svc
            FROM flows WHERE {w} GROUP BY port, proto ORDER BY flows DESC LIMIT 30""", x, ttl=60)
        cc = self.q(sc, f"""
            SELECT if(INB, SrcCountry, DstCountry) AS cc, sumIf(Bytes * SamplingRate, INB) AS in_b, sumIf(Bytes * SamplingRate, OUTB) AS out_b,
                   count() AS flows, uniq({REMOTE_IP}) AS peers, topK(1)(if(INB, SrcAS, DstAS)) AS top_as
            FROM flows WHERE {w} GROUP BY cc ORDER BY in_b + out_b DESC LIMIT 250""", x, ttl=60)
        out_r = [{"ip": r["ip"], "cc": (r["cc"] or "").strip("\x00") or "??", "asn": int(r["asn"] or 0), "in_b": int(r["in_b"]), "out_b": int(r["out_b"]),
                  "flows": int(r["flows"]), "ports": sorted({int(p) for p in r["ports"]}), "proto": PROTO.get(int(r["proto"] or 0), str(r["proto"])),
                  "first": int(r["first"]), "last": int(r["last"]), "name": self.cfg.label(r["ip"]),
                  "pair": self._rpair(r["ip"], r["loc"], r["in_b"], r["out_b"], r["flows"])} for r in remotes]
        self._names(out_r, "asn", "asname", sc)
        for r in out_r:
            r["cc_name"] = cname(r["cc"])
        out_c = []
        for r in cc:
            c = (r["cc"] or "").strip("\x00") or "??"
            out_c.append({"cc": c, "name": cname(c), "in_b": int(r["in_b"]), "out_b": int(r["out_b"]), "flows": int(r["flows"]), "servers": 1 if subject else 0,
                          "peers": int(r["peers"]), "top_asn": int(r["top_as"][0]) if r["top_as"] else 0, "ll": META.get(c, {}).get("ll")})
        self._names(out_c, "top_asn", "top_asname", sc)
        out_p = [{"port": int(r["port"]), "proto": PROTO.get(int(r["proto"] or 0), str(r["proto"])), "service": r["svc"],
                  "flows": int(r["flows"]), "remotes": int(r["remotes"]), "bytes": int(r["b"]), "in_flows": int(r["in_flows"]), "out_flows": int(r["out_flows"])}
                 for r in ports]
        return {"remotes": out_r, "countries": out_c, "ports": out_p}

    def _names(self, rows, key, dest, sc):
        asns = sorted({int(r[key]) for r in rows if r.get(key)})
        names = {}
        if asns:
            for n in self.q(sc, "SELECT arrayJoin({a:Array(UInt32)}) AS asn, dictGetOrDefault('asns', 'name', toUInt64(asn), '') AS name",
                            {"a": asns}, ttl=3600):
                names[int(n["asn"])] = n["name"]
        for r in rows:
            r[dest] = names.get(int(r.get(key) or 0), "")
        return rows

    # ---- servers -----------------------------------------------------------------------
    def servers(self, sc: Scope, limit=500):
        rx = self.q(sc, f"""
            SELECT {IPS.format(c='DstAddr')} AS ip, sum(Bytes * SamplingRate) AS rx, count() AS flows,
                   uniq(SrcAddr) AS peers, uniqIf(SrcCountry, SrcCountry != '') AS countries,
                   toUInt32(max(TimeReceived)) AS last, topK(1)({IPS.format(c='SrcAddr')}) AS top_remote
            FROM flows WHERE {self.where(sc)} AND INB AND TOLAN GROUP BY DstAddr ORDER BY rx DESC LIMIT {{l:UInt32}}""",
                    {"l": limit})
        bins = self.cfg.binat
        exp = tuples(sorted({(e.public_ip, p) for e in self.cfg.exposures for p in range(e.lo, e.hi + 1) if e.public_ip not in bins}))
        btx = self.q(sc, f"""
            SELECT {IPS.format(c='SrcAddr')} AS src, sum(Bytes * SamplingRate) AS tx, toUInt32(max(TimeReceived)) AS last
            FROM flows WHERE {self.where(sc)} AND OUTB AND has({{bins:Array(String)}}, {IPS.format(c='SrcAddr')})
            GROUP BY SrcAddr""", {"bins": sorted(bins)}) if bins else []
        tx = self.q(sc, f"""
            SELECT {IPS.format(c='SrcAddr')} AS src, SrcPort AS sport, Proto AS proto, sum(Bytes * SamplingRate) AS tx,
                   toUInt32(max(TimeReceived)) AS last
            FROM flows WHERE {self.where(sc)} AND OUTB AND SrcAddr IN {PUBS}
              AND has({{exp:Array(Tuple(String, UInt16))}}, ({IPS.format(c='SrcAddr')}, SrcPort))
            GROUP BY SrcAddr, sport, proto""", {"exp": exp, "pubs": self.public_ips()})
        hosts = {}
        for r in rx:
            hosts[r["ip"]] = {"ip": r["ip"], "rx": int(r["rx"]), "tx": 0, "flows": int(r["flows"]), "peers": int(r["peers"]),
                              "countries": int(r["countries"]), "last": r["last"], "top_remote": (r["top_remote"] or [""])[0]}
        for t in btx:   # 1:1 NAT: everything the public address sends is that host's
            h = hosts.setdefault(bins[t["src"]], {"ip": bins[t["src"]], "rx": 0, "tx": 0, "flows": 0, "peers": 0, "countries": 0,
                                                  "last": 0, "top_remote": ""})
            h["tx"] += int(t["tx"])
            h["last"] = max(h["last"], t["last"])
        for t in tx:
            ip, _, _ = self.cfg.attribute_public(t["src"], t["sport"], PROTO.get(t["proto"], "tcp"))
            if ip:
                h = hosts.setdefault(ip, {"ip": ip, "rx": 0, "tx": 0, "flows": 0, "peers": 0, "countries": 0,
                                          "last": 0, "top_remote": ""})
                h["tx"] += int(t["tx"])
                h["last"] = max(h["last"], t["last"])
        att = self.nat_attribution(sc)
        for t in att["hosts"]:   # shared NAT: upload bytes matched to the LAN host that received the replies
            h = hosts.setdefault(t["host"], {"ip": t["host"], "rx": 0, "tx": 0, "flows": 0, "peers": 0, "countries": 0, "last": 0, "top_remote": ""})
            h["tx"] += t["bytes"]
            h["tx_nat"] = h.get("tx_nat", 0) + t["bytes"]
            h.setdefault("tx_conf", set()).add(t["confidence"])
        out = sorted(hosts.values(), key=lambda h: h["rx"] + h["tx"], reverse=True)
        for h in out:
            h["tx_conf"] = sorted(h.get("tx_conf", ()))
            a = self.cfg.asset(h["ip"])
            h["name"] = a["name"] if a["name"] != h["ip"] else ""
            h["role"], h["sensitive"] = a.get("role", "unknown"), bool(a.get("sensitive"))
            h["in_bps"], h["out_bps"] = h["rx"] * 8 / sc.span, h["tx"] * 8 / sc.span
        return {"servers": out, "unattributed_nat_tx": att["unattributed"], "nat_attribution": att}

    def nat_attribution(self, sc: Scope):
        """Attribute shared-NAT (post-NAT) upload bytes to LAN hosts from the return path.

        The WAN egress record of a NATed connection carries only the shared address. When the remote end answers, the
        reply leaves the LAN bridge towards the real host, and that record (InIf=WAN -> LAN, destination = host) is
        exported too. An egress group (remote address, remote port, protocol) is matched to the host(s) that received
        traffic from that same remote address and port: exactly one host in the same minute -> "high", in the same
        5 minutes -> "medium", anywhere in the window -> "low"; several hosts -> "ambiguous" (never split); none ->
        no LAN return path: unanswered, or originated by the firewall itself (an empty input interface alone does not
        prove that). TCP egress flows with SYN and never ACK are counted separately as unanswered attempts.
        The accounting boundary is unchanged (WAN egress bytes); this only says whose bytes they are."""
        nat = self.cfg.get("outbound_nat_ips", [])
        empty = {"hosts": [], "high": 0, "medium": 0, "low": 0, "ambiguous": 0, "no_return": 0, "unanswered": 0, "unanswered_flows": 0,
                 "unattributed": 0, "total": 0, "nat_ips": nat}
        if not nat:
            return empty
        ret = lambda bucket: f"""SELECT {bucket} AS b, SrcAddr AS x, SrcPort AS p, Proto AS pr, groupUniqArray(3)({IPS.format(c='DstAddr')}) AS hosts
                  FROM flows WHERE {self.where(sc)} AND INB AND TOLAN GROUP BY b, x, p, pr"""
        rows = self.q(sc, f"""
            WITH e AS (
                SELECT toStartOfMinute(TimeReceived) AS m, toStartOfFiveMinutes(TimeReceived) AS b5, DstAddr AS x, DstPort AS p, Proto AS pr,
                       sum(Bytes * SamplingRate) AS bytes,
                       countIf(Proto = 6 AND bitAnd(TCPFlags, 2) != 0 AND bitAnd(TCPFlags, 16) = 0) AS syn_only
                FROM flows WHERE {self.where(sc)} AND OUTB AND has({{nat:Array(String)}}, {IPS.format(c='SrcAddr')})
                GROUP BY m, b5, x, p, pr),
            r1 AS ({ret("toStartOfMinute(TimeReceived)")}),
            r5 AS ({ret("toStartOfFiveMinutes(TimeReceived)")}),
            w AS ({ret("toDateTime(0)")})
            SELECT multiIf(length(r1.hosts) = 1, 'high', length(r1.hosts) = 0 AND length(r5.hosts) = 1, 'medium',
                           length(r1.hosts) = 0 AND length(r5.hosts) = 0 AND length(w.hosts) = 1, 'low',
                           length(r1.hosts) > 1 OR length(r5.hosts) > 1 OR length(w.hosts) > 1, 'ambiguous', e.syn_only > 0, 'unanswered', 'no_return') AS conf,
                   multiIf(conf = 'high', r1.hosts[1], conf = 'medium', r5.hosts[1], conf = 'low', w.hosts[1], '') AS host,
                   sum(e.bytes) AS nbytes, sum(e.syn_only) AS syn_n, count() AS groups
            FROM e LEFT JOIN r1 ON e.m = r1.b AND e.x = r1.x AND e.p = r1.p AND e.pr = r1.pr
                   LEFT JOIN r5 ON e.b5 = r5.b AND e.x = r5.x AND e.p = r5.p AND e.pr = r5.pr
                   LEFT JOIN w ON e.x = w.x AND e.p = w.p AND e.pr = w.pr
            GROUP BY conf, host""", {"nat": nat}, ttl=30)
        out = {**empty, "hosts": []}
        for r in rows:
            out[r["conf"]] += int(r["nbytes"])
            out["total"] += int(r["nbytes"])
            out["unanswered_flows"] += int(r["syn_n"])
            if r["host"]:
                out["hosts"].append({"host": r["host"], "bytes": int(r["nbytes"]), "confidence": r["conf"]})
        out["unattributed"] = out["ambiguous"] + out["no_return"] + out["unanswered"]
        return out

    # ---- organizations / peers ----------------------------------------------------------
    def orgs(self, sc: Scope, limit=15):
        t = self.table_for(sc)
        rows = self.q(sc, f"""
            SELECT if(INB, SrcAS, DstAS) AS asn, sumIf(Bytes * SamplingRate, INB) AS in_b,
                   sumIf(Bytes * SamplingRate, OUTB) AS out_b, topK(1)(if(INB, SrcCountry, DstCountry)) AS cc
            FROM {t} WHERE {self.where(sc, t)} GROUP BY asn ORDER BY in_b + out_b DESC LIMIT {{l:UInt32}}""", {"l": limit})
        out = [{"asn": int(r["asn"]), "in_b": int(r["in_b"]), "out_b": int(r["out_b"]),
                "cc": (r["cc"] or [""])[0]} for r in rows]
        return self._names(out, "asn", "asname", sc)

    def remotes(self, sc: Scope, limit=15):
        rows = self.q(sc, f"""
            SELECT {REMOTE_IP} AS ip, any(if(INB, SrcCountry, DstCountry)) AS cc, any(if(INB, SrcAS, DstAS)) AS asn,
                   sumIf(Bytes * SamplingRate, INB) AS in_b, sumIf(Bytes * SamplingRate, OUTB) AS out_b, count() AS flows
            FROM flows WHERE {self.where(sc)} GROUP BY if(INB, SrcAddr, DstAddr) ORDER BY in_b + out_b DESC LIMIT {{l:UInt32}}""", {"l": limit})
        for r in rows:
            r["in_b"], r["out_b"], r["asn"] = int(r["in_b"]), int(r["out_b"]), int(r["asn"])
        return self._names(rows, "asn", "asname", sc)

    # ---- services -------------------------------------------------------------------------
    def services(self, sc: Scope, limit=15):
        exposed = self.q(sc, f"""
            SELECT {IPS.format(c='DstAddr')} AS ip, Proto AS proto, DstPort AS port, sum(Bytes * SamplingRate) AS b,
                   uniq(SrcAddr) AS clients, count() AS flows
            FROM flows WHERE {self.where(sc)} AND INB AND TOLAN AND DstPort < 32768
            GROUP BY DstAddr, proto, port ORDER BY b DESC LIMIT 400""")
        ex = []
        for r in exposed:
            p = PROTO.get(r["proto"], str(r["proto"]))
            if self.cfg.exposed(r["ip"], p, r["port"]):
                ex.append({"ip": r["ip"], "proto": p, "port": r["port"], "b": int(r["b"]), "clients": int(r["clients"]),
                           "name": self.cfg.asset(r["ip"])["name"], "mgmt": r["port"] in MGMT_PORTS,
                           "evidence": "Exposed service (port forward)"})
        used = self.q(sc, f"""
            SELECT Proto AS proto, SrcPort AS port, sum(Bytes * SamplingRate) AS b, uniq(DstAddr) AS servers,
                   if(Proto = 6, dictGetOrDefault('tcp', 'name', toUInt64(SrcPort), ''),
                      if(Proto = 17, dictGetOrDefault('udp', 'name', toUInt64(SrcPort), ''), '')) AS svc
            FROM flows WHERE {self.where(sc)} AND INB AND TOLAN AND (SrcPort < 1024 OR has({{svc:Array(UInt16)}}, SrcPort))
              AND DstPort >= 1024
            GROUP BY proto, port ORDER BY b DESC LIMIT {{l:UInt32}}""", {"l": limit})
        for u in used:
            u["proto"], u["b"], u["servers"] = PROTO.get(u["proto"], str(u["proto"])), int(u["b"]), int(u["servers"])
            u["evidence"] = "Port-based guess"
        return {"exposed": ex[:limit], "outbound": used}

    # ---- conversations ----------------------------------------------------------------------
    def conversations(self, sc: Scope, page=1, per=50, sort="bytes", direction="", proto=""):
        order = "last DESC" if sort == "time" else "rx DESC"
        # direction is inferred from which side used the service port (see the row's direction evidence)
        having = {"in": "HAVING svc_side = 'server'", "out": "HAVING svc_side = 'remote'",
                  "unknown": "HAVING svc_side = 'unknown'"}.get(direction, "")
        pnum = {"tcp": "Proto = 6", "udp": "Proto = 17", "icmp": "Proto IN (1, 58)", "other": "Proto NOT IN (1, 6, 17, 58)"}.get(proto)
        base = f"""
            SELECT {IPS.format(c='DstAddr')} AS server, {IPS.format(c='SrcAddr')} AS remote, Proto AS proto,
                   multiIf(SrcPort < 1024 OR has({{svc:Array(UInt16)}}, SrcPort), SrcPort,
                           DstPort < 32768, DstPort, 0) AS svc_port,
                   multiIf(SrcPort < 1024 OR has({{svc:Array(UInt16)}}, SrcPort), 'remote',
                           DstPort < 32768, 'server', 'unknown') AS svc_side,
                   sum(Bytes * SamplingRate) AS rx, sum(Packets) AS pkts, count() AS flows,
                   toUInt32(min(TimeReceived)) AS first, toUInt32(max(TimeReceived)) AS last,
                   any(SrcCountry) AS cc, any(SrcAS) AS asn, groupUniqArray(4)(DstPort) AS server_ports,
                   groupUniqArray(4)(SrcPort) AS remote_ports
            FROM flows WHERE {self.where(sc)} AND INB AND TOLAN{" AND " + pnum if pnum else ""}
            GROUP BY DstAddr, SrcAddr, proto, svc_port, svc_side {having}"""
        total = self.q(sc, f"SELECT count() AS n FROM ({base})")[0]["n"]
        rows = self.q(sc, f"{base} ORDER BY {order} LIMIT {{per:UInt32}} OFFSET {{off:UInt32}}",
                      {"per": per, "off": (page - 1) * per})
        for r in rows:
            proto = PROTO.get(r["proto"], str(r["proto"]))
            r["proto"] = proto
            r["rx"], r["pkts"], r["flows"], r["asn"] = int(r["rx"]), int(r["pkts"]), int(r["flows"]), int(r["asn"])
            a = self.cfg.asset(r["server"])
            r["server_name"] = a["name"] if a["name"] != r["server"] else ""
            if r["svc_side"] == "server" and self.cfg.exposed(r["server"], proto, r["svc_port"]):
                r["direction"], r["evidence"] = "Inbound to server", "Port forward (inventory)"
            elif r["svc_side"] == "remote":
                r["direction"], r["evidence"] = "Outbound from server", "Inferred from ports (remote used a service port)"
            elif r["svc_side"] == "server":
                r["direction"], r["evidence"] = "Inbound to server", "Inferred from ports — not a configured port forward"
            else:
                r["direction"], r["evidence"] = "Unknown", "Both ports ephemeral"
            r["service_evidence"] = ("Exposed service (port forward)" if r["evidence"].startswith("Port forward")
                                     else "Port-based guess" if r["svc_port"] else "Unknown")
            r["cc_name"] = cname(r["cc"] or "??")
            r["remote_name"] = self.cfg.label(r["remote"])
        self._names(rows, "asn", "asname", sc)
        self._fqdns(rows, sc)
        ports = sorted({(r["proto"], r["svc_port"]) for r in rows if r["svc_port"]})
        if ports:
            names = {(n["p"], n["port"]): n["name"] for n in self.q(sc, """
                SELECT tupleElement(t, 1) AS p, tupleElement(t, 2) AS port,
                       if(p = 'tcp', dictGetOrDefault('tcp', 'name', toUInt64(port), ''), dictGetOrDefault('udp', 'name', toUInt64(port), '')) AS name
                FROM (SELECT arrayJoin({pp:Array(Tuple(String, UInt16))}) AS t)""", {"pp": tuples(ports)}, ttl=3600)}
            for r in rows:
                r["service"] = names.get((r["proto"], r["svc_port"]), "") or (f"{r['proto']}/{r['svc_port']}" if r["svc_port"] else "—")
        else:
            for r in rows:
                r["service"] = "—"
        return {"rows": rows, "total": int(total), "page": page, "per": per,
                "note": "Observed conversations aggregated from flow records (not live connection state). "
                        "Bytes are remote → server; server → remote bytes are only attributable for port-forward replies."}

    # ---- novelty for a server -------------------------------------------------------------------
    def server_novelty(self, sc: Scope, days=14):
        p = {"b0": max(0, sc.start - days * 86400)}
        rows = self.q(sc, f"""
            SELECT 'country' AS kind, SrcCountry AS v FROM flows
            WHERE {self.where(sc)} AND INB AND TOLAN AND SrcCountry != ''
              AND SrcCountry NOT IN (SELECT SrcCountry FROM flows WHERE has({{exps:Array(String)}}, ExporterName)
                    AND TimeReceived >= toDateTime({{b0:UInt32}}) AND TimeReceived < toDateTime({{t0:UInt32}})
                    AND INB AND TOLAN AND {IPS.format(c='DstAddr')} = {{host:String}})
            GROUP BY v
            UNION ALL
            SELECT 'asn' AS kind, toString(SrcAS) AS v FROM flows
            WHERE {self.where(sc)} AND INB AND TOLAN AND SrcAS != 0
              AND SrcAS NOT IN (SELECT SrcAS FROM flows WHERE has({{exps:Array(String)}}, ExporterName)
                    AND TimeReceived >= toDateTime({{b0:UInt32}}) AND TimeReceived < toDateTime({{t0:UInt32}})
                    AND INB AND TOLAN AND {IPS.format(c='DstAddr')} = {{host:String}})
            GROUP BY v LIMIT 100""", p)
        return rows
