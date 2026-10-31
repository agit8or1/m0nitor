"""Logged firewall blocks by country: the evidence behind the Countries map's "logged block events".

Source: OPNsense filterlog records with action block/reject (netmon.fw_events, via remote syslog). Not NetFlow, not
GeoIP alias membership and not IDS alerts. Each record is one packet the firewall logged as blocked; pf logs every
packet a logging block rule drops (blocked packets create no state), and its IP total length is in the record.

Direction is relative to the protected network (the site's internal + public networks):
  inbound  = external source -> one of our addresses   -> attributed to the source's country
  outbound = one of our addresses -> external destination -> attributed to the destination's country
Anything else (both ends ours, both external, private/link-local/multicast "external" ends) is "not attributable"
and counted separately, never given a country. Countries come from the same IPinfo country database Akvorado uses
for flow enrichment, so map traffic and block counts agree on where an address is; the firewall's GeoIP alias uses
OPNsense's own GeoIP source, which can differ for individual addresses.

Duplicates: identical records (same firewall, second, rule, interface, direction, addresses, ports, protocol,
length and TCP flags) are counted once - an ingestion retry re-inserts exactly such rows. Counts are per firewall
and summed across firewalls of the scope; two firewalls in an HA pair would log the same packet twice.
"""
import ipaddress
import os
import threading
import time

GEO_DB = os.environ.get("NETMON_GEOIP_DB", "/usr/share/GeoIP/country.mmdb")
STALE_AFTER = 900      # no firewall log line for 15 min -> feed is stale
_SPECIAL = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")]


class CsvGeo:
    """`network,country` CSV with the mmdb reader's interface (offline tests and demo mode; no real GeoIP data)."""

    def __init__(self, path):
        import bisect
        import csv
        self._bisect, rows = bisect, []
        with open(path) as fh:
            for r in csv.reader(fh):
                if r and not r[0].startswith("#"):
                    n = ipaddress.ip_network(r[0].strip(), strict=False)
                    rows.append((n.version, int(n.network_address), int(n.broadcast_address), r[1].strip().upper()))
        rows.sort()
        self._rows, self._keys, self.mtime = rows, [(v, lo) for v, lo, _, _ in rows], os.path.getmtime(path)

    def get(self, ip):
        a = norm(ip)
        i = self._bisect.bisect_right(self._keys, (a.version, int(a))) - 1
        if i >= 0:
            v, lo, hi, cc = self._rows[i]
            if v == a.version and lo <= int(a) <= hi:
                return {"country": cc}
        return None

    def metadata(self):
        class M:
            database_type, build_epoch = "csv (synthetic/offline)", self.mtime
        return M()


class Geo:
    """Country lookups from the mounted mmdb (read-only); results cached per address."""

    def __init__(self, path=GEO_DB):
        self.path, self._r, self._cache, self._lock, self.error = path, None, {}, threading.Lock(), None

    def _reader(self):
        if self._r is None:
            if self.path.endswith(".csv"):
                self._r = CsvGeo(self.path)
            else:
                import maxminddb
                self._r = maxminddb.open_database(self.path)
        return self._r

    def provenance(self):
        try:
            m = self._reader().metadata()
            return {"database": m.database_type, "built": time.strftime("%Y-%m-%d", time.gmtime(m.build_epoch)), "path": self.path}
        except Exception as ex:
            return {"database": None, "error": str(ex)[:160], "path": self.path}

    def cc(self, ip):
        with self._lock:
            hit = self._cache.get(ip)
        if hit is not None:
            return hit
        try:
            rec = self._reader().get(ip) or {}
            c = rec.get("country") or rec.get("country_code") or ""
            c = (c.get("iso_code", "") if isinstance(c, dict) else str(c)).upper()   # MaxMind layout / IPinfo layout
        except Exception as ex:
            self.error, c = str(ex)[:160], ""
        with self._lock:
            if len(self._cache) > 400_000:
                self._cache.clear()
            self._cache[ip] = c
        return c


def norm(ip):
    a = ipaddress.ip_address(ip)
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a


def kind(ours, ip, memo=None):
    """("ours" | "ext" | "special", normalized address string)."""
    if memo is not None and ip in memo:
        return memo[ip]
    a = norm(ip)
    k = ("ours" if any(a in n for n in ours) else "special" if any(a in n for n in _SPECIAL) else "ext", str(a))
    if memo is not None:
        memo[ip] = k
    return k


def classify(ours, src, dst, memo=None):
    """(direction, external address) relative to the protected networks `ours`; ("ambiguous", None) otherwise."""
    (sk, s), (dk, d) = kind(ours, src, memo), kind(ours, dst, memo)
    if sk == "ext" and dk == "ours":
        return "in", s
    if sk == "ours" and dk == "ext":
        return "out", d
    return "ambiguous", None


def blank():
    return {"in": 0, "out": 0, "in_geo": 0, "out_geo": 0, "in_bytes": 0, "out_bytes": 0, "last": 0, "ips": set(), "rules": {}}


def aggregate(rows, ours_by_site, geo_rids, lookup):
    """rows: one per (site, rid, iface, src, dst) with deduplicated `events`, `bytes`, `last`.
    Returns per-country counters plus the not-attributable and no-GeoIP-country buckets."""
    out, amb, nogeo = {}, {"events": 0, "bytes": 0}, {"events": 0, "bytes": 0}
    memo = {}
    for r in rows:
        d, ext = classify(ours_by_site.get(r["site"], []), r["src"], r["dst"], memo.setdefault(r["site"], {}))
        if d == "ambiguous":
            amb["events"] += r["events"]
            amb["bytes"] += r["bytes"]
            continue
        cc = lookup(ext)
        if not cc:
            nogeo["events"] += r["events"]
            nogeo["bytes"] += r["bytes"]
            continue
        c = out.setdefault(cc, blank())
        c[d] += r["events"]
        c[f"{d}_bytes"] += r["bytes"]
        if r["rid"] in geo_rids:
            c[f"{d}_geo"] += r["events"]
        c["last"] = max(c["last"], r["last"])
        c["ips"].add(ext)
        k = (r["site"], r["rid"], r["iface"], d)
        x = c["rules"].setdefault(k, [0, 0, 0])
        x[0], x[1], x[2] = x[0] + r["events"], x[1] + r["bytes"], max(x[2], r["last"])
    return out, amb, nogeo


BLOCK_SQL = """
SELECT site, rid, iface, replaceOne(IPv6NumToString(src), '::ffff:', '') AS src, replaceOne(IPv6NumToString(dst), '::ffff:', '') AS dst,
       count() AS events, sum(length) AS bytes, countIf(length = 0) AS nolen, toUInt32(max(ts)) AS last
FROM (SELECT DISTINCT site, ts, rid, iface, dir, src, dst, sport, dport, proto, length, tcpflags FROM netmon.fw_events
      WHERE has({sites:Array(String)}, site) AND action IN ('block', 'reject')
        AND ts >= toDateTime64({t0:UInt32}, 3) AND ts < toDateTime64({t1:UInt32}, 3))
GROUP BY site, rid, iface, src, dst"""


class Blocks:
    def __init__(self, cfg, ch, geo_policy, enforcer):
        self.cfg, self.ch, self.geo_policy, self.enforcer = cfg, ch, geo_policy, enforcer
        self.geo = Geo()
        self._cache, self._rules, self._lock = {}, {}, threading.Lock()
        self._latest, self._inflight = {}, set()   # newest result per (sites, window length); refreshes running

    # ---- firewall rule list: which block rules log (logging coverage) and rule names for drill-down ----
    def rules(self, site):
        with self._lock:
            hit = self._rules.get(site["id"])
            if hit and time.time() - hit["t"] < 300:
                return hit["v"]
        try:
            fw = self.enforcer(site)
            if not getattr(fw, "enabled", False) or not hasattr(fw, "_call"):
                raise RuntimeError("no OPNsense API access for this site")
            rows = fw._call("POST", "/api/firewall/filter/search_rule", data={"rowCount": "-1"}).get("rows", [])
            idx = {x["uuid"]: {"description": x.get("description", ""), "action": x.get("action", ""), "sequence": x.get("sequence"),
                               "interface": x.get("interface") or "floating", "log": x.get("log") in ("1", True),
                               "enabled": x.get("enabled") in ("1", True)} for x in rows if x.get("uuid")}
            v = {"known": True, "index": idx, "unlogged": [dict(u=u, **r) for u, r in idx.items()
                                                           if r["enabled"] and r["action"] in ("block", "reject") and not r["log"]]}
        except Exception as ex:
            v = {"known": False, "index": {}, "unlogged": [], "error": str(ex)[:160]}
        with self._lock:
            self._rules[site["id"]] = {"t": time.time(), "v": v}
        return v

    def coverage(self, sites, t0, t1):
        """Per-site log-feed state for the window: unavailable / stale / partial / ok."""
        rows = {r["site"]: r for r in self.ch.query(
            "SELECT site, toUInt32(min(received)) AS first, toUInt32(max(received)) AS last FROM netmon.fw_events "
            "WHERE has({sites:Array(String)}, site) GROUP BY site", {"sites": [s["id"] for s in sites]})}
        now, out = time.time(), []
        for s in sites:
            r, rl = rows.get(s["id"]), self.rules(s)
            x = {"site": s["id"], "name": s["name"], "first": r["first"] if r else None, "last": r["last"] if r else None,
                 "rules_known": rl["known"], "unlogged": [{"description": u["description"], "interface": u["interface"]} for u in rl["unlogged"]]}
            if not r:
                x["state"], x["note"] = "unavailable", "Blocked activity unavailable — connect firewall logs."
            elif now - r["last"] > STALE_AFTER:
                x["state"], x["note"] = "stale", f"Firewall log feed is stale: last line received {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(r['last']))}."
            elif rl["unlogged"]:
                x["state"], x["note"] = "partial", f"Logged blocks only; {len(rl['unlogged'])} block rule(s) are not logged."
            elif r["first"] > t0 + 60:
                x["state"], x["note"] = "partial", (f"Logged blocks only from {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(r['first']))}, "
                                                    "when log collection started; the earlier part of this window has no log data.")
            elif not rl["known"]:
                x["state"], x["note"] = "partial", "Logged blocks only; the firewall rule list could not be read, so logging coverage is unverified."
            else:
                x["state"], x["note"] = "ok", "All enabled block rules log."
            out.append(x)
        return out

    def stats(self, sites, t0, t1):
        """Per-country logged blocks for the sites and window (the map hover reads this one result).
        Cached for the window's life. For a rolling window ending now, the previous step's result is served while the
        new one is computed in the background (it carries its own `window`), so a page never waits on the window
        rolling over; historical windows are always computed exactly."""
        key = (tuple(s["id"] for s in sites), t0 // 60, t1 // 60)
        ttl = 300 if t1 - t0 > 86400 else 120 if t1 - t0 > 21600 else 60   # long windows: matches the scope rounding
        skey = (key[0], (t1 - t0) // 60)
        now = time.time()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit["t"] < ttl:
                return hit["v"]
            prev = self._latest.get(skey) if now - t1 < 2 * ttl else None
            if prev and now - prev["t"] < 3 * ttl:
                if key not in self._inflight:
                    self._inflight.add(key)
                    threading.Thread(target=self._refresh, args=(sites, t0, t1), daemon=True).start()
                return prev["v"]
        return self._compute(sites, t0, t1)

    def _refresh(self, sites, t0, t1):
        try:
            self._compute(sites, t0, t1)
        except Exception:
            pass   # the next request computes it on demand
        finally:
            with self._lock:
                self._inflight.discard((tuple(s["id"] for s in sites), t0 // 60, t1 // 60))

    def _compute(self, sites, t0, t1):
        key = (tuple(s["id"] for s in sites), t0 // 60, t1 // 60)
        geo_rids = set()
        for s in sites:
            try:
                for r in self.geo_policy(s).get("rules", []):
                    if r.get("blocks") and r.get("uuid"):
                        geo_rids.add(r["uuid"])
            except Exception:
                pass
        p = {"sites": [s["id"] for s in sites], "t0": int(t0), "t1": int(t1)}
        rows = self.ch.query(BLOCK_SQL, p)
        raw = self.ch.query("SELECT count() AS n FROM netmon.fw_events WHERE has({sites:Array(String)}, site) AND action IN ('block', 'reject') "
                            "AND ts >= toDateTime64({t0:UInt32}, 3) AND ts < toDateTime64({t1:UInt32}, 3)", p)[0]["n"]
        for r in rows:
            r["events"], r["bytes"] = int(r["events"]), int(r["bytes"])
        ours = {s["id"]: [ipaddress.ip_network(n) for n in self.cfg.site_ours(s)] for s in sites}
        per, amb, nogeo = aggregate(rows, ours, geo_rids, self.geo.cc)
        cov = self.coverage(sites, t0, t1)
        events = sum(r["events"] for r in rows)
        v = {"countries": per, "not_attributable": amb, "no_country": nogeo, "events": events, "duplicates": int(raw) - events,
             "bytes_complete": all(int(r["nolen"]) == 0 for r in rows), "geo_rules": sorted(geo_rids), "coverage": cov,
             "state": next((k for k in ("unavailable", "stale", "partial") if any(c["state"] == k for c in cov)), "ok"),
             "provenance": {"source": "OPNsense filterlog (remote syslog) · action block/reject", "geoip": self.geo.provenance()},
             "window": [int(t0), int(t1)]}
        if all(c["state"] == "unavailable" for c in cov):
            v["state"] = "unavailable"
        with self._lock:
            if len(self._cache) > 50:
                self._cache.clear()
            self._cache[key] = {"t": time.time(), "v": v}
            skey = (key[0], (t1 - t0) // 60)
            if t1 >= self._latest.get(skey, {}).get("end", 0):
                self._latest[skey] = {"t": time.time(), "v": v, "end": t1}
        return v

    def public(self, v):
        """JSON-safe view for the map: counts only (address sets stay server-side)."""
        return {**{k: x for k, x in v.items() if k != "countries"},
                "countries": {cc: {k: x for k, x in c.items() if k not in ("ips", "rules")} for cc, c in v["countries"].items()}}

    def events(self, sites, t0, t1, cc, limit=50):
        """Drill-down: the per-rule breakdown (from the same aggregate as the map) and the newest logged block
        records behind one country's count, with rule names, interface, firewall and timestamps."""
        v = self.stats(sites, t0, t1)
        c = v["countries"].get(cc)
        if not c:
            return {"rows": [], "by_rule": [], "summary": None}
        names = {s["id"]: s for s in sites}
        geo = set(v["geo_rules"])

        def rule(site, rid):
            ri = self.rules(names[site])["index"].get(rid, {})
            return ri.get("description") or (f"rule {rid[:12]}" if rid else "unknown rule")
        by = sorted(({"site": k[0], "firewall": names[k[0]]["name"], "rid": k[1], "iface": k[2], "direction": k[3], "rule": rule(k[0], k[1]),
                      "geoip_rule": k[1] in geo, "events": x[0], "bytes": x[1], "last": x[2]} for k, x in c["rules"].items()),
                    key=lambda r: -r["events"])
        p = {"sites": [s["id"] for s in sites], "t0": int(t0), "t1": int(t1), "lim": limit * 2}
        # a large country has thousands of addresses: too many for URL query parameters, so they go into the SQL body
        # (every entry is an ipaddress-normalized string, so the literal is safe)
        lit = "(" + ",".join(f"'{ipaddress.ip_address(x)}'" for x in sorted(c["ips"])) + ")"
        rows = []
        for side in ("src", "dst"):   # newest records with the country's addresses as source (inbound) and as destination (outbound)
            rows += self.ch.query(f"""SELECT toUnixTimestamp64Milli(ts) / 1000 AS ts, site, rid, rulenr, iface, dir, action, proto,
                replaceOne(IPv6NumToString(src), '::ffff:', '') AS src, replaceOne(IPv6NumToString(dst), '::ffff:', '') AS dst, sport, dport, length
                FROM (SELECT DISTINCT site, ts, rid, rulenr, iface, dir, action, src, dst, sport, dport, proto, length, tcpflags FROM netmon.fw_events
                      WHERE has({{sites:Array(String)}}, site) AND action IN ('block', 'reject')
                        AND ts >= toDateTime64({{t0:UInt32}}, 3) AND ts < toDateTime64({{t1:UInt32}}, 3)
                        AND replaceOne(IPv6NumToString({side}), '::ffff:', '') IN {lit})
                ORDER BY ts DESC LIMIT {{lim:UInt32}}""", p)
        rows.sort(key=lambda r: -r["ts"])
        ours = {s["id"]: [ipaddress.ip_network(n) for n in self.cfg.site_ours(s)] for s in sites}
        keep = []
        for r in rows:
            r["direction"], ext = classify(ours[r["site"]], r["src"], r["dst"])
            if ext in c["ips"]:
                r.update(rule=rule(r["site"], r["rid"]), geoip_rule=r["rid"] in geo, firewall=names[r["site"]]["name"])
                keep.append(r)
        per_dir = [r for d in ("in", "out") for r in [x for x in keep if x["direction"] == d][:limit]]   # up to `limit` of each direction
        return {"rows": sorted(per_dir, key=lambda r: -r["ts"]), "by_rule": by, "summary": self.public(v)["countries"][cc]}
