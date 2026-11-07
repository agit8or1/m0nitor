"""'What changed?': deterministic comparisons of two periods, as a short prioritized list of plain sentences.

Comparisons: today vs yesterday, this week vs last week, a selected period vs the one before, the same weekday and time
on previous weeks, or two custom periods. Days and weeks follow each firewall's time zone (DST-aware).

Honesty rules:
  - *Newly observed* means not seen in the history searched (stated with every item), never "newly created" or
    "newly exposed". When less history exists than asked for, confidence drops and the item says so.
  - Volumes are compared per hour *with telemetry*: hours without flow records are not treated as zero traffic. A
    period with incomplete data is flagged and lowers confidence.
  - "Contacted" uses the port heuristic the detector uses (service port on the remote side, ephemeral port locally);
    it is labelled as inferred.
  - A service counts as newly reachable only if the device *answered* outside clients from that port.
  - Outbound traffic through a shared NAT address cannot be tied to one device from WAN flow records; such items name
    the NAT address and say so.
  - A configuration change followed by new inbound traffic is an *association*, never presented as the cause.

All queries are parameterized, bounded (time span, LIMIT, ClickHouse max_execution_time) and cached for 5 minutes.
"""
import ipaddress
import threading
import time
from datetime import datetime, timedelta

from .core import expand_flow_sql, flow_predicates
from .dash import IPS, LOCAL_IP, cname
from .detect import human_bytes
from .ux import ratio_text, site_tz

MAX_SPAN = 31 * 86400
LOOKBACK_DAYS = 14
SHARED_DEMOTE = 35               # novelty on the shared NAT address is common and unattributable
MIN_BYTES = 100_000_000          # volume changes below this (per period) are not worth a line
VOLUME_FACTOR = 3.0
CACHE_TTL = 300
WATCH_CATEGORIES = {"IoT & peripherals", "Management", "Network"}   # devices where any new destination is notable
PRIORITY = {"telemetry": 95, "exposure": 90, "watch_dest": 85, "upload": 80, "config": 70, "new_device": 60, "new_country": 55,
            "download": 50, "new_network": 40, "decrease": 30, "coverage": 65}
MODES = {"day": "Today vs yesterday", "week": "This week vs last week", "period": "Selected period vs the period before",
         "weekday": "Same weekday and time on previous weeks", "custom": "Two custom periods"}
PERIOD_SPANS = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}

_cache, _lock = {}, threading.Lock()


# ---- periods ---------------------------------------------------------------------------------------------------
def _local_midnight(ts, tz):
    d = datetime.fromtimestamp(ts, tz)
    return datetime(d.year, d.month, d.day, tzinfo=tz)


def _same_local_time(base_day, ref, tz):
    """The local wall-clock time of `ref` placed on `base_day` (both aware datetimes), DST-correct."""
    return datetime(base_day.year, base_day.month, base_day.day, ref.hour, ref.minute, ref.second, tzinfo=tz)


def periods(mode, now, site=None, span="24h", a=None, b=None, weeks=4):
    """{"a": (start, end), "b": [(start, end), ...], "label_a", "label_b"} in epoch seconds. All windows end <= now."""
    tz = site_tz(site)
    now = int(now)
    if mode == "day":
        m = _local_midnight(now, tz)
        nowd = datetime.fromtimestamp(now, tz)
        y = _local_midnight((m - timedelta(hours=12)).timestamp(), tz)
        yend = _same_local_time(y, nowd, tz)
        return {"a": (int(m.timestamp()), now), "b": [(int(y.timestamp()), int(yend.timestamp()))],
                "label_a": f"today since 00:00 ({tz.key})", "label_b": f"yesterday 00:00–{nowd:%H:%M}"}
    if mode == "week":
        nowd = datetime.fromtimestamp(now, tz)
        mon = _local_midnight(now, tz) - timedelta(days=nowd.weekday())
        mon = datetime(mon.year, mon.month, mon.day, tzinfo=tz)
        prev = mon - timedelta(days=7)
        prev = datetime(prev.year, prev.month, prev.day, tzinfo=tz)
        pend = _same_local_time(prev + timedelta(days=nowd.weekday()), nowd, tz)
        return {"a": (int(mon.timestamp()), now), "b": [(int(prev.timestamp()), int(pend.timestamp()))],
                "label_a": "this week so far (from Monday)", "label_b": f"last week, same days up to {nowd:%a %H:%M}"}
    if mode == "weekday":
        s = PERIOD_SPANS.get(span, 3600) if span != "7d" else 86400
        a0d, nowd = datetime.fromtimestamp(now - s, tz), datetime.fromtimestamp(now, tz)
        bs = []
        for w in range(1, max(1, min(weeks, 8)) + 1):
            day0, day1 = a0d - timedelta(days=7 * w), nowd - timedelta(days=7 * w)
            bs.append((int(_same_local_time(day0, a0d, tz).timestamp()), int(_same_local_time(day1, nowd, tz).timestamp())))
        return {"a": (now - s, now), "b": bs, "label_a": f"the last {_span_txt(s)}",
                "label_b": f"the same {nowd:%A} hours on the previous {len(bs)} weeks"}
    if mode == "custom":
        (a0, a1), (b0, b1) = a, b
        for x0, x1 in (a, b):
            if not x0 < x1 or x1 - x0 > MAX_SPAN:
                raise ValueError("each period must have its end after its start and be at most 31 days")
        return {"a": (int(a0), min(int(a1), now)), "b": [(int(b0), min(int(b1), now))], "label_a": "period A", "label_b": "period B"}
    s = PERIOD_SPANS.get(span, 86400)
    return {"a": (now - s, now), "b": [(now - 2 * s, now - s)], "label_a": f"the last {_span_txt(s)}", "label_b": f"the {_span_txt(s)} before"}


def _span_txt(s):
    return f"{s // 3600} hours" if s < 86400 else "24 hours" if s == 86400 else f"{s // 86400} days"


# ---- queries ---------------------------------------------------------------------------------------------------
class Changes:
    def __init__(self, cfg, ch, conn):
        self.cfg, self.ch, self.conn = cfg, ch, conn

    def q(self, sites, sql, params):
        macros, fp = flow_predicates(self.cfg, sites)
        return self.ch.query(expand_flow_sql(sql, macros), {**fp, "exps": [s["exporter"] for s in sites],
                                                           "svc": self.cfg["service_ports"], **params})

    W = "ExporterName IN {exps:Array(String)} AND TimeReceived >= toDateTime({%s0:UInt32}) AND TimeReceived < toDateTime({%s1:UInt32})"

    def coverage(self, sites, t0, t1):
        """Share of 5-minute slots with flow records, per exporter (from Akvorado's 5-minute table: cheap)."""
        rows = self.q(sites, """SELECT ExporterName AS e, uniqExact(toStartOfFiveMinutes(TimeReceived)) AS slots FROM flows_5m0s
            WHERE ExporterName IN {exps:Array(String)} AND TimeReceived >= toDateTime({c0:UInt32}) AND TimeReceived < toDateTime({c1:UInt32})
            GROUP BY e""", {"c0": t0, "c1": t1})
        want = max(1, (t1 - t0) // 300)
        got = {r["e"]: min(1.0, r["slots"] / want) for r in rows}
        return {s["id"]: round(got.get(s["exporter"], 0.0), 3) for s in sites}

    def history_days(self, sites, before):
        r = self.q(sites, "SELECT toUInt32(min(TimeReceived)) AS t FROM flows_1h0m0s WHERE ExporterName IN {exps:Array(String)}", {})
        first = r[0]["t"] if r and r[0]["t"] else before
        return max(0.0, (before - first) / 86400)

    def volume(self, sites, t0, t1):
        return self.q(sites, f"""SELECT {LOCAL_IP} AS l, sumIf(Bytes * SamplingRate, INB) AS in_b, sumIf(Bytes * SamplingRate, OUTB) AS out_b,
                   count() AS n FROM flows WHERE {self.W % ('v', 'v')} AND (INB OR OUTB) AND NOT FWORIG
            GROUP BY l HAVING in_b + out_b >= {{minb:UInt64}} ORDER BY in_b + out_b DESC LIMIT 2000""",
                      {"v0": t0, "v1": t1, "minb": MIN_BYTES // 10})

    INIT = "(OUTB AND (has({svc:Array(UInt16)}, DstPort) OR DstPort < 1024) AND SrcPort >= 1024)"   # local opened it (inferred)
    # outbound records: the local side is SrcAddr. Lookbacks compare raw IPv6 columns (no per-row string formatting) and only
    # for devices active in the period, which keeps a 14-day lookback to a few seconds.

    def novel(self, sites, a0, a1, l0, what):
        """Outbound connections the device opened (inferred) to a network/country/address not seen in [l0, a0)."""
        col = {"asn": "DstAS", "cc": "DstCountry", "ip": "DstAddr"}[what]
        cond = {"asn": "DstAS != 0", "cc": "DstCountry != ''", "ip": "1"}[what]
        out = "toString(v)" if what != "ip" else IPS.format(c="v")
        return self.q(sites, f"""WITH a AS (
                SELECT SrcAddr AS lr, {col} AS v, any(DstAS) AS asn, any(DstCountry) AS cc, any(DstPort) AS port,
                       sum(Bytes * SamplingRate) AS b, count() AS n, uniqExact(DstAddr) AS peers, toUInt32(min(TimeReceived)) AS first
                FROM flows WHERE {self.W % ('a', 'a')} AND {self.INIT} AND NOT FWORIG AND {cond} GROUP BY lr, v HAVING n >= 2)
            SELECT {IPS.format(c='lr')} AS l, {out} AS v, asn, cc, port, b, n, peers, first FROM a
            WHERE (lr, v) NOT IN (SELECT DISTINCT SrcAddr, {col} FROM flows WHERE {self.W % ('l', 'l')} AND {self.INIT} AND NOT FWORIG
                                  AND SrcAddr IN (SELECT lr FROM a))
            ORDER BY b DESC LIMIT 300""", {"a0": a0, "a1": a1, "l0": l0, "l1": a0})

    ANS = ("OUTB AND NOT FWORIG AND SrcPort < 49152 AND DstPort >= 1024 "
           "AND (has({svc:Array(UInt16)}, SrcPort) OR SrcPort < 1024 OR SrcPort < DstPort)")

    def answered(self, sites, a0, a1, l0):
        """(device, service port) pairs that answered outside clients in A but never in [l0, a0): newly observed exposure."""
        return self.q(sites, f"""WITH a AS (
                SELECT SrcAddr AS lr, SrcPort AS port, any(Proto) AS proto, uniqExact(DstAddr) AS clients, sum(Bytes * SamplingRate) AS b,
                       count() AS n, toUInt32(min(TimeReceived)) AS first FROM flows WHERE {self.W % ('a', 'a')} AND {self.ANS}
                GROUP BY lr, port HAVING clients >= 2 AND n >= 4)
            SELECT {IPS.format(c='lr')} AS l, port, proto, clients, b, n, first FROM a
            WHERE (lr, port) NOT IN (SELECT DISTINCT SrcAddr, SrcPort FROM flows WHERE {self.W % ('l', 'l')} AND OUTB AND NOT FWORIG
                                     AND SrcAddr IN (SELECT lr FROM a))
            ORDER BY clients DESC LIMIT 200""", {"a0": a0, "a1": a1, "l0": l0, "l1": a0})

    def new_locals(self, sites, a0, a1, l0):
        """Internal addresses receiving internet traffic in A but not in [l0, a0)."""
        return self.q(sites, f"""WITH a AS (SELECT DstAddr AS lr, count() AS n, sum(Bytes * SamplingRate) AS b, toUInt32(min(TimeReceived)) AS first
                FROM flows WHERE {self.W % ('a', 'a')} AND INB AND TOLAN GROUP BY lr)
            SELECT {IPS.format(c='lr')} AS l, n, b, first FROM a
            WHERE lr NOT IN (SELECT DISTINCT DstAddr FROM flows WHERE {self.W % ('l', 'l')} AND INB AND TOLAN AND DstAddr IN (SELECT lr FROM a))
            ORDER BY n DESC LIMIT 200""", {"a0": a0, "a1": a1, "l0": l0, "l1": a0})

    def config_changes(self, sites, t0, t1):
        return self.ch.query("""SELECT site, toUInt32(ts) AS t, substring(message, 1, 300) AS m FROM netmon.sys_events
            WHERE site IN {sites:Array(String)} AND app = 'audit' AND message LIKE '%changed configuration%'
              AND ts >= toDateTime({t0:UInt32}) AND ts < toDateTime({t1:UInt32}) ORDER BY ts DESC LIMIT 200""",
                             {"sites": [s["id"] for s in sites], "t0": t0, "t1": t1})

    def source_slots(self, sites, t0, t1):
        """Hours with data per log source (firewall log, DNS, IDS) — for 'lost telemetry'."""
        p = {"sites": [s["id"] for s in sites], "t0": t0, "t1": t1}
        out = {}
        for name, table in (("firewall log", "netmon.fw_events"), ("DNS query log", "netmon.dns_events"), ("system log", "netmon.sys_events")):
            for r in self.ch.query(f"""SELECT site, uniqExact(toStartOfHour(ts)) AS h FROM {table}
                    WHERE site IN {{sites:Array(String)}} AND ts >= toDateTime({{t0:UInt32}}) AND ts < toDateTime({{t1:UInt32}}) GROUP BY site""", p):
                out[(r["site"], name)] = r["h"]
        return out

    # ---- compose ---------------------------------------------------------------------------------------------
    def compute(self, sites, per, now=None, lookback_days=LOOKBACK_DAYS):
        from . import access
        key = (tuple(s["id"] for s in sites), per["a"], tuple(per["b"]), lookback_days, access.allowed_key())  # labels differ per user
        with _lock:
            hit = _cache.get(key)
            if hit and time.time() - hit[0] < CACHE_TTL:
                return hit[1]
        res = self._compute(sites, per, now or time.time(), lookback_days)
        with _lock:
            _cache[key] = (time.time(), res)
            for k in [k for k, v in _cache.items() if time.time() - v[0] > CACHE_TTL]:
                _cache.pop(k, None)
        return res

    def _compute(self, sites, per, now, lookback_days):
        from concurrent.futures import ThreadPoolExecutor
        from . import identity as idn
        from .core import expected_devices, expected_match
        from .devtypes import category_of
        a0, a1 = per["a"]
        hours_a = max(1e-9, (a1 - a0) / 3600)
        hist = self.history_days(sites, a0)
        look = min(lookback_days, hist)
        l0 = int(a0 - look * 86400)
        # independent queries in parallel (each bounded by ClickHouse max_execution_time); failures are reported, not fatal
        jobs = {"cov_a": lambda: self.coverage(sites, a0, a1),
                "vol_a": lambda: self.volume(sites, a0, a1),
                "cc": lambda: self.novel(sites, a0, a1, l0, "cc"), "asn": lambda: self.novel(sites, a0, a1, l0, "asn"),
                "ans": lambda: self.answered(sites, a0, a1, l0), "newl": lambda: self.new_locals(sites, a0, a1, l0),
                "cfgc": lambda: self.config_changes(sites, a0, a1), "src_a": lambda: self.source_slots(sites, a0, a1)}
        for k, (b0, b1) in enumerate(per["b"]):
            jobs[f"cov_b{k}"] = lambda b0=b0, b1=b1: self.coverage(sites, b0, b1)
            jobs[f"vol_b{k}"] = lambda b0=b0, b1=b1: self.volume(sites, b0, b1)
            jobs[f"src_b{k}"] = lambda b0=b0, b1=b1: self.source_slots(sites, b0, b1)
        watch_known = any(category_of(a.get("kind", "")) in WATCH_CATEGORIES for a in (self.cfg.get("assets") or {}).values())
        if watch_known:
            jobs["ipn"] = lambda: self.novel(sites, a0, a1, l0, "ip")
        R, notes = {}, []
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = {k: pool.submit(f) for k, f in jobs.items()}
            cfg_f = {}
            for k, f in futs.items():
                try:
                    R[k] = f.result()
                except Exception as ex:
                    R[k] = None
                    notes.append(f"Part of the comparison is unavailable ({k}: {type(ex).__name__}).")
                if k == "cfgc" and R[k]:   # stage 2: before/after evidence for the latest configuration changes
                    for c in R[k][:3]:
                        st = self.cfg.site(c["site"]) or sites[0]
                        cfg_f[(c["site"], c["t"])] = pool.submit(self.answered, [st], c["t"], min(int(now), c["t"] + 86400), c["t"] - 86400)
            after_cfg = {}
            for key, f in cfg_f.items():
                try:
                    after_cfg[key] = f.result()[:3]
                except Exception:
                    after_cfg[key] = []
        nb = len(per["b"])
        cov_a = R["cov_a"] or {s["id"]: 0.0 for s in sites}
        cov_b = [R[f"cov_b{k}"] or {s["id"]: 0.0 for s in sites} for k in range(nb)]
        mean = lambda d: sum(d.values()) / max(1, len(d))  # noqa: E731
        ca, cb = mean(cov_a), (sum(mean(x) for x in cov_b) / max(1, nb))
        items = []
        complete = ca >= 0.9 and cb >= 0.9
        base_conf = "high" if complete and look >= lookback_days else "medium" if ca >= 0.6 and cb >= 0.6 else "low"
        if look < lookback_days:
            notes.append(f"Only {look:.1f} days of history exist before this period (asked for {lookback_days}); “newly observed” "
                         f"means not seen in those {look:.1f} days.")
        if not complete:
            notes.append(f"Telemetry is incomplete: flow records cover {ca:.0%} of {per['label_a']} and {cb:.0%} of {per['label_b']}. "
                         "Volumes are compared per hour with data; gaps are not counted as zero traffic.")
        exp = expected_devices(self.conn, now)
        labs = {}

        def dev(ip, site_id=None):
            if ip in labs:
                return labs[ip]
            inner = self.cfg.binat.get(ip)   # 1:1 NAT public address -> the one internal server behind it
            lab = idn.label(self.conn, self.cfg, inner or ip, site_id, ts=a1)
            if ip in self.cfg.get("outbound_nat_ips", []):
                lab.update(name="Shared NAT address", shared=True)
            lab["category"] = category_of(((self.cfg.get("assets") or {}).get(inner or ip) or {}).get("kind", ""))
            lab["internal"] = _internal(self.cfg, inner or ip)
            t = expected_match(exp, inner or ip) or expected_match(exp, ip)
            if t:
                lab["expected"] = exp[t].get("reason") or "marked expected"
            labs[ip] = lab
            return lab

        def ev_link(ip, rip="", t0=a0, t1=a1):
            from urllib.parse import urlencode
            p = {"range": "custom", "from": int(t0), "to": int(t1)}
            if rip:
                p["rip"] = rip
            if _internal(self.cfg, self.cfg.binat.get(ip, ip)):
                p["host"] = self.cfg.binat.get(ip, ip)
            elif not rip:
                p["rip"] = ip
            return "/netmon/connections?" + urlencode(p)

        # 1. telemetry and monitoring coverage (these change how much everything else can be trusted)
        for s in sites:
            a, b = cov_a.get(s["id"], 0), sum(x.get(s["id"], 0) for x in cov_b) / max(1, nb)
            if b - a >= 0.2 or (a < 0.5 and b >= 0.5):
                items.append(_item("telemetry", f"Traffic records from {s['name']} cover only {a:.0%} of {per['label_a']}",
                                   f"{b:.0%} in {per['label_b']}. Changes below are less certain for this firewall.", "high",
                                   "/netmon/coverage", site=s["id"], cur=a, prev=b))
        if R["src_a"] is not None and all(R[f"src_b{k}"] is not None for k in range(nb)):
            srcb = [R[f"src_b{k}"] for k in range(nb)]
            hb_hours = (per["b"][0][1] - per["b"][0][0]) / 3600
            for key in set().union(*[set(x) for x in srcb]):
                hb_rate = (sum(x.get(key, 0) for x in srcb) / nb) / max(1e-9, hb_hours)
                ha = R["src_a"].get(key, 0)
                if hb_rate >= 0.5 and ha / hours_a < 0.5 * hb_rate:
                    sid, name = key
                    s = self.cfg.site(sid) or {"name": sid}
                    items.append(_item("telemetry", f"{name.capitalize()} from {s['name']} went quiet",
                                       f"data in {ha} of {int(hours_a + .999)} hours, vs {hb_rate:.0%} of hours in {per['label_b']}.", "high",
                                       "/netmon/coverage", site=sid))
        for r in self.conn.execute("SELECT ts, user, detail FROM audit WHERE action='site_monitoring' AND ts>=? AND ts<?", (a0, a1)):
            items.append(_item("coverage", "Monitoring choices changed", f"by {r['user']}: switched off {r['detail']}", "high",
                               "/netmon/settings/sites"))

        # 2. volume per device, normalized per hour with data
        va = {r["l"]: r for r in (R["vol_a"] or [])}
        vbs = [{r["l"]: r for r in (R[f"vol_b{k}"] or [])} for k in range(nb)]
        if R["vol_a"] is not None and all(R[f"vol_b{k}"] is not None for k in range(nb)):
            cov_hours_a = hours_a * max(ca, 0.01)
            cov_hours_b = [max(1e-9, (b1 - b0) / 3600) * max(mean(c), 0.01) for (b0, b1), c in zip(per["b"], cov_b)]
            for ip in set(va) | set().union(*[set(x) for x in vbs]):
                for key, kind, verb in (("out_b", "upload", "uploaded"), ("in_b", "download", "received")):
                    cur = (va.get(ip) or {}).get(key, 0)
                    prev_rate = sum((x.get(ip) or {}).get(key, 0) / h for x, h in zip(vbs, cov_hours_b)) / max(1, nb)
                    cur_rate = cur / cov_hours_a
                    prev_equiv = prev_rate * cov_hours_a   # what the comparison period moved in the same number of hours
                    if cur >= MIN_BYTES and cur_rate >= VOLUME_FACTOR * max(prev_rate, 1):
                        d = dev(ip)
                        shared = " Many devices share this address; one device cannot be singled out from WAN records." if d.get("shared") else ""
                        items.append(_item(kind, f"{d['name']} {verb} {ratio_text(cur_rate, prev_rate)} its usual amount" if prev_rate else
                                           f"{d['name']} {verb} {human_bytes(cur)} with no comparable traffic before",
                                           f"{human_bytes(cur)} in {per['label_a']} vs about {human_bytes(prev_equiv)} for the same number of "
                                           f"hours in {per['label_b']}.{shared}", base_conf, ev_link(ip), device=d, cur=cur, prev=prev_equiv))
                    elif prev_equiv >= 10 * MIN_BYTES and cur_rate * VOLUME_FACTOR <= prev_rate and ca >= 0.9:
                        d = dev(ip)
                        if cur <= 0:   # nothing at all: say so plainly instead of "-100%"; the device may simply be off
                            items.append(_item("decrease", f"{d['name']} had no {'upload' if key == 'out_b' else 'download'} traffic in {per['label_a']}",
                                               f"about {human_bytes(prev_equiv)} for the same hours in {per['label_b']}. The device may be off, "
                                               "moved to another address, or a job stopped.", _cap(base_conf, "medium"), ev_link(ip, t0=per['b'][0][0], t1=per['b'][0][1]),
                                               device=d, cur=cur, prev=prev_equiv))
                        else:
                            items.append(_item("decrease", f"{d['name']} {verb} much less than usual ({ratio_text(cur_rate, prev_rate)})",
                                               f"{human_bytes(cur)} vs about {human_bytes(prev_equiv)} for the same hours in {per['label_b']}. "
                                               "A drop can mean a stopped job or service.", base_conf, ev_link(ip), device=d, cur=cur, prev=prev_equiv))

        # 3. newly observed destinations (connections the device opened; direction inferred from ports), one line per device
        hist_txt = f"not seen in the {look:.0f} days before" if look >= 1 else "no earlier history"
        for kind, rows, what in (("new_country", R["cc"], "countr"), ("new_network", R["asn"], "network")):
            by = {}
            for r in rows or []:
                by.setdefault(r["l"], []).append(r)
            for ip, rs in by.items():
                d = dev(ip)
                if kind == "new_network" and d["category"] in WATCH_CATEGORIES:
                    continue   # covered per address below
                names = [cname(r["v"]) if kind == "new_country" else f"AS{r['v']}" + (f" ({cname(r['cc'])})" if r["cc"] else "") for r in rs]
                n, b = sum(r["n"] for r in rs), sum(r["b"] for r in rs)
                label = (f"{'a country' if len(rs) == 1 else f'{len(rs)} countries'}" if kind == "new_country" else
                         f"{'a network' if len(rs) == 1 else f'{len(rs)} networks'}")
                title = (f"{d['name']} contacted {names[0]} for the first time" if len(rs) == 1 and kind == "new_country" else
                         f"{d['name']} contacted {label} it has not used before")
                if d.get("shared"):   # many devices behind one address: novelty is expected and cannot be pinned on one device
                    title = (f"Devices behind the shared NAT address contacted {label} not seen before")
                it = _item(kind, title, f"{', '.join(names[:8])}{' …' if len(names) > 8 else ''} · {n:,} connections, {human_bytes(b)} "
                           f"· first {_t(min(r['first'] for r in rs))} · {hist_txt}." + (" A country is not malicious by itself."
                                                                                      if kind == "new_country" else "")
                           + (" WAN records do not show which device behind the NAT address made these connections." if d.get("shared") else ""),
                           _cap(base_conf, "low" if d.get("shared") else "medium"), ev_link(ip), device=d, cur=b)
                if d.get("shared"):
                    it["priority"] -= SHARED_DEMOTE
                items.append(it)
        if R.get("ipn"):
            try:
                by = {}
                for r in R["ipn"]:
                    if dev(r["l"])["category"] in WATCH_CATEGORIES:
                        by.setdefault(r["l"], []).append(r)
                for ip, rs in by.items():
                    d = dev(ip)
                    first = rs[0]
                    items.append(_item("watch_dest", f"{d['name']} contacted {'a destination' if len(rs) == 1 else f'{len(rs)} destinations'} "
                                       "it has not used before",
                                       f"{first['v']} (AS{first['asn']}, {cname(first['cc'])}) port {first['port']}"
                                       f"{f' and {len(rs) - 1} more' if len(rs) > 1 else ''} · {sum(r['n'] for r in rs):,} connections · {hist_txt}. "
                                       "Devices like this usually talk to a fixed set of addresses.", base_conf, ev_link(ip, first["v"]), device=d))
            except Exception as ex:
                notes.append(f"Destination check for fixed-function devices unavailable ({type(ex).__name__}).")

        # 4. newly observed inbound exposure: services that answered outside clients
        for r in R["ans"] or []:
            d = dev(r["l"])
            items.append(_item("exposure", f"{d['name']} answered outside clients on {_proto(r['proto'])}/{r['port']} — newly observed",
                               f"{r['clients']} client address(es), {r['n']:,} connections, first {_t(r['first'])} · {hist_txt}. "
                               "This shows the service answered; it does not prove when it was opened.",
                               _cap(base_conf, "medium"), ev_link(r["l"]), device=d))

        # 5. newly observed devices
        for r in R["newl"] or []:
            d = dev(r["l"])
            items.append(_item("new_device", f"{d['name']} received internet traffic for the first time",
                               f"{r['n']:,} connections, first {_t(r['first'])} · {hist_txt}. Newly observed — the device may have "
                               "existed before without internet traffic.", _cap(base_conf, "medium"), ev_link(r["l"]), device=d))
        known = {(i["device"] or {}).get("ip") for i in items if i["kind"] == "new_device"}
        if self._identity_history_start() and self._identity_history_start() < a0:   # tracking began before A: creations are real news
            ids = ",".join("?" * len(sites))
            for r in self.conn.execute(f"SELECT id, site FROM identities WHERE status='active' AND basis IN ('mac','random-mac') "
                                       f"AND created_at>=? AND created_at<? AND site IN ({ids}) LIMIT 100", (a0, a1, *[s["id"] for s in sites])).fetchall():
                ip = idn.current_ip(self.conn, r["id"])
                if ip in known:
                    continue
                items.append(_item("new_device", f"{idn.name_of(self.conn, self.cfg, r['id'])} appeared on the network",
                                   f"first reported by the firewall's address tables at {ip or '?'} · newly observed by netmon.",
                                   "medium", f"/netmon/identities/{r['id']}", device=dev(ip, r["site"]) if ip else None))

        # 6. configuration changes, with before/after inbound evidence for the latest few (association only)
        for c in (R["cfgc"] or [])[:20]:
            s = self.cfg.site(c["site"]) or {"name": c["site"]}
            who, pg = _config_who(c["m"])
            assoc = ""
            after = after_cfg.get((c["site"], c["t"])) or []
            if after:
                svc = ", ".join(f"{dev(x['l'])['name']} {_proto(x['proto'])}/{x['port']}" for x in after)
                assoc = (f" After this change, inbound traffic to previously unseen service(s) was observed: {svc}. "
                         "This is an association in time, not proof that the change caused it.")
            items.append(_item("config", f"Configuration changed on {s['name']}" + (f" by {who}" if who else ""),
                               f"{_t(c['t'])}{' · ' + pg if pg else ''}.{assoc}", "high",
                               f"/netmon/changes/config?site={c['site']}&t={c['t']}", site=c["site"], raw=c["m"]))

        for x in items:   # expected devices: listed, labelled, never at the top
            if (x.get("device") or {}).get("expected"):
                x["priority"] -= 60
                x["detail"] += f" Expected device: {x['device']['expected']}."
        items.sort(key=lambda x: (-x["priority"], -(x.get("cur") or 0)))
        return {"items": items, "notes": notes, "coverage_a": cov_a, "coverage_b": cov_b, "history_days": round(hist, 1),
                "lookback_days": round(look, 1), "period": per, "complete": complete, "computed": time.time()}

    def _identity_history_start(self):
        r = self.conn.execute("SELECT min(created_at) FROM identities").fetchone()[0]
        return r or 0


def _item(kind, title, detail, confidence, link, device=None, site=None, cur=None, prev=None, raw=None):
    return {"kind": kind, "priority": PRIORITY.get(kind, 10), "title": title, "detail": detail, "confidence": confidence,
            "link": link, "device": device, "site": site or (device or {}).get("site"), "cur": cur, "prev": prev, "raw": raw}


def _cap(level, cap):
    order = ["low", "medium", "high"]
    return order[min(order.index(level), order.index(cap))]


def _t(ts):
    return time.strftime("%Y-%m-%d %H:%MZ", time.gmtime(ts)) if ts else "—"


def _proto(p):
    return {6: "tcp", 17: "udp"}.get(int(p or 0), str(p))


def _internal(cfg, ip):
    try:
        return cfg.is_internal(ip)
    except ValueError:
        return False


def _config_who(msg):
    """OPNsense audit line: 'user root@198.51.100.4 changed configuration to /conf/backup/... in /page.php ...'."""
    import re
    m = re.search(r"user (\S+?)(?:@(\S+))? changed configuration.* in (/[^\s?]+)", msg or "")
    if not m:
        return "", ""
    page = m.group(3).rsplit("/", 1)[-1].replace(".php", "").replace("_", " ")
    return m.group(1) + (f" from {m.group(2)}" if m.group(2) else ""), page


def valid_ip(v):
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return ""
