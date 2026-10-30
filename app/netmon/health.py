"""Health of the monitoring system itself: one check per source, evidence-backed, never optimistic.

Each check returns a state:
  ok              working, with evidence
  warn / fail     degraded / broken (thresholds configurable, Settings -> Coverage)
  awaiting        adapter present, no data source connected yet ("awaiting setup" / "awaiting traffic feed")
  not_configured  feature deliberately not set up (e.g. threat intelligence)
  unknown         cannot be measured with the access the monitor has

A quiet IDS is not a broken IDS: Suricata is judged by its transport (the same syslog stream that carries
firewall logs) and, where available, by its own heartbeat; "no alerts" is reported as such.

Alerting: a check that stays warn/fail for `consecutive` runs (after a startup grace period) opens one health
alert per check (de-duplicated by key, cooldown merges repeats); when it recovers for `consecutive` runs the
alert is closed and, if notifications are enabled for health, a recovery notice is sent. Health notifications
are OFF by default: alerts appear in the UI until an administrator enables them after a successful test.
"""
import glob
import json
import os
import re
import threading
import time

import httpx

from .core import audit, get_setting, get_state, put_setting, set_state

DEFAULTS = {
    "enabled": True, "notify": False, "grace_seconds": 600, "consecutive": 2, "cooldown_minutes": 60,
    "netflow_warn_s": 300, "netflow_fail_s": 900, "syslog_warn_s": 300, "syslog_fail_s": 900,
    "kafka_lag_warn": 100000, "parse_fail_pct": 2.0, "ingest_backlog_mb": 64, "ingest_delay_s": 120,
    "disk_warn_pct": 80, "disk_fail_pct": 90, "geoip_max_age_days": 14, "clock_drift_s": 30,
    "detector_stale_s": 900, "snmp_stale_s": 300,
}
LIMITS = {k: (1, 10 ** 9) for k in DEFAULTS if k not in ("enabled", "notify", "parse_fail_pct")} | {"parse_fail_pct": (0.01, 100)}
STATES = ("ok", "warn", "fail", "awaiting", "not_configured", "unknown")


def settings(conn):
    return {**DEFAULTS, **(get_setting(conn, "health", {}) or {})}


def save_settings(conn, form, user):
    s = settings(conn)
    for k, d in DEFAULTS.items():
        if isinstance(d, bool):
            s[k] = form.get(k) in ("1", "on", "true", True)
        elif k in form and str(form[k]).strip() != "":
            try:
                v = float(form[k]) if isinstance(d, float) else int(form[k])
            except ValueError:
                raise ValueError(f"{k}: not a number")
            lo, hi = LIMITS[k]
            if not lo <= v <= hi:
                raise ValueError(f"{k}: must be between {lo} and {hi}")
            s[k] = v
    put_setting(conn, "health", s, user)
    audit(conn, user, "health_settings", s)
    return s


def check(cid, group, label, state, value, last=None, evidence="", limits="", action=""):
    assert state in STATES
    return {"id": cid, "group": group, "label": label, "state": state, "value": value, "last": last,
            "evidence": evidence, "limits": limits, "action": action}


def _age(t):
    if not t:
        return "never"
    s = int(time.time() - t)
    return f"{s} s ago" if s < 120 else f"{s // 60} min ago" if s < 7200 else f"{s // 3600} h ago"


def prom(text):
    """Prometheus text -> {(name, frozenset(labels)): value}."""
    out = {}
    for line in text.splitlines():
        if not line or line[0] == "#":
            continue
        m = re.match(r'([a-zA-Z_:][\w:]*)(\{[^}]*\})?\s+([-+0-9.eE]+|NaN|\+Inf|-Inf)', line)
        if not m:
            continue
        labels = frozenset(re.findall(r'(\w+)="([^"]*)"', m.group(2) or ""))
        try:
            out[(m.group(1), labels)] = float(m.group(3))
        except ValueError:
            pass
    return out


def msum(metrics, name, **want):
    return sum(v for (n, labels), v in metrics.items() if n == name and all((k, x) in labels for k, x in want.items()))


class Health:
    def __init__(self, cfg, ch, conn, notifier=None, metrics_urls=None, log_dir=None, geo=None):
        self.cfg, self.ch, self.conn, self.notifier = cfg, ch, conn, notifier
        # config `akvorado_metrics: {}` = no Akvorado collector to watch (e.g. demo mode): reported as not configured
        self.metrics_urls = metrics_urls if metrics_urls is not None else cfg.get("akvorado_metrics", {
            "inlet": "http://akvorado-inlet:8080/api/v0/inlet/metrics", "outlet": "http://akvorado-outlet:8080/api/v0/outlet/metrics"})
        self.log_dir = log_dir or os.environ.get("NETMON_SYSLOG_DIR", "/var/log/netmon")
        self.geo = geo
        self.started = time.time()
        self.streak = {}          # check id -> (state, consecutive count)
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- checks
    def _metrics(self, which):
        try:
            return prom(httpx.get(self.metrics_urls[which], timeout=5).text), None
        except Exception as ex:
            return None, str(ex)[:120]

    def _delta(self, key, value):
        """Counter increase since the previous run (None on first sample or reset)."""
        prev, _ = get_state(self.conn, f"health:ctr:{key}", None)
        set_state(self.conn, f"health:ctr:{key}", {"v": value, "t": time.time()})
        if not prev or value < prev["v"]:
            return None
        return value - prev["v"]

    def collect(self):
        s = settings(self.conn)
        out = []
        for fn in (self.c_netflow, self.c_collector, self.c_syslog, self.c_suricata, self.c_clickhouse, self.c_storage,
                   self.c_geoip, self.c_notifications, self.c_detector, self.c_snmp, self.c_clock, self.c_optional):
            try:
                out += fn(s)
            except Exception as ex:
                out.append(check(f"internal:{fn.__name__}", "Monitor", fn.__name__, "unknown", "check failed", evidence=str(ex)[:200]))
        return out

    def c_netflow(self, s):
        rows = {r["e"]: r for r in self.ch.query(
            "SELECT ExporterName AS e, toUInt32(max(TimeReceived)) AS last, count() AS n FROM flows "
            "WHERE TimeReceived > now() - INTERVAL 1 DAY GROUP BY e", {})}
        out = []
        for site in self.cfg.sites:
            r = rows.get(site["exporter"])
            last = r["last"] if r else None
            age = time.time() - last if last else None
            st = "fail" if age is None or age > s["netflow_fail_s"] else "warn" if age > s["netflow_warn_s"] else "ok"
            out.append(check(f"netflow:{site['id']}", "Flows", f"NetFlow from {site['name']}", st,
                             f"last flow {_age(last)}", last, f"{int(r['n']):,} flow records in 24 h" if r else "no flow records in 24 h",
                             "Flow records are metadata only (no payload); see Coverage for what each boundary shows.",
                             "" if st == "ok" else "Check NetFlow export on the firewall (Reporting -> NetFlow) and UDP 2055 to the monitor."))
        return out

    def c_collector(self, s):
        out = []
        if not self.metrics_urls:
            return [check("collector", "Flows", "Flow collector (Akvorado)", "not_configured", "no collector metrics configured")]
        inl, err_i = self._metrics("inlet")
        outl, err_o = self._metrics("outlet")
        if inl is None or outl is None:
            return [check("collector", "Flows", "Flow collector (Akvorado)", "fail", "metrics unreachable", evidence=err_i or err_o,
                          action="Check the Akvorado containers (inlet, outlet, kafka, clickhouse).")]
        drops = msum(inl, "akvorado_inlet_flow_input_udp_in_dropped_packets_total") + msum(inl, "akvorado_inlet_flow_input_udp_errors_total")
        d = self._delta("udp_drops", drops)
        out.append(check("collector:udp", "Flows", "Collector UDP receive loss", "warn" if d else "ok",
                         f"{int(d)} dropped/errored datagrams since last check" if d is not None else "first sample",
                         evidence=f"inlet counters: {int(drops)} dropped/errored datagrams since collector start",
                         limits="Counts datagrams the collector socket dropped; loss on the network path before the monitor is not visible here.",
                         action="" if not d else "Increase the inlet UDP receive buffer or reduce export rate."))
        for site in self.cfg.sites:
            ex = site["exporter"]
            pk = msum(outl, "akvorado_outlet_flow_decoder_netflow_packets_total", exporter=ex) or \
                msum(outl, "akvorado_outlet_flow_decoder_netflow_packets_total")
            tp = msum(outl, "akvorado_outlet_flow_decoder_netflow_templates_total", exporter=ex) or \
                msum(outl, "akvorado_outlet_flow_decoder_netflow_templates_total")
            errs = sum(v for (n, labels), v in outl.items() if n.startswith("akvorado_outlet_flow_decoder") and "error" in n)
            de = self._delta(f"decode_err:{ex}", errs)
            st = "fail" if pk and not tp else "warn" if de else "ok"
            out.append(check(f"templates:{site['id']}", "Flows", f"NetFlow v9 templates and decoding ({ex})", st,
                             "no templates received" if pk and not tp else f"{int(tp)} template sets · {int(de or 0)} new decode errors",
                             evidence=f"{int(pk):,} NetFlow packets decoded since collector start",
                             action="" if st == "ok" else "Templates arrive periodically; restart the firewall NetFlow service if they never do."))
        lag = msum(outl, "akvorado_outlet_kafkainput_consumergroup_lag_messages")
        out.append(check("collector:kafka", "Flows", "Flow queue backlog (Kafka consumer lag)", "warn" if lag > s["kafka_lag_warn"] else "ok",
                         f"{int(lag):,} messages behind", evidence="outlet consumer-group lag",
                         limits="Kafka buffers up to its retention (1 day); a growing lag means ClickHouse inserts are not keeping up.",
                         action="" if lag <= s["kafka_lag_warn"] else "Check ClickHouse load and the outlet logs."))
        return out

    def _ingest_backlog(self):
        st, _ = get_state(self.conn, "ingest:offset", {})
        files = sorted(glob.glob(os.path.join(self.log_dir, "opnsense-*.log")))
        if not files:
            return None, 0
        cur, off = (st or {}).get("file"), (st or {}).get("offset", 0)
        total = 0
        for f in files:
            size = os.path.getsize(f)
            if cur and f < cur:
                continue
            total += size - off if f == cur else size
        return max(0, total), len(files)

    def c_syslog(self, s):
        out = []
        ing, ts = get_state(self.conn, "ingest", {})
        ing = ing or {}
        rows = {r["site"]: r for r in self.ch.query(
            "SELECT site, toUInt32(max(received)) AS last, toUInt32(maxIf(received, received > now() - 3600)) AS last1h, "
            "countIf(received > now() - 3600) AS n1h FROM netmon.fw_events WHERE received > now() - INTERVAL 2 DAY GROUP BY site", {})}
        for site in self.cfg.sites:
            if not site.get("syslog_source"):
                out.append(check(f"syslog:{site['id']}", "Logs", f"Firewall logs from {site['name']}", "awaiting", "remote syslog not configured",
                                 action="Settings -> Sites: set the syslog source, then configure remote syslog on the firewall."))
                continue
            r = rows.get(site["id"])
            last = r["last"] if r else None
            age = time.time() - last if last else None
            st = "awaiting" if not last else "fail" if age > s["syslog_fail_s"] else "warn" if age > s["syslog_warn_s"] else "ok"
            out.append(check(f"syslog:{site['id']}", "Logs", f"Firewall logs (filterlog) from {site['name']}", st, f"last line {_age(last)}", last,
                             f"{int(r['n1h']):,} firewall log records in the last hour" if r else "no firewall log records in 2 days",
                             "Only rules with logging enabled produce records.",
                             "" if st == "ok" else "Check System -> Settings -> Logging -> Remote on the firewall and rsyslog on the monitor."))
        lines = int(ing.get("lines") or 0)
        bad = sum(int(v) for k, v in (ing.get("unparsed") or {}).items() if "EVE preferred" not in k)
        d_lines, d_bad = self._delta("ingest_lines", lines), self._delta("ingest_bad", bad)
        pct = 100.0 * d_bad / d_lines if d_lines and d_bad is not None else 0.0
        out.append(check("ingest:parse", "Logs", "Log parsing", "warn" if pct > s["parse_fail_pct"] else "ok",
                         f"{pct:.2f}% of new lines unparsed" if d_lines else "no new lines since last check",
                         evidence=f"{lines:,} lines since ingester start, {bad:,} unparsed (by type: "
                                  f"{', '.join(f'{k}: {v}' for k, v in list((ing.get('unparsed') or {}).items())[:4]) or 'none'})",
                         limits="Unparsed lines are application messages without a parser; they are counted, not stored."))
        backlog, nfiles = self._ingest_backlog()
        delay = time.time() - ing["last_line"] if ing.get("last_line") else None
        err = ing.get("error")
        st = "fail" if err else "warn" if backlog and backlog > s["ingest_backlog_mb"] * 2 ** 20 else "ok"
        if backlog is None:
            st = "awaiting"
        out.append(check("ingest:queue", "Logs", "Log ingestion queue", st,
                         "no log files yet" if backlog is None else f"{backlog / 2 ** 20:.1f} MB not yet ingested · last line parsed {_age(ing.get('last_line'))}",
                         ing.get("last_line"), f"error: {err}" if err else f"{nfiles} rsyslog file(s) on disk",
                         "rsyslog files are the disk buffer: lines received while the ingester is down are read on restart.",
                         "" if st == "ok" else "See the app logs; ClickHouse inserts may be failing."))
        if delay is not None and delay > s["ingest_delay_s"] and backlog:
            out[-1]["state"] = "warn"
        return out

    def c_suricata(self, s):
        out = []
        rows = {r["site"]: r for r in self.ch.query(
            "SELECT site, toUInt32(max(received)) AS last, countIf(received > now() - 86400) AS n24, "
            "countIf(event_type = 'stats' AND received > now() - 3600) AS hb FROM netmon.ids_events GROUP BY site", {})}
        fw = {r["site"]: r["last"] for r in self.ch.query(
            "SELECT site, toUInt32(max(received)) AS last FROM netmon.fw_events WHERE received > now() - 3600 GROUP BY site", {})}
        for site in self.cfg.sites:
            r, tr = rows.get(site["id"]), fw.get(site["id"])
            transport_ok = bool(tr and time.time() - tr < s["syslog_fail_s"])
            if not r:
                st, val = "awaiting", "no Suricata event ever received"
            elif r["hb"]:
                st, val = "ok", f"heartbeat (EVE stats) in the last hour · last alert {_age(r['last'])}"
            elif transport_ok:
                st, val = "ok", f"transport healthy · {int(r['n24'])} alerts in 24 h (quiet is not failure)"
            else:
                st, val = "fail", "log transport silent"
            out.append(check(f"ids:{site['id']}", "Logs", f"Suricata IDS from {site['name']}", st, val, r["last"] if r else None,
                             "Judged by the syslog transport that also carries firewall logs; Suricata's own process state "
                             "needs the firewall API privilege for IDS status (not granted).",
                             "Alert mode only: no drop events, no full EVE DNS/TLS/HTTP streams.",
                             "" if st == "ok" else "Enable Suricata syslog/EVE output on the firewall (Settings -> Firewall logs tip)."))
        return out

    def c_clickhouse(self, s):
        t = time.time()
        try:
            self.ch.query("SELECT 1", {})
        except Exception as ex:
            return [check("db:clickhouse", "Storage", "ClickHouse", "fail", "query failed", evidence=str(ex)[:200],
                          action="Check the ClickHouse container and its disk.")]
        ms = (time.time() - t) * 1000
        out = [check("db:clickhouse", "Storage", "ClickHouse", "ok", f"responding in {ms:.0f} ms")]
        disks = self.ch.query("SELECT name, free_space AS f, total_space AS t FROM system.disks", {})
        for d in disks:
            pct = 100 * (1 - d["f"] / d["t"]) if d["t"] else 0
            st = "fail" if pct >= s["disk_fail_pct"] else "warn" if pct >= s["disk_warn_pct"] else "ok"
            out.append(check(f"disk:clickhouse:{d['name']}", "Storage", f"ClickHouse disk ({d['name']})", st,
                             f"{pct:.0f}% used · {d['f'] / 2 ** 30:.1f} GiB free"))
        # retention: data older than its TTL (+2 days of slack for part merges) means TTL deletes are failing
        ret = [("default.flows", "TimeReceived", 30), ("netmon.fw_events", "ts", 14), ("netmon.ids_events", "ts", 90)]
        late = []
        for tbl, col, days in ret:
            r = self.ch.query(f"SELECT toUInt32(min({col})) AS m FROM {tbl}", {})[0]["m"]
            if r and time.time() - r > (days + 2) * 86400:
                late.append(f"{tbl} keeps data from {_age(r)} (TTL {days} d)")
        out.append(check("db:retention", "Storage", "Retention (TTL deletes)", "warn" if late else "ok",
                         "; ".join(late) or "no table holds data beyond its retention",
                         evidence=", ".join(f"{t} {d} d" for t, _, d in ret)))
        return out

    def c_storage(self, s):
        out = []
        data = os.environ.get("NETMON_DATA_DIR", os.path.dirname(os.environ.get("NETMON_DB", "/data/netmon.db")))
        st = os.statvfs(data)
        pct = 100 * (1 - st.f_bavail / st.f_blocks)
        state = "fail" if pct >= s["disk_fail_pct"] else "warn" if pct >= s["disk_warn_pct"] else "ok"
        out.append(check("disk:app", "Storage", "Application data disk", state, f"{pct:.0f}% used · {st.f_bavail * st.f_frsize / 2 ** 30:.1f} GiB free"))
        res, _ = get_state(self.conn, "health:quick_check", None)
        if not res or time.time() - res["t"] > 3600:
            r = self.conn.execute("PRAGMA quick_check").fetchone()[0]
            res = {"t": time.time(), "r": r}
            set_state(self.conn, "health:quick_check", res)
        out.append(check("db:sqlite", "Storage", "Settings/alerts database (SQLite)", "ok" if res["r"] == "ok" else "fail",
                         f"integrity quick_check: {res['r']}", res["t"]))
        return out

    def c_geoip(self, s):
        out = []
        if self.geo:
            p = self.geo.provenance()
            if p.get("database"):
                built = time.mktime(time.strptime(p["built"], "%Y-%m-%d"))
                age_d = (time.time() - built) / 86400
                out.append(check("geoip", "Enrichment", "GeoIP country database", "warn" if age_d > s["geoip_max_age_days"] else "ok",
                                 f"{p['database']}, built {p['built']} ({age_d:.0f} days)", built,
                                 limits="Country-level only; the firewall's GeoIP alias uses its own source."))
            else:
                out.append(check("geoip", "Enrichment", "GeoIP country database", "fail", "not readable", evidence=p.get("error", "")))
        out.append(self.c_threatintel())
        return out

    def c_threatintel(self):
        from . import threatradar as tr
        ts = tr.settings(self.conn)
        lim = "Enrichment only: it lists vulnerabilities, not addresses. Findings never depend on it."
        if not ts["enabled"]:
            return check("threatintel", "Enrichment", "Threat intelligence (ExploitHound Threat Radar)", "not_configured", "turned off",
                         limits=lim, action="Security → Threat intel")
        st = tr.data(self.conn)
        if not st.get("fetched"):
            return check("threatintel", "Enrichment", "Threat intelligence (ExploitHound Threat Radar)", "fail" if st.get("error") else "warn",
                         "never fetched" + (f": {st['error']}" if st.get("error") else " yet"), limits=lim, action="Security → Threat intel")
        c = st.get("counts", {})
        stale = time.time() - st["fetched"] > 2 * ts["interval_hours"] * 3600 + 1800
        return check("threatintel", "Enrichment", "Threat intelligence (ExploitHound Threat Radar)", "warn" if stale or st.get("error") else "ok",
                     f"{sum(c.values()):,} CVEs ({c.get('confirmed', 0)} confirmed exploited, {c.get('predicted', 0)} predicted, "
                     f"{c.get('disclosed', 0)} new) · fetched {_age(st['fetched'])}", st["fetched"],
                     f"last fetch failed: {st['error']}" if st.get("error") else "", lim, "Security → Threat intel")

    def c_notifications(self, s):
        chans = self.conn.execute("SELECT count(*) FROM channels WHERE enabled=1").fetchone()[0]
        if not chans:
            return [check("notify", "Monitor", "Notification delivery", "not_configured", "no channel enabled")]
        r = self.conn.execute("SELECT sum(status='failed') AS f, sum(status='delivered') AS d, max(CASE WHEN status='delivered' THEN ts END) AS last "
                              "FROM deliveries WHERE ts > ?", (time.time() - 86400,)).fetchone()
        lf = self.conn.execute("SELECT detail, ts FROM deliveries WHERE status='failed' ORDER BY id DESC LIMIT 1").fetchone()
        st = "fail" if (r["f"] or 0) and not (r["d"] or 0) else "warn" if (r["f"] or 0) else "ok"
        return [check("notify", "Monitor", "Notification delivery", st, f"{int(r['d'] or 0)} delivered, {int(r['f'] or 0)} failed in 24 h",
                      r["last"], f"last failure: {lf['detail'][:120]}" if lf and st != "ok" else "",
                      f"Health alerts are {'sent' if s['notify'] else 'NOT sent (shown here only)'} to channels.")]

    def c_detector(self, s):
        d, _ = get_state(self.conn, "detector", {})
        last = (d or {}).get("last_run")
        st = "fail" if not last or time.time() - last > s["detector_stale_s"] else "warn" if (d or {}).get("errors") else "ok"
        return [check("detector", "Monitor", "Detector", st, f"last run {_age(last)}", last,
                      "; ".join((d or {}).get("errors") or [])[:200])]

    def c_snmp(self, s):
        out = []
        for site in self.cfg.sites:
            if not site.get("snmp"):
                out.append(check(f"snmp:{site['id']}", "Infrastructure", f"Interface/CPU/memory (SNMP) for {site['name']}", "not_configured",
                                 "SNMP not configured", action="Optional: Settings -> Sites -> SNMP (read-only v2c)."))
                continue
            for name in site["snmp"].get("interfaces", {}):
                st_, ts = get_state(self.conn, f"snmp:{site['id']}:{name}", None)
                state = "ok" if st_ and st_.get("ok") and ts and time.time() - ts < s["snmp_stale_s"] else "warn" if st_ else "awaiting"
                out.append(check(f"snmp:{site['id']}:{name}", "Infrastructure", f"Interface counters {name} ({site['name']})", state,
                                 f"last sample {_age(ts)}", ts, (st_ or {}).get("error", "")))
            sy, ts = get_state(self.conn, f"snmp:{site['id']}:system", None)
            if sy and sy.get("ok"):
                errs = {n: sum(v.values()) for n, v in sy.get("interfaces", {}).items()}
                d = {n: self._delta(f"iferr:{site['id']}:{n}", v) for n, v in errs.items()}
                mem = 100 * (1 - sy["mem_avail_kb"] / sy["mem_total_kb"]) if sy.get("mem_total_kb") else None
                bad = any(v for v in d.values())
                out.append(check(f"fwres:{site['id']}", "Infrastructure", f"Firewall resources ({site['name']})", "warn" if bad else "ok",
                                 f"CPU {100 - sy['cpu_idle_pct']:.0f}% · load {sy['load1']:.2f} · memory {mem:.0f}% used · "
                                 f"interface errors/discards: {', '.join(f'{n} +{int(v or 0)}' for n, v in d.items())}", ts,
                                 limits="State-table use and gateway latency need firewall API read privileges (not granted)."))
            elif sy:
                out.append(check(f"fwres:{site['id']}", "Infrastructure", f"Firewall resources ({site['name']})", "warn", "SNMP system query failed",
                                 ts, sy.get("error", "")))
        return out

    def c_clock(self, s):
        out = []
        r = self.ch.query("SELECT toUnixTimestamp(now()) AS n", {})[0]["n"]
        skew = r - time.time()
        out.append(check("clock:monitor", "Monitor", "Clock: app vs ClickHouse", "warn" if abs(skew) > s["clock_drift_s"] else "ok", f"{skew:+.1f} s"))
        for row in self.ch.query("SELECT site, quantileExact(0.5)(toUnixTimestamp(received) - toUnixTimestamp(ts)) AS d, count() AS n "
                                 "FROM netmon.fw_events WHERE received > now() - 600 GROUP BY site", {}):
            d = row["d"]
            out.append(check(f"clock:{row['site']}", "Monitor", f"Clock: firewall {row['site']} vs monitor", "warn" if abs(d) > s["clock_drift_s"] else "ok",
                             f"{d:+.0f} s (median of {int(row['n']):,} log lines)",
                             limits="Includes transport/ingest delay and 1 s timestamp resolution; measures drift only where logs flow."))
        return out

    def c_optional(self, s):
        """Optional sources: present only as adapters until data arrives."""
        out = []
        for cid, label, table, action in (
                ("dns", "DNS resolver logs", "netmon.dns_events", "See docs/dns-zeek-hostlogs.md (Unbound query logging via remote syslog, or Zeek dns.log)."),
                ("zeek", "Zeek sensor (internal traffic)", "netmon.zeek_conn", "Awaiting traffic feed: see docs/zeek-sensor.md (Proxmox bridge mirror, switch SPAN or firewall bridge span)."),
                ("hostlogs", "Server authentication logs", "netmon.auth_events", "See docs/dns-zeek-hostlogs.md (forward sshd/sudo logs via syslog).")):
            try:
                r = self.ch.query(f"SELECT toUInt32(max(received)) AS last, countIf(received > now() - 3600) AS n FROM {table}", {})[0]
            except Exception:
                r = {"last": 0, "n": 0}
            last = r["last"] or None
            st = "awaiting" if not last else "ok" if time.time() - last < 3600 else "warn"
            out.append(check(cid, "Optional", label, st, "awaiting setup" if not last else f"last event {_age(last)} · {int(r['n']):,} in 1 h",
                             last, action=action if st != "ok" else ""))
        return out

    # ---------------------------------------------------------------- alerting
    def run_once(self):
        s = settings(self.conn)
        res = self.collect()
        now = time.time()
        set_state(self.conn, "health", {"ts": now, "checks": res})
        if not s["enabled"] or now - self.started < s["grace_seconds"]:
            return res
        for c in res:
            bad = c["state"] in ("warn", "fail")
            prev_state, n = self.streak.get(c["id"], (None, 0))
            n = n + 1 if (prev_state in ("warn", "fail")) == bad else 1
            self.streak[c["id"]] = (c["state"], n)
            if n < s["consecutive"]:
                continue
            key = f"monitor|source_health|{c['id']}|{c['id']}"
            row = self.conn.execute("SELECT id, last_seen FROM alerts WHERE key=? AND status IN ('open','acked') ORDER BY id DESC LIMIT 1",
                                    (key,)).fetchone()
            if bad:
                title = f"{c['label']}: {c['value']}"
                if row and now - row["last_seen"] < s["cooldown_minutes"] * 60:
                    self.conn.execute("UPDATE alerts SET last_seen=?, count=count+1, title=?, severity=? WHERE id=?",
                                      (now, title, "high" if c["state"] == "fail" else "medium", row["id"]))
                    self.conn.commit()
                elif not row:
                    cur = self.conn.execute(
                        "INSERT INTO alerts(key,rule,severity,confidence,asset,subject,title,first_seen,last_seen,window_start,window_end,"
                        "evidence,query,baseline,alternatives,next_steps,akvorado_filter,site) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (key, "source_health", "high" if c["state"] == "fail" else "medium", "high", "monitor", c["id"], title, now, now,
                         now - 300, now, json.dumps([c], default=str), json.dumps({"sql": "", "params": {}}),
                         "Monitoring health check (Coverage page)", json.dumps(["A source stopped, or the monitor cannot reach it"]),
                         json.dumps([c["action"] or "Open Settings -> Coverage for evidence"]), "", self.cfg.sites[0]["id"]))
                    self.conn.commit()
                    audit(self.conn, "health", "alert_created", {"id": cur.lastrowid, "check": c["id"]})
                    if s["notify"] and self.notifier:
                        self.notifier.alert(cur.lastrowid)
            elif row and c["state"] == "ok":
                self.conn.execute("UPDATE alerts SET status='closed', acked_by='health', acked_at=?, title=title || ' — recovered' WHERE id=?",
                                  (now, row["id"]))
                self.conn.commit()
                audit(self.conn, "health", "alert_recovered", {"id": row["id"], "check": c["id"]})
                if s["notify"] and self.notifier and hasattr(self.notifier, "recovery"):
                    self.notifier.recovery(row["id"])
        return res

    def loop(self, interval=60):
        while True:
            try:
                self.run_once()
            except Exception as ex:
                set_state(self.conn, "health", {"ts": time.time(), "checks": [], "error": str(ex)[:300]})
            time.sleep(interval)
