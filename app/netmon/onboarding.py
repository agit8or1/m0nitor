"""Per-site onboarding test: is each evidence source arriving, is it fresh, and how far can NAT attribution be trusted?

Four sources per firewall, each judged on its own data (never inferred from another source):
  wan_flows    flow records crossing the WAN interface (INB / OUTB for this exporter)
  lan_return   replies delivered to internal hosts on the same exporter (INB AND TOLAN, destination inside the site's
               internal networks). Impossible by design for capture (WAN-only) exporters.
  fw_logs      firewall log records (netmon.fw_events) from the site's syslog source
  nat          usable NAT evidence: shared NAT egress exists AND at least some of it pairs with LAN return flows
States: fresh | stale | missing | not_possible | not_configured. A source that is not fresh comes with the question the
technician cannot answer without it and the exporter / interface setting to inspect for this vendor.

Collection quality (export loss, duplicate exports, clock skew, asymmetric return paths) is recorded by the health
loop in state "attrq" and turned into CAPS: a recorded problem can only lower NAT attribution tiers (dash.nat_attribution),
never raise them. Unmeasured export-path loss is stated as a limit, not hidden.

Guided validation (optional): an operator generates known uploads from two hosts they own to a destination they are
authorised to use; netmon then shows what the attribution concluded for that destination, with ambiguous and
unanswered results kept as such. The app never generates traffic itself and never touches firewall settings.
"""
import ipaddress
import time

from . import access
from .core import get_state, set_state

TIERS = ("high", "medium", "low", "ambiguous", "no_return", "unanswered", "wan_only")
RANK = {"high": 3, "medium": 2, "low": 1}
TIER_TEXT = {"high": "one host, same minute", "medium": "one host, same 5 minutes", "low": "one host, same window",
             "ambiguous": "several hosts (not split)", "no_return": "no LAN return path", "unanswered": "unanswered attempts",
             "wan_only": "WAN-only capture (no LAN view)"}
DUP_FRAC = 0.01          # duplicate-record share above this is a duplicate export, not coincidence
LOSS_KEEP_S = 8 * 86400
FLOWDIAG_MAX_AGE = 30 * 86400
QKEY = "attrq"


# ------------------------------------------------------------------------------------------------ caps
def cap_tier(conf, max_tier):
    """The lower of two single-host tiers; non-host tiers are returned unchanged."""
    if conf not in RANK or max_tier not in RANK:
        return conf
    return conf if RANK[conf] <= RANK[max_tier] else max_tier


def caps(quality, sites, start, end):
    """{exporter: {"max": tier, "reasons": [...], "notes": [...]}} for the attribution window [start, end).

    - export loss recorded in the window (collector receive drops: every exporter; flowdiag sequence gaps: that site)
      -> at most "low": a lost return record can hide a second host, so "exactly one host" is no longer proof;
    - duplicate exports recorded in the window -> at most "medium": a second export path can add return records the
      pairing would otherwise not see, and bytes are counted twice;
    - no export-path loss measurement for the site in 30 days -> a note (stated limit), no cap.
    Clock skew does not cap: pairing uses the collector's receive time, so exporter clock error cannot move records
    into the same minute; it is reported by the onboarding test instead."""
    q = quality or {}
    out = {}
    for s in sites:
        c = {"max": "high", "reasons": [], "notes": []}
        for ev in q.get("loss", []):
            if start - 120 <= ev["ts"] <= end + 60 and ev.get("site") in (None, s["id"]):
                c["max"] = cap_tier(c["max"], "low")
                r = (f"export loss ({ev['source']}): {int(ev['n']):,} lost at {_ts(ev['ts'])}; a lost return record can hide "
                     "a second host, so single-host results are capped at low")
                if r not in c["reasons"]:
                    c["reasons"].append(r)
        for ev in q.get("dups", []):
            if start - 600 <= ev["ts"] <= end + 60 and ev.get("site") == s["id"] and ev["frac"] >= DUP_FRAC:
                c["max"] = cap_tier(c["max"], "medium")
                r = (f"duplicate flow exports: {100 * ev['frac']:.1f}% of records duplicated at {_ts(ev['ts'])}; capped at medium "
                     "(a second export path), bytes may be counted twice")
                if r not in c["reasons"]:
                    c["reasons"].append(r)
        fd = (q.get("flowdiag") or {}).get(s["id"])
        if not fd or end - fd["ts"] > FLOWDIAG_MAX_AGE:
            c["notes"].append(f"{s['name']}: loss on the export path has not been measured (no sequence-number check in 30 days); "
                              "high confidence assumes no records were lost on the way. Run the export check (Onboarding test).")
        if c["reasons"] or c["notes"]:
            out[s["exporter"]] = c
    return out


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(t)) if t else "—"


# ------------------------------------------------------------------------------------------------ quality recording
def load_quality(conn):
    q, _ = get_state(conn, QKEY, None)
    return q or {"loss": [], "dups": [], "flowdiag": {}, "dup_now": {}}


def _save(conn, q, now=None):
    now = now or time.time()
    q["loss"] = [x for x in q.get("loss", []) if now - x["ts"] < LOSS_KEEP_S][-500:]
    q["dups"] = [x for x in q.get("dups", []) if now - x["ts"] < LOSS_KEEP_S][-500:]
    set_state(conn, QKEY, q)


def record_loss(conn, n, source, site=None, now=None):
    """Export loss seen at `now`: collector receive drops (site None: affects every exporter) or a site's sequence gaps."""
    if not n:
        return
    q = load_quality(conn)
    q.setdefault("loss", []).append({"ts": now or time.time(), "n": int(n), "source": source, "site": site})
    _save(conn, q, now)


def record_duplicates(conn, per_site, now=None):
    """per_site: {site_id: {"rows": n, "dup": n}} for the last check interval. Shares >= DUP_FRAC become events."""
    now = now or time.time()
    q = load_quality(conn)
    q["dup_now"] = {}
    for sid, r in per_site.items():
        frac = r["dup"] / r["rows"] if r["rows"] else 0.0
        q["dup_now"][sid] = {"ts": now, "rows": int(r["rows"]), "dup": int(r["dup"]), "frac": round(frac, 4)}
        if r["rows"] >= 50 and frac >= DUP_FRAC:
            q.setdefault("dups", []).append({"ts": now, "site": sid, "frac": round(frac, 4), "rows": int(r["rows"])})
    _save(conn, q, now)


def record_flowdiag(conn, cfg, report, seconds, now=None):
    """Store a flowdiag (netmon.flowdiag) report per site: matched by the exporter address. Lost records and
    duplicated packets become quality events; clock drift is kept for the onboarding test."""
    now = now or time.time()
    q = load_quality(conn)
    by_ip = {str(s.get("exporter_ip")): s for s in cfg.all_sites if s.get("exporter_ip")}
    matched = []
    for r in report:
        s = by_ip.get(str(r.get("exporter")).replace("::ffff:", ""))
        if not s or r.get("protocol") == "malformed":
            continue
        q.setdefault("flowdiag", {})[s["id"]] = {"ts": now, "seconds": seconds, "protocol": r.get("protocol"), "packets": r.get("packets"),
                                                 "lost": r.get("lost", 0), "duplicates": r.get("duplicates", 0),
                                                 "clock_drift_s": r.get("clock_drift_s"), "issues": r.get("issues", [])}
        if r.get("lost"):
            q.setdefault("loss", []).append({"ts": now, "n": int(r["lost"]), "source": "flowdiag sequence gaps", "site": s["id"]})
        if r.get("duplicates") and r.get("packets"):
            q.setdefault("dups", []).append({"ts": now, "site": s["id"], "frac": round(r["duplicates"] / r["packets"], 4),
                                             "rows": int(r["packets"])})
        matched.append(s["id"])
    _save(conn, q, now)
    return matched


DUP_SQL = """SELECT ExporterName AS e, count() AS n,
       n - uniqExact(cityHash64(TimeReceived, SrcAddr, DstAddr, SrcPort, DstPort, Proto, Bytes, Packets, InIfName, OutIfName, TCPFlags)) AS dup
FROM flows WHERE TimeReceived > now() - 600 AND TimeReceived <= now() - 60 GROUP BY e"""


def measure_duplicates(ch, sites):
    """Identical flow records (same second, addresses, ports, protocol, bytes, packets, interfaces, flags) per exporter
    over the last 10 minutes. Independent connections practically never coincide on all of these."""
    rows = {r["e"]: r for r in ch.query(DUP_SQL, {})}
    return {s["id"]: {"rows": int(rows[s["exporter"]]["n"]), "dup": int(rows[s["exporter"]]["dup"])}
            for s in sites if s["exporter"] in rows}


# ------------------------------------------------------------------------------------------------ vendor guidance
CANNOT = {
    "wan_flows": "How much traffic crossed the internet link, to which countries and organisations, and which published "
                 "services were reached. Without WAN flows every traffic page for this firewall is empty or out of date.",
    "lan_return": "Which internal host is behind the shared NAT address for an outbound connection (per-host uploads stay "
                  "'unattributed'), and which internal host an inbound connection was delivered to.",
    "fw_logs": "What the firewall blocked and which rule allowed or denied a connection. Flows only describe passed traffic, "
               "so blocked attempts, scans and denied outbound connections are invisible.",
    "nat": "Which internal host uploaded data through the shared NAT address. Per-host outbound volume, data-exfiltration "
           "checks and fan-out findings can name only the NAT address.",
}
INSPECT = {
    "opnsense": {
        "wan_flows": "Reporting → NetFlow: Listening interfaces include WAN, WAN interfaces = WAN, Destinations = {MON}:2055, "
                     "version v9. Settings → Firewalls & sites: the exporter address must be {EXIP} and the WAN interface name "
                     "{WAN} must match the records (see 'interfaces seen').",
        "lan_return": "Reporting → NetFlow → Listening interfaces must include the LAN (or LAN bridge) interface, and Firewalls & "
                      "sites → LAN interface must name it ({LAN}). Without it only WAN-side records arrive.",
        "fw_logs": "System → Settings → Logging → Remote: {MON}:5514, TCP, RFC 5424, application filterlog; enable 'Log' on the "
                   "rules you care about. Firewalls & sites → syslog source must be the sending address ({SYS}).",
        "nat": "Firewall → NAT → Outbound: note the shared address(es) and enter them under Firewalls & sites → outbound NAT "
               "addresses ({NAT}). LAN return flows must arrive on the same exporter.",
    },
    "pfsense": {
        "wan_flows": "Services → softflowd: Interface = WAN, Host {MON}, Port 2055, NetFlow version 9 (or 10 = IPFIX), flow "
                     "tracking level 'full'. The exporter address must be {EXIP}.",
        "lan_return": "softflowd on WAN only (capture mode, the default) never exports the LAN side, so this is not possible "
                      "for this profile as configured. A second softflowd instance on the LAN interface is not validated "
                      "with m0nitor yet (docs/field-validation.md); until then shared-NAT uploads stay 'wan_only'.",
        "fw_logs": "Status → System Logs → Settings → Remote Logging: server {MON}:5514 (UDP), contents 'Firewall Events'. "
                   "Firewalls & sites → syslog source must be the sending address ({SYS}).",
        "nat": "Firewall → NAT → Outbound: enter the shared address(es) under Firewalls & sites ({NAT}). With WAN-only "
               "softflowd only 1:1 NAT and port forwards are attributable.",
    },
    "fortigate": {
        "wan_flows": "config system netflow: collector {MON} port 2055 (FortiOS 7.2+: config collectors), and on the WAN "
                     "interface `set netflow-sampler both`. The exporter address must be {EXIP}; WAN interface name {WAN}.",
        "lan_return": "`set netflow-sampler both` on the internal (LAN) interface as well, and Firewalls & sites → LAN interface "
                      "= its name ({LAN}). Not yet validated on FortiGate hardware (docs/field-validation.md).",
        "fw_logs": "config log syslogd setting: server {MON}, port 5514, mode reliable, format default; config log syslogd "
                   "filter: forward-traffic enable. Policies need 'Log Allowed Traffic' or 'Log Violation Traffic'.",
        "nat": "Note the policy's NAT (interface address or IP pool) and enter those addresses under Firewalls & sites ({NAT}).",
    },
    "generic": {
        "wan_flows": "Flow export (NetFlow v9 / IPFIX) on the WAN interface towards {MON}:2055, both directions, from address {EXIP}.",
        "lan_return": "Flow export must include the LAN-facing interface (records leaving towards internal hosts) and Firewalls & "
                      "sites → LAN interface must name it ({LAN}).",
        "fw_logs": "Remote syslog towards {MON}:5514 (TCP preferred) from {SYS}; a vendor parser is needed for allow/deny decisions.",
        "nat": "Enter the shared outbound NAT address(es) under Firewalls & sites ({NAT}).",
    },
}


def inspect_text(site, key, cfg, monitor="MONITOR"):
    t = (INSPECT.get(site.get("vendor") or "generic") or INSPECT["generic"])[key]
    nat = ", ".join(nat_ips(cfg, site)) or "not set"
    return (t.replace("{MON}", monitor).replace("{EXIP}", str(site.get("exporter_ip") or "not set"))
            .replace("{WAN}", str(site.get("wan_if") or "not set")).replace("{LAN}", str(site.get("lan_if") or "not set"))
            .replace("{SYS}", str(site.get("syslog_source") or "not set")).replace("{NAT}", nat))


def nat_ips(cfg, site):
    return sorted(site.get("outbound_nat_ips") or [])     # the site's own (first site: legacy top-level list)


# ------------------------------------------------------------------------------------------------ evaluation
def _state(last, now, warn, fail):
    if not last:
        return "missing"
    age = now - last
    return "fresh" if age <= warn else "stale"


def evaluate(cfg, ch, dash, conn, site, now=None, monitor="MONITOR"):
    """Onboarding result for one firewall (must be one the request may see). Small aggregates over the last hour/day."""
    from .health import settings
    from .ux import monitored
    access.require(site["id"])
    now = now or time.time()
    hs = settings(conn)
    sc = dash.scope(site=site["id"], range_key="15m")
    sc24 = dash.scope(site=site["id"], range_key="24h")
    capture = site.get("flow_mode") == "capture"
    src = {}

    # exporter rows at all, and how they split by boundary: a name mismatch shows as rows that are neither INB nor OUTB.
    # The last hour answers "arriving and fresh"; the 24 h scan runs only when the last hour is empty (quiet or broken).
    wan_sql = """SELECT toUInt32(maxIf(TimeReceived, INB OR OUTB)) AS last, countIf(INB OR OUTB) AS n1h,
               countIf(INB) AS inb, countIf(OUTB) AS outb, toUInt32(max(TimeReceived)) AS any_last, count() AS any_n,
               topK(4)(InIfName) AS in_ifs, topK(4)(OutIfName) AS out_ifs
               FROM flows WHERE ExporterName IN {exps:Array(String)} AND TimeReceived > now() - {win:UInt32}"""
    f = (dash.q(sc24, wan_sql, {"win": 3600}) or [{}])[0]
    if not f.get("last"):
        g = (dash.q(sc24, wan_sql, {"win": 86400}) or [{}])[0]
        f = {**g, "n1h": f.get("n1h", 0), "inb": f.get("inb", 0), "outb": f.get("outb", 0)}
    st = _state(f.get("last"), now, hs["netflow_warn_s"], hs["netflow_fail_s"])
    ifs = sorted({x for x in (f.get("in_ifs") or []) + (f.get("out_ifs") or []) if x})
    ev = (f"{int(f.get('n1h') or 0):,} WAN flow records in the last hour ({int(f.get('inb') or 0):,} inbound, "
          f"{int(f.get('outb') or 0):,} outbound)")
    warn = ""
    if f.get("any_n") and not f.get("last"):
        st = "missing"
        warn = (f"{int(f['any_n']):,} records arrived from this exporter but none on WAN interface '{site.get('wan_if')}': "
                f"interfaces seen {', '.join(ifs) or 'none (ifindex not mapped)'}. Fix the WAN interface name.")
    elif st == "fresh" and (not f.get("inb") or not f.get("outb")):
        warn = "Only one direction arrives: check that the exporter samples both ingress and egress on the WAN interface."
    src["wan_flows"] = {"label": "WAN flows", "state": st if monitored(site, "flows") else "not_configured", "last": f.get("last"),
                        "evidence": ev, "warn": warn, "interfaces": ifs}

    # LAN return flows (internal destination on the same exporter)
    if capture:
        src["lan_return"] = {"label": "LAN return flows", "state": "not_possible", "last": None,
                             "evidence": "WAN-only capture exporter: records show the NAT address, never the internal host", "warn": ""}
    elif not site.get("lan_if"):
        src["lan_return"] = {"label": "LAN return flows", "state": "not_configured", "last": None,
                             "evidence": "no LAN interface configured for this firewall", "warn": ""}
    else:
        inets = [str(n) for n in (site.get("internal_nets") or [])] or [str(n) for n in cfg.internal_nets]
        lan_sql = """SELECT toUInt32(max(TimeReceived)) AS last, count() AS n1h, uniqExact(DstAddr) AS hosts
                   FROM flows WHERE ExporterName IN {exps:Array(String)} AND TimeReceived > now() - {win:UInt32} AND INB AND TOLAN
                   AND arrayExists(n -> isIPAddressInRange(replaceOne(IPv6NumToString(DstAddr), '::ffff:', ''), n), {inets:Array(String)})"""
        r = (dash.q(sc24, lan_sql, {"inets": inets, "win": 3600}) or [{}])[0]
        if not r.get("last"):
            r = {**(dash.q(sc24, lan_sql, {"inets": inets, "win": 86400}) or [{}])[0], "n1h": 0, "hosts": 0}
        st = _state(r.get("last"), now, hs["netflow_warn_s"], hs["netflow_fail_s"])
        src["lan_return"] = {"label": "LAN return flows", "state": st, "last": r.get("last") or None,
                             "evidence": f"{int(r.get('n1h') or 0):,} replies delivered to {int(r.get('hosts') or 0):,} internal hosts in the last hour",
                             "warn": ""}

    # firewall logs
    if not site.get("syslog_source") or not monitored(site, "syslog"):
        src["fw_logs"] = {"label": "Firewall logs", "state": "not_configured", "last": None, "evidence": "remote syslog not configured", "warn": ""}
    else:
        fw_sql = ("SELECT toUInt32(max(received)) AS last, count() AS n1h, countIf(action = 'block') AS blk FROM netmon.fw_events "
                  "WHERE site = {s:String} AND received > now() - {win:UInt32}")
        r = (ch.query(fw_sql, {"s": site["id"], "win": 3600}) or [{}])[0]
        if not r.get("last"):
            r = {**(ch.query(fw_sql, {"s": site["id"], "win": 172800}) or [{}])[0], "n1h": 0, "blk": 0}
        st = _state(r.get("last"), now, hs["syslog_warn_s"], hs["syslog_fail_s"])
        src["fw_logs"] = {"label": "Firewall logs", "state": st, "last": r.get("last") or None,
                          "evidence": f"{int(r.get('n1h') or 0):,} log records in the last hour ({int(r.get('blk') or 0):,} blocks)",
                          "warn": "Records exist only for rules with logging enabled; a quiet log is not proof nothing was blocked."}

    # NAT evidence: shared-NAT egress that pairs with return flows
    nat = nat_ips(cfg, site)
    quality = load_quality(conn)
    att = dash.nat_attribution(sc, quality=quality) if nat else None
    if not nat:
        src["nat"] = {"label": "Usable NAT evidence", "state": "not_configured", "last": None,
                      "evidence": "no shared outbound NAT address configured (1:1 NAT and port forwards are still attributed)", "warn": ""}
    else:
        usable = att["high"] + att["medium"] + att["low"]
        pct = (lambda k: 100.0 * att[k] / att["total"]) if att["total"] else (lambda k: 0.0)
        st = "fresh" if usable else "missing"
        if capture:
            st = "not_possible"
        ev = (f"last 15 minutes: {att['total'] / 2 ** 20:.1f} MB shared-NAT egress; " +
              ", ".join(f"{pct(k):.0f}% {TIER_TEXT[k]}" for k in TIERS if att[k]) if att["total"] else "no shared-NAT egress in the last 15 minutes")
        src["nat"] = {"label": "Usable NAT evidence", "state": st, "last": None, "evidence": ev, "attribution": att,
                      "warn": "; ".join(att["capped"]["reasons"])}
    for k, v in src.items():
        if v["state"] not in ("fresh",):
            v["cannot_answer"] = CANNOT[k]
            v["inspect"] = inspect_text(site, k, cfg, monitor)

    # collection quality
    qual = quality_rows(cfg, ch, conn, site, quality, att, src, now)
    # no shared NAT configured: the NAT question does not arise for this firewall (1:1 NAT / port forwards are exact)
    needed = [v for k, v in src.items() if not (k == "nat" and v["state"] == "not_configured")]
    verdict = ("ready" if all(v["state"] == "fresh" for v in needed) and not any(q["state"] == "problem" for q in qual)
               else "partial" if src["wan_flows"]["state"] == "fresh" else "not_ready")
    return {"site": site["id"], "name": site["name"], "vendor": site.get("vendor") or "generic", "capture": capture, "ts": now,
            "sources": src, "quality": qual, "verdict": verdict}


def quality_rows(cfg, ch, conn, site, quality, att, src, now):
    from .health import settings
    hs = settings(conn)
    out = []
    loss = [x for x in quality.get("loss", []) if now - x["ts"] < 86400 and x.get("site") in (None, site["id"])]
    fd = (quality.get("flowdiag") or {}).get(site["id"])
    if loss:
        out.append({"label": "Export loss", "state": "problem",
                    "evidence": f"{sum(x['n'] for x in loss):,} lost in 24 h ({', '.join(sorted({x['source'] for x in loss}))})",
                    "effect": "NAT attribution in affected windows is capped at low: a lost return record can hide a second host.",
                    "inspect": "Collector drops: raise the inlet UDP buffer or reduce the export rate. Sequence gaps: check the path "
                               "between firewall and monitor (MTU, rate limits) and the exporter's own drop counters."})
    elif fd and now - fd["ts"] <= FLOWDIAG_MAX_AGE:
        out.append({"label": "Export loss", "state": "ok", "evidence": f"export check {_ts(fd['ts'])}: no sequence gaps in "
                                                                      f"{int(fd.get('packets') or 0):,} packets ({fd.get('protocol')})",
                    "effect": "", "inspect": ""})
    else:
        out.append({"label": "Export loss", "state": "unknown",
                    "evidence": "collector reports no receive drops, but loss on the path has not been measured (no export check in 30 days)",
                    "effect": "High confidence assumes no records were lost; this is stated on the attribution, not assumed silently.",
                    "inspect": "Run the export check below (flowdiag on a second port) while the exporter also sends to it."})
    dn = (quality.get("dup_now") or {}).get(site["id"])
    dups = [x for x in quality.get("dups", []) if now - x["ts"] < 86400 and x.get("site") == site["id"]]
    if dups:
        out.append({"label": "Duplicate exports", "state": "problem",
                    "evidence": f"up to {100 * max(x['frac'] for x in dups):.1f}% of records duplicated in 24 h",
                    "effect": "Byte totals can be doubled; NAT attribution in affected windows is capped at medium.",
                    "inspect": "Look for two export destinations that both reach the monitor, two sampled interfaces exporting the "
                               "same packet, or an HA pair where both members export."})
    else:
        out.append({"label": "Duplicate exports", "state": "ok" if dn else "unknown",
                    "evidence": f"{100 * dn['frac']:.2f}% identical records in the last 10 minutes ({dn['rows']:,} records)" if dn
                    else "not measured yet (health loop runs every minute)", "effect": "", "inspect": ""})
    hc, _ = get_state(conn, "health", {})
    clk = next((c for c in (hc or {}).get("checks", []) if c["id"] == f"clock:{site['id']}"), None)
    drift = fd.get("clock_drift_s") if fd else None
    bad = (clk and clk["state"] == "warn") or (drift is not None and abs(drift) > hs["clock_drift_s"])
    out.append({"label": "Clock skew", "state": "problem" if bad else "ok" if (clk or drift is not None) else "unknown",
                "evidence": "; ".join(x for x in (f"firewall logs vs monitor {clk['value']}" if clk else "",
                                                   f"flow export header {drift:+.0f} s" if drift is not None else "") if x)
                or "no firewall logs in the last 10 minutes and no export check: not measured",
                "effect": "Log times are shifted against flows (correlation by time is unreliable). NAT pairing uses the collector's "
                          "receive time, so skew lowers rather than raises attribution confidence." if bad else "",
                "inspect": "Enable NTP on the firewall (System → Settings → General / config system ntp) and check its time zone." if bad else ""})
    if src["lan_return"]["state"] == "fresh" and att and att["total"]:
        share = att["no_return"] / att["total"]
        out.append({"label": "Return path (asymmetric routing)", "state": "problem" if share > 0.5 else "ok",
                    "evidence": f"{100 * share:.0f}% of shared-NAT egress had no reply on this firewall's LAN side in the last 15 minutes",
                    "effect": "Unpaired egress stays 'no LAN return path' (never attributed to a host)." if share > 0.5 else "",
                    "inspect": "Check whether replies return through another firewall or WAN (multi-WAN, HA, policy routing) or whether "
                               "the LAN interface is missing from the export." if share > 0.5 else ""})
    if site.get("flow_mode") == "capture":
        out.append({"label": "WAN-only capture", "state": "problem", "evidence": "the exporter captures on the WAN interface only",
                    "effect": "Shared-NAT uploads are 'wan_only': never attributed to a host.", "inspect": inspect_text(site, "lan_return", cfg)})
    return out


# ------------------------------------------------------------------------------------------------ guided validation
VKEY = "nat_validation:"
SOLO_A, SOLO_B, BOTH = 1_500_000, 3_000_000, 500_000


def _ip(v, what):
    try:
        return str(ipaddress.ip_address((v or "").strip()))
    except ValueError:
        raise ValueError(f"{what}: not an IP address")


def start_validation(conn, cfg, site, host_a, host_b, dest, port, user, confirmed, now=None):
    """Validate the operator's input and store a running validation. Nothing is sent from the monitor."""
    access.require(site["id"])
    if not confirmed:
        raise ValueError("Confirm that you operate both hosts and are authorised to send test traffic to the destination")
    a, b, d = _ip(host_a, "Host A"), _ip(host_b, "Host B"), _ip(dest, "Destination")
    nets = [ipaddress.ip_network(str(n), strict=False) for n in (site.get("internal_nets") or cfg.internal_nets)]
    for ip, what in ((a, "Host A"), (b, "Host B")):
        if not any(ipaddress.ip_address(ip) in n for n in nets):
            raise ValueError(f"{what} {ip} is not inside {site['name']}'s internal networks")
    if a == b:
        raise ValueError("Host A and host B must be two different hosts")
    da = ipaddress.ip_address(d)
    if not da.is_global or cfg.is_ours(d):
        raise ValueError("The destination must be a public address outside your own networks")
    if d in nat_ips(cfg, site):
        raise ValueError("The destination must not be your own NAT address")
    try:
        port = int(port)
        assert 1 <= port <= 65535
    except (ValueError, AssertionError):
        raise ValueError("Port must be 1-65535")
    if not nat_ips(cfg, site):
        raise ValueError("No shared outbound NAT address is configured for this firewall: there is nothing to attribute")
    v = {"site": site["id"], "host_a": a, "host_b": b, "dest": d, "port": port, "by": user, "started": now or time.time(),
         "status": "running", "sizes": {"a": SOLO_A, "b": SOLO_B, "both": BOTH}, "result": None}
    set_state(conn, VKEY + site["id"], v)
    return v


def get_validation(conn, site_id):
    access.require(site_id)
    v, _ = get_state(conn, VKEY + site_id, None)
    return v


def steps(v):
    """Commands the operator runs on their own hosts (POST uploads to the approved destination)."""
    url = f"https://{v['dest']}:{v['port']}/" if v["port"] != 80 else f"http://{v['dest']}/"
    up = lambda n: f"head -c {n} /dev/urandom > /tmp/m0n.bin && curl -sk -o /dev/null -m 60 --data-binary @/tmp/m0n.bin {url}"
    return [
        ("1", "On host A only", v["host_a"], up(v["sizes"]["a"]), "high or medium for host A"),
        ("2", "Wait two minutes, then on host B only", v["host_b"], up(v["sizes"]["b"]), "high or medium for host B"),
        ("3", "Optional: wait two minutes, then on both hosts at the same moment", f"{v['host_a']} and {v['host_b']}", up(v["sizes"]["both"]),
         "ambiguous (both hosts got replies in the same minute: never split)"),
        ("4", "Optional: on host A, a connection the destination does not answer (closed/filtered port)", v["host_a"],
         f"curl -s -m 5 -o /dev/null http://{v['dest']}:9/ ; true", "unanswered or no LAN return path (never a host)"),
    ]


def evaluate_validation(conn, cfg, dash, site, now=None):
    """Compare what attribution concluded for the destination with what the operator sent. Ambiguous and unanswered
    bytes are reported as such, never assigned to A or B."""
    v = get_validation(conn, site["id"])
    if not v:
        raise ValueError("No validation running for this firewall")
    now = now or time.time()
    end = min(int(now), int(v["started"]) + 6 * 3600)
    sc = dash.scope(site=site["id"], range_key="custom", start=int(v["started"]) - 60, end=end, rip=v["dest"])
    att = dash.nat_attribution(sc, quality=load_quality(conn))
    per = {}
    for h in att["hosts"]:
        per.setdefault(h["host"], {})[h["confidence"]] = per.get(h["host"], {}).get(h["confidence"], 0) + h["bytes"]
    checks = []

    def host_check(key, ip, size):
        got = sum(per.get(ip, {}).values())
        tiers = ", ".join(f"{t} {b / 1e6:.2f} MB" for t, b in sorted(per.get(ip, {}).items())) or "nothing"
        st = "pass" if got >= 0.9 * size else "fail" if got else "not_observed"
        checks.append({"check": f"Host {key} ({ip}) upload attributed to host {key}", "state": st,
                       "detail": f"sent ≥ {size / 1e6:.2f} MB; attributed {got / 1e6:.2f} MB ({tiers})"})
    host_check("A", v["host_a"], v["sizes"]["a"])
    host_check("B", v["host_b"], v["sizes"]["b"])
    foreign = {h: b for h, b in per.items() if h not in (v["host_a"], v["host_b"])}
    checks.append({"check": "No other host named for this destination", "state": "fail" if foreign else "pass",
                   "detail": ", ".join(f"{h}: {sum(b.values()) / 1e6:.2f} MB" for h, b in foreign.items()) or "only host A and host B"})
    checks.append({"check": "Simultaneous uploads kept ambiguous (step 3)", "state": "pass" if att["ambiguous"] else "not_observed",
                   "detail": f"{att['ambiguous'] / 1e6:.2f} MB ambiguous (several hosts, not split)" if att["ambiguous"]
                   else "no ambiguous bytes: step 3 was skipped or the uploads did not overlap in the same minute"})
    checks.append({"check": "Unanswered attempt not attributed (step 4)", "state": "pass" if att["unanswered"] or att["no_return"] else "not_observed",
                   "detail": f"{att['unanswered_flows']:,} unanswered TCP attempts, {att['no_return'] / 1e3:.1f} kB without a LAN return path"})
    if att["capped"]["bytes"]:
        checks.append({"check": "Collection problems in the window", "state": "limited",
                       "detail": f"{att['capped']['bytes'] / 1e6:.2f} MB lowered: " + "; ".join(att["capped"]["reasons"])})
    if att["wan_only"]:
        checks.append({"check": "WAN-only capture", "state": "fail", "detail": f"{att['wan_only'] / 1e6:.2f} MB with no LAN view: "
                                                                                 "per-host attribution is not possible on this exporter"})
    states = {c["state"] for c in checks}
    verdict = "fail" if "fail" in states else "pass" if {x["state"] for x in checks[:3]} == {"pass"} else "incomplete"
    res = {"ts": now, "window": [sc.start, sc.end], "verdict": verdict, "checks": checks,
           "totals": {t: att[t] for t in TIERS}, "total": att["total"], "limits": att["limits"]}
    v.update(status="evaluated", result=res)
    set_state(conn, VKEY + site["id"], v)
    summary = (f"{verdict}: host A {checks[0]['detail']}; host B {checks[1]['detail']}; {checks[3]['detail']}")
    set_state(conn, "validation:nat_attribution:" + site["id"], {"ts": now, "summary": summary, "verdict": verdict, "site": site["id"]})
    return res


def cancel_validation(conn, site_id):
    access.require(site_id)
    conn.execute("DELETE FROM state WHERE k=?", (VKEY + site_id,))
    conn.commit()
