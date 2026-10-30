"""Coverage & source health: what the monitor can see, with evidence - replaces the former static table.

Two parts:
  1. Source health - live checks from netmon.health (configured? healthy? last data? evidence, next action).
  2. Capabilities - one row per *kind of visibility*, each with a coverage status derived from current data:
       verified        data present and validated (controlled test or reconciliation) for this capability
       partial         data present but with a measured gap (the gap is quantified where possible)
       unavailable     not possible with the current sources (by design or missing sensor)
       awaiting setup  an adapter exists; a source has to be connected
"""
import time

from fastapi import Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .core import get_state
from .web import app, ch, check_csrf, conn, csrf_field, dash, e, need, page

COV = {"verified": ("good", "✓ verified"), "partial": ("warning", "◐ partial"), "unavailable": ("muted", "✕ unavailable"),
       "awaiting": ("muted", "… awaiting setup")}
HST = {"ok": ("good", "● healthy"), "warn": ("warning", "▲ degraded"), "fail": ("critical", "✕ failing"),
       "awaiting": ("muted", "… awaiting setup"), "not_configured": ("muted", "○ not configured"), "unknown": ("muted", "? unknown")}


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(t)) if t else "—"


def _q1(sql, p=None, default=0):
    try:
        r = ch.query(sql, p or {})
        return r[0] if r else default
    except Exception:
        return default


def capabilities():
    """Evidence-backed coverage per capability (queries are small aggregates over the last hour/day)."""
    sc = dash.scope(range_key="24h")
    caps = []
    f = _q1("SELECT countIf(InIfBoundary = 'external' AND OutIfBoundary = 'internal') AS inb, "
            "countIf(OutIfBoundary = 'external') AS outb, toUInt32(max(TimeReceived)) AS last FROM flows WHERE TimeReceived > now() - 3600", {}, {})
    caps.append(("Inbound across the WAN (to published services)", "verified" if f.get("inb") else "unavailable",
                 f"{int(f.get('inb') or 0):,} inbound flow records in the last hour, delivered to internal hosts (after de-NAT)",
                 "Only traffic the firewall passed is exported as flows; blocked packets appear in firewall logs instead.", f.get("last")))
    try:
        att = dash.nat_attribution(sc)
    except Exception as ex:
        att = {"total": 0, "error": str(ex)}
    v, _ = get_state(conn, "validation:nat_attribution", None)
    if att.get("total"):
        pct = lambda k: 100 * att[k] / att["total"]
        caps.append(("Outbound per-host attribution behind shared NAT", "partial",
                     f"24 h: {pct('high'):.0f}% of shared-NAT upload bytes attributed to one host with high confidence, "
                     f"{pct('medium') + pct('low'):.0f}% medium/low, {pct('ambiguous'):.0f}% ambiguous (several hosts), "
                     f"{pct('no_return'):.0f}% with no LAN return path, {pct('unanswered'):.0f}% unanswered attempts.",
                     "Return-path correlation proves a host received replies, not that every outbound packet is visible: unanswered "
                     "and firewall-originated traffic has no LAN-side record (bridge ingress is not exported). Full pre-NAT attribution "
                     "needs LAN-rule logging or a LAN-side sensor (see docs/nat-attribution.md).",
                     v["ts"] if v else None, v))
    caps.append(("Outbound volume across the WAN (post-NAT)", "verified" if f.get("outb") else "unavailable",
                 f"{int(f.get('outb') or 0):,} WAN egress flow records in the last hour; 1:1 NAT addresses map to exactly one host",
                 "Accounting boundary: WAN egress (post-NAT) for outbound and LAN delivery for inbound; other observation points are "
                 "not added to totals, so NAT and interface hops are not double-counted.", f.get("last")))
    caps.append(("Firewall-originated traffic", "partial",
                 f"{(att.get('no_return', 0)) / 2 ** 20:.0f} MB/24 h of shared-NAT egress had no LAN return path "
                 "(firewall's own resolver/updates, or unanswered)",
                 "An empty input interface alone does not prove the firewall originated a flow: NATed LAN traffic can be exported "
                 "the same way. It is labelled 'no LAN return path', not 'firewall'.", None))
    lan = _q1("SELECT count() AS n FROM netmon.zeek_conn WHERE ts > now() - 3600", {}, {}).get("n", 0)
    caps.append(("LAN ↔ LAN (server-to-server, same subnet)", "verified" if lan else "awaiting",
                 f"{int(lan):,} Zeek connection records in the last hour" if lan else "Bridged/switched locally: never crosses the firewall",
                 "Needs a Zeek sensor fed by a mirror (docs/zeek-sensor.md); same-host VM traffic needs the Proxmox bridge mirror option.", None))
    fw = _q1("SELECT count() AS n, toUInt32(max(received)) AS last FROM netmon.fw_events WHERE received > now() - 3600", {}, {})
    caps.append(("Blocked / denied traffic", "verified" if fw.get("n") else "awaiting",
                 f"{int(fw.get('n') or 0):,} firewall log records in the last hour; counts reconciled with the Countries map",
                 "Only rules with logging enabled; a quiet log is not proof that nothing was blocked.", fw.get("last")))
    ids = _q1("SELECT count() AS n, toUInt32(max(received)) AS last FROM netmon.ids_events WHERE received > now() - 86400", {}, {})
    caps.append(("IDS signature alerts (Suricata)", "verified" if ids.get("n") else "awaiting",
                 f"{int(ids.get('n') or 0):,} alerts in 24 h", "Alert mode: matches only; no drop events, no EVE protocol streams.", ids.get("last")))
    dn = _q1("SELECT count() AS n, countIf(length(answers) > 0) AS a, toUInt32(max(received)) AS last FROM netmon.dns_events "
             "WHERE received > now() - 86400", {}, {})
    tr = _q1("SELECT count() AS n FROM flows WHERE TimeReceived > now() - 3600 AND SrcPort IN (53, 853) AND OutIfBoundary = 'internal'", {}, {})
    caps.append(("DNS names (queries)", "verified" if dn.get("n") else "awaiting",
                 f"{int(dn.get('n') or 0):,} DNS log records in 24 h ({int(dn.get('a') or 0):,} with answers)" if dn.get("n")
                 else f"No resolver logs yet. DNS transport is visible from flows: {int(tr.get('n') or 0):,} resolver reply records in the last hour.",
                 "Resolver logs carry names but no answers; Zeek dns.log adds answers/TTLs. DoH/DoT content is never visible.", dn.get("last")))
    tls = _q1("SELECT count() AS n FROM netmon.zeek_tls WHERE ts > now() - 86400", {}, {}).get("n", 0)
    caps.append(("TLS metadata (SNI, version)", "verified" if tls else "awaiting", f"{int(tls):,} TLS records in 24 h" if tls else "needs a Zeek sensor",
                 "Metadata only; no decryption and no TLS interception.", None))
    http = _q1("SELECT count() AS n FROM netmon.zeek_http WHERE ts > now() - 86400", {}, {}).get("n", 0)
    caps.append(("HTTP URLs", "verified" if http else "awaiting", f"{int(http):,} HTTP requests in 24 h" if http else "needs a Zeek sensor",
                 "Cleartext HTTP only; HTTPS URLs are not visible.", None))
    au = _q1("SELECT count() AS n, toUInt32(max(received)) AS last FROM netmon.auth_events WHERE received > now() - 86400", {}, {})
    caps.append(("Authentication & privilege events", "partial" if au.get("n") else "awaiting",
                 f"{int(au.get('n') or 0):,} events in 24 h (firewall GUI/SSH)" if au.get("n") else "no server logs forwarded",
                 "Only from systems that forward their own auth logs; never inferred from flows (docs/dns-zeek-hostlogs.md).", au.get("last")))
    caps.append(("Payload content", "unavailable", "Flow records, logs and Zeek metadata carry no payload",
                 "Full packet capture is off by design.", None))
    v6l = _q1("SELECT count() AS n FROM netmon.fw_events WHERE received > now() - 86400 AND ipver = 6", {}, {}).get("n", 0)
    v6f = _q1("SELECT count() AS n FROM flows WHERE TimeReceived > now() - 86400 AND NOT startsWith(IPv6NumToString(SrcAddr), '::ffff:')", {}, {}).get("n", 0)
    caps.append(("IPv6", "partial" if v6l or v6f else "unavailable",
                 f"{int(v6f):,} IPv6 flow records and {int(v6l):,} IPv6 firewall log records in 24 h (link-local/multicast seen)",
                 "No global IPv6 on the WAN does not mean no IPv6 on the LAN: link-local traffic between hosts never reaches the WAN.", None))
    caps.append(("WireGuard tunnel traffic", "partial", "Where tunnel traffic is routed to the LAN or WAN",
                 "The tunnel interface itself has no NetFlow hook; an old handshake is not a failure for an idle peer.", None))
    return caps


@app.get("/netmon/coverage", response_class=HTMLResponse)
def coverage_page(req: Request, msg: str = ""):
    need(req, "viewer")
    from . import health as H
    from .admin import SETTINGS_TABS, tabs
    hs, ts = get_state(conn, "health", {})
    checks = (hs or {}).get("checks", [])
    groups = {}
    for c in checks:
        groups.setdefault(c["group"], []).append(c)
    rows = "".join(
        f"<tr><td>{e(c['label'])}</td><td><span class='sev s-{HST[c['state']][0]}'>{HST[c['state']][1]}</span></td>"
        f"<td>{e(c['value'])}</td><td class='num'>{e(_ts(c['last']))}</td><td class='small'>{e(c['evidence'])}"
        f"{'<div class=muted>' + e(c['limits']) + '</div>' if c['limits'] else ''}</td><td class='small'>{e(c['action'])}</td></tr>"
        for g in groups for c in groups[g])
    caps = capabilities()
    crow = ""
    for name, st, ev, lim, last, *val in caps:
        vd = val[0] if val else None
        vtxt = f"<div class='small'><b>Last validation</b> {e(_ts(vd['ts']))}: {e(vd['summary'])}</div>" if vd else ""
        crow += (f"<tr><td>{e(name)}</td><td><span class='sev s-{COV[st][0]}'>{COV[st][1]}</span></td><td class='small'>{e(ev)}{vtxt}</td>"
                 f"<td class='small muted'>{e(lim)}</td><td class='num'>{e(_ts(last))}</td></tr>")
    s = H.settings(conn)
    form = ""
    from .web import user_of, ROLES
    _, role = user_of(req)
    if ROLES[role] >= ROLES["admin"]:
        num = lambda k, label, unit="": (f"<label>{e(label)}<input name={k} type=number step=any value='{s[k]}' class='short'> {e(unit)}</label>")
        form = f"""<section class="card"><div class="card-h"><h2>Health alert thresholds</h2></div>
<form method="post" action="/netmon/coverage/settings" class="stackform wide">{csrf_field(req)}
<label class="check"><input type=checkbox name=enabled value=1 {'checked' if s['enabled'] else ''}> Raise health alerts</label>
<label class="check"><input type=checkbox name=notify value=1 {'checked' if s['notify'] else ''}> Send health alerts and recoveries to notification channels
 (off by default — enable only after a successful channel test)</label>
<div class="row">{num('grace_seconds', 'Startup grace', 's')}{num('consecutive', 'Consecutive failing checks before an alert')}{num('cooldown_minutes', 'Cooldown', 'min')}</div>
<div class="row">{num('netflow_warn_s', 'NetFlow silence warn', 's')}{num('netflow_fail_s', 'fail', 's')}{num('syslog_warn_s', 'Firewall log silence warn', 's')}{num('syslog_fail_s', 'fail', 's')}</div>
<div class="row">{num('kafka_lag_warn', 'Queue lag warn', 'messages')}{num('parse_fail_pct', 'Unparsed lines warn', '%')}{num('ingest_backlog_mb', 'Log backlog warn', 'MB')}{num('ingest_delay_s', 'Ingest delay warn', 's')}</div>
<div class="row">{num('disk_warn_pct', 'Disk warn', '%')}{num('disk_fail_pct', 'Disk fail', '%')}{num('geoip_max_age_days', 'GeoIP max age', 'days')}{num('clock_drift_s', 'Clock drift warn', 's')}</div>
<div class="row"><button class="primary">Save thresholds</button></div></form></section>"""
    banner = f"<p class='note'>{e(msg)}</p>" if msg else ""
    body = f"""{tabs(SETTINGS_TABS, '/netmon/coverage')}{banner}
<section class="card"><div class="card-h"><h2>Source health</h2><span class="muted small">checked {e(_ts(ts))} · every 60 s</span></div>
<p class="note">“No events” and “broken collection” are different states: each source is judged by its own transport, heartbeat or counters.</p>
<div class="wrap"><table class="tbl"><tr><th>Source</th><th>State</th><th>Observed</th><th>Last data</th><th>Evidence / limits</th><th>Next action</th></tr>
{rows or "<tr><td colspan=6 class='state empty'>First health check pending (runs within a minute of startup)</td></tr>"}</table></div></section>
<section class="card"><div class="card-h"><h2>What is visible</h2></div>
<div class="wrap"><table class="tbl"><tr><th>Capability</th><th>Coverage</th><th>Evidence</th><th>Limits</th><th>Last data / validation</th></tr>{crow}</table></div></section>
{form}"""
    return page(req, "Coverage & source health", body, "/netmon/settings", scoped=False)


@app.post("/netmon/coverage/settings")
async def coverage_settings(req: Request, csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    from urllib.parse import quote
    from . import health as H
    form = dict(await req.form())
    try:
        H.save_settings(conn, form, u)
        msg = "Thresholds saved"
    except ValueError as ex:
        msg = str(ex)
    return RedirectResponse("/netmon/coverage?msg=" + quote(msg), 303)
