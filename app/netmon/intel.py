"""Security → Threat intel: ExploitHound Threat Radar feed status and settings, radar CVEs that name software your
servers run, and CVEs cited by your IDS alerts. Enrichment only; see threatradar.py."""
import time
from urllib.parse import quote

from fastapi import Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import threatradar as tr
from .admin import SECURITY_TABS, tabs
from .core import audit
from .detect import fmt_ts
from .web import app, cfg, ch, check_csrf, conn, csrf_field, e, need, page, user_of

BADGE = {"confirmed": ("sev s-critical", "KEV · exploited"), "predicted": ("sev s-serious", "EPSS · predicted"),
         "disclosed": ("sev s-warning", "new")}


def badge(section):
    cls, text = BADGE[section]
    return f"<span class='{cls}' title='{e(tr.SECTIONS[section])}'>{text}</span>"


def cve_rows(hits, extra=lambda h: ""):
    return "".join(f"""<tr><td><a class="mono" href="https://nvd.nist.gov/vuln/detail/{e(h['cve'])}" target="_blank" rel="noopener">{e(h['cve'])}</a></td>
<td>{badge(h['section'])}</td><td class="num">{'' if h['cvss'] is None else f"{h['cvss']:.1f}"}</td>
<td class="num">{'' if h['epss'] is None else f"{100 * h['epss']:.1f}%"}</td>{extra(h)}<td class="small">{e(h['desc'])}</td>
<td class="small muted">{e(h['date'])}</td></tr>""" for h in hits)


def exposed(ip):
    return any(x.ip == ip for x in cfg.exposures) or bool(cfg.binat_ext(ip))


def ids_cves(days=30):
    """CVE ids cited by IDS alert metadata in the last `days`, with hit counts and signatures."""
    try:
        return ch.query("""
            SELECT c, count() AS hits, groupUniqArray(3)(signature) AS sigs, toUInt32(max(ts)) AS last FROM (
              SELECT arrayJoin(arrayDistinct(extractAll(raw, '(?i)cve[-_][0-9]{4}[-_][0-9]{4,7}'))) AS c, signature, ts
              FROM netmon.ids_events WHERE ts > now() - INTERVAL {d:UInt32} DAY AND event_type = 'alert')
            GROUP BY c ORDER BY hits DESC LIMIT 500""", {"d": days}), ""
    except Exception as ex:
        return [], str(ex)[:200]


def kev_date(h):
    try:
        return time.mktime(time.strptime(h["date"], "%d %b %Y"))
    except (ValueError, TypeError):
        return 0


@app.get("/netmon/threat-intel", response_class=HTMLResponse)
def intel_page(req: Request, msg: str = ""):
    _, r = user_of(req)
    admin = r == "admin"
    s, st = tr.settings(conn), tr.data(conn)
    c = st.get("counts", {})
    status = (f"{sum(c.values()):,} CVEs · {c.get('confirmed', 0)} confirmed exploited · {c.get('predicted', 0)} predicted · "
              f"{c.get('disclosed', 0)} newly disclosed · fetched {fmt_ts(st['fetched'])}" if st.get("fetched") else "Not fetched yet.")
    err = f"<p class='warnline'>Last fetch failed: {e(st['error'])} (keeping the last good copy)</p>" if st.get("error") else ""
    form = (f"""<form method=post action="/netmon/threat-intel/settings" class="stackform">{csrf_field(req)}
<label class="check"><input type=checkbox name=enabled value=1 {'checked' if s['enabled'] else ''}> Fetch the radar automatically</label>
<label>Fetch interval (hours)<input name=interval_hours value="{s['interval_hours']}" inputmode=numeric maxlength=3 class="short"></label>
<label class="check"><input type=checkbox name=raise_known_exploited value=1 {'checked' if s['raise_known_exploited'] else ''}> Raise KEV-cited IDS findings one level</label>
<p class="muted small">When on, an IDS finding whose signature cites a confirmed-exploited (CISA KEV) CVE is raised one severity level.</p>
<div class="row"><button class="primary">Save</button></div></form>
<form method=post action="/netmon/threat-intel/refresh" class="row">{csrf_field(req)}<button>Fetch now</button></form>""" if admin else
            "<p class='muted small'>Only admins can change the feed settings.</p>")
    feed = f"""<section class="card"><div class="card-h"><h2>Feed</h2><a class="small" href="{e(s['url'])}" target="_blank" rel="noopener">ExploitHound Threat Radar ↗</a></div>
{f"<div class='banner'>{e(msg)}</div>" if msg else ''}<p>{e(status)}</p>{err}
<p class="muted small">Public CVE intelligence (CISA KEV, FIRST EPSS, CVE Program). It lists vulnerabilities, not addresses, so it never
marks traffic as malicious: netmon uses it to mark IDS findings whose signature cites a listed CVE and to list CVEs naming software your
servers run. The radar shows the most recent KEV additions and the top EPSS forecasts, not the whole KEV catalog. KEV = exploited in
the wild; EPSS = a 30-day forecast, not an observation; a match does not mean a server is vulnerable.</p>{form}</section>"""

    # software you run
    srows = ""
    named = [(ip, a) for ip, a in cfg.get("assets", {}).items() if a.get("software")]
    for ip, a in sorted(named, key=lambda kv: kv[1]["name"].lower()):
        exp = exposed(ip)
        srows += cve_rows(tr.software_matches(conn, a["software"])[:25], lambda h, ip=ip, a=a, exp=exp: (
            f"<td><a href='/netmon/servers/{e(ip)}'>{e(a['name'])}</a>{' <span class=tag>internet-exposed</span>' if exp else ''}"
            f"<div class='sub'>{e(h['term'])}</div></td>"))
    for site in cfg.sites:   # the firewalls themselves: their vendor is known
        vendor = {"opnsense": "opnsense", "pfsense": "pfsense"}.get(site.get("vendor", ""), "")
        if vendor:
            srows += cve_rows(tr.software_matches(conn, [vendor])[:25], lambda h, site=site: (
                f"<td>{e(site.get('name') or site['id'])} <span class=tag>firewall</span><div class='sub'>{e(h['term'])}</div></td>"))
    hint = ("<p class='muted'>No server lists its software yet. Add it with ✎ on Servers (field <b>Software</b>, e.g. "
            "<span class='mono'>nextcloud</span>, <span class='mono'>proxmox ve</span>, <span class='mono'>opnsense</span>).</p>")
    table = "<table class='tbl'><tr><th>CVE</th><th>Radar</th><th>CVSS</th><th>EPSS</th>{}<th>What it is</th><th>Date</th></tr>{}</table>"
    sw = f"""<section class="card wrap"><div class="card-h"><h2>Software you run</h2><span class="muted small">radar CVEs whose product name contains a server's software entry (firewalls: their vendor)</span></div>
{table.format('<th>Server</th>', srows) if srows else "<p class='muted'>No radar CVE names the software your servers or firewalls run.</p>"}{'' if named else hint}</section>"""

    # cited by IDS alerts
    seen, ch_err = ids_cves()
    radar = {h["cve"]: h for h in tr.lookup(conn, [x["c"] for x in seen])}
    irows = cve_rows([dict(radar[tr.norm(x["c"])], hits=x["hits"], sigs=x["sigs"]) for x in seen if tr.norm(x["c"]) in radar],
                     lambda h: f"<td class='num'>{h['hits']:,}</td><td class='small'>{e('; '.join(h['sigs']))}</td>")
    other = len({tr.norm(x["c"]) for x in seen} - set(radar))
    ids = f"""<section class="card wrap"><div class="card-h"><h2>Cited by your IDS alerts</h2><span class="muted small">last 30 days · from Suricata rule metadata</span></div>
{f"<p class='warnline'>{e(ch_err)}</p>" if ch_err else ''}
{table.format('<th>Alerts</th><th>Signatures</th>', irows) if irows else "<p class='muted'>No IDS alert in the last 30 days cites a CVE on the radar.</p>"}
<p class="muted small">{len(seen)} CVE id(s) cited by IDS alerts in 30 days{f'; {other} of them are not on the radar right now' if other else ''}.</p></section>"""

    kev = sorted((dict(v, cve=k) for k, v in st.get("rows", {}).items() if v["section"] == "confirmed"), key=kev_date, reverse=True)
    latest = f"""<section class="card wrap"><div class="card-h"><h2>Recently confirmed exploited</h2><span class="muted small">latest CISA KEV additions on the radar</span></div>
{table.format('', cve_rows(kev[:40])) if kev else "<p class='muted'>No data yet.</p>"}</section>"""
    return page(req, "Security · Threat intel", tabs(SECURITY_TABS, "/netmon/threat-intel") + feed + sw + ids + latest,
                "/netmon/security", scoped=False)


@app.post("/netmon/threat-intel/settings")
def intel_settings(req: Request, enabled: str = Form(""), interval_hours: str = Form("6"), raise_known_exploited: str = Form(""),
                   csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    try:
        s = tr.save_settings(conn, {"enabled": enabled == "1", "interval_hours": int(interval_hours or 6),
                                    "raise_known_exploited": raise_known_exploited == "1"}, u)
        audit(conn, u, "threatintel_settings", s)
        msg = "Saved."
    except ValueError as ex:
        msg = f"Not saved: {ex}"
    return RedirectResponse(f"/netmon/threat-intel?msg={quote(msg)}", 303)


@app.post("/netmon/threat-intel/refresh")
def intel_refresh(req: Request, csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    st = tr.refresh(conn, force=True)
    audit(conn, u, "threatintel_refresh", {"ok": not st.get("error"), "error": st.get("error", "")})
    msg = f"Fetch failed: {st['error']}" if st.get("error") else "Fetched."
    return RedirectResponse(f"/netmon/threat-intel?msg={quote(msg)}", 303)
