"""Investigate → What changed: the comparison page, configuration-change history, and the Overview summary."""
import time
from datetime import datetime

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .changes import MODES, Changes, periods
from .ux import INVESTIGATE_TABS, conf_badge, device_html, empty_state, fmt_local, site_tz, tabs
from .web import app, cfg, ch, conn, e, page, user_of

ENGINE = Changes(cfg, ch, conn)
KIND_TITLE = {"telemetry": "Monitoring data", "coverage": "Monitoring coverage", "exposure": "Newly observed inbound services",
              "watch_dest": "New destinations of fixed-function devices", "upload": "More uploaded than usual",
              "download": "More received than usual", "decrease": "Less traffic than usual", "config": "Configuration changes",
              "new_device": "Newly observed devices", "new_country": "New countries", "new_network": "New networks"}
SUMMARY_MAX, PER_KIND = 12, 3


def pick_sites(site):
    want = {x for x in (site or "all").split(",") if x}
    return [s for s in cfg.sites if not want or "all" in want or s["id"] in want] or list(cfg.sites)


def _ts(v, tz):
    """datetime-local value in the firewall's time zone -> epoch."""
    try:
        d = datetime.strptime(v, "%Y-%m-%dT%H:%M").replace(tzinfo=tz)
        return int(d.timestamp())
    except (TypeError, ValueError):
        raise HTTPException(400, "custom periods need start and end (date and time)")


def summarize(items):
    """Top of the list: highest priority first, at most PER_KIND per kind so one noisy kind cannot flood it."""
    out, per = [], {}
    for x in items:
        if per.get(x["kind"], 0) >= PER_KIND:
            continue
        per[x["kind"]] = per.get(x["kind"], 0) + 1
        out.append(x)
        if len(out) >= SUMMARY_MAX:
            break
    return out


def item_html(x):
    dev = f"<span class='small'>{device_html(x['device'], show_conf=True)}</span> · " if x.get("device") and x["device"].get("ip") else ""
    return (f"<li><span class='s1'>{e(x['title'])}</span><span class='s2'>{e(x['detail'])}</span>"
            f"<span class='acts'>{dev}{conf_badge(x['confidence'])} · <span class='muted'>{e(KIND_TITLE.get(x['kind'], x['kind']))}</span>"
            f" · <a href='{e(x['link'])}'>View evidence →</a></span></li>")


@app.get("/netmon/changes", response_class=HTMLResponse)
def changes_page(req: Request, mode: str = "day", site: str = "all", span: str = "24h", a0: str = "", a1: str = "", b0: str = "",
                 b1: str = "", weeks: int = 4):
    user_of(req)
    mode = mode if mode in MODES else "day"
    sites = pick_sites(site)
    tz = site_tz(sites[0])
    a = b = None
    if mode == "custom":
        if not (a0 and a1 and b0 and b1):
            return _page(req, mode, site, span, a0, a1, b0, b1, weeks, None, "Pick both periods to compare.")
        a, b = (_ts(a0, tz), _ts(a1, tz)), (_ts(b0, tz), _ts(b1, tz))
    try:
        per = periods(mode, time.time(), sites[0], span, a, b, weeks)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    try:
        res = ENGINE.compute(sites, per)
    except Exception as ex:
        return _page(req, mode, site, span, a0, a1, b0, b1, weeks, None, f"The comparison could not run: {type(ex).__name__}: {str(ex)[:200]}")
    return _page(req, mode, site, span, a0, a1, b0, b1, weeks, res)


def _page(req, mode, site, span, a0, a1, b0, b1, weeks, res, err=""):
    opts = "".join(f"<option value='{k}' {'selected' if k == mode else ''}>{e(v)}</option>" for k, v in MODES.items())
    spans = "".join(f"<option value='{k}' {'selected' if k == span else ''}>{k}</option>" for k in ("1h", "6h", "24h", "7d"))
    multi = len(cfg.sites) > 1
    sitesel = ("<label>Firewalls<select name=site><option value=all>All firewalls</option>" + "".join(
        f"<option value='{e(s['id'])}' {'selected' if s['id'] == site else ''}>{e(s['name'])}</option>" for s in cfg.sites) + "</select></label>") if multi else ""
    form = f"""<form method=get class="row wrapform" aria-label="What to compare"><label>Compare<select name=mode>{opts}</select></label>
<label>Period length<select name=span>{spans}</select></label>{sitesel}
<label>Weeks back<input name=weeks type=number min=1 max=8 value="{int(weeks)}" class="short"></label>
<details class="tech"><summary>Two custom periods</summary><div class="row">
<label>A from<input type=datetime-local name=a0 value="{e(a0)}"></label><label>A to<input type=datetime-local name=a1 value="{e(a1)}"></label>
<label>B from<input type=datetime-local name=b0 value="{e(b0)}"></label><label>B to<input type=datetime-local name=b1 value="{e(b1)}"></label>
<span class="muted small">in the firewall's time zone · at most 31 days each · choose “Two custom periods” above</span></div></details>
<button class="primary">Compare</button></form>
<p class="muted small">“Period length” applies to “Selected period” and “Same weekday and time”. “Weeks back” applies to the weekday comparison.</p>"""
    if err or res is None:
        body = tabs(INVESTIGATE_TABS, "/netmon/changes") + f"<section class='card'>{form}</section>" + empty_state("nomatch" if not err else "unavailable", " " + err)
        return page(req, "What changed?", body, "/netmon/investigate", scoped=False)
    per, items = res["period"], res["items"]
    top = summarize(items)
    notes = "".join(f"<div class='banner warn'>{e(n)}</div>" for n in res["notes"])
    tzs = site_tz(pick_sites(site)[0])
    head = (f"Comparing <b>{e(per['label_a'])}</b> ({e(fmt_local(per['a'][0], {'tz': tzs.key}))} → {e(fmt_local(per['a'][1], {'tz': tzs.key}))}) with "
            f"<b>{e(per['label_b'])}</b>. History searched for “newly observed”: {res['lookback_days']} days.")
    if top:
        summary = f"<ul class='sentence-list'>{''.join(item_html(x) for x in top)}</ul>"
    elif not res["complete"]:
        summary = empty_state("unavailable", " No notable changes were found, but the data is incomplete (see above), so this is not a clean bill of health.",
                              "/netmon/coverage", "What is visible")
    else:
        summary = empty_state("nomatch", " Nothing notable changed between these periods: no new services, destinations or devices, "
                              "and no unusual volume. This covers what netmon can see (flow records and logs), not everything.")
    groups = {}
    for x in items:
        groups.setdefault(x["kind"], []).append(x)
    allg = "".join(f"<details><summary>{e(KIND_TITLE.get(k, k))} <span class='count'>{len(v)}</span></summary>"
                   f"<ul class='sentence-list'>{''.join(item_html(x) for x in v[:100])}</ul>"
                   f"{'<p class=muted>Showing 100 of ' + str(len(v)) + '</p>' if len(v) > 100 else ''}</details>" for k, v in groups.items())
    cov = "".join(f"<li>{e((cfg.site(s) or {'name': s})['name'])}: {res['coverage_a'].get(s, 0):.0%} of period A, "
                  f"{sum(c.get(s, 0) for c in res['coverage_b']) / max(1, len(res['coverage_b'])):.0%} of the comparison</li>" for s in res["coverage_a"])
    body = f"""{tabs(INVESTIGATE_TABS, '/netmon/changes')}<section class="card">{form}</section>{notes}
<section class="card"><div class="card-h"><h2>Most important changes</h2><span class="muted small">{len(top)} of {len(items)} · computed {e(fmt_local(res['computed']))}</span></div>
<p class="small">{head}</p>{summary}</section>
<section class="card"><div class="card-h"><h2>All changes by type</h2></div>{allg or '<p class="muted">None</p>'}
<details class="tech"><summary>How this is calculated</summary><ul class="small">
<li>Volumes are compared per hour <i>with telemetry</i>; hours without flow records are not counted as zero. Flagged at ≥ 3× (and ≥ 100 MB) or ≤ ⅓.</li>
<li>“Contacted” = connections the device opened, inferred from ports (service port remote, ephemeral port local).</li>
<li>“Newly observed” = not seen in the history searched. It does not prove something is new.</li>
<li>Inbound services count only when the device answered outside clients from that port.</li>
<li>Outbound traffic through the shared NAT address cannot be tied to one device from WAN flow records.</li>
<li>Coverage per firewall:<ul>{cov}</ul></li></ul></details></section>"""
    return page(req, "What changed?", body, "/netmon/investigate", scoped=False,
                subtitle="Prioritized differences between two periods, with the evidence")


@app.get("/netmon/changes/config", response_class=HTMLResponse)
def config_change_page(req: Request, site: str, t: int):
    """One configuration change with the inbound services observed in the 24 h before and after (association only)."""
    user_of(req)
    s = cfg.site(site)
    if not s:
        raise HTTPException(404)
    rows = ch.query("""SELECT toUInt32(ts) AS t, app, substring(message, 1, 600) AS m FROM netmon.sys_events WHERE site = {s:String}
        AND app = 'audit' AND ts >= toDateTime({t0:UInt32}) AND ts <= toDateTime({t1:UInt32}) ORDER BY ts LIMIT 50""",
                    {"s": site, "t0": int(t) - 120, "t1": int(t) + 120})
    after = ENGINE.answered([s], int(t), min(int(time.time()), int(t) + 86400), int(t) - 86400)
    lis = "".join(f"<li>{device_html(_lab(x['l'], site))} answered on {'tcp' if x['proto'] == 6 else 'udp'}/{x['port']} — "
                  f"{x['clients']} clients, first {e(fmt_local(x['first'], s))}</li>" for x in after[:30])
    body = f"""{tabs(INVESTIGATE_TABS, '/netmon/changes')}<section class="card"><div class="card-h"><h2>Configuration change on {e(s['name'])}</h2>
<span class="muted small">{e(fmt_local(t, s))}</span></div>
<ul class="timeline">{''.join(f"<li><span class='t'>{e(fmt_local(r['t'], s))}</span><div class='mono small'>{e(r['m'])}</div></li>" for r in rows) or '<li>No audit lines found around this time.</li>'}</ul></section>
<section class="card"><div class="card-h"><h2>Traffic after the change</h2><span class="muted small">24 h after vs 24 h before</span></div>
{f"<p>Inbound traffic to services not seen in the 24 hours before was observed afterwards:</p><ul>{lis}</ul>" if lis else
 empty_state('nomatch', ' No inbound service was newly observed in the 24 hours after this change.')}
<p class="note">This is an association in time, not proof that the change caused it: services also start on their own, and scanners find
services at random. Check the change itself (the page and user above) to establish cause.</p></section>"""
    return page(req, "Configuration change", body, "/netmon/investigate", scoped=False)


def _lab(ip, site):
    from . import identity as idn
    return idn.label(conn, cfg, cfg.binat.get(ip, ip), site)


_TOP = {}   # allowed-firewalls key -> {"t", "v", "busy"}: each set of visible firewalls has its own card


@app.get("/netmon/api/changes/top")
def api_changes_top(req: Request):
    """Overview card: the three most important changes today vs yesterday (the user's firewalls). Computed in the
    background and cached, so the Overview never waits for it."""
    user_of(req)
    from . import access
    top = _TOP.setdefault(access.allowed_key(), {"t": 0, "v": None, "busy": False})
    if (top["v"] is None or time.time() - top["t"] > 300) and not top["busy"]:
        top["busy"] = True

        def run():
            try:
                per = periods("day", time.time(), cfg.sites[0])
                res = ENGINE.compute(list(cfg.sites), per)
                top.update(t=time.time(), v={"items": [{k: x[k] for k in ("kind", "title", "detail", "confidence", "link")}
                                                     | {"device": (x.get("device") or {}).get("name")} for x in summarize(res["items"])[:3]],
                                           "total": len(res["items"]), "complete": res["complete"], "notes": res["notes"][:2]})
            except Exception as ex:
                top.update(t=time.time(), v={"error": f"{type(ex).__name__}"})
            finally:
                top["busy"] = False
        access.spawn(run)       # keeps this request's firewall restriction
    return JSONResponse({"ready": top["v"] is not None, **(top["v"] or {})})
