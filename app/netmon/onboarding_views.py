"""Settings → Status → Onboarding test: per-firewall evidence check, export check instructions and guided NAT validation.

Read-only towards firewalls: nothing here changes exporter, NAT, rule or blocking settings, and the monitor never sends
test traffic itself. Every page and action is limited to the firewalls the signed-in user may see (netmon.access).
"""
import time
from urllib.parse import quote

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import access
from . import onboarding as O
from .core import audit
from .web import ROLES, app, cfg, ch, check_csrf, conn, csrf_field, dash, e, need, page, user_of

dash.quality_source = lambda: O.load_quality(conn)      # recorded loss / duplicates cap NAT attribution everywhere

ST = {"fresh": ("good", "● arriving, fresh"), "stale": ("warning", "▲ stale"), "missing": ("critical", "✕ missing"),
      "not_possible": ("muted", "✕ not possible with this export"), "not_configured": ("muted", "○ not configured")}
QST = {"ok": ("good", "● ok"), "problem": ("warning", "▲ problem"), "unknown": ("muted", "? not measured")}
VST = {"pass": ("good", "✓ pass"), "fail": ("critical", "✕ fail"), "not_observed": ("muted", "… not observed"),
       "limited": ("warning", "◐ limited"), "incomplete": ("warning", "◐ incomplete")}
VERDICT = {"ready": ("good", "Ready: every source arrives and is fresh"),
           "partial": ("warning", "Partly ready: some questions cannot be answered yet (see below)"),
           "not_ready": ("critical", "Not ready: WAN flows are not arriving")}


def _site(site):
    if site:
        s = cfg.site(site)
        if not s:
            raise HTTPException(404, "not found")      # unknown, or another firewall the user may not see
        return s
    if not cfg.sites:
        raise HTTPException(404, "no firewall")
    return cfg.sites[0]


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(t)) if t else "—"


def _monitor_addr(req):
    return (req.headers.get("host") or "MONITOR").split(":")[0]


def _back(sid, msg):
    return RedirectResponse(f"/netmon/onboarding?site={quote(sid)}&msg={quote(msg)}", 303)


_CACHE = {}


def evaluate_cached(s, monitor, ttl=60):
    """O.evaluate per firewall, reused for `ttl` seconds (the sources are per firewall; access is checked first)."""
    access.require(s["id"])
    key = (s["id"], monitor, access.allowed_key())
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    r = O.evaluate(cfg, ch, dash, conn, s, monitor=monitor)
    if len(_CACHE) > 200:
        _CACHE.clear()
    _CACHE[key] = (time.time(), r)
    return r


def summary_html(req, limit=12):
    """Per-firewall onboarding summary for the Coverage page: only the signed-in user's firewalls, evaluated live."""
    rows = ""
    for s in cfg.sites[:limit]:
        try:
            r = evaluate_cached(s, _monitor_addr(req))
        except HTTPException:
            raise
        except Exception as ex:
            rows += f"<tr><td>{e(s['name'])}</td><td colspan=5 class='small'>not evaluated: {e(str(ex)[:160])}</td></tr>"
            continue
        cells = "".join(f"<td><span class='sev s-{ST[v['state']][0]}' title='{e(v['evidence'])}'>{e(ST[v['state']][1])}</span></td>"
                        for v in r["sources"].values())
        vc, vt = VERDICT[r["verdict"]]
        rows += (f"<tr><td><a href='/netmon/onboarding?site={quote(s['id'])}'>{e(s['name'])}</a></td>{cells}"
                 f"<td><span class='sev s-{vc}'>{e(vt.split(':')[0])}</span></td></tr>")
    more = (f"<p class='small muted'>{len(cfg.sites) - limit} more firewalls: open the onboarding test per firewall.</p>"
            if len(cfg.sites) > limit else "")
    return ("<section class='card'><div class='card-h'><h2>Onboarding test per firewall</h2><a class='small' href='/netmon/onboarding'>"
            "details, missing-source guidance and guided NAT validation →</a></div><div class='wrap'><table class='tbl'><tr><th>Firewall</th>"
            "<th>WAN flows</th><th>LAN return flows</th><th>Firewall logs</th><th>Usable NAT evidence</th><th>Result</th></tr>"
            f"{rows}</table></div>{more}</section>")


@app.get("/netmon/onboarding", response_class=HTMLResponse)
def onboarding_page(req: Request, site: str = "", msg: str = ""):
    need(req, "viewer")
    from .admin import SETTINGS_TABS, tabs
    _, role = user_of(req)
    can_act = ROLES[role] >= ROLES["analyst"]
    s = _site(site.split(",")[0])
    mon = _monitor_addr(req)
    try:
        r = O.evaluate(cfg, ch, dash, conn, s, monitor=mon)
        err = ""
    except HTTPException:
        raise
    except Exception as ex:          # ClickHouse down: say so instead of showing sources as missing
        r, err = None, str(ex)[:300]
    sitesel = ("<form method=get class=row><label>Firewall<select name=site>" + "".join(
        f"<option value='{e(x['id'])}' {'selected' if x['id'] == s['id'] else ''}>{e(x['name'])}</option>" for x in cfg.sites)
        + "</select></label><button>Test</button></form>") if len(cfg.sites) > 1 else ""
    banner = f"<div class='banner'>{e(msg)}</div>" if msg else ""
    intro = ("<p class='note'>The onboarding test checks, for one firewall, whether each kind of evidence is arriving and fresh, "
             "and for each missing source which question you cannot answer yet and which exporter or interface setting to "
             "inspect. It only reads data the monitor already received: no firewall setting is changed and no traffic is sent.</p>")
    if err:
        body = f"{tabs(SETTINGS_TABS, '/netmon/onboarding')}{banner}{sitesel}{intro}<section class='card'><p class='state empty'>" \
               f"The test could not query the flow database: {e(err)}. Sources are not shown as missing while it is unreachable.</p></section>"
        return page(req, "Settings · Onboarding test", body, "/netmon/settings", scoped=False)
    vc, vt = VERDICT[r["verdict"]]
    rows = ""
    for k, v in r["sources"].items():
        cls, txt = ST[v["state"]]
        miss = ""
        if v.get("cannot_answer"):
            miss = (f"<div><b>Cannot answer:</b> {e(v['cannot_answer'])}</div>"
                    f"<div class='muted'><b>Inspect:</b> {e(v['inspect'])}</div>")
        warn = f"<div class='cellwarn small'>{e(v['warn'])}</div>" if v.get("warn") else ""
        rows += (f"<tr><td>{e(v['label'])}</td><td><span class='sev s-{cls}'>{e(txt)}</span></td><td class='num'>{e(_ts(v.get('last')))}</td>"
                 f"<td class='small'>{e(v['evidence'])}{warn}</td><td class='small'>{miss or '—'}</td></tr>")
    qrows = "".join(
        f"<tr><td>{e(q['label'])}</td><td><span class='sev s-{QST[q['state']][0]}'>{e(QST[q['state']][1])}</span></td>"
        f"<td class='small'>{e(q['evidence'])}</td><td class='small'>{e(q['effect']) or '—'}"
        f"{'<div class=muted><b>Inspect:</b> ' + e(q['inspect']) + '</div>' if q['inspect'] else ''}</td></tr>" for q in r["quality"])
    att = r["sources"]["nat"].get("attribution")
    attr = ""
    if att and att["total"]:
        tr = "".join(f"<tr><td>{e(t)}</td><td class='small'>{e(O.TIER_TEXT[t])}</td><td class='num'>{att[t] / 2 ** 20:.2f} MB</td>"
                     f"<td class='num'>{100 * att[t] / att['total']:.0f}%</td></tr>" for t in O.TIERS)
        lim = "".join(f"<li>{e(x)}</li>" for x in att["capped"]["reasons"] + att["limits"])
        attr = (f"<section class='card'><div class='card-h'><h2>NAT attribution, last 15 minutes</h2></div>"
                f"<p class='note'>Ambiguous, unanswered and no-return bytes are never split between hosts or assigned to one. "
                f"Collection problems can only lower a tier.</p><div class='wrap'><table class='tbl'><tr><th>Tier</th><th>Meaning</th>"
                f"<th>Bytes</th><th>Share</th></tr>{tr}</table></div>{'<ul class=small>' + lim + '</ul>' if lim else ''}</section>")
    exp = s.get("exporter_ip") or "EXPORTER"
    export_check = f"""<details class="tech"><summary>Export check (loss, duplicates, clock): optional, run by an operator</summary>
<p class="small">Sequence numbers in the export packets show loss and duplicates on the path; the collector does not keep them.
Add the monitor's port <b>2056/udp</b> as a <b>second</b> flow destination on the firewall for a few minutes (keep the existing
2055 destination), publish the port only for the test, then run on the monitor host:</p>
<pre class="mono small">docker exec app-netmon-app-1 python -m netmon.flowdiag --listen 0.0.0.0:2056 --seconds 300 --record</pre>
<p class="small">The result is stored for the firewall whose exporter address matches ({e(exp)}) and shown above. Remove the
second destination afterwards. Adding a destination is a firewall change: do it only when you are authorised to.</p></details>"""
    v = O.get_validation(conn, s["id"])
    val = _validation_html(req, s, v, can_act)
    body = f"""{tabs(SETTINGS_TABS, '/netmon/onboarding')}{banner}{sitesel}{intro}
<section class="card"><div class="card-h"><h2>{e(s['name'])}</h2><span class="muted small">{e(r['vendor'])} · tested {e(_ts(r['ts']))}</span></div>
<p><span class="sev s-{vc}">{e(vt)}</span></p>
<div class="wrap"><table class="tbl"><tr><th>Evidence</th><th>State</th><th>Last data</th><th>Observed</th><th>If missing</th></tr>{rows}</table></div></section>
<section class="card"><div class="card-h"><h2>Collection quality</h2></div>
<div class="wrap"><table class="tbl"><tr><th>Check</th><th>State</th><th>Evidence</th><th>Effect / inspect</th></tr>{qrows}</table></div>{export_check}</section>
{attr}{val}"""
    return page(req, "Settings · Onboarding test", body, "/netmon/settings", scoped=False)


def _validation_html(req, s, v, can_act):
    head = "<section class='card'><div class='card-h'><h2>Guided NAT validation (optional)</h2></div>"
    expl = ("<p class='small'>Proves on your own network that shared-NAT uploads are attributed to the right host. You need two hosts "
            "you operate behind this firewall's shared NAT and a destination you are authorised to send test uploads to (for example "
            "a server you run). The monitor sends nothing: you run the commands on the hosts, then evaluate. Results that the evidence "
            "cannot pin to one host stay <b>ambiguous</b> or <b>unanswered</b>.</p>")
    if not v:
        if not can_act:
            return head + expl + "<p class='muted small'>Analysts and admins can start a validation.</p></section>"
        return head + expl + f"""<form method=post action="/netmon/onboarding/validate" class="stackform">{csrf_field(req)}
<input type=hidden name=site value="{e(s['id'])}">
<div class=row><label>Host A (internal address)<input name=host_a class=mono required></label>
<label>Host B (internal address)<input name=host_b class=mono required></label></div>
<div class=row><label>Approved destination (public address)<input name=dest class=mono required></label>
<label>Port<input name=port type=number value=443 min=1 max=65535 class=short></label></div>
<label class=check><input type=checkbox name=confirm value=1> I operate both hosts and am authorised to send test uploads to this destination</label>
<button class=primary>Start validation</button></form></section>"""
    st = "".join(f"<tr><td>{e(n)}</td><td>{e(w)}<div class='muted small'>{e(h)}</div></td><td><pre class='mono small'>{e(c)}</pre></td>"
                 f"<td class='small'>{e(x)}</td></tr>" for n, w, h, c, x in O.steps(v))
    res = ""
    if v.get("result"):
        rr = v["result"]
        res = (f"<h3>Result {e(_ts(rr['ts']))}: <span class='sev s-{VST[rr['verdict']][0]}'>{e(VST[rr['verdict']][1])}</span></h3>"
               "<div class='wrap'><table class='tbl'><tr><th>Check</th><th>Result</th><th>Detail</th></tr>" + "".join(
                   f"<tr><td>{e(c['check'])}</td><td><span class='sev s-{VST[c['state']][0]}'>{e(VST[c['state']][1])}</span></td>"
                   f"<td class='small'>{e(c['detail'])}</td></tr>" for c in rr["checks"]) + "</table></div>"
               + "<p class='small muted'>Window totals: " + e(", ".join(f"{t} {b / 1e6:.2f} MB" for t, b in rr["totals"].items() if b)
                                                             or "no shared-NAT egress to the destination") + "</p>"
               + "".join(f"<p class='small muted'>{e(x)}</p>" for x in rr.get("limits", [])))
    act = (f"""<form method=post action="/netmon/onboarding/validate/evaluate" class=row>{csrf_field(req)}<input type=hidden name=site value="{e(s['id'])}">
<button class=primary>Evaluate now</button></form>
<form method=post action="/netmon/onboarding/validate/cancel" class=row>{csrf_field(req)}<input type=hidden name=site value="{e(s['id'])}">
<button>{'Finish' if v.get('result') else 'Cancel'} validation</button></form>""" if can_act else "")
    return (head + expl + f"<p class='small'>Started {e(_ts(v['started']))} by {e(v['by'])}: host A {e(v['host_a'])}, host B "
            f"{e(v['host_b'])}, destination {e(v['dest'])}:{v['port']}. Wait about two minutes after the last step (export delay), then evaluate.</p>"
            "<div class='wrap'><table class='tbl'><tr><th>Step</th><th>Where</th><th>Command</th><th>Expected</th></tr>" + st + "</table></div>"
            + res + act + "</section>")


@app.post("/netmon/onboarding/validate")
def validate_start(req: Request, csrf: str = Form(""), site: str = Form(""), host_a: str = Form(""), host_b: str = Form(""),
                   dest: str = Form(""), port: str = Form("443"), confirm: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    s = _site(site)
    try:
        O.start_validation(conn, cfg, s, host_a, host_b, dest, port, u, confirm == "1")
    except ValueError as ex:
        return _back(s["id"], str(ex))
    audit(conn, u, "nat_validation_start", {"site": s["id"], "host_a": host_a, "host_b": host_b, "dest": dest, "port": port})
    return _back(s["id"], "Validation started: run the steps on your hosts, then evaluate")


@app.post("/netmon/onboarding/validate/evaluate")
def validate_evaluate(req: Request, csrf: str = Form(""), site: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    s = _site(site)
    try:
        r = O.evaluate_validation(conn, cfg, dash, s)
    except ValueError as ex:
        return _back(s["id"], str(ex))
    audit(conn, u, "nat_validation_evaluate", {"site": s["id"], "verdict": r["verdict"]})
    return _back(s["id"], f"Validation evaluated: {r['verdict']}")


@app.post("/netmon/onboarding/validate/cancel")
def validate_cancel(req: Request, csrf: str = Form(""), site: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    s = _site(site)
    O.cancel_validation(conn, s["id"])
    audit(conn, u, "nat_validation_end", {"site": s["id"]})
    return _back(s["id"], "Validation closed (the last result stays on the Coverage page)")


@app.get("/netmon/api/onboarding")
def onboarding_api(req: Request, site: str = ""):
    need(req, "viewer")
    s = _site(site)
    r = O.evaluate(cfg, ch, dash, conn, s, monitor=_monitor_addr(req))
    nat = r["sources"]["nat"]
    if nat.get("attribution"):
        nat["attribution"] = {k: v for k, v in nat["attribution"].items() if k != "hosts"} | {"hosts": nat["attribution"]["hosts"][:20]}
    return r | {"validation": O.get_validation(conn, s["id"])}
