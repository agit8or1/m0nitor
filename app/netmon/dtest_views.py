"""Investigate → Test detections: run a synthetic scenario against the real rules (expected vs actual, and why), and
preview rule changes on synthetic scenarios and on retained data. Nothing here records, notifies or blocks.
Running tests: analyst. Previewing rule changes: admin (the rules page)."""
import json
import time
from urllib.parse import quote

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import dtest as T
from .ux import INVESTIGATE_TABS, evidence_details, fmt_local, tabs
from .web import ROLES, app, cfg, ch, check_csrf, conn, csrf_field, e, need, page, user_of

PATH = "/netmon/detections/test"


def _site(sid):
    return cfg.site(sid) if sid and cfg.site(sid) else cfg.sites[0]


def _result_html(r):
    badge = ("<b class='s-good'>✓ as expected</b>" if r["passed"] else "<b class='s-warning'>▲ not as expected</b>")
    rows = ""
    for x in r["expected"]:
        exp = x["expected"]
        what = f"{e(exp['rule'])} for {e(exp['asset'] if exp['asset'] != '*' else 'the device or its public address')}"
        got = (f"<a class='small'>{e(x['finding']['title'])}</a>" if x["finding"] else "<span class='muted'>no finding</span>")
        why = "".join(f"<li>{e(w)}</li>" for w in x["why"] if w)
        rows += (f"<tr><td>{what}</td><td>{'<b class=s-good>raised</b>' if x['ok'] else '<b class=s-warning>not raised</b>'}<div>{got}</div></td>"
                 f"<td class='small'><b>{'Why it triggered' if x['ok'] else 'Why not'}</b><ul>{why}</ul></td></tr>")
    if not r["expected"]:
        rows = ("<tr><td>no finding</td><td>" + ("<b class=s-good>none raised</b>" if not r["unexpected"] else "<b class=s-warning>raised</b>")
                + "</td><td class='small'>A good detection stays quiet on usual traffic.</td></tr>")
    extra = "".join(f"<li><b>{e(f['rule'])}</b>: {e(f['title'])} <span class='muted'>({e(f.get('baseline') or '')[:200]})</span></li>"
                    for f in r["unexpected"])
    hid = "".join(f"<li>{e(f['rule'])}: {e(f['title'])} — {e(w)}</li>" for f, w in r["hidden"])
    return (f"<section class='card'><div class='card-h'><h2>{e(r['name'])}</h2>{badge}</div>"
            f"<p class='muted small'>Synthetic data only ({r['records']:,} made-up records, never stored), the real rules with "
            f"{'the proposed' if r.get('proposed') else 'the current'} settings, {r['queries']} read-only queries, {r['ms']} ms. "
            "Nothing was recorded or notified.</p>"
            f"<div class='wrap'><table class='tbl'><tr><th scope=col>Expected</th><th scope=col>Actual</th><th scope=col>Explanation</th></tr>{rows}</table></div>"
            + (f"<p><b>Also raised (not expected):</b></p><ul class='small'>{extra}</ul>" if extra else "")
            + (f"<p class='small'><b>Raised but hidden:</b></p><ul class='small'>{hid}</ul>" if hid else "")
            + ("<p class='warnline small'>" + e("; ".join(r["errors"])) + "</p>" if r["errors"] else "")
            + evidence_details("First query as sent (synthetic tables as values())", "\n\n".join(q[:3000] for q in r["sql"][:1]))
            + "</section>")


def _scenario_form(req, site, key, params, action=PATH, hidden=""):
    opts = "".join(f"<option value='{k}' {'selected' if k == key else ''}>{e(v['name'])}</option>" for k, v in T.SCENARIOS.items())
    sc = T.SCENARIOS[key]
    fields = "".join(f"<label>{e(spec[0])}<input name={k} value='{e(params.get(k, spec[2]))}'></label>" for k, spec in sc["params"].items())
    sitesel = ("<label>Firewall<select name=site>" + "".join(f"<option value='{e(x['id'])}' {'selected' if x['id'] == site['id'] else ''}>{e(x['name'])}</option>"
                                                           for x in cfg.sites) + "</select></label>") if len(cfg.sites) > 1 else ""
    pick = (f"<form method=get action='{PATH}' class='row'><label>Scenario<select name=scenario>{opts}</select></label>"
            f"<input type=hidden name=site value='{e(site['id'])}'><button class='ghost'>Choose</button></form>")
    return (pick + f"<form method=post action='{action}' class='stackform'>{csrf_field(req)}{hidden}{sitesel}"
            f"<input type=hidden name=scenario value='{e(key)}'><p><b>{e(sc['name'])}</b>: <span class='muted small'>{e(sc['text'])}</span></p>"
            f"<label>Device (internal address)<input name=device class=mono value='{e(params.get('device', T.default_device(cfg)))}'></label>{fields}"
            "<div class='row'><button>Test detection</button> <button name=all value=1 class='ghost'>Run all scenarios</button></div></form>")


def _intro():
    return ("<p class='muted small'>Tests run the real detection rules against made-up records that exist only inside the query (they are "
            "never written anywhere), so production data and findings are untouched. Nothing is recorded, notified or blocked. "
            "Exceptions and expected devices are applied the way the detector applies them, so a test also shows when one of them would "
            "hide a finding.</p>")


@app.get(PATH, response_class=HTMLResponse)
def dtest_page(req: Request, scenario: str = "new_country", site: str = "", msg: str = ""):
    u, r = user_of(req)
    s = _site(site)
    key = scenario if scenario in T.SCENARIOS else "new_country"
    analyst = ROLES[r] >= ROLES["analyst"]
    banner = f"<div class='banner'>{e(msg)}</div>" if msg else ""
    form = _scenario_form(req, s, key, {}) if analyst else "<p class='muted'>Analysts and admins run detection tests.</p>"
    last, ts = _last_replay(s)
    body = (tabs(INVESTIGATE_TABS, PATH) + banner + _intro()
            + f"<section class='card'><div class='card-h'><h2>Test a detection</h2></div>{form}</section>"
            + "<section class='card'><div class='card-h'><h2>Preview rule changes</h2></div><p>Change thresholds on "
              "<a href='/netmon/settings/rules'>Settings → Alert rules</a> and choose <b>Preview rule changes</b> instead of Save: the changed "
              "rules are tested with these scenarios and replayed on your retained data, comparing how many findings the current and "
              "the proposed settings would raise. Nothing is saved until you save on the rules page.</p>"
            + (f"<p class='small'>Last replay: {e(fmt_local(ts))} by {e(last.get('user', '?'))} — <a href='{PATH}/replay/last?site={quote(s['id'])}'>"
               "see the comparison</a></p>" if last else "") + "</section>")
    return page(req, "Test detections", body, "/netmon/investigations", scoped=False, subtitle="Synthetic scenarios and replay; nothing is recorded")


@app.post(PATH, response_class=HTMLResponse)
async def dtest_run(req: Request):
    need(req, "analyst")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    s = _site(str(f.get("site", "")))
    key = str(f.get("scenario", "new_country"))
    if key not in T.SCENARIOS:
        raise HTTPException(400, "unknown scenario")
    keys = list(T.SCENARIOS) if f.get("all") else [key]
    results = []
    try:
        dev_params = T.scenario_params(key, f, cfg)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    t0 = time.time()
    for k in keys:
        if time.time() - t0 > T.SCENARIO_RUNTIME:
            results.append(None)
            break
        p = dev_params if k == key else T.scenario_params(k, {"device": dev_params["device"]}, cfg)
        try:
            results.append(T.run_scenario(conn, cfg, ch, s, k, p))
        except T.Isolated as ex:
            raise HTTPException(500, f"isolation check stopped the test: {ex}")
        except Exception as ex:
            results.append({"error": f"{T.SCENARIOS[k]['name']}: {type(ex).__name__}: {str(ex)[:200]}"})
    ok = sum(1 for x in results if x and x.get("passed"))
    summary = (f"<p><b>{ok} of {len(results)}</b> scenario(s) behaved as expected.</p>" if len(results) > 1 else "")
    out = "".join(_result_html(x) if x and "error" not in x else
                  f"<div class='banner warn'>{e(x['error'] if x else 'time limit reached; remaining scenarios skipped')}</div>" for x in results)
    body = (tabs(INVESTIGATE_TABS, PATH) + _intro() + summary + out
            + f"<section class='card'><div class='card-h'><h2>Test again</h2></div>{_scenario_form(req, s, key, dev_params)}</section>")
    return page(req, "Test detections", body, "/netmon/investigations", scoped=False)


# ---- preview rule changes ------------------------------------------------------------------------------------------
SCENARIO_FOR = {"new_dest_country": ["new_country", "normal"], "outbound_volume": ["large_upload", "normal"], "unexpected_inbound": ["exposed_port"],
                "fanout": ["port_scan"], "beaconing": ["beaconing"]}


async def preview_from_form(req, form):
    """Called from the Alert rules page (button 'Preview rule changes'): admin, CSRF already checked."""
    from .admin import parse_rules_form
    rules_ov, det_ov = parse_rules_form(form)
    s = _site(str(form.get("site", "")))
    chg = T.changes(cfg, rules_ov, det_ov)
    if not chg:
        return RedirectResponse("/netmon/settings/rules?msg=" + quote("Nothing changed compared with the current settings."), 303)
    rules = T.changed_rules(cfg, rules_ov, det_ov)
    keys = sorted({k for r in rules for k in SCENARIO_FOR.get(r, [])}, key=list(T.SCENARIOS).index)
    rows = "".join(f"<tr><td>{e(n)}</td><td>{e(k.replace('_', ' '))}</td><td>{e(a)}</td><td><b>{e(b)}</b></td></tr>" for n, k, a, b in chg)
    comp = ""
    t0 = time.time()
    for k in keys:
        if time.time() - t0 > T.SCENARIO_RUNTIME:
            comp += "<tr><td colspan=3 class=muted>time limit reached; remaining scenarios skipped</td></tr>"
            break
        p = T.scenario_params(k, {}, cfg)
        try:
            a = T.run_scenario(conn, cfg, ch, s, k, p)
            b = T.run_scenario(conn, cfg, ch, s, k, p, rules_ov, det_ov)
        except Exception as ex:
            comp += f"<tr><td>{e(T.SCENARIOS[k]['name'])}</td><td colspan=2 class=warnline>{e(type(ex).__name__)}</td></tr>"
            continue

        def cell(x):
            return ("<b class='s-good'>✓ as expected</b>" if x["passed"] else "<b class='s-warning'>▲ not as expected</b>") + \
                "<div class='small muted'>" + e("; ".join(w for y in x["expected"] for w in y["why"][:1])[:240]) + "</div>"
        comp += f"<tr><td>{e(T.SCENARIOS[k]['name'])}</td><td>{cell(a)}</td><td>{cell(b)}</td></tr>"
    replayable = [r for r in rules if r in T.REPLAYABLE]
    skipped = [f"{r} ({T.NOT_REPLAYABLE.get(r, 'not replayable')})" for r in rules if r not in T.REPLAYABLE]
    payload = json.dumps({"rules": rules_ov, "detector": det_ov})
    replay = (f"""<form method=post action="{PATH}/replay" class="row">{csrf_field(req)}<input type=hidden name=site value="{e(s['id'])}">
<input type=hidden name=changes value="{e(payload)}"><label>Retained data<select name=span><option value=86400>last 24 hours</option>
<option value=259200>last 3 days</option><option value=604800>last 7 days</option></select></label><button>Replay on retained data</button>
<span class="muted small">Up to {T.REPLAY_MAX_WINDOWS} sampled windows, at most {T.REPLAY_MAX_RUNTIME // 60} min, in the background; you can cancel it.</span></form>"""
              if replayable else "<p class='muted'>None of the changed rules can be replayed.</p>")
    hidden_form = "".join(f"<input type=hidden name='{e(k)}' value='{e(v)}'>" for k, v in form.multi_items() if k not in ("csrf", "preview"))
    body = (tabs(INVESTIGATE_TABS, PATH) + f"""<section class="card"><div class="card-h"><h2>Preview rule changes</h2><span class="muted small">nothing is saved</span></div>
<div class="wrap"><table class="tbl"><tr><th>Rule</th><th>Setting</th><th>Now</th><th>Proposed</th></tr>{rows}</table></div></section>
<section class="card"><div class="card-h"><h2>Synthetic scenarios</h2></div>""" + _intro()
            + (f"<div class='wrap'><table class='tbl'><tr><th>Scenario</th><th>Current settings</th><th>Proposed settings</th></tr>{comp}</table></div>"
               if comp else "<p class='muted'>No scenario covers the changed rules.</p>")
            + f"""</section><section class="card"><div class="card-h"><h2>Replay on your retained data</h2></div>
<p class="small">Runs the changed rules ({e(', '.join(replayable) or 'none')}) with the current and the proposed settings over past windows and
compares how many findings each would have raised. Exceptions and expected devices apply as usual. Nothing is recorded or notified.</p>
{('<p class="muted small">Not replayable: ' + e(', '.join(skipped)) + '</p>') if skipped else ''}{replay}</section>
<form method=post action="/netmon/settings/rules" class="row">{csrf_field(req)}{hidden_form}<button class="primary">Save these rules</button>
<a href="/netmon/settings/rules">Back without saving</a></form>""")
    return page(req, "Preview rule changes", body, "/netmon/investigations", scoped=False)


@app.post(f"{PATH}/replay")
async def dtest_replay_start(req: Request):
    u = need(req, "admin")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    s = _site(str(f.get("site", "")))
    try:
        ch_ = json.loads(str(f.get("changes", "{}")))
        rules_ov, det_ov = ch_.get("rules") or {}, ch_.get("detector") or {}
        if not isinstance(rules_ov, dict) or not isinstance(det_ov, dict):
            raise ValueError("bad changes")
        known = cfg["rules"]
        rules_ov = {n: {k: v for k, v in ov.items() if k in known.get(n, {}) and isinstance(v, (int, float, bool, list))}
                    for n, ov in rules_ov.items() if n in known and isinstance(ov, dict)}
        det_ov = {k: int(v) for k, v in det_ov.items() if k in cfg["detector"] and isinstance(v, (int, float))}
        from .core import db_connect
        jid = T.start_replay(cfg, ch, db_connect, s, rules_ov, det_ov, int(f.get("span", 86400)), u)
    except (ValueError, TypeError) as ex:
        raise HTTPException(400, str(ex))
    return RedirectResponse(f"{PATH}/replay/{jid}", 303)


def _replay_html(st, live):
    res = st.get("result") or {}
    status = {"running": "running", "queued": "starting", "done": "finished", "cancelled": "cancelled", "stopped": "stopped"}.get(st["status"], st["status"])
    prog = f"{st.get('done', 0)} of {st.get('total', 0)} windows"
    rows = ""
    for r, v in res.items():
        delta = v["proposed"] - v["current"]
        ex = "".join(f"<li>+ {e(x['title'])} <span class='muted'>({x['windows']} window(s))</span></li>" for x in v["added"][:8])
        ex += "".join(f"<li>− {e(x['title'])} <span class='muted'>({x['windows']} window(s))</span></li>" for x in v["removed"][:8])
        rows += (f"<tr><td>{e(r)}</td><td class=num>{v['current']}</td><td class=num><b>{v['proposed']}</b></td>"
                 f"<td class=num>{'+' if delta > 0 else ''}{delta}</td><td class='small'><ul>{ex or '<li class=muted>same findings</li>'}</ul></td></tr>")
    table = (f"<div class='wrap'><table class='tbl'><tr><th>Rule</th><th>Current</th><th>Proposed</th><th>Change</th><th>Examples (+ new, − gone)</th></tr>"
             f"{rows}</table></div><p class='muted small'>Counted as distinct findings (rule, device, subject) over the sampled windows, the way "
             "repeated findings merge into one alert. Sampled windows: an estimate, not every hour.</p>" if res else "")
    return (f"<p>Status: <b>{e(status)}</b> · {e(prog)}{' · ' + e(st['note']) if st.get('note') else ''} · started {e(fmt_local(st['started']))} by "
            f"{e(st.get('user', '?'))}</p>" + table
            + ("<p class='warnline small'>Errors: " + e("; ".join(st["errors"][:5])) + "</p>" if st.get("errors") else ""))


@app.get(PATH + "/replay/{jid}", response_class=HTMLResponse)
def dtest_replay_page(req: Request, jid: str, site: str = ""):
    need(req, "admin")
    if jid == "last":
        st, _ = _last_replay(_site(site))
        if not st:
            raise HTTPException(404)
        live = False
    else:
        j = T.job(jid)
        if not j:
            raise HTTPException(404, "this replay is no longer in memory; see the last result")
        st, live = j.state, j.is_alive()
    cancel = (f"<form method=post action='{PATH}/replay/{e(jid)}/cancel' class='inline'>{csrf_field(req)}<button>Cancel</button></form>" if live else "")
    refresh = "<meta http-equiv='refresh' content='3'>" if live else ""
    body = (tabs(INVESTIGATE_TABS, PATH) + refresh + f"<section class='card' aria-live='polite'><div class='card-h'><h2>Replay of proposed rule changes</h2>{cancel}</div>"
            + _replay_html(st, live) + "<p class='small'><a href='/netmon/settings/rules'>Back to Alert rules</a></p></section>")
    return page(req, "Replay", body, "/netmon/investigations", scoped=False)


@app.get("/netmon/api" + PATH.removeprefix("/netmon") + "/replay/{jid}")
def dtest_replay_api(req: Request, jid: str):
    need(req, "admin")
    j = T.job(jid)
    if not j:
        raise HTTPException(404)
    return JSONResponse({k: v for k, v in j.state.items() if k != "result"} | {"result": j.state.get("result")})


@app.post(PATH + "/replay/{jid}/cancel")
async def dtest_replay_cancel(req: Request, jid: str):
    need(req, "admin")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    j = T.job(jid)
    if not j:
        raise HTTPException(404)
    j.cancel.set()
    return RedirectResponse(f"{PATH}/replay/{jid}", 303)


def _last_replay(site):
    from .core import get_state
    st, ts = get_state(conn, f"dtest:replay:{site['id']}", None)
    return st, ts
