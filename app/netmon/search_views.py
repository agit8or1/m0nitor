"""Investigate → Search: plain-English questions, editable filters, results, saved searches, reviewed detections.
Viewing and searching: viewer. Sharing and proposing detections: analyst. Approving detections: admin."""
import json
import time
from urllib.parse import quote, urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import nlsearch as N
from .ux import INVESTIGATE_TABS, empty_state, evidence_details, fmt_local, tabs
from .web import ROLES, app, cfg, ch, check_csrf, conn, csrf_field, e, human_bytes, need, page, user_of

PATH = "/netmon/search/flows"
SPEC_KEYS = [k for k in N.FIELDS if k not in ("sites",)]


def _ai():
    from .ai import AI
    return AI(cfg, conn)


def _spec_from_query(qp):
    spec = {k: qp.get(k) for k in SPEC_KEYS if qp.get(k) not in (None, "")}
    sites = [x for x in qp.getlist("sites") if x] if hasattr(qp, "getlist") else []
    if sites:
        spec["sites"] = sites
    return spec


def _qs(spec):
    items = [(k, v) for k, v in spec.items() if k != "sites" and not k.startswith("_")]
    items += [("sites", x) for x in spec.get("sites", [])]
    return urlencode([("f", "1")] + items)


def _dev_html(ip):
    if not ip:
        return "—"
    nat = set(cfg.get("outbound_nat_ips") or [])
    for s in cfg.sites:
        nat |= set(s.get("outbound_nat_ips") or [])
    if ip in nat:
        return f"<span class=mono>{e(ip)}</span> <span class='muted small'>(shared public address: several devices)</span>"
    try:
        internal = cfg.is_internal(ip)
    except ValueError:
        return e(ip)
    inner = cfg.binat.get(ip) if ip in getattr(cfg, "binat", {}) else None
    if internal or inner:
        dev = inner or ip
        return f"<a href='/netmon/servers/{quote(dev)}'>{e(cfg.asset_label(dev))}</a>" + (f" <span class='muted small'>via {e(ip)}</span>" if inner else "")
    return e(ip)


def _remote_html(ip):
    if not ip:
        return "—"
    try:
        if cfg.is_internal(ip):
            return f"<a href='/netmon/servers/{quote(ip)}'>{e(cfg.asset_label(ip))}</a>"
    except ValueError:
        return e(ip)
    lab = cfg.label(ip)
    return f"<a href='/netmon/connections?rip={quote(ip)}'>{e(lab or ip)}</a>" + (f" <span class='muted small mono'>{e(ip)}</span>" if lab else "")


def _cell(k, v):
    from .dash import META
    if k == "device":
        return _dev_html(v)
    if k == "remote":
        return _remote_html(v)
    if k == "bytes":
        return human_bytes(v)
    if k in ("first", "last", "first_seen", "last_seen"):
        return e(fmt_local(v, with_tz=False))
    if k in ("country", "cc"):
        return e(META.get(v, {}).get("name", "")) if v and v.strip("\x00") else "—"
    if k == "proto":
        return e({6: "tcp", 17: "udp", 1: "icmp", 58: "icmp6"}.get(v, str(v)))
    if k == "asn":
        return f"<a href='/netmon/connections?asn={int(v)}'>AS{int(v)}</a>" if v else "—"
    if k == "records":
        return f"{int(v):,}"
    if k == "title":
        return e(v)
    return e(v if v not in (None, "") else "—")


HEAD = {"device": "Device", "remote": "Remote", "proto": "Protocol", "port": "Port", "direction": "Opened", "records": "Records", "bytes": "Volume",
        "first": "First", "last": "Last", "org": "Network owner", "cc": "Country", "country": "Country", "asn": "AS", "domain": "Name",
        "qtype": "Type", "rcode": "Result", "action": "Action", "iface": "Interface", "rule": "Finding type", "severity": "Severity",
        "title": "Finding", "status": "Status", "last_seen": "Last seen", "worst": "Worst severity", "subject": "Subject"}


def _results_table(spec, res):
    rows = res["rows"]
    if not rows:
        return empty_state("nomatch", " Nothing matched these filters in this period. Widen the period or remove a filter.")
    if spec["source"] == "findings" and spec["group"] == "none":
        cols = ["title", "severity", "asset", "status", "last_seen"]
        body = "".join(f"<tr><td><a href='/netmon/alert/{r['id']}'>{e(r['title'])}</a></td><td>{e(r['severity'])}</td><td>{_dev_html(r['asset'])}</td>"
                       f"<td>{e(r['status'])}</td><td>{_cell('last', r['last_seen'])}</td></tr>" for r in rows)
        head = "".join(f"<th scope=col>{HEAD.get(c, c)}</th>" for c in ["title", "severity", "device", "status", "last_seen"])
    else:
        cols = [c for c in rows[0] if c not in ("first",)]
        head = "".join(f"<th scope=col>{HEAD.get(c, c)}</th>" for c in cols)
        body = "".join("<tr>" + "".join(f"<td>{_cell(c, r.get(c))}</td>" for c in cols) + "</tr>" for r in rows)
    more = (f"<p class='muted small'>Showing the top {len(rows)}; there may be more (raise the limit, up to {N.MAX_LIMIT}).</p>"
            if len(rows) >= spec["limit"] else "")
    return f"<div class='wrap'><table class='tbl'><tr>{head}</tr>{body}</table></div>{more}"


def _filters_form(spec, admin_sites=True):
    def sel(name, opts, cur):
        return f"<select name={name}>" + "".join(f"<option value='{e(k)}' {'selected' if str(k) == str(cur) else ''}>{e(v)}</option>"
                                                for k, v in opts) + "</select>"
    rng = [(k, k) for k in N.RANGES] + ([("custom", "custom")] if spec.get("range") == "custom" else [])
    sites = "".join(f"<label class='inline'><input type=checkbox name=sites value='{e(s['id'])}' {'checked' if s['id'] in spec.get('sites', []) else ''}> "
                    f"{e(s['name'])}</label>" for s in cfg.sites) if len(cfg.sites) > 1 else ""
    custom = (f"<input type=hidden name=from value={spec['from']}><input type=hidden name=to value={spec['to']}>"
              if spec.get("range") == "custom" else "")
    v = lambda k: e(spec.get(k, ""))  # noqa: E731
    return f"""<details class="tech"><summary>Change the filters (no AI needed)</summary>
<form method=get action="{PATH}" class="stackform searchf"><input type=hidden name=f value=1>{custom}
<label>Data{sel('source', N.SOURCES.items(), spec.get('source', 'traffic'))}</label>
<label>Period{sel('range', rng, spec.get('range', '24h'))}</label>{('<fieldset><legend>Firewalls (none = all)</legend>' + sites + '</fieldset>') if sites else ''}
<label>Device (internal IP or range)<input name=device value="{v('device')}" class=mono></label>
<label>Remote (IP or range)<input name=remote value="{v('remote')}" class=mono></label>
<label>Country code<input name=country value="{v('country')}" maxlength=2 class=short></label>
<label>AS number<input name=asn value="{v('asn')}" inputmode=numeric class=short></label>
<label>Network owner name contains<input name=org value="{v('org')}"></label>
<label>Port<input name=port value="{v('port')}" inputmode=numeric class=short></label>
<label>Protocol{sel('proto', [('', 'any'), ('tcp', 'tcp'), ('udp', 'udp'), ('icmp', 'icmp')], spec.get('proto', ''))}</label>
<label>Direction (traffic){sel('direction', N.DIRECTIONS.items(), spec.get('direction', 'any'))}</label>
<label>Volume (traffic){sel('measure', [('received', 'received by the device'), ('sent', 'sent by the device')], spec.get('measure', 'received'))}</label>
<label>At least (bytes)<input name=min_bytes value="{v('min_bytes')}" inputmode=numeric></label>
<label>Name looked up (DNS)<input name=domain value="{v('domain')}"></label>
<label>Firewall action{sel('action', [('', 'any'), ('block', 'blocked'), ('pass', 'passed')], spec.get('action', ''))}</label>
<label>Minimum severity (findings){sel('severity', [('', 'any')] + [(x, x) for x in N.SEVERITIES], spec.get('severity', ''))}</label>
<label>Finding type<input name=rule value="{v('rule')}" class=mono></label>
<label>Group by{sel('group', N.GROUPS.items(), spec.get('group', 'none'))}</label>
<label>Limit<input name=limit type=number min=1 max={N.MAX_LIMIT} value="{spec.get('limit', 50)}"></label>
<button>Search with these filters</button></form></details>"""


@app.get(PATH, response_class=HTMLResponse)
def search_flows_page(req: Request, q: str = "", f: str = "", saved: int = 0, ai: str = "", msg: str = ""):
    u, r = user_of(req)
    analyst = ROLES[r] >= ROLES["analyst"]
    spec_in, notes, question = {}, [], q.strip()[:300]
    if saved:
        try:
            row = N.get(conn, saved)
        except N.SpecError:
            raise HTTPException(404)
        if not N.can_see(row, u):
            raise HTTPException(404)
        spec_in, question = json.loads(row["spec"]), row["question"] or ""
        conn.execute("UPDATE saved_searches SET last_run=? WHERE id=?", (time.time(), saved))
        conn.commit()
    elif f:
        spec_in = _spec_from_query(req.query_params)
    elif question:
        spec_in, notes = N.parse(question, cfg)
    banner = f"<div class='banner'>{e(msg)}</div>" if msg else ""
    ai_obj = _ai()
    askbox = (f"<form method=get action='{PATH}' class='row askq' role='search'><label class='grow'>Ask a question"
              f"<input name=q value='{e(question)}' maxlength=300 placeholder='e.g. Which devices talked to Russia in the last 7 days?' "
              "autocomplete=off></label><button>Search</button></form>")
    examples = "<p class='small'>Examples: " + " · ".join(f"<a href='{PATH}?q={quote(x)}'>{e(x)}</a>" for x in N.EXAMPLES[:6]) + "</p>"
    privacy = ("<p class='muted small'>Questions are interpreted by netmon itself; nothing is sent anywhere. "
               + ("You can also ask the AI service to interpret a question: you see exactly what is sent first." if ai_obj.enabled else
                  "AI interpretation is optional and not configured.") + " Searches are read-only and limited in time and size.</p>")
    saved_card = _saved_card(req, u, r)
    top = f"<section class='card'>{askbox}{examples}{privacy}</section>"
    if not spec_in and not f:
        if question and notes:
            body = (tabs(INVESTIGATE_TABS, PATH) + banner + top
                    + empty_state("nomatch", f" I could not turn “{question}” into filters ({notes[0].split(': ', 1)[-1]} not understood). "
                                  "Try one of the examples, or use the filters.") + _filters_form({}) + _ai_button(req, question, ai_obj) + saved_card)
        else:
            body = tabs(INVESTIGATE_TABS, PATH) + banner + top + _filters_form({}) + saved_card
        return page(req, "Search", body, "/netmon/investigations", scoped=False, subtitle="Ask in plain English; read-only")
    try:
        spec = N.validate(spec_in, cfg)
    except N.SpecError as ex:
        body = (tabs(INVESTIGATE_TABS, PATH) + banner + top + f"<div class='banner warn'>{e(str(ex))}</div>"
                + _filters_form({k: v for k, v in spec_in.items() if k in N.FIELDS}) + saved_card)
        return page(req, "Search", body, "/netmon/investigations", scoped=False)
    chips = "".join(f"<span class='tag'>{e(x)}</span> " for x in N.describe(spec, cfg))
    drop = (f"<p class='warnline small'>Left out because they do not apply to {e(N.SOURCES[spec['source']].lower())}: {e(', '.join(spec['_dropped']))}</p>"
            if spec.get("_dropped") else "")
    how = "interpreted by AI (check the filters)" if ai else "from the filters" if f else "interpreted by netmon" if question else "saved search"
    interp = (f"<section class='card'><div class='card-h'><h2>Searching for</h2></div><p>{chips}</p><p class='muted small'>{e(how)}</p>"
              + "".join(f"<p class='warnline small'>{e(n)}</p>" for n in notes) + drop + _filters_form(spec)
              + (_ai_button(req, question, ai_obj) if question and not ai and notes else "") + "</section>")
    try:
        res = N.run(conn, cfg, ch, spec)
        table = _results_table(spec, res)
        tech = evidence_details("Query (netmon's fixed template, typed parameters)", (res["sql"] or "SQLite: alerts") + "\n\n"
                                + json.dumps({k: v for k, v in (res.get("params") or {}).items() if not k.startswith("fd_")}, default=str))
        meta = f"<p class='muted small'>{len(res['rows'])} row(s) in {res['ms']} ms. {e(res['note'])}</p>"
    except N.SpecError as ex:
        table, tech, meta = f"<div class='banner warn'>{e(str(ex))}</div>", "", ""
    except Exception as ex:
        table, tech, meta = empty_state("unavailable", f" The data could not be read ({type(ex).__name__}). Try a shorter period."), "", ""
    save = "" if not meta else (f"""<details class="tech"><summary>Save this search</summary><form method=post action="/netmon/search/save" class="row">{csrf_field(req)}
<input type=hidden name=question value="{e(question)}"><input type=hidden name=spec value="{e(json.dumps({k: v for k, v in spec.items() if not k.startswith('_')}))}">
<label>Name<input name=name maxlength=80 required></label>{'<label><input type=checkbox name=shared value=1> Share with everyone</label>' if analyst else ''}
<button>Save</button></form></details>""")
    body = (tabs(INVESTIGATE_TABS, PATH) + banner + top + interp
            + f"<section class='card'><div class='card-h'><h2>Results</h2></div>{meta}{table}{save}{tech}</section>" + saved_card)
    return page(req, "Search", body, "/netmon/investigations", scoped=False, subtitle="Ask in plain English; read-only")


def _ai_button(req, question, ai_obj):
    if not ai_obj.enabled or not question:
        return ""
    return (f"<form method=post action='/netmon/search/ai/preview' class='row'>{csrf_field(req)}<input type=hidden name=q value='{e(question)}'>"
            "<button class='ghost'>Interpret with AI instead…</button><span class='muted small'>You see exactly what is sent before anything is sent.</span></form>")


def _saved_card(req, u, r):
    rows = N.visible(conn, u)
    admin = ROLES[r] >= ROLES["admin"]
    analyst = ROLES[r] >= ROLES["analyst"]
    if not rows:
        return ("<section class='card'><div class='card-h'><h2>Saved searches</h2></div><p class='muted'>None yet. Run a search and use "
                "“Save this search”. Saved searches can be proposed as detections; an admin reviews them before they run.</p></section>")
    lis = []
    for x in rows:
        det = ""
        if x["detect"] == "proposed":
            det = " <span class='tag warn'>detection proposed — waiting for review</span>"
        elif x["detect"] == "approved":
            det = (f" <span class='tag ok'>detection: every {x['detect_interval_s'] // 60} min, {x['detect_threshold']}+ results, "
                   f"{e(x['detect_severity'])}</span>")
        acts = ""
        if analyst and x["detect"] == "none" and json.loads(x["spec"])["source"] != "findings":
            acts += (f"<details class='inline'><summary class='sm'>Propose as detection</summary><form method=post action='/netmon/search/saved/{x['id']}/propose' "
                     f"class='stackform'>{csrf_field(req)}<label>Run every (minutes)<input name=interval_m type=number min=15 max=1440 value=60></label>"
                     "<label>Raise a finding at (results)<input name=threshold type=number min=1 value=1></label>"
                     "<label>Severity<select name=severity><option>low</option><option selected>medium</option><option>high</option></select></label>"
                     "<button>Propose</button><p class='muted small'>Nothing runs until an admin reviews it.</p></form></details>")
        if admin and x["detect"] in ("proposed", "approved"):
            acts += f" <a class='sm' href='/netmon/search/saved/{x['id']}/review'>{'Review' if x['detect'] == 'proposed' else 'Review / stop'}</a>"
        if x["owner"] == u or admin:
            acts += (f" <form method=post action='/netmon/search/saved/{x['id']}/delete' class='inline' data-confirm='Delete saved search {e(x['name'])}?'>"
                     f"{csrf_field(req)}<button class='sm'>Delete</button></form>")
        lis.append(f"<li><span class='s1'><a href='{PATH}?saved={x['id']}'>{e(x['name'])}</a>{' <span class=tag>shared</span>' if x['shared'] else ''}{det}</span>"
                   f"<span class='s2'>by {e(x['owner'])}{' · ' + e(x['question']) if x['question'] else ''}</span><span class='acts'>{acts}</span></li>")
    return f"<section class='card'><div class='card-h'><h2>Saved searches</h2></div><ul class='sentences'>{''.join(lis)}</ul></section>"


@app.post("/netmon/search/ai/preview", response_class=HTMLResponse)
async def search_ai_preview(req: Request):
    u, _ = user_of(req)
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    ai_obj = _ai()
    if not ai_obj.enabled:
        raise HTTPException(400, "AI is not configured")
    q = str(f.get("q", ""))[:300]
    pv = N.ai_preview(ai_obj, q)
    left = pv["limit"] - pv["used_today"]
    body = (tabs(INVESTIGATE_TABS, PATH) + f"""<section class="card"><div class="card-h"><h2>Send this question to the AI service?</h2></div>
<p>Exactly this text is sent, and nothing else (no traffic data):</p><pre class="mono">{e(pv['text'])}</pre>
<p class="small">{len(pv['mapping'])} internal address(es) or device name(s) are replaced by placeholders; the mapping stays here.
Model: <b>{e(pv['model'])}</b>. AI requests today: {pv['used_today']} of {pv['limit']}. The answer is only a set of filters, which
netmon checks and shows to you; it never becomes a database query by itself.</p>
""" + (f"""<form method=post action="/netmon/search/ai/run" class="row">{csrf_field(req)}<input type=hidden name=q value="{e(q)}">
<input type=hidden name=digest value="{e(pv['digest'])}"><button>Send</button> <a href="{PATH}?q={quote(q)}">Cancel</a></form>""" if left > 0 else
           "<p class='warnline'>The daily AI request limit is reached. Use the filters instead.</p>") + "</section>")
    return page(req, "Search · AI preview", body, "/netmon/investigations", scoped=False)


@app.post("/netmon/search/ai/run")
async def search_ai_run(req: Request):
    u, _ = user_of(req)
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    q = str(f.get("q", ""))[:300]
    try:
        spec = N.ai_interpret(_ai(), u, q, str(f.get("digest", "")))
    except N.SpecError as ex:
        return RedirectResponse(f"{PATH}?q={quote(q)}&msg={quote(str(ex))}", 303)
    return RedirectResponse(f"{PATH}?{_qs(spec)}&ai=1&q={quote(q)}", 303)


@app.post("/netmon/search/save")
async def search_save(req: Request):
    u, r = user_of(req)
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    try:
        spec = N.validate(json.loads(str(f.get("spec", "{}"))), cfg)
        shared = bool(f.get("shared")) and ROLES[r] >= ROLES["analyst"]
        sid = N.save(conn, u, str(f.get("name", "")), str(f.get("question", "")), spec, shared)
    except (N.SpecError, ValueError) as ex:
        raise HTTPException(400, str(ex))
    return RedirectResponse(f"{PATH}?saved={sid}&msg={quote('Saved.')}", 303)


@app.post("/netmon/search/saved/{sid}/delete")
async def search_saved_delete(req: Request, sid: int):
    u, r = user_of(req)
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    try:
        N.delete(conn, sid, u, admin=ROLES[r] >= ROLES["admin"])
    except N.SpecError:
        raise HTTPException(404)
    except PermissionError as ex:
        raise HTTPException(403, str(ex))
    return RedirectResponse(f"{PATH}?msg={quote('Deleted.')}", 303)


@app.post("/netmon/search/saved/{sid}/propose")
async def search_saved_propose(req: Request, sid: int):
    u = need(req, "analyst")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    try:
        row = N.get(conn, sid)
        if not N.can_see(row, u):
            raise HTTPException(404)
        N.propose(conn, sid, u, int(f.get("interval_m", 60)) * 60, int(f.get("threshold", 1)), str(f.get("severity", "medium")))
    except (N.SpecError, ValueError) as ex:
        raise HTTPException(400, str(ex))
    return RedirectResponse(f"{PATH}?msg={quote('Proposed. An admin reviews it before it runs.')}", 303)


@app.get("/netmon/search/saved/{sid}/review", response_class=HTMLResponse)
def search_saved_review(req: Request, sid: int):
    need(req, "admin")
    try:
        row = N.get(conn, sid)
    except N.SpecError:
        raise HTTPException(404)
    if row["detect"] not in ("proposed", "approved"):
        raise HTTPException(400, "this saved search is not a detection")
    spec = N.validate(json.loads(row["spec"]), cfg)
    try:
        pv = N.review_preview(conn, cfg, ch, row)
        pv_html = (f"<p>Sampled {pv['sampled']} windows of {row['detect_interval_s'] // 60} min over the last 7 days: it would have fired in "
                   f"<b>{pv['fires']}</b>; roughly <b>{pv['per_day']:.1f} finding(s) per day</b>.</p>"
                   + ("<p class='warnline'>That is noisy: raise the threshold or narrow the search.</p>" if pv["per_day"] > 5 else ""))
    except Exception as ex:
        pv_html = f"<p class='warnline'>Could not preview ({type(ex).__name__}).</p>"
    chips = "".join(f"<span class='tag'>{e(x)}</span> " for x in N.describe(spec, cfg) if not x.startswith(("last ", "from ")))
    act = (f"""<form method=post action="/netmon/search/saved/{sid}/approve" class="row">{csrf_field(req)}<label>Note<input name=note maxlength=200></label>
<button>Approve: run every {row['detect_interval_s'] // 60} min</button></form>""" if row["detect"] == "proposed" else "")
    body = (tabs(INVESTIGATE_TABS, PATH) + f"""<section class="card"><div class="card-h"><h2>Review detection: {e(row['name'])}</h2></div>
<p>Proposed by {e(row['proposed_by'] or '?')}{' on ' + e(fmt_local(row['proposed_at'])) if row['proposed_at'] else ''}.
Raises a <b>{e(row['detect_severity'])}</b> finding when the search returns <b>{row['detect_threshold']}</b> or more results in a
{row['detect_interval_s'] // 60}-minute window.</p><p>{chips}</p>{pv_html}
<p class="muted small">Findings follow the normal notification rules and exceptions. A search detection never blocks anything.</p>{act}
<form method=post action="/netmon/search/saved/{sid}/reject" class="row">{csrf_field(req)}<label>Note<input name=note maxlength=200></label>
<button class="ghost">{'Reject' if row['detect'] == 'proposed' else 'Stop this detection'}</button></form></section>""")
    return page(req, "Review detection", body, "/netmon/investigations", scoped=False)


@app.post("/netmon/search/saved/{sid}/approve")
async def search_saved_approve(req: Request, sid: int):
    u = need(req, "admin")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    try:
        N.approve(conn, sid, u, str(f.get("note", "")))
    except N.SpecError as ex:
        raise HTTPException(400, str(ex))
    return RedirectResponse(f"{PATH}?msg={quote('Approved: the detection runs from the next detector cycle.')}", 303)


@app.post("/netmon/search/saved/{sid}/reject")
async def search_saved_reject(req: Request, sid: int):
    u = need(req, "admin")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    N.reject(conn, sid, u, str(f.get("note", "")))
    return RedirectResponse(f"{PATH}?msg={quote('Detection stopped.')}", 303)
