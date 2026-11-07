"""Investigate → Threat hunt: indicator lists, retro searches with progress and cancellation, results that say what
was searched and how much a match means. Running hunts and manual lists: analyst. Feeds (netmon fetches a URL): admin."""
import json
import time
from urllib.parse import quote, urlencode

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import access
from . import hunt as H
from . import identity as idn
from .core import audit
from .ux import INVESTIGATE_TABS, conf_badge, device_html, empty_state, fmt_local, tabs
from .web import need_all_sites, ROLES, app, cfg, ch, check_csrf, conn, csrf_field, e, human_bytes, need, page, site_name, user_of

PERIODS = {"24h": ("Last 24 hours", 86400), "7d": ("Last 7 days", 7 * 86400), "all": ("All retained history (up to 31 days)", H.MAX_DAYS * 86400)}
SOURCE_LABEL = {"flows": "traffic records", "dns": "DNS query", "dns_answer": "DNS answer", "firewall": "firewall log"}
TYPE_LABEL = {"ip": "IP address", "cidr": "address range", "domain": "domain"}
NOT_PROOF = ("A match is evidence to investigate, not proof: indicators go stale, addresses are reused, and CDN or shared-hosting "
             "addresses serve many unrelated sites.")


def _run_ok(x):
    """A hunt run is visible when every firewall it searched is visible to the signed-in user (netmon.access)."""
    try:
        sites = json.loads(x["spec"] or "{}").get("sites") or []
    except ValueError:
        sites = []
    return all(access.can_site(s) for s in sites) and (sites or not access.restricted())


def _run(rid, cols="*"):
    x = conn.execute(f"SELECT {cols}, spec FROM hunt_runs WHERE id=?", (rid,)).fetchone()
    if not x or not _run_ok(x):
        raise HTTPException(404)
    return x


def _msg(m):
    return f"<div class='banner'>{e(m)}</div>" if m else ""


def _d(ts):
    return time.strftime("%Y-%m-%d", time.gmtime(ts)) if ts else "—"


@app.get("/netmon/hunt", response_class=HTMLResponse)
def hunt_page(req: Request, msg: str = ""):
    u, r = user_of(req)
    can, admin = ROLES[r] >= ROLES["analyst"], ROLES[r] >= ROLES["admin"]
    lists = conn.execute("SELECT l.*, (SELECT count(*) FROM indicators i WHERE i.list_id=l.id AND i.active=1) AS n FROM indicator_lists l "
                         "ORDER BY l.enabled DESC, l.id DESC").fetchall()
    runs = [x for x in conn.execute("SELECT * FROM hunt_runs ORDER BY id DESC LIMIT 200").fetchall() if _run_ok(x)][:15]
    chk = "".join(f"<label class='chk'><input type=checkbox name=lists value={x['id']} {'checked' if x['enabled'] else 'disabled'}> "
                  f"{e(x['name'])} <span class='muted small'>({x['n']:,})</span></label>" for x in lists)
    per = "".join(f"<option value={k} {'selected' if k == '7d' else ''}>{e(v[0])}</option>" for k, v in PERIODS.items())
    sites = ("<label>Firewalls<select name=site><option value=all>All firewalls</option>" + "".join(
        f"<option value='{e(s['id'])}'>{e(s['name'])}</option>" for s in cfg.sites) + "</select></label>") if len(cfg.sites) > 1 else ""
    busy = conn.execute("SELECT id, spec FROM hunt_runs WHERE status IN ('queued','running','cancelling')").fetchone()
    form = (f"""<form method=post action="/netmon/hunt/run" class="stackform">{csrf_field(req)}
<fieldset><legend>Indicator lists</legend><div class="chkgrid">{chk or '<span class="muted">No lists yet — paste indicators below or add a list.</span>'}</div></fieldset>
<label>And/or paste indicators for this hunt only<textarea name=adhoc rows=4 class="mono" placeholder="one per line: 198.51.100.7, 203.0.113.0/24, bad.example.com, hxxps://evil[.]example/x"></textarea></label>
<div class="row"><label>Period<select name=period>{per}</select></label>{sites}<label>Confidence of pasted indicators<select name=conf>
<option>low</option><option selected>medium</option><option>high</option></select></label></div>
<div class="row"><button class="primary" {'disabled' if busy else ''}>Search history</button>
{(f"<span class='muted small'>Hunt <a href='/netmon/hunt/{busy[0]}'>#{busy[0]}</a> is running; one hunt runs at a time.</span>" if _run_ok(busy)
   else "<span class='muted small'>Another hunt is running; one hunt runs at a time.</span>") if busy else ''}</div>
<p class="muted small">Searches traffic records (both directions), the DNS query log and the firewall log. Read-only and bounded: at most
{H.MAX_DAYS} days, {H.MAX_IPS:,} addresses, {H.MAX_CIDRS} ranges and {H.MAX_DOMAINS:,} domains per hunt, {H.MAX_RUNTIME // 60} minutes.</p></form>"""
            if can else "<p class='muted'>Analysts can run hunts.</p>")
    lrows = "".join(
        f"<tr><td>{e(x['name'])}<div class='muted small'>{e(x['source'])}</div></td><td>{'feed' if x['kind'] == 'feed' else 'manual'}</td>"
        f"<td class='num'>{x['n']:,}</td><td>{conf_badge(x['confidence'])}</td>"
        f"<td class='small'>{e(x['last_status'] or ('—' if x['kind'] == 'manual' else 'not fetched yet'))}"
        f"{'<div class=muted>' + e(fmt_local(x['last_fetch'])) + '</div>' if x['last_fetch'] else ''}</td><td>"
        + ((f"<form method=post action='/netmon/hunt/lists/{x['id']}/fetch' class='inline'>{csrf_field(req)}<button class='sm'>Fetch now</button></form> "
            if x["kind"] == "feed" and admin and x["enabled"] else "")
           + (f"<form method=post action='/netmon/hunt/lists/{x['id']}/toggle' class='inline'>{csrf_field(req)}<button class='sm'>"
              f"{'Disable' if x['enabled'] else 'Enable'}</button></form>" if (admin or (can and x["kind"] == "manual")) else ""))
        + "</td></tr>" for x in lists)
    add = ""
    if can:
        add = f"""<details class="tech"><summary>Add a list</summary>
<form method=post action="/netmon/hunt/lists" class="stackform">{csrf_field(req)}
<div class="row"><label>Name<input name=name required maxlength=80></label><label>Source<input name=source maxlength=200 placeholder="who published it"></label>
<label>Confidence<select name=confidence><option>low</option><option selected>medium</option><option>high</option></select></label></div>
<label>Indicators (manual list)<textarea name=text rows=5 class="mono" placeholder="one per line, or CSV: value,confidence,published (YYYY-MM-DD),valid until"></textarea></label>
{'''<div class="row"><label>Or a feed URL (https, plain list or CSV)<input name=url type=url placeholder="https://"></label>
<label>Refresh every (hours)<input name=refresh_hours inputmode=numeric value=24 class="short"></label></div>
<p class="muted small">Only admins can add feeds: netmon will fetch the URL on a schedule (size-limited, https only).</p>''' if admin else ''}
<button>Add list</button></form></details>"""
    rrows = "".join(
        f"<tr><td><a href='/netmon/hunt/{x['id']}'>#{x['id']}</a></td><td>{e(fmt_local(x['created_at']))}</td><td>{e(x['created_by'])}</td>"
        f"<td>{e(x['status'])}</td><td>{_run_line(x)}</td></tr>" for x in runs)
    body = f"""{tabs(INVESTIGATE_TABS, '/netmon/hunt')}{_msg(msg)}
<div class="banner">{e(NOT_PROOF)}</div>
<section class="card"><div class="card-h"><h2>Search history for indicators</h2></div>{form}</section>
<section class="card"><div class="card-h"><h2>Indicator lists</h2><span class="muted small">deduplicated across lists when hunting</span></div>
<div class="wrap"><table class="tbl"><tr><th>List</th><th>Kind</th><th class="num">Active</th><th>Confidence</th><th>Last update</th><th></th></tr>
{lrows or '<tr><td colspan=6 class=muted>No lists yet</td></tr>'}</table></div>{add}</section>
<section class="card"><div class="card-h"><h2>Recent hunts</h2></div><div class="wrap"><table class="tbl"><tr><th>#</th><th>Started</th><th>By</th><th>Status</th><th>Result</th></tr>
{rrows or '<tr><td colspan=5 class=muted>No hunts yet</td></tr>'}</table></div></section>"""
    return page(req, "Threat hunt", body, "/netmon/investigate", scoped=False, subtitle="Did anything here talk to a known-bad address or domain?")


def _run_line(x):
    if x["status"] != "done":
        return e(x["error"] or (json.loads(x["progress"] or "{}").get("step") or ""))
    s = json.loads(x["summary"] or "{}")
    return e(f"{s.get('matched_indicators', 0)} indicator(s) matched on {s.get('devices', 0)} device(s)") if s.get("matches") else "no matches"


@app.post("/netmon/hunt/lists")
def add_list(req: Request, name: str = Form(...), source: str = Form(""), confidence: str = Form("medium"), text: str = Form(""),
             url: str = Form(""), refresh_hours: str = Form("24"), csrf: str = Form("")):
    need_all_sites(req, "viewer", "Indicator lists")
    u, r = user_of(req)
    need(req, "admin" if url.strip() else "analyst")
    check_csrf(req, csrf)
    try:
        if url.strip():
            lid = H.add_list(conn, name, "feed", source, confidence, u, url=url.strip(), refresh_hours=int(refresh_hours or 24))
            st = H.fetch_feed(conn, lid)
            return RedirectResponse(f"/netmon/hunt?msg={quote('Feed added: ' + st)}", 303)
        items, bad = H.parse_text(text, confidence)
        if not items:
            raise ValueError("no valid indicators found (IP addresses, ranges of at most /16, or domains)")
        lid = H.add_list(conn, name, "manual", source, confidence, u)
        added, total = H.store(conn, lid, items)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    audit(conn, u, "indicators_added", {"list": lid, "count": total, "rejected": bad})
    return RedirectResponse(f"/netmon/hunt?msg={quote(f'List added with {total:,} indicators' + (f'; {bad:,} lines not understood' if bad else ''))}", 303)


@app.post("/netmon/hunt/lists/{lid}/fetch")
def fetch_list(req: Request, lid: int, csrf: str = Form("")):
    u = need_all_sites(req, "admin", "Indicator lists")
    check_csrf(req, csrf)
    try:
        st = H.fetch_feed(conn, lid)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    audit(conn, u, "indicator_feed_fetched", {"list": lid, "status": st})
    return RedirectResponse(f"/netmon/hunt?msg={quote(st)}", 303)


@app.post("/netmon/hunt/lists/{lid}/toggle")
def toggle_list(req: Request, lid: int, csrf: str = Form("")):
    need_all_sites(req, "viewer", "Indicator lists")
    u, r = user_of(req)
    x = conn.execute("SELECT * FROM indicator_lists WHERE id=?", (lid,)).fetchone()
    if not x:
        raise HTTPException(404)
    need(req, "admin" if x["kind"] == "feed" else "analyst")
    check_csrf(req, csrf)
    conn.execute("UPDATE indicator_lists SET enabled=1-enabled WHERE id=?", (lid,))
    conn.commit()
    audit(conn, u, "indicator_list_toggled", {"list": lid, "enabled": not x["enabled"]})
    return RedirectResponse("/netmon/hunt", 303)


def retained_from(sites):
    try:
        r = ch.query("SELECT toUInt32(min(TimeReceived)) AS a FROM flows WHERE ExporterName IN {exps:Array(String)}",
                     {"exps": [s["exporter"] for s in sites]})
        return r[0]["a"] if r and r[0]["a"] else None
    except Exception:
        return None


@app.post("/netmon/hunt/run")
async def run_hunt(req: Request):
    u = need(req, "analyst")
    form = await req.form()
    check_csrf(req, str(form.get("csrf", "")))
    lists = [int(x) for x in form.getlist("lists") if str(x).isdigit()]
    adhoc, bad = H.parse_text(str(form.get("adhoc", "")), str(form.get("conf", "medium")) if form.get("conf") in H.CONFIDENCES else "medium")
    if not lists and not adhoc:
        raise HTTPException(400, "choose a list or paste indicators" + (f" ({bad} lines were not understood)" if bad else ""))
    want = str(form.get("site", "all"))
    sites = [s for s in cfg.sites if want == "all" or s["id"] == want] or list(cfg.sites)
    now = int(time.time())
    span = PERIODS.get(str(form.get("period", "7d")), PERIODS["7d"])[1]
    t0 = now - span
    ret = retained_from(sites)
    if ret and t0 < ret:
        t0 = ret
    try:
        rid = H.create_run(conn, u, {"lists": lists, "adhoc": adhoc, "t0": t0, "t1": now, "sites": [s["id"] for s in sites], "rejected": bad})
    except ValueError as ex:
        raise HTTPException(409, str(ex))
    H.start(cfg, ch, rid)
    return RedirectResponse(f"/netmon/hunt/{rid}", 303)


@app.post("/netmon/hunt/{rid}/cancel")
def cancel_hunt(req: Request, rid: int, csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    _run(rid, "id")
    H.cancel(conn, rid, u)
    return RedirectResponse(f"/netmon/hunt/{rid}", 303)


@app.get("/netmon/api/hunt/{rid}")
def hunt_status(req: Request, rid: int):
    user_of(req)
    x = _run(rid, "status, progress, error")
    return JSONResponse({"status": x["status"], "progress": json.loads(x["progress"] or "{}"), "error": x["error"]})


def _lab(site, ip, iid):
    if iid:
        return {**idn.label(conn, cfg, ip, site), "name": idn.name_of(conn, cfg, idn.resolve(conn, iid))}
    if ip in (cfg.get("outbound_nat_ips") or []):
        return {"name": "Shared NAT address", "ip": ip, "internal": False, "site": site}
    try:
        return idn.label(conn, cfg, cfg.binat.get(ip, ip), site)
    except Exception:
        return {"name": ip, "ip": ip}


@app.get("/netmon/hunt/{rid}", response_class=HTMLResponse)
def hunt_result(req: Request, rid: int, msg: str = ""):
    u, r = user_of(req)
    x = _run(rid)
    spec = json.loads(x["spec"])
    can = ROLES[r] >= ROLES["analyst"]
    head = (f"<p class='small'>Period {e(fmt_local(spec['t0']))} → {e(fmt_local(spec['t1']))} · firewalls "
            f"{e(', '.join(site_name(s) for s in spec['sites']))} · started by {e(x['created_by'])}</p>")
    if x["status"] in ("queued", "running", "cancelling"):
        p = json.loads(x["progress"] or "{}")
        body = f"""{tabs(INVESTIGATE_TABS, '/netmon/hunt')}<meta http-equiv="refresh" content="3">
<section class="card"><div class="card-h"><h2>Hunt #{rid} is {e(x['status'])}</h2></div>{head}
<div class="jobbar" role="progressbar" aria-valuenow="{int(p.get('pct', 0))}" aria-valuemin="0" aria-valuemax="100"><i style="width:{int(p.get('pct', 0))}%"></i></div>
<p class="small">{e(p.get('step', ''))} · {int(p.get('pct', 0))}%. This page refreshes by itself.</p>
{f"<form method=post action='/netmon/hunt/{rid}/cancel'>{csrf_field(req)}<button>Cancel</button></form>" if can and x['status'] != 'cancelling' else ''}</section>"""
        return page(req, f"Hunt #{rid}", body, "/netmon/investigate", scoped=False)
    if x["status"] != "done":
        body = (f"{tabs(INVESTIGATE_TABS, '/netmon/hunt')}<section class='card'><div class='card-h'><h2>Hunt #{rid} {e(x['status'])}</h2></div>{head}"
                + empty_state("unavailable" if x["status"] == "failed" else "nomatch", f" {x['error'] or 'The hunt was cancelled before it finished.'}",
                              "/netmon/hunt", "New hunt") + "</section>")
        return page(req, f"Hunt #{rid}", body, "/netmon/investigate", scoped=False)
    s = json.loads(x["summary"] or "{}")
    ms = conn.execute("SELECT * FROM hunt_matches WHERE run_id=? AND site_ok(site) ORDER BY ind_value, events DESC", (rid,)).fetchall()
    by = {}
    for m in ms:
        by.setdefault((m["ind_type"], m["ind_value"]), []).append(m)
    cov = ""
    for c in s.get("coverage", []):
        if c.get("error"):
            cov += f"<li>{e(c['source'])}: could not be checked ({e(c['error'])})</li>"
            continue
        pct = int(100 * (c.get("hours") or 0) / max(1, c.get("want") or 1))
        cov += (f"<li>{e(c['source'])} at {e(site_name(c['site']))}: "
                + (f"{e(fmt_local(c['from']))} → {e(fmt_local(c['to']))}, data in {min(100, pct)}% of the hours searched"
                   + (" — <b>gaps</b>: activity in the missing hours cannot be seen" if pct < 90 else "") if c.get("from") else "<b>no data in this period</b>")
                + "</li>")
    if spec.get("t0") and s.get("coverage"):
        ret = next((c.get("retained_from") for c in s["coverage"] if c.get("retained_from")), None)
        if ret and ret > spec["t0"] - 60:
            cov += f"<li>Traffic records are kept since {e(fmt_local(ret))}; older contact cannot be found.</li>"
    ind = s.get("indicators", {})
    sentence = (f"{s['matched_indicators']} of {sum(ind.values()):,} indicator(s) matched: {s['matches']} match(es) on {s['devices']} device(s)."
                if s.get("matches") else f"None of the {sum(ind.values()):,} indicator(s) appeared in the history searched.")
    groups = ""
    for (t, v), rows in by.items():
        d0 = json.loads(rows[0]["detail"] or "{}")
        flags = []
        if d0.get("stale"):
            flags.append("<span class='tag warn'>stale indicator</span>")
        if any(json.loads(m["detail"] or "{}").get("cdn") for m in rows):
            flags.append(f"<span class='tag'>CDN address ({e(next(json.loads(m['detail'])['cdn'] for m in rows if json.loads(m['detail']).get('cdn')))})</span>")
        items = ""
        for m in rows:
            d = json.loads(m["detail"] or "{}")
            lab = _lab(m["site"], m["device"], m["identity_id"]) if m["device"] else {"name": "—", "ip": ""}
            notes = []
            if d.get("before_published"):
                notes.append(f"This contact was before the indicator was published ({_d(d['published'])}); it may not have been malicious then.")
            if d.get("cdn"):
                notes.append(f"{d['cdn']} address: it serves many unrelated sites; the match may have nothing to do with the indicator.")
            elif (d.get("shared_names") or 0) >= H.SHARED_NAMES:
                notes.append(f"The address answered {d['shared_names']} different names here (shared hosting); the match may be unrelated.")
            if d.get("nat"):
                notes.append("Outbound records through the shared NAT address do not show which device made the connection (no replies seen).")
            if m["source"] == "dns_answer":
                notes.append(f"Looked up {m['matched']}, which resolved to this address.")
            conn_link = "/netmon/connections?" + urlencode({"range": "custom", "from": int(m["first"]) - 60, "to": int(m["last"]) + 60,
                                                             **({"host": cfg.binat.get(m["device"], m["device"])} if m["device"] and not d.get("nat") else {}),
                                                             **({"rip": m["matched"]} if m["source"] in ("flows", "firewall") else {})})
            more = f" and {d['remote_count'] - 1} more address(es) in the range" if d.get("remote_count", 1) > 1 else ""
            items += (f"<li><span class='s1'>{device_html(lab, show_conf=True)} — {e(SOURCE_LABEL.get(m['source'], m['source']))}, {e(m['direction'])}</span>"
                      f"<span class='s2'>{e(m['matched'])}{e(more)} · {m['events']:,} {'records' if m['source'] != 'dns' else 'queries'}"
                      f"{' · ' + human_bytes(m['bytes']) if m['bytes'] else ''} · first {e(fmt_local(m['first'], cfg.site(m['site'])))} · last "
                      f"{e(fmt_local(m['last'], cfg.site(m['site'])))}{(' · ' + e(site_name(m['site']))) if len(cfg.sites) > 1 else ''}</span>"
                      + "".join(f"<span class='s2 warnline'>{e(n)}</span>" for n in notes)
                      + f"<span class='acts'>{'<a href=' + chr(39) + e(conn_link) + chr(39) + '>View records →</a>' if m['source'] in ('flows', 'firewall') else ''}"
                      + (f" <form method=post action='/netmon/hunt/match/{m['id']}/finding' class='inline'>{csrf_field(req)}<button class='sm'>Create a finding</button></form>"
                         if can else "") + "</span></li>")
        groups += (f"<section class='card'><div class='card-h'><h2 class='mono'>{e(v)}</h2><span class='muted small'>{e(TYPE_LABEL.get(t, t))}</span></div>"
                   f"<p class='small'>From {e(', '.join(d0.get('lists') or []))} · {conf_badge(d0.get('confidence') or 'low')} · known to netmon since "
                   f"{e(_d(d0.get('known_since')))}{' · published ' + e(_d(d0['published'])) if d0.get('published') else ''}"
                   f"{' · valid until ' + e(_d(d0['valid_until'])) if d0.get('valid_until') else ''} {' '.join(flags)}</p>"
                   f"<ul class='sentence-list'>{items}</ul></section>")
    extra = []
    if s.get("limited"):
        extra.append(f"Only the first {H.MAX_IPS:,} addresses, {H.MAX_CIDRS} ranges and {H.MAX_DOMAINS:,} domains were searched.")
    if s.get("folded_nat"):
        extra.append(f"{s['folded_nat']} outbound record group(s) through the shared NAT address are shown under the devices named by the replies.")
    if spec.get("rejected"):
        extra.append(f"{spec['rejected']} pasted line(s) were not understood and were skipped.")
    body = f"""{tabs(INVESTIGATE_TABS, '/netmon/hunt')}{_msg(msg)}
<section class="card"><div class="card-h"><h2>Hunt #{rid}</h2><span class="muted small">{s.get('seconds', '?')} s</span></div>{head}
<p><b>{e(sentence)}</b></p><div class="banner">{e(NOT_PROOF)}</div>{''.join(f"<p class='muted small'>{e(t)}</p>" for t in extra)}
<details class="tech" open><summary>History searched</summary><ul class="small">{cov or '<li>unknown</li>'}</ul>
<p class="muted small">Searched {ind.get('ip', 0):,} addresses, {ind.get('cidr', 0)} ranges and {ind.get('domain', 0):,} domains. Akvorado's
long-term tables keep no addresses, so only the raw retention can be searched.</p></details></section>
{groups or empty_state('nomatch', ' No matches. That covers only the history above: contact outside it, or through sources netmon does not see, is unknown.', '/netmon/hunt', 'New hunt')}"""
    return page(req, f"Hunt #{rid}", body, "/netmon/investigate", scoped=False)


@app.post("/netmon/hunt/match/{mid}/finding")
def match_finding(req: Request, mid: int, csrf: str = Form("")):
    """Turn a match into a finding (so it can be triaged and grouped into an incident). Not notified: a person made it."""
    u = need(req, "analyst")
    check_csrf(req, csrf)
    m = conn.execute("SELECT * FROM hunt_matches WHERE id=? AND site_ok(site)", (mid,)).fetchone()
    if not m:
        raise HTTPException(404)
    d = json.loads(m["detail"] or "{}")
    weak = d.get("cdn") or d.get("stale") or (d.get("shared_names") or 0) >= H.SHARED_NAMES or d.get("before_published")
    sev = "medium" if d.get("confidence") == "high" and not weak else "low"
    now = time.time()
    dev = m["device"] or ""
    title = f"{dev or 'Unknown device'} matched indicator {m['ind_value']} ({SOURCE_LABEL.get(m['source'], m['source'])})"
    ev = [{"indicator": m["ind_value"], "type": m["ind_type"], "matched": m["matched"], "peer": m["matched"] if m["ind_type"] != "domain" else None,
           "source": m["source"], "direction": m["direction"], "first": m["first"], "last": m["last"], "events": m["events"], "bytes": m["bytes"],
           "lists": d.get("lists"), "hunt": m["run_id"]}]
    cur = conn.execute(
        "INSERT INTO alerts(key,rule,severity,confidence,asset,subject,title,first_seen,last_seen,window_start,window_end,evidence,query,baseline,"
        "alternatives,next_steps,akvorado_filter,site,identity_id,notify_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (f"{m['site']}|indicator_match|{dev}|{m['ind_value']}|{now}", "indicator_match", sev, d.get("confidence") or "low", dev, m["matched"], title,
         now, now, m["first"], m["last"], json.dumps(ev, default=str), json.dumps({"hunt": m["run_id"], "match": mid}),
         f"Matched an indicator from {', '.join(d.get('lists') or [])}, known to netmon since {_d(d.get('known_since'))}. {NOT_PROOF}",
         json.dumps(["The indicator is stale or a false positive", "A CDN or shared-hosting address serving unrelated sites",
                     "Contact before the address was malicious"]),
         json.dumps(["Check what the device did with this address or domain at that time (connections, DNS)",
                     "Look up the indicator's current reputation with its source", "Group it with related findings if it is part of an incident"]),
         "", m["site"], m["identity_id"], f"created by {u} from hunt #{m['run_id']} (not notified)"))
    conn.commit()
    audit(conn, u, "finding_from_hunt", {"alert": cur.lastrowid, "match": mid, "hunt": m["run_id"]})
    from .incidents import correlate
    correlate(conn, cfg, cur.lastrowid)
    return RedirectResponse(f"/netmon/alert/{cur.lastrowid}", 303)
