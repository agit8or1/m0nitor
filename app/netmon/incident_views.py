"""Investigate → Incidents: related findings as one case (what happened, affected devices, why it matters, confidence
and missing information, next step, timeline, raw evidence), with assignment, notes, status, resolution and history.
Viewing needs the viewer role; changes and evidence export need analyst (the role that triages findings)."""
import json
import time
from urllib.parse import quote

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import identity as idn
from . import incidents as inc
from .notify import category
from .ux import INVESTIGATE_TABS, conf_badge, device_html, empty_state, evidence_details, fmt_local, monitored, tabs
from .web import (RULE_LABEL, ROLES, app, cfg, ch, check_csrf, conn, csrf_field, e, need, page, sev, site_name, user_of)

STATUS_LABEL = {"open": "Open", "investigating": "Investigating", "resolved": "Resolved"}
ACTION_LABEL = {"created": "Incident created", "finding_added": "Finding added", "finding_removed": "Finding split out",
                "finding_moved": "Finding moved to another incident", "merged_into": "Merged into another incident",
                "merged_from": "Another incident merged in", "updated": "Updated", "note": "Note", "findings_closed": "Findings closed"}


def _visible(iid):
    """The incident if the signed-in user may see its firewall (netmon.access), else 404."""
    i = conn.execute(f"SELECT * FROM incidents i WHERE i.id=? AND {inc.VISIBLE}", (iid,)).fetchone()
    if not i:
        raise HTTPException(404)
    return i


def _alert_ok(aid):
    if not conn.execute("SELECT 1 FROM alerts WHERE id=? AND site_ok(site)", (aid,)).fetchone():
        raise HTTPException(404, "no such finding")


def _not_in_hidden(aid):
    """A finding that already sits in an incident the user cannot see (it also groups another firewall's findings)
    stays there: moving it would change that incident."""
    cur = inc.incident_of(conn, aid)
    if cur and not conn.execute(f"SELECT 1 FROM incidents i WHERE i.id=? AND {inc.VISIBLE}", (cur,)).fetchone():
        raise HTTPException(409, "this finding is part of an incident that also covers another firewall; ask a user who can see every firewall")


def _msg(msg):
    return f"<div class='banner'>{e(msg)}</div>" if msg else ""


def _back(path, msg):
    return RedirectResponse(f"{path}{'&' if '?' in path else '?'}msg={quote(msg)}", 303)


def _safe_back(back, iid):
    """Only return to the incidents list or this incident (never an arbitrary URL)."""
    if back.startswith("/netmon/incidents?") and all(c.isalnum() or c in "/?=&_" for c in back):
        return back
    return f"/netmon/incidents/{iid}"


def _quick_form(req, i, back):
    """One-click Dismiss for an unresolved incident, or Reopen for a dismissed one. Findings are left as they are."""
    if i["status"] != "resolved":
        return (f"<form method=post action='/netmon/incidents/{i['id']}/dismiss' class='inline' data-confirm='Dismiss incident #{i['id']}? "
                f"Its findings stay as they are.'>{csrf_field(req)}<input type=hidden name=back value='{e(back)}'>"
                f"<button class='sm' title='Resolve as dismissed (no action needed). Recorded in the history; can be reopened.'>Dismiss</button></form>")
    if i["resolution"] == "dismissed":
        return (f"<form method=post action='/netmon/incidents/{i['id']}/reopen' class='inline'>{csrf_field(req)}"
                f"<input type=hidden name=back value='{e(back)}'><button class='sm'>Reopen</button></form>")
    return ""


def _dev(asset, site):
    if not asset:
        return {"name": "—", "ip": ""}
    if asset in (cfg.get("outbound_nat_ips") or []):
        return {"name": "Shared NAT address", "ip": asset, "internal": False}
    try:
        return idn.label(conn, cfg, cfg.binat.get(asset, asset), site)
    except Exception:
        return {"name": asset, "ip": asset}


def _users():
    return [r[0] for r in conn.execute("SELECT username FROM users WHERE role IN ('analyst','admin') ORDER BY username")]


# ---- list ----------------------------------------------------------------------------------------------------
@app.get("/netmon/incidents", response_class=HTMLResponse)
def incidents_page(req: Request, status: str = "active", mine: int = 0, msg: str = ""):
    u, r = user_of(req)
    status = status if status in ("active", "resolved", "all", *inc.STATUSES) else "active"
    where, p = {"active": ("status != 'resolved'", ()), "resolved": ("status = 'resolved'", ()), "all": ("1=1", ())}.get(
        status, ("status = ?", (status,)))
    where += f" AND {inc.VISIBLE}"
    if mine:
        where, p = where + " AND assignee = ?", (*p, u)
    rows = conn.execute(f"SELECT i.*, (SELECT count(*) FROM incident_alerts ia WHERE ia.incident_id=i.id AND ia.removed=0) AS n "
                        f"FROM incidents i WHERE {where} ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                        f"WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC LIMIT 200", p).fetchall()
    seg = "".join(f"<a class='{'on' if k == status else ''}' href='/netmon/incidents?status={k}{'&mine=1' if mine else ''}'>{e(v)}</a>"
                  for k, v in (("active", "Open & investigating"), ("open", "Open"), ("investigating", "Investigating"),
                               ("resolved", "Resolved"), ("all", "All")))
    mine_link = (f"<a href='/netmon/incidents?status={status}'>Everyone's</a>" if mine else
                 f"<a href='/netmon/incidents?status={status}&mine=1'>Assigned to me</a>")
    can = ROLES[r] >= ROLES["analyst"]
    back = f"/netmon/incidents?status={status}" + ("&mine=1" if mine else "")
    cards = ""
    for i in rows:
        reasons = sorted({x[0] for x in conn.execute("SELECT reason FROM incident_alerts WHERE incident_id=? AND removed=0 AND reason "
                                                     "IS NOT NULL", (i["id"],))})
        cards += f"""<article class="finding f-{'bad' if i['severity'] in ('high', 'critical') else 'warn' if i['severity'] == 'medium' else 'muted'}">
<div class="fh">{sev(i['severity'])}<span class="muted small">{(e(site_name(i['site'])) + ' · ') if len(cfg.sites) > 1 else ''}{i['n']} findings ·
 last activity {e(fmt_local(i['last_seen'], cfg.site(i['site'])))}</span><span class="tag">{e(STATUS_LABEL.get(i['status'], i['status']))}</span>
 {f"<span class='tag'>assigned to {e(i['assignee'])}</span>" if i['assignee'] else "<span class='tag muted'>unassigned</span>"}</div>
<a class="ft" href="/netmon/incidents/{i['id']}">#{i['id']} · {e(i['title'])}</a>
<div class="small muted">Grouped because: {e('; '.join(reasons) or 'grouped by a person')}</div>{_quick_form(req, i, back) if can else ''}</article>"""
    ungrouped = conn.execute("SELECT count(*) FROM alerts WHERE status='open' AND test=0 AND severity IN ('high','critical') AND site_ok(site) AND id NOT IN "
                             "(SELECT alert_id FROM incident_alerts WHERE removed=0)").fetchone()[0]
    if not cards:
        cards = empty_state("nomatch", " No incidents in this view. Related findings are grouped here automatically; single findings stay on "
                            "Security." if status == "active" else " No incidents in this view.", "/netmon/security", "Open findings")
    body = f"""{tabs(INVESTIGATE_TABS, '/netmon/incidents')}{_msg(msg)}
<div class="toolbar"><div class="seg links">{seg}</div><span class="small">{mine_link}</span></div>
{f"<div class='banner warn'>{ungrouped} high-severity finding(s) are not part of an incident. <a href='/netmon/security'>Review on Security →</a></div>" if ungrouped else ''}
<section class="card"><div class="card-h"><h2>Incidents <span class="count">{len(rows)}</span></h2>
<span class="muted small">related findings grouped by device or remote address within {inc.CORRELATE_WINDOW // 3600} hours</span></div>{cards}
<details class="tech"><summary>How findings are grouped</summary><ul class="small">
<li><b>Same device:</b> findings for the same device (its identity, so an address change does not split it) within {inc.CORRELATE_WINDOW // 3600} hours.</li>
<li><b>Same remote address:</b> findings on different devices involving the same external IP within {inc.CORRELATE_WINDOW // 3600} hours.</li>
<li>An incident starts only with two related findings and at least one security finding. Informational changes (new country, new network)
can join but never start one. Monitoring-health and TEST findings are not grouped. The shared NAT address is not grouped by device.</li>
<li>Grouping says the findings are related in time and place. It does not mean one caused another.</li>
<li>A channel that already received a finding of an incident in the last {inc.NOTIFY_DEDUP // 3600} hours is not sent another one of the
same or lower severity. Higher-severity findings are always sent.</li></ul></details></section>"""
    return page(req, "Incidents", body, "/netmon/investigate", scoped=False, subtitle="Related findings, handled as one case")


# ---- detail --------------------------------------------------------------------------------------------------
def _missing(i, fs):
    """What netmon could not see or verify for this incident (plain sentences)."""
    out = []
    t0, t1 = i["first_seen"] - 3600, i["last_seen"] + 600
    for h in conn.execute("SELECT id, title FROM alerts WHERE test=0 AND site IS ? AND site_ok(site) AND first_seen <= ? AND last_seen >= ? ORDER BY id LIMIT 50",
                          (i["site"], t1, t0)).fetchall():
        a = conn.execute("SELECT rule FROM alerts WHERE id=?", (h["id"],)).fetchone()
        if category(a["rule"]) == "health":
            out.append(f"Monitoring problem around this time: <a href='/netmon/alert/{h['id']}'>{e(h['title'])}</a>. Some activity may be missing.")
    if any(f["direction"] and not f["direction_verified"] for f in fs):
        out.append("Who opened some connections is inferred from ports, not verified from firewall state.")
    if any(f["asset"] in (cfg.get("outbound_nat_ips") or []) for f in fs):
        out.append("Some findings are on the shared NAT address: WAN records do not show which device behind it was involved.")
    weak = []
    for f in fs:
        if not f["asset"] or f["identity_id"] or f["asset"] in (cfg.get("outbound_nat_ips") or []):
            continue
        try:
            o = idn.owner_at(conn, f["site"], cfg.binat.get(f["asset"], f["asset"]), f["window_start"] or f["first_seen"])
        except Exception:
            o = {"identity": None, "confidence": "low"}
        if not o["identity"] or o["confidence"] == "low":
            weak.append(f["asset"])
    if weak:
        out.append(f"{', '.join(e(x) for x in sorted(set(weak))[:5])}: identified by address only at the time (no MAC address evidence), "
                   "so a different device may have used it.")
    s = cfg.site(i["site"]) or {}
    off = [k for k, label in (("ids", "IDS alerts"), ("dns", "DNS queries"), ("syslog", "firewall log")) if not monitored(s, k)]
    if off:
        out.append(f"Not monitored on this firewall (your choice): {', '.join(off)}.")
    return out


def _config_changes(site, t0, t1):
    try:
        return ch.query("SELECT toUInt32(ts) AS t, substring(message, 1, 300) AS m FROM netmon.sys_events WHERE site = {s:String} AND app = 'audit' "
                        "AND message LIKE '%changed configuration%' AND ts >= toDateTime({t0:UInt32}) AND ts <= toDateTime({t1:UInt32}) "
                        "ORDER BY ts LIMIT 20", {"s": site or "", "t0": int(t0), "t1": int(t1)})
    except Exception:
        return None


@app.get("/netmon/incidents/{iid}", response_class=HTMLResponse)
def incident_page(req: Request, iid: int, msg: str = ""):
    u, r = user_of(req)
    i = _visible(iid)
    s = cfg.site(i["site"]) or {}
    fs = inc.members(conn, iid)   # only findings of firewalls this user may see
    can = ROLES[r] >= ROLES["analyst"]
    top = max(fs, key=lambda x: inc.SEV.get(x["severity"], 0)) if fs else None
    devs = {}
    for f in fs:
        if f["asset"]:
            devs.setdefault((f["asset"], f["site"]), []).append(f)
    what = "".join(f"<li><span class='s1'>{sev(f['severity'])} <a href='/netmon/alert/{f['id']}'>{e(f['title'])}</a></span>"
                   f"<span class='s2'>{e(RULE_LABEL.get(f['rule'], f['rule']))} · {f['count']}× · {e(fmt_local(f['first_seen'], s))} → "
                   f"{e(fmt_local(f['last_seen'], s))} · {conf_badge(f['confidence'])} · grouped because: {e(f['link_reason'] or 'added by ' + f['link_by'])}</span>"
                   + (f"<span class='acts'><form method=post action='/netmon/incidents/{iid}/remove' class='inline'>{csrf_field(req)}"
                      f"<input type=hidden name=alert_id value={f['id']}><button class='sm' title='Split this finding out of the incident'>Split out</button></form></span>"
                      if can and len(fs) > 1 else "") + "</li>" for f in fs)
    affected = "".join(f"<li>{device_html(_dev(a, st), show_conf=True)} — {len(v)} finding(s)"
                       + (f" <span class='muted small'>(at the time: {e(idn.name_of(conn, cfg, idn.resolve(conn, v[0]['identity_id'])))})</span>"
                          if v[0]["identity_id"] else "") + "</li>" for (a, st), v in devs.items())
    why = (f"<p>{e(top['baseline'])}</p><p class='muted small'>Highest severity: {e(top['severity'])} ({e(RULE_LABEL.get(top['rule'], top['rule']))}). "
           "Findings are grouped because they share a device or remote address in time; that does not mean one caused another.</p>") if top else ""
    miss = _missing(i, fs)
    nxt = []
    if i["status"] == "open" and not i["assignee"]:
        nxt.append("Assign the incident, so others know it is being looked at.")
    if top:
        steps = json.loads(top["next_steps"] or "[]")
        nxt += steps[:2]
    if i["status"] != "resolved":
        nxt.append("When done, resolve it with a reason (you can close its findings at the same time).")
    # timeline: findings, people's actions, and configuration changes on the firewall around the same time (association only)
    tl = []
    for f in fs:
        tl.append((f["first_seen"], "finding", f"{sev(f['severity'])} First detected: <a href='/netmon/alert/{f['id']}'>{e(f['title'])}</a>"))
        if f["count"] > 1 and f["last_seen"] - f["first_seen"] > 60:
            tl.append((f["last_seen"], "finding", f"Last seen again ({f['count']}×): {e(f['title'])}"))
    for h in inc.history(conn, iid):
        d = h["detail"]
        text = (e(d.get("text", "")) if h["action"] == "note" else
                e(", ".join(f"{k}: {' → '.join(map(str, v)) if isinstance(v, list) else v}" for k, v in d.items() if k not in ("reason",)))
                + (f" — {e(d['reason'])}" if d.get("reason") else ""))
        tl.append((h["ts"], "note" if h["action"] == "note" else "event", f"<b>{e(ACTION_LABEL.get(h['action'], h['action']))}</b> by {e(h['user'])}: {text}"))
    cc = _config_changes(i["site"], i["first_seen"] - 3600, i["last_seen"] + 600)
    for c in cc or []:
        tl.append((c["t"], "config", f"Firewall configuration changed (around the same time; not necessarily related): "
                                     f"<a href='/netmon/changes/config?site={quote(i['site'] or '')}&t={c['t']}'>{e(c['m'][:160])}</a>"))
    tl.sort(key=lambda x: x[0])
    timeline = "".join(f"<li class='tl-{k}'><span class='t'>{e(fmt_local(t, s))}</span><div>{h}</div></li>" for t, k, h in tl)
    raw = "".join(evidence_details(f"Finding #{f['id']} — raw evidence and query", {"evidence": json.loads(f["evidence"] or "[]"),
                                                                                       "query": json.loads(f["query"] or "{}")}) for f in fs)
    users = _users()
    acts = ""
    if can:
        st_opts = "".join(f"<option value={k} {'selected' if k == i['status'] else ''}>{v}</option>" for k, v in STATUS_LABEL.items())
        res_opts = "<option value=''>— resolution (required to resolve) —</option>" + "".join(
            f"<option value={k} {'selected' if k == i['resolution'] else ''}>{e(v)}</option>" for k, v in inc.RESOLUTIONS.items())
        as_opts = "<option value=''>unassigned</option>" + "".join(f"<option {'selected' if x == i['assignee'] else ''}>{e(x)}</option>" for x in users)
        acts = f"""<section class="card" id="handle"><div class="card-h"><h2>Handle this incident</h2></div>
<form method=post action="/netmon/incidents/{iid}/update" class="stackform">{csrf_field(req)}
<div class="row"><label>Status<select name=status>{st_opts}</select></label><label>Assigned to<select name=assignee>{as_opts}</select></label>
<label>Resolution<select name=resolution>{res_opts}</select></label></div>
<label>Note<textarea name=note rows=3 maxlength=2000 placeholder="what you checked, what you found, what you decided"></textarea></label>
<label class="check"><input type=checkbox name=close_findings value=1> When resolving, also close its open findings</label>
<div class="row"><button class="primary">Save</button></div></form>
<details class="tech"><summary>Group or merge</summary>
<form method=post action="/netmon/incidents/{iid}/add" class="row">{csrf_field(req)}<label>Add finding #<input name=alert_id inputmode=numeric required class="short"></label>
<input name=reason maxlength=200 placeholder="why it belongs here"><button>Add</button></form>
<form method=post action="/netmon/incidents/{iid}/merge" class="row">{csrf_field(req)}<label>Merge incident #<input name=other inputmode=numeric required class="short"> into this one</label>
<button>Merge</button></form><p class="muted small">Added or split-out findings are never moved back automatically.</p></details>
<p>{_quick_form(req, i, f"/netmon/incidents/{iid}") if can else ''}<a class="btn" href="/netmon/incidents/{iid}/export.json">Export evidence (JSON)</a> <span class="muted small">recorded in the audit log</span></p></section>"""
    status_line = (f"{e(STATUS_LABEL.get(i['status'], i['status']))}" + (f" · {e(inc.RESOLUTIONS.get(i['resolution'], i['resolution'] or ''))}" if i["resolution"] else "")
                   + (f" · assigned to {e(i['assignee'])}" if i["assignee"] else " · unassigned"))
    body = f"""{tabs(INVESTIGATE_TABS, '/netmon/incidents')}{_msg(msg)}
<section class="card"><div class="fh">{sev(i['severity'])}<span class="muted small">{e(site_name(i['site']))} · {len(fs)} findings ·
{e(fmt_local(i['first_seen'], s))} → {e(fmt_local(i['last_seen'], s))}</span><span class="tag">{status_line}</span></div>
<h2 class="title">{e(i['title'])}</h2>{f"<p class='muted'>Resolution note: {e(i['resolution_note'])}</p>" if i['resolution_note'] else ''}
<div class="grid2 even"><div><h3>What happened</h3><ul class="sentence-list">{what or '<li>No findings left in this incident.</li>'}</ul></div>
<div><h3>Affected devices</h3><ul>{affected or '<li class=muted>none</li>'}</ul><h3>Why it matters</h3>{why}</div></div>
<div class="grid2 even"><div><h3>Confidence and missing information</h3><p class="small">Each finding has its own confidence (above).</p>
<ul class="small">{''.join(f'<li>{m}</li>' for m in miss) or '<li>No known gaps in monitoring during this incident.</li>'}
{'' if cc is not None else '<li>Firewall configuration history is unavailable right now.</li>'}</ul></div>
<div><h3>Next step</h3><ol>{''.join(f'<li>{e(x)}</li>' for x in nxt)}</ol></div></div></section>
<section class="card"><div class="card-h"><h2>Timeline</h2><span class="muted small">findings, people's actions and firewall configuration changes</span></div>
<ul class="timeline">{timeline}</ul></section>
{acts}
<section class="card"><div class="card-h"><h2>Raw evidence</h2></div>{raw or '<p class=muted>none</p>'}</section>"""
    return page(req, f"Incident #{iid}", body, "/netmon/investigate", scoped=False)


# ---- actions -------------------------------------------------------------------------------------------------
def _int(v):
    try:
        return int(str(v).strip().lstrip("#"))
    except ValueError:
        raise HTTPException(400, "enter a number")


@app.post("/netmon/incidents/{iid}/update")
def incident_update(req: Request, iid: int, status: str = Form(""), assignee: str = Form(""), resolution: str = Form(""),
                    note: str = Form(""), close_findings: str = Form(""), csrf: str = Form("")):
    u = need(req, "analyst")
    _visible(iid)
    check_csrf(req, csrf)
    if assignee and assignee not in _users():
        raise HTTPException(400, "assign to an analyst or admin")
    try:
        ch_ = inc.update(conn, iid, u, status=status or None, assignee=assignee, resolution=resolution or None,
                         note=note.strip() or None, close_findings=bool(close_findings))
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(f"/netmon/incidents/{iid}", "Saved." if ch_ or note.strip() else "Nothing changed.")


@app.post("/netmon/incidents/{iid}/dismiss")
def incident_dismiss(req: Request, iid: int, back: str = Form(""), csrf: str = Form("")):
    u = need(req, "analyst")
    _visible(iid)
    check_csrf(req, csrf)
    i = conn.execute("SELECT status FROM incidents WHERE id=?", (iid,)).fetchone()
    if not i:
        raise HTTPException(404)
    if i["status"] == "resolved":      # never overwrite the reason someone already gave
        return _back(_safe_back(back, iid), f"Incident #{iid} was already resolved.")
    inc.update(conn, iid, u, status="resolved", resolution="dismissed")
    return _back(_safe_back(back, iid), f"Incident #{iid} dismissed.")


@app.post("/netmon/incidents/{iid}/reopen")
def incident_reopen(req: Request, iid: int, back: str = Form(""), csrf: str = Form("")):
    u = need(req, "analyst")
    _visible(iid)
    check_csrf(req, csrf)
    if not conn.execute("SELECT 1 FROM incidents WHERE id=?", (iid,)).fetchone():
        raise HTTPException(404)
    inc.update(conn, iid, u, status="open")
    return _back(_safe_back(back, iid), f"Incident #{iid} reopened.")


@app.post("/netmon/incidents/{iid}/add")
def incident_add(req: Request, iid: int, alert_id: str = Form(...), reason: str = Form(""), csrf: str = Form("")):
    u = need(req, "analyst")
    _visible(iid)
    check_csrf(req, csrf)
    try:
        _alert_ok(_int(alert_id))
        _not_in_hidden(_int(alert_id))
        inc.link(conn, iid, _int(alert_id), u, (reason.strip() or f"added by {u}")[:200])
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(f"/netmon/incidents/{iid}", f"Finding #{_int(alert_id)} added.")


@app.post("/netmon/incidents/{iid}/remove")
def incident_remove(req: Request, iid: int, alert_id: str = Form(...), csrf: str = Form("")):
    u = need(req, "analyst")
    _visible(iid)
    check_csrf(req, csrf)
    try:
        inc.unlink(conn, iid, _int(alert_id), u)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(f"/netmon/incidents/{iid}", f"Finding #{_int(alert_id)} split out. It stays a separate finding.")


@app.post("/netmon/incidents/{iid}/merge")
def incident_merge(req: Request, iid: int, other: str = Form(...), csrf: str = Form("")):
    u = need(req, "analyst")
    _visible(iid)
    check_csrf(req, csrf)
    try:
        _visible(_int(other))
        inc.merge(conn, iid, _int(other), u)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(f"/netmon/incidents/{iid}", f"Incident #{_int(other)} merged into this one.")


@app.post("/netmon/incidents/new")
def incident_new(req: Request, alert_id: str = Form(...), csrf: str = Form("")):
    """Start an incident from one finding (by hand); more findings can then be added."""
    u = need(req, "analyst")
    check_csrf(req, csrf)
    a = conn.execute("SELECT * FROM alerts WHERE id=? AND site_ok(site)", (_int(alert_id),)).fetchone()
    if not a:
        raise HTTPException(404)
    _not_in_hidden(a["id"])
    old = inc.incident_of(conn, a["id"])
    if old:
        return RedirectResponse(f"/netmon/incidents/{old}", 303)
    iid = inc.create(conn, cfg, [a], u, f"started by {u}")
    return _back(f"/netmon/incidents/{iid}", "Incident started. Add related findings under Group or merge.")


@app.get("/netmon/incidents/{iid}/export.json")
def incident_export(req: Request, iid: int):
    u = need(req, "analyst")
    _visible(iid)
    try:
        data = inc.export(conn, cfg, iid)
    except ValueError:
        raise HTTPException(404)
    from .core import audit
    audit(conn, u, "incident_exported", {"incident": iid, "findings": len(data["findings"])})
    return JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="incident-{iid}.json"', "Cache-Control": "no-store"})


def finding_incident_box(req, a, role):
    """On the finding page: the incident it belongs to, or 'Start an incident'."""
    iid = inc.incident_of(conn, a["id"])
    if iid:
        i = conn.execute(f"SELECT id, title, status FROM incidents i WHERE i.id=? AND {inc.VISIBLE}", (iid,)).fetchone()
        if not i:
            return ("<div class='banner'>Part of an incident that also covers another firewall; it is handled by users who can "
                    "see every firewall.</div>")
        n = conn.execute("SELECT count(*) FROM incident_alerts WHERE incident_id=? AND removed=0", (iid,)).fetchone()[0]
        return (f"<div class='banner'>Part of <a href='/netmon/incidents/{iid}'>incident #{iid}: {e(i['title'])}</a> "
                f"({n} related findings, {e(STATUS_LABEL.get(i['status'], i['status']).lower())}).</div>")
    if ROLES[role] >= ROLES["analyst"] and not a["test"]:
        return (f"<form method=post action='/netmon/incidents/new' class='inline'>{csrf_field(req)}<input type=hidden name=alert_id value={a['id']}>"
                f"<button class='sm'>Start an incident from this finding</button></form>")
    return ""


def attention():
    """Overview strip: open incidents, ungrouped serious findings, monitoring health. Never 'all fine' while a source is down."""
    n_inc = conn.execute(f"SELECT count(*) FROM incidents i WHERE status != 'resolved' AND {inc.VISIBLE}").fetchone()[0]
    n_unassigned = conn.execute(f"SELECT count(*) FROM incidents i WHERE status = 'open' AND assignee IS NULL AND {inc.VISIBLE}").fetchone()[0]
    ungrouped = conn.execute("SELECT count(*) FROM alerts WHERE status='open' AND test=0 AND severity IN ('high','critical') AND site_ok(site) AND id NOT IN "
                             "(SELECT alert_id FROM incident_alerts WHERE removed=0)").fetchone()[0]
    health = [r for r in conn.execute("SELECT id, rule, title FROM alerts WHERE status IN ('open','acked') AND test=0 AND site_ok(site) ORDER BY last_seen DESC LIMIT 200")
              if category(r["rule"]) == "health"]
    try:
        from .quality import overview
        q = overview(conn, cfg)["bad"]
    except Exception:
        q = []
    return {"incidents": n_inc, "unassigned": n_unassigned, "ungrouped_serious": ungrouped,
            "health": [{"id": h["id"], "title": h["title"]} for h in health[:3]], "health_count": len(health),
            "quality": [{"name": x["name"], "site": x["site_name"], "state": x["state"], "text": x["text"]} for x in q[:3]], "quality_count": len(q),
            "ts": time.time()}


@app.get("/netmon/api/attention")
def api_attention(req: Request):
    user_of(req)
    return JSONResponse(attention())
