"""Internal devices → Applications: group devices into applications and see observed vs confirmed dependencies,
new dependencies and outage impact. A list first; the picture is optional. Viewing: viewer. Editing: analyst."""
from urllib.parse import quote, urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import apps as A
from .ux import DEVICE_TABS, ago, empty_state, fmt_local, tabs
from .web import ROLES, app, cfg, ch, check_csrf, conn, csrf_field, e, human_bytes, need, page, user_of

CONF_TEXT = {"high": "seen regularly", "medium": "seen sometimes", "low": "seen once or rarely", "confirmed": "confirmed, not seen in this period"}


def _site(site):
    s = cfg.site(site) if site else None
    return s or cfg.sites[0]


def _back(path, msg):
    return RedirectResponse(f"{path}{'&' if '?' in path else '?'}msg={quote(msg)}", 303)


def _label(ip):
    try:
        return cfg.asset_label(ip)
    except Exception:
        return ip


def _n(n, word):
    return f"{n:,} {word}{'es' if word.endswith('s') else 's'}" if n != 1 else f"1 {word}"


def _target_html(d):
    if d.get("app"):
        return f"<a href='/netmon/apps/{d['app'][0]}'><b>{e(d['app'][1])}</b></a> <span class='muted small'>({e(_label(d['target']))})</span>"
    if d["kind"] == "internal":
        return f"<a href='/netmon/servers/{quote(d['target'])}'>{e(_label(d['target']))}</a>"
    if d["target"] == "internet clients":
        return f"internet clients <span class='muted small'>({_n(d.get('remotes', 0), 'address')})</span>"
    return (f"{e(d.get('org') or d['target'])} <span class='muted small'>{e(d['target'])}"
            f"{', ' + _n(d['remotes'], 'address') if d.get('remotes') else ''}</span>")


@app.get("/netmon/apps", response_class=HTMLResponse)
def apps_page(req: Request, site: str = "", device: str = "", msg: str = ""):
    u, r = user_of(req)
    edit = ROLES[r] >= ROLES["analyst"]
    s = _site(site.split(",")[0])
    rows = conn.execute("SELECT * FROM apps WHERE site=? ORDER BY critical DESC, name", (s["id"],)).fetchall()
    banner = f"<div class='banner'>{e(msg)}</div>" if msg else ""
    intro = ("<p class='muted small'>Group the devices that make up an application (for example a mail server, its database and its backup "
             "target). netmon then lists what the application talks to and what uses it, from the traffic the firewall reports. "
             "Traffic that does not pass the firewall (same switch or VLAN) cannot be seen, and <b>lack of traffic does not prove a dependency "
             "is gone</b>.</p>")
    sitesel = ("<label>Firewall<select name=site>" + "".join(f"<option value='{e(x['id'])}' {'selected' if x['id'] == s['id'] else ''}>{e(x['name'])}</option>"
                                                           for x in cfg.sites) + "</select></label>") if len(cfg.sites) > 1 else ""
    focus = (f"<form method=get class='row'>{sitesel}<label>Focus on a device<input name=device value='{e(device)}' placeholder='internal IP address' "
             "class=mono></label><button>Show impact</button></form>")
    lis = []
    for a in rows:
        ms = A.members(conn, a["id"])
        lis.append(f"<li><span class='s1'><a href='/netmon/apps/{a['id']}'><b>{e(a['name'])}</b></a>"
                   f"{' <span class=tag>critical</span>' if a['critical'] else ''}</span>"
                   f"<span class='s2'>{len(ms)} device{'s' if len(ms) != 1 else ''}: {e(', '.join(_label(m['ip']) for m in ms[:4]))}"
                   f"{' …' if len(ms) > 4 else ''}{' · owner ' + e(a['owner']) if a['owner'] else ''}</span></li>")
    create = (f"""<details class="tech" {'open' if not rows else ''}><summary>New application</summary>
<form method=post action="/netmon/apps/new" class="stackform">{csrf_field(req)}<input type=hidden name=site value="{e(s['id'])}">
<label>Name<input name=name maxlength=60 required placeholder="e.g. Mail"></label>
<label>Devices (internal IP addresses, separated by spaces)<input name=members class=mono placeholder="10.0.0.10 10.0.0.11"></label>
<label>Owner (optional)<input name=owner maxlength=80></label>
<label><input type=checkbox name=critical value=1> Critical (listed first; outage impact is highlighted)</label>
<button>Create</button></form></details>""" if edit else "<p class='muted small'>Analysts and admins create applications.</p>")
    lst = (f"<ul class='sentences'>{''.join(lis)}</ul>" if lis else
           empty_state("setup", " No applications yet. Create one and add the devices it runs on; its dependencies appear from the traffic records."))
    body = (tabs(DEVICE_TABS, "/netmon/apps") + banner + intro
            + f"<section class='card'><div class='card-h'><h2>Applications</h2></div>{lst}{create}</section>"
            + f"<section class='card'><div class='card-h'><h2>Outage impact of one device</h2></div>{focus}")
    if device.strip():
        body += _impact_html(s, device.strip())
    body += "</section>"
    return page(req, "Applications", body, "/netmon/servers", scoped=False, subtitle="Application dependencies, observed and confirmed")


def _impact_html(s, device):
    import ipaddress
    try:
        ip = str(ipaddress.ip_address(device))
    except ValueError:
        return "<p class='warnline'>Enter an IP address.</p>"
    if not cfg.is_internal(ip):
        return "<p class='warnline'>That is not an internal address.</p>"
    try:
        im = A.impact(conn, cfg, ch, s, {ip})
    except Exception as ex:
        return empty_state("unavailable", f" Traffic records could not be read ({type(ex).__name__}).")
    apps_txt = "".join(f"<li><a href='/netmon/apps/{a[0]}'><b>{e(a[1])}</b></a> uses it ({e(', '.join(sorted(svcs)))})</li>"
                       for a, svcs in sorted(im["apps"].items(), key=lambda x: x[0][1]))
    member = ", ".join(f"<a href='/netmon/apps/{a[0]}'>{e(a[1])}</a>" for a in im["member_of"])
    devs = "".join(f"<li><span class='s1'><a href='/netmon/servers/{quote(d['ip'])}'>{e(_label(d['ip']))}</a> → {e(', '.join(sorted(d['services'])))}</span>"
                   f"<span class='s2'>{d['n']:,} records · last {e(ago(d['last']))}</span></li>" for d in im["devices"][:30])
    inet = "".join(f"<li>{_n(x['remotes'], 'internet address')} on {e(x['service'])} ({x['n']:,} records)</li>" for x in im["internet"])
    return (f"<h3>If {e(_label(ip))} were down (last 7 days of traffic)</h3>"
            + (f"<p>Part of: {member}</p>" if member else "")
            + (f"<p><b>Applications that used it</b></p><ul>{apps_txt}</ul>" if apps_txt else "")
            + (f"<p><b>{len(im['devices'])} internal device{'s' if len(im['devices']) != 1 else ''} used it</b></p><ul class='sentences'>{devs}</ul>"
               if devs else "<p class='muted'>No internal device was seen using it in the last 7 days (traffic inside one VLAN is not visible).</p>")
            + (f"<p><b>Reached from the internet</b></p><ul>{inet}</ul>" if inet else "")
            + "<p class='muted small'>Based on observed traffic only: something that uses this device rarely, or over a path the firewall does not "
              "see, is not listed.</p>")


@app.get("/netmon/apps/{aid}", response_class=HTMLResponse)
def app_detail(req: Request, aid: int, period: str = "7d", graph: int = 0, msg: str = ""):
    u, r = user_of(req)
    edit = ROLES[r] >= ROLES["analyst"]
    try:
        a = A.get(conn, aid)
    except ValueError:
        raise HTTPException(404)
    span = A.PERIODS.get(period, 7 * 86400)
    s = _site(a["site"])
    banner = f"<div class='banner'>{e(msg)}</div>" if msg else ""
    head = (f"<p><a href='/netmon/apps'>← Applications</a></p><section class='card'><div class='card-h'><h2>{e(a['name'])}"
            f"{' <span class=tag>critical</span>' if a['critical'] else ''}</h2></div>"
            + (f"<p>{e(a['note'])}</p>" if a["note"] else "") + (f"<p class='muted small'>Owner: {e(a['owner'])}</p>" if a["owner"] else ""))
    ms = A.members(conn, aid)
    mlis = "".join(
        f"<li><a href='/netmon/servers/{quote(m['ip'])}'>{e(_label(m['ip']))}</a>"
        f"{' <span class=muted small>(was ' + e(m['stored']) + ')</span>' if m['stored'] != m['ip'] else ''}"
        + (f" <form method=post action='/netmon/apps/{aid}/members/remove' class='inline'>{csrf_field(req)}<input type=hidden name=ip value='{e(m['stored'])}'>"
           f"<button class='sm' aria-label='Remove {e(m['ip'])}'>Remove</button></form>" if edit else "") + "</li>" for m in ms)
    madd = (f"<form method=post action='/netmon/apps/{aid}/members' class='row'>{csrf_field(req)}<label>Add device<input name=ip class=mono "
            "placeholder='internal IP address' required></label><button>Add</button></form>" if edit else "")
    manage = (f"""<details class="tech"><summary>Edit application</summary><form method=post action="/netmon/apps/{aid}/edit" class="stackform">{csrf_field(req)}
<label>Name<input name=name value="{e(a['name'])}" maxlength=60></label><label>Owner<input name=owner value="{e(a['owner'] or '')}" maxlength=80></label>
<label>Note<input name=note value="{e(a['note'] or '')}" maxlength=300></label>
<label><input type=checkbox name=critical value=1 {'checked' if a['critical'] else ''}> Critical</label><button>Save</button></form>
<form method=post action="/netmon/apps/{aid}/delete" data-confirm="Delete application {e(a['name'])}? Devices and traffic are not affected.">{csrf_field(req)}
<button class="sm">Delete application</button></form></details>""" if edit else "")
    head += f"<h3>Devices</h3><ul>{mlis or '<li class=muted>No devices yet: add the devices this application runs on.</li>'}</ul>{madd}{manage}</section>"
    if not ms:
        return page(req, a["name"], tabs(DEVICE_TABS, "/netmon/apps") + banner + head, "/netmon/servers", scoped=False)
    try:
        res = A.dependencies(conn, cfg, ch, aid, span)
    except Exception as ex:
        body = tabs(DEVICE_TABS, "/netmon/apps") + banner + head + empty_state("unavailable", f" Traffic records could not be read ({type(ex).__name__}).")
        return page(req, a["name"], body, "/netmon/servers", scoped=False)
    deps = res["deps"]
    per = ("<form method=get class='row'><label>Period<select name=period>"
           + "".join(f"<option {'selected' if k == period else ''}>{k}</option>" for k in A.PERIODS)
           + f"</select></label><label><input type=checkbox name=graph value=1 {'checked' if graph else ''}> Show picture</label><button>Show</button></form>")
    new = [d for d in deps if d["new"] and d["status"] != "dismissed"]
    uses = [d for d in deps if d["direction"] == "uses" and d["status"] != "dismissed"]
    used = [d for d in deps if d["direction"] == "used by" and d["status"] != "dismissed"]
    gone = [d for d in deps if not d["seen"]]
    summary = (f"<p>In the last {'24 hours' if period == '24h' else '7 days'}: <b>{len(uses)}</b> dependenc{'ies' if len(uses) != 1 else 'y'} "
               f"(what {e(a['name'])} uses), <b>{len(used)}</b> user{'s' if len(used) != 1 else ''} (what uses it)"
               + (f", <b class='warnline'>{len(new)} new</b> in the last 24 hours" if new else "")
               + (f", <b>{len(gone)}</b> confirmed but not seen" if gone else "") + ".</p>")
    if res["truncated"]:
        summary += "<p class='warnline small'>Very many conversations: only the busiest are listed.</p>"

    def row(d):
        st = {"confirmed": "<span class='tag ok'>confirmed</span>", "dismissed": "<span class='tag'>dismissed</span>"}.get(d["status"], "")
        nw = " <span class='tag warn'>new</span>" if d["new"] else ""
        if d["seen"]:
            facts = (f"{d['n']:,} records · {human_bytes(d['bytes'])} · {CONF_TEXT[d['confidence']]} ({d['days']} of {res['days']} {res['unit']}) · "
                     f"last {e(ago(d['last']))} · first seen {e(fmt_local(d['first_known'], s))}"
                     + (f" · via {e(', '.join(_label(x) for x in d['members'][:3]))}" if len(ms) > 1 else ""))
        else:
            facts = (f"not seen in this period (last seen {e(fmt_local(d['last'], s)) if d.get('last') else 'never'}): lack of traffic does not prove "
                     "the dependency is gone, it may be used rarely or only during failover")
        acts = ""
        if edit:
            for status, lab in (("confirmed", "Confirm"), ("dismissed", "Not a dependency"), ("observed", "Reset")):
                if status != d["status"] and not (status == "observed" and d["status"] == "observed"):
                    acts += (f"<form method=post action='/netmon/apps/{aid}/deps' class='inline'>{csrf_field(req)}<input type=hidden name=dkey value='{e(d['dkey'])}'>"
                             f"<input type=hidden name=status value={status}><button class='sm'>{lab}</button></form>")
        if d["seen"] and d["kind"] == "internal":
            c, sv = (d["members"][0], d["target"]) if d["direction"] == "uses" else (d["target"], d["members"][0])
            acts += (f"<a class='sm' href='/netmon/connections?{e(urlencode({'host': c, 'rip': sv, 'range': 'custom', 'from': res['t0'], 'to': res['t1']}))}'>"
                     "View records →</a>")
        return (f"<tr class='{'dim' if d['status'] == 'dismissed' else ''}'><td>{_target_html(d)}{nw} {st}</td><td>{e(d['service'])}</td>"
                f"<td class='small'>{facts}{' · ' + e(d['note']) if d['note'] else ''}</td><td>{acts}</td></tr>")

    def table(title, items, empty):
        if not items:
            return f"<h3>{title}</h3><p class='muted'>{empty}</p>"
        return (f"<h3>{title}</h3><div class='wrap'><table class='tbl'><tr><th scope=col>Other side</th><th scope=col>Service</th>"
                f"<th scope=col>Evidence</th><th scope=col></th></tr>{''.join(row(d) for d in items)}</table></div>")
    dismissed = [d for d in deps if d["status"] == "dismissed"]
    body = (tabs(DEVICE_TABS, "/netmon/apps") + banner + head
            + f"<section class='card'><div class='card-h'><h2>Dependencies</h2></div>{per}{summary}"
            + (A.graph_svg(a["name"], uses + used) if graph and (uses or used) else "")
            + table(f"What {e(a['name'])} uses", uses, "Nothing seen. Traffic within one VLAN does not pass the firewall.")
            + table(f"What uses {e(a['name'])} (outage impact)", used, "Nothing seen using it in this period.")
            + (f"<details class='tech'><summary>{len(dismissed)} dismissed</summary>{table('Dismissed', dismissed, '')}</details>" if dismissed else "")
            + "<p class='muted small'>Confidence is in how many days (4-hour periods when looking at 24 hours) of the period the dependency was seen. Internet dependencies are grouped by "
              "network owner (AS) and service, from reply records, so they are tied to the device even behind a shared address. "
              "“New” means first seen by netmon in the last 24 hours.</p></section>")
    return page(req, a["name"], body, "/netmon/servers", scoped=False, subtitle="Application dependencies")


def _form_aid(aid):
    try:
        return A.get(conn, aid)
    except ValueError:
        raise HTTPException(404)


@app.post("/netmon/apps/new")
async def app_new(req: Request):
    u = need(req, "analyst")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    s = _site(str(f.get("site", "")))
    try:
        aid = A.create(conn, cfg, s["id"], str(f.get("name", "")), str(f.get("members", "")), u, owner=str(f.get("owner", "")),
                       critical=bool(f.get("critical")))
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(f"/netmon/apps/{aid}", "Application created.")


@app.post("/netmon/apps/{aid}/edit")
async def app_edit(req: Request, aid: int):
    u = need(req, "analyst")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    _form_aid(aid)
    try:
        A.update(conn, aid, u, name=str(f.get("name", "")), owner=str(f.get("owner", "")), critical=bool(f.get("critical")), note=str(f.get("note", "")))
    except Exception:
        raise HTTPException(400, "an application with that name already exists")
    return _back(f"/netmon/apps/{aid}", "Saved.")


@app.post("/netmon/apps/{aid}/delete")
async def app_delete(req: Request, aid: int):
    u = need(req, "analyst")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    _form_aid(aid)
    A.delete(conn, aid, u)
    return _back("/netmon/apps", "Application deleted.")


@app.post("/netmon/apps/{aid}/members")
async def app_member_add(req: Request, aid: int):
    u = need(req, "analyst")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    a = _form_aid(aid)
    ip = str(f.get("ip", "")).strip()
    try:
        if not cfg.is_internal(ip):
            raise ValueError("not an internal address")
        A.add_member(conn, aid, a["site"], ip, u)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    A._cache.clear()
    return _back(f"/netmon/apps/{aid}", "Device added.")


@app.post("/netmon/apps/{aid}/members/remove")
async def app_member_remove(req: Request, aid: int):
    u = need(req, "analyst")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    _form_aid(aid)
    A.remove_member(conn, aid, str(f.get("ip", "")), u)
    A._cache.clear()
    return _back(f"/netmon/apps/{aid}", "Device removed.")


@app.post("/netmon/apps/{aid}/deps")
async def app_dep_status(req: Request, aid: int):
    u = need(req, "analyst")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    _form_aid(aid)
    try:
        A.set_status(conn, aid, str(f.get("dkey", ""))[:200], str(f.get("status", "")), u, str(f.get("note", "")))
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(f"/netmon/apps/{aid}", "Dependency updated.")
