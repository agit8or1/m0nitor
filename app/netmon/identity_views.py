"""Device identity UI: 'Address history' on the device page and Internal devices → Identity review
(suggestions, merge, separate, undo, rename, history). Review actions need the admin role (names are admin-edited)."""
import json
import time
from urllib.parse import quote

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import access
from . import identity as idn
from .ux import DEVICE_TABS, conf_badge, empty_state, fmt_local, tabs
from .web import ROLES, app, cfg, check_csrf, conn, csrf_field, e, need, page, site_name, user_of

KIND_LABEL = {"ip": "IP address", "mac": "MAC address", "hostname": "Hostname", "dhcp": "DHCP lease"}
SOURCE_LABEL = {"arp": "firewall ARP table", "ndp": "firewall IPv6 neighbour table", "dhcp": "DHCP lease", "traffic": "traffic only (no MAC)",
                "manual": "entered by a person"}


def _site_for(ip, site=""):
    if site and cfg.site(site):
        return site
    c = idn.sites_for_ip(cfg, ip)
    return c[0] if len(c) == 1 else (c[0] if c else cfg.sites[0]["id"])


def basis_sentence(iid):
    r = conn.execute("SELECT basis FROM identities WHERE id=?", (iid,)).fetchone()
    return idn.BASIS_TEXT.get(r["basis"], "") if r else ""


def history_rows(iid, site):
    rows = idn.evidence(conn, iid)
    from .devtypes import vendor_of
    out = ""
    for r in sorted(rows, key=lambda x: (-x["last_seen"], x["kind"])):
        val = r["value"]
        extra = ""
        if r["kind"] == "mac":
            v = vendor_of(val)
            extra = (f" <span class='muted small'>{e(v)}</span>" if v else "") + (
                " <span class='tag' title='locally administered: randomized or virtual'>randomized</span>" if idn.randomized(val) else "")
        if r["kind"] == "dhcp" and r["detail"]:
            d = json.loads(r["detail"])
            extra = f" <span class='muted small'>lease {e(fmt_local(d.get('starts'), cfg.site(site)))} → {e(fmt_local(d.get('ends'), cfg.site(site)))}</span>"
        inferred = " <span class='tag' title='seen again without MAC confirmation'>probable</span>" if r["inferred"] else ""
        merged = f" <span class='muted small'>(from device #{r['original_identity']})</span>" if r["original_identity"] else ""
        out += (f"<tr><td>{e(KIND_LABEL.get(r['kind'], r['kind']))}</td><td class='mono'>{e(val)}{extra}{inferred}{merged}</td>"
                f"<td class='num'>{e(fmt_local(r['first_seen'], cfg.site(site)))}</td><td class='num'>{e(fmt_local(r['last_seen'], cfg.site(site)))}</td>"
                f"<td class='small'>{e(SOURCE_LABEL.get(r['source'], r['source']))}</td></tr>")
    return out


def address_history_card(ip, site=""):
    """For the device page: who has this address now, and that device's address/MAC/hostname history."""
    site = _site_for(ip, site)
    o = idn.owner_at(conn, site, ip, time.time())
    multi = len(cfg.sites) > 1
    head = f"<div class='card-h'><h2>Address history</h2><span class='muted small'>{e(site_name(site)) if multi else ''}</span></div>"
    if not o["identity"]:
        if o["ambiguous"]:
            names = ", ".join(f"<a href='/netmon/identities/{i}'>{e(idn.name_of(conn, cfg, i))}</a>" for i in o["ambiguous"])
            return f"<section class='card' id='addrhist'>{head}<p>More than one device used this address recently: {names}. {e(o['explain'])}.</p></section>"
        return (f"<section class='card' id='addrhist'>{head}" + empty_state(
            "learning", " No device history for this address yet. It is built from the firewall's ARP / neighbour tables, DHCP leases "
            "and traffic every 15 minutes.", "" if access.restricted() else "/netmon/settings/inventory#discovery", "Discovery status") + "</section>")
    iid = o["identity"]
    moved = conn.execute("SELECT count(DISTINCT value) FROM identity_evidence WHERE identity_id=? AND kind='ip'", (iid,)).fetchone()[0]
    prior = conn.execute("SELECT count(DISTINCT identity_id) FROM identity_evidence WHERE site=? AND kind='ip' AND value=?", (site, ip)).fetchone()[0]
    notes = []
    if moved > 1:
        notes.append(f"This device has used {moved} addresses; its history stays with it.")
    if prior > 1:
        notes.append(f"{prior} different devices have used {ip} over time. Older events are attributed to whoever had the address then.")
    return f"""<section class='card' id='addrhist'>{head}
<p><b>{e(idn.name_of(conn, cfg, iid))}</b> {conf_badge(o['confidence'], o['explain'])} <span class='muted small'>device #{iid} · {e(basis_sentence(iid))}.</span></p>
{''.join(f"<p class='small'>{e(n)}</p>" for n in notes)}
<div class='wrap'><table class='tbl'><thead><tr><th>Evidence</th><th>Value</th><th class='num'>First seen</th><th class='num'>Last seen</th><th>Source</th></tr></thead>
<tbody>{history_rows(iid, site)}</tbody></table></div>
<p class='small'><a href='/netmon/identities/{iid}'>Review this device's identity (merge, separate, rename) →</a></p></section>"""


def _suggestions(site=None, status="open", limit=100):
    q = "SELECT * FROM identity_suggestions WHERE status=? AND site_ok(site)" + (" AND site=?" if site else "") + " ORDER BY created_at DESC LIMIT ?"
    return conn.execute(q, (status, site, limit) if site else (status, limit)).fetchall()


@app.get("/netmon/identities", response_class=HTMLResponse)
def identities_page(req: Request, q: str = "", msg: str = ""):
    u, r = user_of(req)
    admin = ROLES[r] >= ROLES["admin"]
    sugg = _suggestions()
    srows = ""
    for s in sugg:
        d = json.loads(s["detail"] or "{}")
        a = f"<a href='/netmon/identities/{s['a']}'>{e(idn.name_of(conn, cfg, s['a']))}</a>"
        b = f" and <a href='/netmon/identities/{s['b']}'>{e(idn.name_of(conn, cfg, s['b']))}</a>" if s["b"] else ""
        acts = ""
        if admin:
            merge_btn = (f"<form method=post action='/netmon/identities/merge' class='inline'>{csrf_field(req)}<input type=hidden name=keep value={s['a']}>"
                         f"<input type=hidden name=gone value={s['b']}><input type=hidden name=reason value='accepted suggestion #{s['id']}'>"
                         f"<button class='sm'>Same device: merge</button></form>" if s["b"] and s["kind"] == "same_hostname" else "")
            acts = merge_btn + (f"<form method=post action='/netmon/identities/suggestion/{s['id']}' class='inline'>{csrf_field(req)}"
                                f"<button class='sm' name=status value=dismissed>{'Different devices: keep separate' if s['b'] else 'Dismiss'}</button></form>")
        srows += (f"<li><span class='s1'>{a}{b}</span><span class='s2'>{e(idn.suggestion_text(s['kind'], d))}</span>"
                  f"<span class='acts'>{e(site_name(s['site']))} · {e(fmt_local(s['created_at']))} {acts}</span></li>")
    where, args = "WHERE i.status='active' AND site_ok(i.site)", []
    if q.strip():
        where += " AND (i.name LIKE ? OR i.id IN (SELECT identity_id FROM identity_evidence WHERE value LIKE ?))"
        args = [f"%{q.strip()}%", f"%{q.strip().lower()}%"]
    rows = conn.execute(f"""SELECT i.*, (SELECT count(DISTINCT value) FROM identity_evidence WHERE identity_id=i.id AND kind='ip') AS ips,
        (SELECT count(DISTINCT value) FROM identity_evidence WHERE identity_id=i.id AND kind='mac') AS macs
        FROM identities i {where} ORDER BY i.updated_at DESC LIMIT 200""", args).fetchall()
    trs = "".join(
        f"<tr><td><a href='/netmon/identities/{x['id']}'>{e(idn.name_of(conn, cfg, x['id']))}</a></td><td class='mono small'>{e(idn.current_ip(conn, x['id']))}</td>"
        f"<td>{e(site_name(x['site']))}</td><td class='small'>{e({'mac': 'MAC', 'random-mac': 'randomized MAC', 'ip-only': 'IP only', 'manual': 'manual'}.get(x['basis'], x['basis']))}</td>"
        f"<td class='num'>{x['ips']}</td><td class='num'>{x['macs']}</td><td class='num'>{e(fmt_local(x['updated_at']))}</td></tr>" for x in rows)
    total = conn.execute("SELECT count(*) FROM identities WHERE status='active' AND site_ok(site)").fetchone()[0]
    body = f"""{tabs(DEVICE_TABS, '/netmon/identities')}{f"<div class='banner'>{e(msg)}</div>" if msg else ''}
<section class="card"><div class="card-h"><h2>Needs your review</h2><span class="muted small">{len(sugg)} open</span></div>
<p class="note">netmon never merges devices on its own because of a shared hostname, vendor or a reused IP address. When the evidence
suggests two records might be one device (or a device moved), it asks here.</p>
{f"<ul class='sentence-list'>{srows}</ul>" if srows else empty_state('nomatch', ' Nothing to review right now.')}</section>
<section class="card"><div class="card-h"><h2>Devices</h2><span class="muted small">{total} known · per site, so overlapping private addresses at different sites stay apart</span></div>
<form class="row" method=get><input name=q value="{e(q)}" placeholder="name, IP, MAC or hostname" aria-label="Find a device"> <button>Find</button></form>
<div class="wrap"><table class="tbl"><thead><tr><th>Device</th><th>Current IP</th><th>Site</th><th>Identified by</th><th class="num">IPs</th><th class="num">MACs</th><th class="num">Updated</th></tr></thead>
<tbody>{trs or '<tr><td colspan=7>' + empty_state('learning', ' No identities yet: they are built by auto-discovery every 15 minutes.', '' if access.restricted() else '/netmon/settings/inventory#discovery', 'Discovery') + '</td></tr>'}</tbody></table></div></section>"""
    return page(req, "Identity review", body, "/netmon/servers", scoped=False,
                subtitle="Which device had which address, and when")


@app.get("/netmon/identities/{iid}", response_class=HTMLResponse)
def identity_page(req: Request, iid: int, msg: str = ""):
    u, r = user_of(req)
    x = conn.execute("SELECT * FROM identities WHERE id=? AND site_ok(site)", (iid,)).fetchone()
    if not x:
        raise HTTPException(404)
    if x["status"] == "merged":
        to = idn.resolve(conn, iid)
        undo = (f"<form method=post action='/netmon/identities/{iid}/unmerge' class='inline'>{csrf_field(req)}<button>Undo merge</button></form>"
                if ROLES[r] >= ROLES["admin"] else "")
        return page(req, f"Device #{iid}", f"<div class='banner'>This record was merged into <a href='/netmon/identities/{to}'>"
                    f"{e(idn.name_of(conn, cfg, to))}</a>. {undo}</div>", "/netmon/servers", scoped=False)
    admin = ROLES[r] >= ROLES["admin"]
    ip = idn.current_ip(conn, iid)
    ev = idn.evidence(conn, iid)
    hist = conn.execute("SELECT * FROM identity_events WHERE identity_id=? ORDER BY ts DESC LIMIT 100", (iid,)).fetchall()
    tl = "".join(f"<li><span class='t'>{e(fmt_local(h['ts'], cfg.site(x['site'])))} · {e(h['user'])}</span><div>{e(h['action'].replace('_', ' '))} "
                 f"<span class='muted small mono'>{e(h['detail'])}</span></div></li>" for h in hist)
    sep = ""
    if admin and len(ev) > 1:
        boxes = "".join(f"<label class='check'><input type=checkbox name=rows value={r_['id']}> {e(KIND_LABEL.get(r_['kind'], r_['kind']))} "
                        f"<span class='mono'>{e(r_['value'])}</span></label>" for r_ in ev)
        sep = f"""<details class="tech"><summary>Separate: these records belong to a different device</summary>
<form method=post action="/netmon/identities/{iid}/separate" class="stackform">{csrf_field(req)}<div class="chkgrid">{boxes}</div>
<label>Why<input name=reason maxlength=200 placeholder="e.g. second NIC belongs to the backup appliance"></label><button>Separate selected</button></form></details>"""
    merge_f = (f"""<details class="tech"><summary>Merge: another record is the same device</summary>
<form method=post action="/netmon/identities/merge" class="row">{csrf_field(req)}<input type=hidden name=keep value={iid}>
<label>Device # to merge into this one<input name=gone inputmode=numeric required class="short"></label>
<label>Why<input name=reason maxlength=200 placeholder="e.g. same server, two network cards"></label><button>Merge</button></form>
<p class="muted small">Only devices at the same site can be merged. A merge can be undone from the merged record.</p></details>""" if admin else "")
    ren = (f"""<form method=post action="/netmon/identities/{iid}/rename" class="row">{csrf_field(req)}
<label>Name for this device<input name=name value="{e(x['name'] or '')}" maxlength=64 placeholder="{e(idn.name_of(conn, cfg, iid))}"></label><button>Save</button></form>
<p class="muted small">Leave empty to use the Inventory name of its current address.</p>""" if admin else "")
    body = f"""{tabs(DEVICE_TABS, '/netmon/identities')}{f"<div class='banner'>{e(msg)}</div>" if msg else ''}
<section class="card"><div class="card-h"><h2>{e(idn.name_of(conn, cfg, iid))}</h2><span class="muted small">device #{iid} · {e(site_name(x['site']))}</span></div>
<p>{e(basis_sentence(iid)).capitalize()}.</p>
{f"<p>Current address: <a href='/netmon/servers/{quote(ip)}'>{e(ip)}</a></p>" if ip else ''}
<div class='wrap'><table class='tbl'><thead><tr><th>Evidence</th><th>Value</th><th class='num'>First seen</th><th class='num'>Last seen</th><th>Source</th></tr></thead>
<tbody>{history_rows(iid, x['site'])}</tbody></table></div>{ren}{merge_f}{sep}</section>
<section class="card"><div class="card-h"><h2>History</h2></div>{f"<ul class='timeline'>{tl}</ul>" if tl else '<p class=muted>No changes recorded.</p>'}</section>"""
    return page(req, f"Device #{iid}", body, "/netmon/servers", scoped=False)


def _back(path, msg):
    return RedirectResponse(f"{path}?msg={quote(msg)}", 303)


@app.post("/netmon/identities/merge")
def post_merge(req: Request, keep: int = Form(...), gone: int = Form(...), reason: str = Form(""), csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    try:
        n = idn.merge(conn, keep, gone, u, reason[:200])
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(f"/netmon/identities/{idn.resolve(conn, keep)}", f"Merged device #{gone} ({n} records). You can undo it from #{gone}.")


@app.post("/netmon/identities/{iid}/unmerge")
def post_unmerge(req: Request, iid: int, csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    try:
        idn.unmerge(conn, iid, u)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(f"/netmon/identities/{iid}", "Merge undone.")


@app.post("/netmon/identities/{iid}/separate")
async def post_separate(req: Request, iid: int):
    u = need(req, "admin")
    form = await req.form()
    check_csrf(req, str(form.get("csrf", "")))
    try:
        rows = [int(x) for x in form.getlist("rows")]
        new = idn.separate(conn, iid, rows, u, str(form.get("reason", ""))[:200])
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(f"/netmon/identities/{new}", f"Separated into a new device #{new}.")


@app.post("/netmon/identities/{iid}/rename")
def post_rename(req: Request, iid: int, name: str = Form(""), csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    idn.rename(conn, iid, name, u)
    return _back(f"/netmon/identities/{iid}", "Saved.")


@app.post("/netmon/identities/suggestion/{sid}")
def post_suggestion(req: Request, sid: int, status: str = Form(...), csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    try:
        idn.decide(conn, sid, status, u)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back("/netmon/identities", "Recorded.")
