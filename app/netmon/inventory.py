"""Names for addresses, kept in the app DB: internal servers (assets:db: name, role, sensitive, notes) and
labels for external addresses (labels:db: name, notes). config.yaml `assets:` only seeds a fresh DB."""
import ipaddress
import re
from urllib.parse import quote

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .core import apply_assets, audit, get_setting, put_setting
from .web import ROLES, app, cfg, check_csrf, conn, csrf_field, current, e, need, page, safe_next, user_of

# no markup or quote characters: names end up in titles, notifications and AI evidence
NAME_RE = re.compile(r"^[\w .,:;/+()&@#=~-]{1,64}$")
ROLE_RE = re.compile(r"^[\w .,/+&-]{0,32}$")

apply_assets(cfg, conn)


def clean(v, rx, what, limit):
    v = " ".join((v or "").split())[:limit]
    if v and not rx.match(v):
        raise ValueError(f"{what} may use letters, digits, spaces and . , : ; / + ( ) & @ # = ~ - only")
    return v


def save(ip, name, role, sensitive, notes, user, role_of_user):
    """Set or clear the name for `ip`. Internal addresses (servers) need admin: `sensitive` changes detection
    severity. External labels need analyst. Returns a status message."""
    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise ValueError("not an IP address")
    internal = cfg.is_internal(ip)
    need_role = "admin" if internal else "analyst"
    if ROLES[role_of_user] < ROLES[need_role]:
        raise PermissionError(f"naming {'servers' if internal else 'external addresses'} requires role {need_role}")
    name = clean(name, NAME_RE, "Name", 64)
    notes = " ".join((notes or "").split())[:300].replace("<", "‹").replace(">", "›")
    key = "assets:db" if internal else "labels:db"
    db = get_setting(conn, key, {}) or {}
    old = db.get(ip)
    if not name:
        db.pop(ip, None)
        msg = f"Removed the name for {ip}."
    elif internal:
        db[ip] = {"name": name, "role": clean(role, ROLE_RE, "Role", 32), "sensitive": bool(sensitive), "notes": notes}
        msg = f"Saved {name} ({ip})."
    else:
        db[ip] = {"name": name, "notes": notes}   # no "source": a person's label, never replaced by a sync
        msg = f"Saved label {name} for {ip}."
    put_setting(conn, key, db, user)
    apply_assets(cfg, conn)
    audit(conn, user, "asset_named" if internal else "label_named", {"ip": ip, "old": old, "new": db.get(ip)})
    return msg


def vip_name(descr):
    """Make a firewall description usable as a name (same character rules as typed names)."""
    import re as _re
    v = " ".join(_re.sub(r"[^\w .,:;/+()&@#=~-]", " ", descr or "").split())[:64]
    return v if v and NAME_RE.match(v) else ""


def sync_vips(user="vip-sync"):
    """Import Interfaces → Virtual IPs from every OPNsense site as labels for those public addresses.
    Imported labels carry source 'vip:<site>' and are refreshed or removed on the next sync; a label a person
    typed (no source) is never overwritten. Returns {site: imported count or error}."""
    from . import block as blk
    db = get_setting(conn, "labels:db", {}) or {}
    before = {k: dict(v) for k, v in db.items()}
    out = {}
    for site in cfg.sites:
        fw = blk.enforcer(site)
        if not isinstance(fw, blk.OPNsense) or not fw.enabled:
            continue
        try:
            rows = fw._call("GET", "/api/interfaces/vip_settings/search_item", params={"rowCount": "-1"}).get("rows", [])
        except Exception as ex:
            out[site["id"]] = f"error: {str(ex)[:150]}"
            continue
        src, seen = f"vip:{site['id']}", set()
        for v in rows:
            try:
                ip = str(ipaddress.ip_address(str(v.get("subnet", "")).strip()))
            except ValueError:
                continue
            name = vip_name(v.get("descr"))
            if not name or cfg.is_internal(ip):
                continue
            cur = db.get(ip)
            if cur and not str(cur.get("source", "")).startswith("vip:"):
                continue   # a person named it; keep theirs
            seen.add(ip)
            db[ip] = {"name": name, "source": src, "notes": f"virtual IP ({v.get('%mode') or v.get('mode')}) on {v.get('%interface') or v.get('interface')}"
                      f" · {v.get('address') or ip} · {site['name']}"}
        nat = []
        try:
            for x in fw._call("GET", "/api/firewall/one_to_one/search_rule", params={"rowCount": "-1"}).get("rows", []):
                try:
                    ext, inner = str(ipaddress.ip_address(x.get("external", ""))), str(ipaddress.ip_address(x.get("source_net", "")))
                except ValueError:
                    continue   # network-to-network or alias mappings: not a single host, skip
                if x.get("enabled") != "1" or x.get("type") != "binat" or not cfg.is_internal(inner):
                    continue
                nat.append({"external": ext, "internal": inner, "description": vip_name(x.get("description")), "site": site["id"]})
                cur = db.get(ext)
                if cur and not str(cur.get("source", "")).startswith("vip:"):
                    continue
                seen.add(ext)
                server = cfg.asset_label(inner)
                db[ext] = {"name": vip_name(x.get("description")) or (cur or {}).get("name") or f"1:1 NAT {inner}", "source": src,
                           "notes": f"1:1 NAT ↔ {server} · {site['name']}" + (f" · {cur['notes']}" if cur and "1:1" not in cur.get("notes", "") else "")}
        except Exception as ex:
            out[site["id"] + ":nat"] = f"1:1 NAT not read: {str(ex)[:120]}"
        else:
            n11 = get_setting(conn, "nat11:db", {}) or {}
            if n11.get(site["id"]) != nat:
                n11[site["id"]] = nat
                put_setting(conn, "nat11:db", n11, user)
                audit(conn, user, "nat11_synced", {"site": site["id"], "rules": nat})
        for ip in [k for k, x in db.items() if x.get("source") == src and k not in seen]:
            db.pop(ip)
        out[site["id"]] = len(seen)
    if db != before:
        put_setting(conn, "labels:db", db, user)
        audit(conn, user, "labels_synced", {"sites": out, "added": sorted(set(db) - set(before)), "removed": sorted(set(before) - set(db))})
    apply_assets(cfg, conn)   # always: 1:1 NAT may have changed even when labels did not
    from .core import set_state
    set_state(conn, "vip_sync", {"ts": __import__("time").time(), "sites": out})
    return out


@app.post("/netmon/settings/inventory/sync")
def vip_sync_now(req: Request, csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    res = sync_vips(u)
    txt = "; ".join(f"{cfg.site(k)['name'] if cfg.site(k) else k}: {v if isinstance(v, str) else f'{v} addresses'}" for k, v in res.items())
    return back_to("/netmon/settings/inventory#labels", f"Synced. {txt or 'No OPNsense firewall with an API key.'}")


def back_to(url, msg):
    url = safe_next(url or "/netmon/settings/inventory")
    sep = "&" if "?" in url else "?"
    frag = ""
    if "#" in url:
        url, frag = url.split("#", 1)
        frag = "#" + frag
    return RedirectResponse(f"{url}{sep}msg={quote(msg)}{frag}", 303)


@app.post("/netmon/names")
def post_name(req: Request, ip: str = Form(...), name: str = Form(""), role: str = Form(""), sensitive: str = Form(""),
              notes: str = Form(""), clear: str = Form(""), back: str = Form(""), csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    _, r = user_of(req)
    js = req.headers.get("x-nm-fetch") == "1"   # the in-page ✎ editor wants JSON, plain forms get a redirect
    try:
        msg = save(ip, "" if clear else name, role, sensitive == "1", notes, u, r)
    except PermissionError as ex:
        if js:
            return JSONResponse({"ok": False, "error": str(ex)}, 403)
        raise HTTPException(403, str(ex))
    except ValueError as ex:
        if js:
            return JSONResponse({"ok": False, "error": str(ex)}, 400)
        msg = f"Not saved: {ex}"
    if js:
        return {"ok": True, "message": msg, **name_json(ip, r)}
    return back_to(back, msg)


def name_json(ip, role):
    ip = str(ipaddress.ip_address(ip.strip()))
    internal = cfg.is_internal(ip)
    a = (cfg.get("assets", {}) if internal else cfg.get("labels", {})).get(ip) or {}
    return {"ip": ip, "internal": internal, "name": a.get("name", ""), "role": a.get("role", ""), "sensitive": bool(a.get("sensitive")),
            "notes": a.get("notes", ""), "can_edit": ROLES[role] >= ROLES["admin" if internal else "analyst"],
            "needs": "admin" if internal else "analyst"}


@app.get("/netmon/api/name")
def get_name(req: Request, ip: str):
    _, r, _ = current(req)
    try:
        return {"ok": True, **name_json(ip, r)}
    except ValueError:
        raise HTTPException(400, "not an IP address")


def name_form(req, ip, back, compact=False):
    """Edit form for one address (server or external), pre-filled from the DB."""
    internal = cfg.is_internal(ip)
    a = (cfg.get("assets", {}) if internal else cfg.get("labels", {})).get(ip) or {}
    extra = (f"""<label>Role<input name=role value="{e(a.get('role', ''))}" maxlength=32 placeholder="web, mail, backup…"></label>
<label class="check"><input type=checkbox name=sensitive value=1 {'checked' if a.get('sensitive') else ''}> Sensitive
<span class="muted small">— new outbound destinations from this server are raised one severity level</span></label>""" if internal else "")
    return f"""<form method=post action="/netmon/names" class="stackform{'' if compact else ' wide'} nameform">{csrf_field(req)}
<input type=hidden name=ip value="{e(ip)}"><input type=hidden name=back value="{e(back)}">
<label>Name<input name=name value="{e(a.get('name', ''))}" maxlength=64 placeholder="{'server name' if internal else 'e.g. Office VPN, Backup provider'}"></label>
{extra}<label>Notes<input name=notes value="{e(a.get('notes', ''))}" maxlength=300 placeholder="optional"></label>
<div class="row"><button class="primary">Save</button>{'<button name=clear value=1 class="ghost" title="Remove this name">Clear name</button>' if a else ''}</div></form>"""


@app.get("/netmon/settings/inventory", response_class=HTMLResponse)
def inventory_page(req: Request, msg: str = ""):
    from .admin import SETTINGS_TABS, tabs
    u, r = user_of(req)
    admin, analyst = r == "admin", ROLES[r] >= ROLES["analyst"]
    back = "/netmon/settings/inventory"
    assets = sorted(cfg.get("assets", {}).items(), key=lambda kv: ipaddress.ip_address(kv[0]))
    labels = sorted(cfg.get("labels", {}).items(), key=lambda kv: ipaddress.ip_address(kv[0]))

    def edit(ip, ok):
        return f"<details class='tech'><summary>Edit</summary>{name_form(req, ip, back + '#n-' + ip.replace(':', '-'), True)}</details>" if ok else ""
    srows = "".join(f"""<tr id="n-{e(ip.replace(':', '-'))}"><td><a href="/netmon/servers/{e(ip)}">{e(a['name'])}</a></td><td class="mono">{e(ip)}</td>
<td>{e(a.get('role') or '—')}</td><td>{'<span class="tag">sensitive</span>' if a.get('sensitive') else ''}</td><td class="small">{e(a.get('notes', ''))}</td>
<td>{edit(ip, admin)}</td></tr>""" for ip, a in assets)
    def src(a):
        s = a.get("source", "")
        return f"<span class='tag' title='imported; edit to make it yours'>{e(cfg.site(s[4:])['name'] if s.startswith('vip:') and cfg.site(s[4:]) else s)} virtual IP</span>" if s else "manual"
    lrows = "".join(f"""<tr id="n-{e(ip.replace(':', '-'))}"><td>{e(a['name'])}</td><td class="mono"><a href="/netmon/connections?rip={e(ip)}">{e(ip)}</a></td>
<td>{src(a)}</td><td class="small">{e(a.get('notes', ''))}</td><td>{edit(ip, analyst)}</td></tr>""" for ip, a in labels)
    from .core import get_state
    vs, _ = get_state(conn, "vip_sync", {})
    vs = vs or {}
    sync = (f"""<form method=post action="/netmon/settings/inventory/sync" class="row">{csrf_field(req)}<button>Sync from firewall now</button>
<span class="muted small">Virtual IPs and 1:1 NAT rules on each OPNsense firewall, imported as labels for those public addresses
(1:1 NAT also makes a server's outbound traffic attributable to it) · hourly
{('· last ' + __import__('time').strftime('%Y-%m-%d %H:%MZ', __import__('time').gmtime(vs['ts']))) if vs.get('ts') else ''}</span></form>""" if analyst else "")
    add = f"""<section class="card" id="add"><div class="card-h"><h2>Name an address</h2></div>
<form method=post action="/netmon/names" class="stackform wide">{csrf_field(req)}<input type=hidden name=back value="{back}">
<label>IP address<input name=ip required placeholder="10.0.0.50 or 203.0.113.7" class="mono"></label>
<label>Name<input name=name required maxlength=64></label>
{'<label>Role <span class="muted small">(internal servers only)</span><input name=role maxlength=32></label><label class="check"><input type=checkbox name=sensitive value=1> Sensitive <span class="muted small">(internal servers only)</span></label>' if admin else ''}
<label>Notes<input name=notes maxlength=300></label><div class="row"><button class="primary">Save</button></div>
<p class="note">Internal addresses become named servers{'' if admin else ' (admins only)'}; any other address gets a label shown next to it in connection tables and findings.</p></form></section>""" if analyst else ""
    body = f"""{tabs(SETTINGS_TABS, back)}{f"<div class='banner'>{e(msg)}</div>" if msg else ''}
<section class="card"><div class="card-h"><h2>Internal servers</h2><span class="muted small">{len(assets)} named · stored in the netmon database</span></div>
<div class="wrap"><table class="tbl"><thead><tr><th>Name</th><th>IP</th><th>Role</th><th></th><th>Notes</th><th></th></tr></thead>
<tbody>{srows or '<tr><td colspan=6 class="state empty">No servers named yet</td></tr>'}</tbody></table></div>
<p class="note">Names appear across the dashboard, in finding titles and notifications. Before AI analysis, server names are replaced by pseudonyms just like internal IPs.</p></section>
<section class="card" id="labels"><div class="card-h"><h2>Public and external address labels</h2><span class="muted small">{len(labels)} labelled</span></div>{sync}
<div class="wrap"><table class="tbl"><thead><tr><th>Label</th><th>IP</th><th>Source</th><th>Notes</th><th></th></tr></thead>
<tbody>{lrows or '<tr><td colspan=5 class="state empty">No labels yet. Use ✎ next to any IP address, or the form below.</td></tr>'}</tbody></table></div>
<p class="note">Tip: every IP address in connection tables, findings, IDS alerts and search results has a ✎ button to name it in place.</p></section>{add}"""
    return page(req, "Inventory", body, "/netmon/settings", scoped=False)
