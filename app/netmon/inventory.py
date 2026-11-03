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
# offered in the role picker (any other text is still accepted); the AI uses the role to judge what is normal for a server
STANDARD_ROLES = ("web", "mail", "dns", "mail+dns", "web+dns", "reverse-proxy", "database", "file server", "storage", "backup",
                  "hypervisor", "firewall", "vpn", "remote-access", "management", "monitoring", "workstation", "marketing crawler")
BULK_MAX = 256
# what an internal address IS (role = what it does); a fixed list so filters and AI analysis can rely on it
DEVICE_TYPES = ("physical server", "virtual machine", "container", "hypervisor host", "workstation / laptop", "mobile device",
                "printer", "IoT / camera", "VoIP phone", "network device (switch / AP)", "firewall / router", "storage / NAS", "other")


def clean_type(v):
    v = (v or "").strip()
    if v == "__none":   # the "not set" option (an empty form value would arrive as "field not sent")
        return ""
    if v and v not in DEVICE_TYPES:
        raise ValueError(f"Type must be one of: {', '.join(DEVICE_TYPES)}")
    return v


def type_select(current="", name="kind", keep=False):
    first = ("<option value='__keep'>keep unchanged</option>" if keep else "") + f"<option value='__none'{'' if current or keep else ' selected'}>not set</option>"
    return f"<select name={name}>{first}" + "".join(
        f"<option{' selected' if t == current else ''}>{e(t)}</option>" for t in DEVICE_TYPES) + "</select>"

apply_assets(cfg, conn)


def clean(v, rx, what, limit):
    v = " ".join((v or "").split())[:limit]
    if v and not rx.match(v):
        raise ValueError(f"{what} may use letters, digits, spaces and . , : ; / + ( ) & @ # = ~ - only")
    return v


def clean_list(v, what, exclude=""):
    """Comma-separated list (aliases: other names for one address; software: products the server runs, matched
    against threat intel). At most 8, deduplicated, never repeating `exclude`; same character rules as names."""
    out = []
    for a in (v or "").split(","):
        a = clean(a, NAME_RE, what, 64)
        if a and a.lower() != exclude.lower() and a.lower() not in (x.lower() for x in out):
            out.append(a)
    if len(out) > 8:
        raise ValueError(f"at most 8 entries in {what}")
    return out


def role_options():
    """Standard roles plus every role already in use, for the role picker."""
    used = {a.get("role") for a in cfg.get("assets", {}).values() if a.get("role")}
    return sorted(set(STANDARD_ROLES) | used, key=str.lower)


def role_datalist():
    return "<datalist id=nm-roles>" + "".join(f"<option value=\"{e(r)}\">" for r in role_options()) + "</datalist>"


def suggest_role(ip):
    """Role observed in the last 7 days of traffic (services remote clients completed connections to)."""
    from .profile import observed
    from .web import dash
    o = observed(dash, ip)
    return {"observed_role": o["observed_role"], "serves": [s["function"] for s in o["observed_serves"]]}


def bulk_targets(text):
    """Internal addresses named by a comma/space separated list of IPs and CIDRs (at most BULK_MAX)."""
    out = []
    for tok in re.split(r"[\s,;]+", (text or "").strip()):
        if not tok:
            continue
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            raise ValueError(f"{tok!r} is not an IP address or CIDR")
        if net.num_addresses > BULK_MAX:
            raise ValueError(f"{tok} has more than {BULK_MAX} addresses")
        hosts = [net.network_address] if net.num_addresses == 1 else list(net.hosts())
        for a in hosts:
            ip = str(a)
            if not cfg.is_internal(ip):
                raise ValueError(f"{ip} is not an internal address; roles are for internal servers")
            if ip not in out:
                out.append(ip)
        if len(out) > BULK_MAX:
            raise ValueError(f"more than {BULK_MAX} addresses")
    if not out:
        raise ValueError("no addresses given")
    return out


def assign_role(text, role, user, role_of_user, only_named=False, kind="__keep", keep_role=False):
    """Set the role of several internal servers at once. Unnamed addresses are added under their IP as the name
    (unless only_named). Name, notes and other fields of named servers are kept."""
    if ROLES[role_of_user] < ROLES["admin"]:
        raise PermissionError("assigning server roles requires role admin")
    role = clean(role, ROLE_RE, "Role", 32)
    kind = kind if kind == "__keep" else clean_type(kind)
    ips = bulk_targets(text)
    db = get_setting(conn, "assets:db", {}) or {}
    changed, added = [], []
    for ip in ips:
        new = {**({} if keep_role else {"role": role}), **({} if kind == "__keep" else {"kind": kind})}
        if ip in db:
            upd = {k: v for k, v in new.items() if db[ip].get(k, "") != v}
            if upd:
                changed.append({"ip": ip, "old": {k: db[ip].get(k, "") for k in upd}})
                db[ip] = {**db[ip], **upd}
                db[ip] = {k: v for k, v in db[ip].items() if not (k == "kind" and not v)}
        elif not only_named:
            db[ip] = {"name": ip, "role": "" if keep_role else role, "sensitive": False, "notes": "", **({"kind": new["kind"]} if new.get("kind") else {})}
            added.append(ip)
    put_setting(conn, "assets:db", db, user)
    apply_assets(cfg, conn)
    audit(conn, user, "asset_role_bulk", {"role": None if keep_role else role, "kind": kind, "changed": changed, "added": added})
    skipped = len(ips) - len(changed) - len(added)
    what = "; ".join(x for x in ("" if keep_role else f"role {role or '(none)'}", "" if kind == "__keep" else f"type {kind or '(none)'}") if x)
    return (f"{what[:1].upper() + what[1:] or 'Nothing to change'}: {len(changed)} address(es) updated, {len(added)} added"
            + (f", {skipped} unchanged or skipped" if skipped else "") + ".")


def save(ip, name, role, sensitive, notes, user, role_of_user, aliases="", software="", kind=None):
    """Set or clear the name (and aliases) for `ip`. Internal addresses (servers) need admin: `sensitive` changes detection
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
    kind = clean_type(kind) if kind is not None and internal else kind
    if not name and internal and (role or software or kind):   # a role alone is enough; the server is listed under its IP
        name = ip
    notes = " ".join((notes or "").split())[:300].replace("<", "‹").replace(">", "›")
    alias_list = clean_list(aliases, "Aliases", name) if name else []
    sw = clean_list(software, "Software") if name and internal else []
    key = "assets:db" if internal else "labels:db"
    db = get_setting(conn, key, {}) or {}
    old = db.get(ip)
    if not name:
        db.pop(ip, None)
        msg = f"Removed the name for {ip}."
    elif internal:
        db[ip] = {"name": name, "role": clean(role, ROLE_RE, "Role", 32), "sensitive": bool(sensitive), "notes": notes,
                  **({"aliases": alias_list} if alias_list else {}), **({"software": sw} if sw else {})}
        k = (old or {}).get("kind", "") if kind is None else kind   # None = caller did not offer the field: keep it
        if k:
            db[ip]["kind"] = k
        msg = f"Saved {name} ({ip})."
    else:
        db[ip] = {"name": name, "notes": notes, **({"aliases": alias_list} if alias_list else {})}   # no "source": a person's label, never replaced by a sync
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
        src, seen, fwa = f"vip:{site['id']}", set(), {}
        for v in rows:
            try:
                ip = str(ipaddress.ip_address(str(v.get("subnet", "")).strip()))
            except ValueError:
                continue
            name = vip_name(v.get("descr"))
            if not cfg.is_internal(ip):   # the firewall's own public addresses (map tooltips name them "WAN alias ...")
                fwa[ip] = {"iface": vip_name(v.get("%interface") or v.get("interface")) or "WAN", "descr": name, "site": site["id"]}
            if not name or cfg.is_internal(ip):
                continue
            cur = db.get(ip)
            if cur and not str(cur.get("source", "")).startswith("vip:"):
                continue   # a person named it; keep theirs
            seen.add(ip)
            db[ip] = {"name": name, "source": src, "notes": f"virtual IP ({v.get('%mode') or v.get('mode')}) on {v.get('%interface') or v.get('interface')}"
                      f" · {v.get('address') or ip} · {site['name']}"}
        fall = get_setting(conn, "fwaddr:db", {}) or {}
        if fall.get(site["id"]) != fwa:
            fall[site["id"]] = fwa
            put_setting(conn, "fwaddr:db", fall, user)
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
              notes: str = Form(""), aliases: str = Form(""), software: str = Form(""), kind: str | None = Form(None), clear: str = Form(""),
              back: str = Form(""), csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    _, r = user_of(req)
    js = req.headers.get("x-nm-fetch") == "1"   # the in-page ✎ editor wants JSON, plain forms get a redirect
    try:
        msg = save(ip, "" if clear else name, role, sensitive == "1", notes, u, r, aliases, software, kind)
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
            "notes": a.get("notes", ""), "aliases": a.get("aliases", []), "software": a.get("software", []), "kind": a.get("kind", ""), "can_edit": ROLES[role] >= ROLES["admin" if internal else "analyst"],
            "needs": "admin" if internal else "analyst",
            **({"role_options": role_options(), "kind_options": list(DEVICE_TYPES)} if internal else {})}


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
    extra = (f"""<label>Type{type_select(a.get('kind', ''))}</label>
<label>Role<input name=role value="{e(a.get('role', ''))}" maxlength=32 list=nm-roles placeholder="pick or type: web, mail, backup…"></label>
<p class="muted small rolehint" data-ip="{e(ip)}"></p>
<label class="check"><input type=checkbox name=sensitive value=1 {'checked' if a.get('sensitive') else ''}> Sensitive
<span class="muted small">— new outbound destinations from this server are raised one severity level</span></label>
<label>Software<input name=software value="{e(', '.join(a.get('software', [])))}" maxlength=400 placeholder="products it runs, comma-separated (e.g. nextcloud, proxmox ve) — matched against threat intel"></label>""" if internal else "")
    return f"""{'' if compact or not internal else role_datalist()}<form method=post action="/netmon/names" class="stackform{'' if compact else ' wide'} nameform">{csrf_field(req)}
<input type=hidden name=ip value="{e(ip)}"><input type=hidden name=back value="{e(back)}">
<label>Name<input name=name value="{e(a.get('name', ''))}" maxlength=64 placeholder="{'server name' if internal else 'e.g. Office VPN, Backup provider'}"></label>
<label>Aliases<input name=aliases value="{e(', '.join(a.get('aliases', [])))}" maxlength=400 placeholder="other names, comma-separated (e.g. ns1, cp.example.com)"></label>
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

    def aka(a):
        return f"<div class='sub'>aka {e(', '.join(a['aliases']))}</div>" if a.get("aliases") else ""

    def edit(ip, ok):
        return f"<details class='tech'><summary>Edit</summary>{name_form(req, ip, back + '#n-' + ip.replace(':', '-'), True)}</details>" if ok else ""
    srows = "".join(f"""<tr id="n-{e(ip.replace(':', '-'))}"><td><a href="/netmon/servers/{e(ip)}">{e(a['name'])}</a>{aka(a)}</td><td class="mono">{e(ip)}</td>
<td>{e(a.get('kind') or '—')}</td><td>{e(a.get('role') or '—')}</td><td>{'<span class="tag">sensitive</span>' if a.get('sensitive') else ''}</td><td class="small">{e(a.get('notes', ''))}</td>
<td>{edit(ip, admin)}</td></tr>""" for ip, a in assets)
    def src(a):
        s = a.get("source", "")
        return f"<span class='tag' title='imported; edit to make it yours'>{e(cfg.site(s[4:])['name'] if s.startswith('vip:') and cfg.site(s[4:]) else s)} virtual IP</span>" if s else "manual"
    lrows = "".join(f"""<tr id="n-{e(ip.replace(':', '-'))}"><td>{e(a['name'])}{aka(a)}</td><td class="mono"><a href="/netmon/connections?rip={e(ip)}">{e(ip)}</a></td>
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
{'<label>Type <span class="muted small">(internal only)</span>' + type_select() + '</label><label>Role <span class="muted small">(internal servers only)</span><input name=role maxlength=32 list=nm-roles></label><label class="check"><input type=checkbox name=sensitive value=1> Sensitive <span class="muted small">(internal servers only)</span></label>' if admin else ''}
<label>Notes<input name=notes maxlength=300></label><div class="row"><button class="primary">Save</button></div>
<p class="note">Internal addresses become named servers{'' if admin else ' (admins only)'}; any other address gets a label shown next to it in connection tables and findings.</p></form></section>""" if analyst else ""
    bulk = f"""<section class="card" id="roles"><div class="card-h"><h2>Assign type and role</h2><span class="muted small">several addresses at once</span></div>
<form method=post action="/netmon/settings/inventory/roles" class="stackform wide">{csrf_field(req)}
<label>Addresses<textarea name=ips rows=2 required class="mono" placeholder="internal IPs or CIDRs, comma- or space-separated (e.g. 10.0.0.21, 10.0.0.30/30)"></textarea></label>
<label>Type{type_select(name="kind", keep=True)}</label>
<label>Role<input name=role maxlength=32 list=nm-roles placeholder="pick or type; leave blank to clear"></label>
<label class="check"><input type=checkbox name=keep_role value=1> Keep each address's current role <span class="muted small">— set only the type</span></label>
<label class="check"><input type=checkbox name=only_named value=1> Only servers already named <span class="muted small">— otherwise unnamed addresses are added, listed under their IP</span></label>
<div class="row"><button class="primary">Assign</button></div>
<p class="note">Only type and role change; names, notes and other settings of named servers are kept. At most {BULK_MAX} addresses.</p></form></section>""" if admin else ""
    body = f"""{role_datalist()}{tabs(SETTINGS_TABS, back)}{f"<div class='banner'>{e(msg)}</div>" if msg else ''}
<section class="card"><div class="card-h"><h2>Internal servers</h2><span class="muted small">{len(assets)} named · stored in the netmon database</span></div>
<div class="wrap"><table class="tbl"><thead><tr><th>Name</th><th>IP</th><th>Type</th><th>Role</th><th></th><th>Notes</th><th></th></tr></thead>
<tbody>{srows or '<tr><td colspan=7 class="state empty">No servers named yet</td></tr>'}</tbody></table></div>
<p class="note">Names appear across the dashboard, in finding titles and notifications. Before AI analysis, server names are replaced by pseudonyms just like internal IPs.
A server's role tells AI analysis what is normal for it (inbound mail to a mail server, outbound connections from a crawler).</p></section>
{bulk}
<section class="card" id="labels"><div class="card-h"><h2>Public and external address labels</h2><span class="muted small">{len(labels)} labelled</span></div>{sync}
<div class="wrap"><table class="tbl"><thead><tr><th>Label</th><th>IP</th><th>Source</th><th>Notes</th><th></th></tr></thead>
<tbody>{lrows or '<tr><td colspan=5 class="state empty">No labels yet. Use ✎ next to any IP address, or the form below.</td></tr>'}</tbody></table></div>
<p class="note">Tip: every IP address in connection tables, findings, IDS alerts and search results has a ✎ button to name it in place.</p></section>{add}"""
    return page(req, "Settings · Inventory", body, "/netmon/settings", scoped=False)


@app.post("/netmon/settings/inventory/roles")
def post_roles(req: Request, ips: str = Form(...), role: str = Form(""), only_named: str = Form(""), kind: str = Form("__keep"),
               keep_role: str = Form(""), csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    _, r = user_of(req)
    try:
        msg = assign_role(ips, role, u, r, only_named == "1", kind, keep_role == "1")
    except PermissionError as ex:
        raise HTTPException(403, str(ex))
    except ValueError as ex:
        msg = f"Not saved: {ex}"
    return back_to("/netmon/settings/inventory#roles", msg)


@app.get("/netmon/api/role-suggest")
def api_role_suggest(req: Request, ip: str):
    need(req, "analyst")
    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise HTTPException(400, "not an IP address")
    if not cfg.is_internal(ip):
        raise HTTPException(400, "roles are for internal servers")
    try:
        return {"ok": True, **suggest_role(ip)}
    except Exception as ex:   # ClickHouse unavailable: the editor just shows no suggestion
        return {"ok": False, "error": type(ex).__name__}
