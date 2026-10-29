"""Wallboards: selectable, editable dashboards for NOC screens (kiosk mode, auto-refresh)."""
import json
import time

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .core import audit
from .dash import PRESETS
from .web import ASSET_V, ROLES, app, cfg, check_csrf, conn, csrf_token, e, need, page, user_of, SECURITY_HEADERS

# type -> (label, default w (of 12), default h (rows), description)
WIDGETS = {
    "kpi_in": ("Inbound bandwidth", 3, 1, "Current WAN inbound (counters) with window average"),
    "kpi_out": ("Outbound bandwidth", 3, 1, "Current WAN outbound (counters) with window average"),
    "kpi_volume": ("Transferred", 3, 1, "Downloaded / uploaded volume in the window"),
    "kpi_servers": ("Servers observed", 3, 1, "Internal servers receiving Internet traffic"),
    "kpi_alerts": ("Open security alerts", 3, 1, "By severity"),
    "kpi_health": ("Collection health", 3, 1, "Flow freshness, counters, logs, IDS"),
    "kpi_fw": ("Firewall blocks", 3, 1, "Blocked events (needs firewall logs)"),
    "kpi_ids": ("IDS alerts", 3, 1, "Suricata alerts (needs IDS)"),
    "clock": ("Clock & site", 3, 1, "Local time, time zone and site"),
    "map": ("World traffic map", 8, 3, "Arcs and shading by country"),
    "security": ("Security activity", 4, 3, "Prioritized open findings"),
    "capacity": ("WAN capacity in use", 4, 2, "Download/upload meters against contracted capacity, per firewall"),
    "bandwidth": ("WAN bandwidth chart", 12, 2, "Inbound/outbound over the window"),
    "top_servers": ("Top servers", 3, 2, "By transfer"),
    "top_orgs": ("Top organizations", 3, 2, "Remote networks (ASN)"),
    "top_countries": ("Top countries", 3, 2, "By volume"),
    "top_services": ("Top services", 3, 2, "Exposed (inventory) and used (port guess)"),
    "recent": ("Recent connections", 12, 2, "Latest observed conversations"),
    "fw_sources": ("Top blocked sources", 4, 2, "From firewall logs"),
    "ids_sigs": ("IDS signatures", 4, 2, "From Suricata alerts"),
}
TEMPLATES = {
    "NOC overview": {"range": "15m", "refresh": 30, "widgets": [
        {"type": t} for t in ("kpi_in", "kpi_out", "kpi_alerts", "kpi_health", "map", "security", "bandwidth",
                              "top_servers", "top_orgs", "top_countries", "top_services")]},
    "Security operations": {"range": "1h", "refresh": 60, "widgets": [
        {"type": t} for t in ("kpi_alerts", "kpi_fw", "kpi_ids", "clock", "security", "fw_sources", "ids_sigs", "map", "recent")]},
}

conn.executescript("""CREATE TABLE IF NOT EXISTS wallboards (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, layout TEXT NOT NULL, created_by TEXT, updated_by TEXT, updated_at REAL)""")
if not conn.execute("SELECT count(*) FROM wallboards").fetchone()[0]:
    for n, lay in TEMPLATES.items():
        conn.execute("INSERT INTO wallboards(name,layout,created_by,updated_at) VALUES (?,?,?,?)", (n, json.dumps(lay), "system", time.time()))
    conn.commit()


def clean_layout(raw):
    """Validate a layout from the editor: known widget types, bounded sizes, whitelisted range/site."""
    if not isinstance(raw, dict):
        raise HTTPException(400, "bad layout")
    sites = {s["id"] for s in cfg["sites"]} | {"all"}
    out = {"range": raw.get("range") if raw.get("range") in PRESETS else "15m",
           "site": raw.get("site") if raw.get("site") in sites else "all",
           "refresh": max(10, min(600, int(raw.get("refresh") or 30))), "widgets": []}
    for w in (raw.get("widgets") or [])[:40]:
        t = w.get("type") if isinstance(w, dict) else None
        if t not in WIDGETS:
            continue
        _, dw, dh, _ = WIDGETS[t]
        out["widgets"].append({"type": t, "w": max(2, min(12, int(w.get("w") or dw))), "h": max(1, min(4, int(w.get("h") or dh))),
                               "title": str(w.get("title") or "")[:60]})
    return out


def board(bid):
    b = conn.execute("SELECT * FROM wallboards WHERE id=?", (bid,)).fetchone()
    if not b:
        raise HTTPException(404)
    lay = json.loads(b["layout"])
    for w in lay["widgets"]:
        _, dw, dh, _ = WIDGETS.get(w["type"], ("", 3, 1, ""))
        w.setdefault("w", dw)
        w.setdefault("h", dh)
    return b, lay


@app.get("/netmon/wallboards", response_class=HTMLResponse)
def wallboards_list(req: Request):
    u, r = user_of(req)
    rows = conn.execute("SELECT * FROM wallboards ORDER BY name").fetchall()
    cards = ""
    for b in rows:
        lay = json.loads(b["layout"])
        types = ", ".join(WIDGETS[w["type"]][0] for w in lay["widgets"][:6] if w["type"] in WIDGETS)
        acts = (f"<a class='btn' href='/netmon/wallboards/{b['id']}/edit'>Edit</a> "
                f"<form method=post action='/netmon/wallboards/{b['id']}/copy' class=inline><input type=hidden name=csrf value='{csrf_token(req)}'><button>Duplicate</button></form> "
                + (f"<form method=post action='/netmon/wallboards/{b['id']}/delete' class='inline confirm'><input type=hidden name=csrf value='{csrf_token(req)}'><button>Delete</button></form>"
                   if r == "admin" or b["created_by"] == u else "")) if ROLES[r] >= 1 else ""
        cards += f"""<div class="card wbcard"><a class="wbopen" href="/netmon/wallboards/{b['id']}"><h2>{e(b['name'])}</h2>
<p class="muted small">{len(lay['widgets'])} tiles · {e(lay['range'])} · refresh {lay['refresh']} s · updated {e(time.strftime('%Y-%m-%d %H:%M', time.localtime(b['updated_at'] or 0)))} by {e(b['updated_by'] or b['created_by'])}</p>
<p class="small">{e(types)}{'…' if len(lay['widgets']) > 6 else ''}</p></a>
<div class="row"><a class="btn primary" href="/netmon/wallboards/{b['id']}">Open</a> <a class="btn" href="/netmon/wallboards/{b['id']}?kiosk=1">Kiosk mode</a> {acts}</div></div>"""
    new = (f"""<section class="card"><div class="card-h"><h2>New wallboard</h2></div>
<form method=post action="/netmon/wallboards" class="row"><input type=hidden name=csrf value="{csrf_token(req)}">
<input name=name placeholder="Wallboard name" required maxlength=60> <select name=template><option value="">Empty</option>
{''.join(f'<option>{e(t)}</option>' for t in TEMPLATES)}</select> <button class="primary">Create</button></form></section>""" if ROLES[r] >= 1 else "")
    body = f"""<section class="wbgrid">{cards or '<p class="state empty">No wallboards</p>'}</section>{new}
<p class="note">Kiosk mode hides navigation for wall displays; the session still needs a login (use a viewer account for screens).</p>"""
    return page(req, "Wallboards", body, "/netmon/wallboards", ("settings.js",), scoped=False)


@app.post("/netmon/wallboards")
async def wallboard_create(req: Request):
    u = need(req, "analyst")
    form = await req.form()
    check_csrf(req, form.get("csrf", ""))
    tpl = TEMPLATES.get(form.get("template", ""), {"range": "15m", "refresh": 30, "widgets": [{"type": "kpi_in"}, {"type": "kpi_out"}]})
    cur = conn.execute("INSERT INTO wallboards(name,layout,created_by,updated_by,updated_at) VALUES (?,?,?,?,?)",
                       (str(form.get("name", "Wallboard"))[:60], json.dumps(clean_layout(tpl)), u, u, time.time()))
    conn.commit()
    audit(conn, u, "wallboard_created", {"id": cur.lastrowid})
    return RedirectResponse(f"/netmon/wallboards/{cur.lastrowid}/edit", 303)


@app.post("/netmon/wallboards/{bid}/{action}")
async def wallboard_action(req: Request, bid: int, action: str):
    u = need(req, "analyst")
    form = await req.form()
    check_csrf(req, form.get("csrf", ""))
    b, lay = board(bid)
    if action == "copy":
        cur = conn.execute("INSERT INTO wallboards(name,layout,created_by,updated_by,updated_at) VALUES (?,?,?,?,?)",
                           (f"{b['name']} (copy)"[:60], json.dumps(lay), u, u, time.time()))
        conn.commit()
        audit(conn, u, "wallboard_copied", {"from": bid, "id": cur.lastrowid})
        return RedirectResponse(f"/netmon/wallboards/{cur.lastrowid}/edit", 303)
    if action == "delete":
        _, r = user_of(req)
        if r != "admin" and b["created_by"] != u:
            raise HTTPException(403)
        conn.execute("DELETE FROM wallboards WHERE id=?", (bid,))
        conn.commit()
        audit(conn, u, "wallboard_deleted", {"id": bid, "name": b["name"]})
        return RedirectResponse("/netmon/wallboards", 303)
    raise HTTPException(404)


@app.get("/netmon/api/wallboards/{bid}")
def wallboard_get(req: Request, bid: int):
    user_of(req)
    b, lay = board(bid)
    return {"ok": True, "id": bid, "name": b["name"], "layout": lay,
            "catalog": {k: {"label": v[0], "w": v[1], "h": v[2], "desc": v[3]} for k, v in WIDGETS.items()},
            "boards": [{"id": x["id"], "name": x["name"]} for x in conn.execute("SELECT id, name FROM wallboards ORDER BY name")],
            "sites": [{"id": s["id"], "name": s["name"]} for s in cfg["sites"]]}


@app.post("/netmon/api/wallboards/{bid}")
async def wallboard_save(req: Request, bid: int):
    u = need(req, "analyst")
    check_csrf(req, req.headers.get("x-csrf", ""))
    board(bid)
    body = await req.json()
    lay = clean_layout(body.get("layout"))
    name = str(body.get("name") or "Wallboard")[:60]
    conn.execute("UPDATE wallboards SET name=?, layout=?, updated_by=?, updated_at=? WHERE id=?", (name, json.dumps(lay), u, time.time(), bid))
    conn.commit()
    audit(conn, u, "wallboard_saved", {"id": bid, "tiles": len(lay["widgets"])})
    return JSONResponse({"ok": True})


SCRIPTS = ("d3.min.js", "topojson-client.min.js", "map.js", "wallboard.js")


@app.get("/netmon/wallboards/{bid}", response_class=HTMLResponse)
def wallboard_view(req: Request, bid: int, kiosk: str = ""):
    u, r = user_of(req)
    b, lay = board(bid)
    if kiosk:
        scr = "".join(f'<script src="/netmon/static/{s}?v={ASSET_V}"></script>' for s in ("common.js",) + SCRIPTS)
        return HTMLResponse(f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(b['name'])} · netmon</title><link rel="stylesheet" href="/netmon/static/app.css?v={ASSET_V}"><script src="/netmon/static/theme.js?v={ASSET_V}"></script></head><body class="kiosk">
<header class="kbar"><span class="brand"><span class="logo">◎</span> {e(b['name'])}</span><span id="fresh" class="pill">…</span><span id="wbclock" class="muted"></span><select class="themebtn" data-theme-toggle aria-label="Color theme" title="Color theme"><option value="auto">◐ System</option><option value="light">☀ Light</option><option value="dark">☾ Dark</option></select>
<a class="small" href="/netmon/wallboards/{bid}">exit kiosk</a></header>
<main class="wbmain"><div id="wb" class="wb" data-id="{bid}" data-kiosk="1"></div></main>{scr}</body></html>""", headers=SECURITY_HEADERS)
    edit = f"<a class='btn' href='/netmon/wallboards/{bid}/edit'>Edit</a>" if ROLES[r] >= 1 else ""
    body = f"""<div class="toolbar"><select id="wbsel" aria-label="Wallboard"></select>
<a class="btn" href="/netmon/wallboards/{bid}?kiosk=1">Kiosk mode</a> <button id="wbfull">Fullscreen</button> {edit}
<span class="muted small" id="wbinfo"></span></div><div id="wb" class="wb" data-id="{bid}"></div>"""
    return page(req, b["name"], body, "/netmon/wallboards", SCRIPTS, scoped=False)


@app.get("/netmon/wallboards/{bid}/edit", response_class=HTMLResponse)
def wallboard_edit(req: Request, bid: int):
    need(req, "analyst")
    b, _ = board(bid)
    body = f"""<div class="wbedit" id="wbedit" data-id="{bid}">
<section class="card"><div class="formgrid"><label>Name<input id="wbname" maxlength=60></label>
<label>Time range<select id="wbrange">{''.join(f'<option>{k}</option>' for k in PRESETS)}</select></label>
<label>Site<select id="wbsite"><option value="all">All sites</option></select></label>
<label>Refresh (seconds)<input id="wbrefresh" type=number min=10 max=600></label></div></section>
<section class="card"><div class="card-h"><h2>Tiles</h2><div class="row"><select id="wbadd"></select><button id="wbaddbtn">Add tile</button></div></div>
<p class="muted small">Width is in twelfths of the screen; height in rows. Order is left-to-right, top-to-bottom.</p>
<div id="wbtiles"></div></section>
<div class="row"><button class="primary" id="wbsave">Save</button> <a class="btn" href="/netmon/wallboards/{bid}">Cancel</a> <span id="wbmsg" class="muted"></span></div>
<section class="card"><div class="card-h"><h2>Preview</h2></div><div id="wb" class="wb preview" data-id="{bid}" data-preview="1"></div></section>
<input type="hidden" id="csrf" value="{e(csrf_token(req))}"></div>"""
    return page(req, f"Edit · {b['name']}", body, "/netmon/wallboards", SCRIPTS + ("wallboard-edit.js",), scoped=False)
