"""Internal devices → Segmentation: groups, expected communication, and the observed matrix. Monitoring only.
Viewing: viewer. Groups and rules: admin (they describe the network)."""
import json
import time
from urllib.parse import quote, urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import segments as S
from .baselines import DAY_NAMES, parse_schedule
from .ux import DEVICE_TABS, empty_state, monitored, tabs
from .web import ROLES, app, cfg, ch, check_csrf, conn, csrf_field, e, human_bytes, need, page, user_of

PERIODS = {"24h": 86400, "7d": 7 * 86400}
STATUS = {"expected": ("as expected", "ok"), "unexpected": ("unexpected traffic", "bad"), "undefined": ("no rule", "na")}


def _site(site):
    s = cfg.site(site) if site else None
    return s or cfg.sites[0]


def _back(site, msg):
    return RedirectResponse(f"/netmon/segments?site={quote(site)}&msg={quote(msg)}", 303)


@app.get("/netmon/segments", response_class=HTMLResponse)
def segments_page(req: Request, site: str = "", period: str = "24h", cell: str = "", msg: str = ""):
    u, r = user_of(req)
    admin = ROLES[r] >= ROLES["admin"]
    s = _site(site.split(",")[0])
    span = PERIODS.get(period, 86400)
    now = int(time.time())
    gs = S.groups(conn, s["id"])
    names = {g["id"]: g["name"] for g in gs}
    pols = S.policies(conn, s["id"])
    sitesel = ("<label>Firewall<select name=site>" + "".join(f"<option value='{e(x['id'])}' {'selected' if x['id'] == s['id'] else ''}>{e(x['name'])}</option>"
                                                           for x in cfg.sites) + "</select></label>") if len(cfg.sites) > 1 else ""
    top = (f"<form method=get class='row'>{sitesel}<label>Period<select name=period>"
           + "".join(f"<option {'selected' if k == period else ''}>{k}</option>" for k in PERIODS) + "</select></label><button>Show</button></form>")
    off = "" if monitored(s, "segmentation") else (
        "<div class='banner warn'>Segmentation checks are switched off for this firewall (Settings → Firewalls & sites → What to monitor): "
        "the matrix below still shows traffic, but no findings are raised.</div>")
    intro = ("<p class='muted small'>Monitoring only: netmon compares the internal traffic the firewall reports with what you expect. It never "
             "changes firewall rules. Traffic between devices on the same switch or VLAN does not pass the firewall and cannot be seen, so "
             "<b>“not seen” never means “blocked”</b>. “Blocked” is shown only when the firewall log recorded blocks.</p>")
    # groups and rules ---------------------------------------------------------------------------------------------
    grow = "".join(
        f"<tr><td><b>{e(g['name'])}</b>{' <span class=tag>sensitive</span>' if g['sensitivity'] == 'high' else ''}"
        f"{'<div class=muted small>' + e(g['note']) + '</div>' if g['note'] else ''}</td>"
        f"<td class='mono small'>{e(', '.join(json.loads(g['cidrs']))) or '<span class=warnline>no address ranges yet — add them</span>'}</td><td>"
        + (f"<details><summary class='sm'>Edit</summary><form method=post action='/netmon/segments/groups' class='stackform'>{csrf_field(req)}"
           f"<input type=hidden name=site value='{e(s['id'])}'><input type=hidden name=gid value={g['id']}>"
           f"<label>Name<input name=name value='{e(g['name'])}' maxlength=60></label>"
           f"<label>Address ranges<input name=cidrs value='{e(' '.join(json.loads(g['cidrs'])))}' class=mono></label>"
           f"<label>Sensitivity<select name=sensitivity><option {'selected' if g['sensitivity'] == 'normal' else ''}>normal</option>"
           f"<option {'selected' if g['sensitivity'] == 'high' else ''}>high</option></select></label><button>Save</button></form>"
           f"<form method=post action='/netmon/segments/groups/{g['id']}/delete' data-confirm='Delete group {e(g['name'])} and its rules?'>{csrf_field(req)}"
           f"<input type=hidden name=site value='{e(s['id'])}'><button class='sm'>Delete</button></form></details>" if admin else "")
        + "</td></tr>" for g in gs)
    opts = "<option value=0>any group</option>" + "".join(f"<option value={g['id']}>{e(g['name'])}</option>" for g in gs)
    days = "".join(f"<label class='chk'><input type=checkbox name=days value={i}> {d}</label>" for i, d in enumerate(DAY_NAMES))
    prow = "".join(f"<li>{e(S.describe_policy(p, names))}{' <span class=muted small>· ' + e(p['note']) + '</span>' if p['note'] else ''}"
                   + (f" <form method=post action='/netmon/segments/rules/{p['id']}/delete' class='inline'>{csrf_field(req)}"
                      f"<input type=hidden name=site value='{e(s['id'])}'><button class='sm'>Remove</button></form>" if admin else "") + "</li>" for p in pols)
    tmpl = "".join(f"<li><b>{e(t['label'])}</b> — {e(t['text'])}" + (
        f" <form method=post action='/netmon/segments/template' class='inline'>{csrf_field(req)}<input type=hidden name=site value='{e(s['id'])}'>"
        f"<input type=hidden name=key value={k}><button class='sm'>Use</button></form>" if admin else "") + "</li>" for k, t in S.TEMPLATES.items())
    manage = (f"""<details class="tech"><summary>Add a group</summary><form method=post action="/netmon/segments/groups" class="stackform">{csrf_field(req)}
<input type=hidden name=site value="{e(s['id'])}"><div class="row"><label>Name<input name=name required maxlength=60 placeholder="Guest Wi-Fi"></label>
<label>Address ranges<input name=cidrs required class="mono" placeholder="10.20.0.0/24 10.20.1.0/24"></label>
<label>Sensitivity<select name=sensitivity><option>normal</option><option>high</option></select></label></div><button>Add group</button></form></details>
<details class="tech"><summary>Add a rule</summary><form method=post action="/netmon/segments/rules" class="stackform">{csrf_field(req)}
<input type=hidden name=site value="{e(s['id'])}"><div class="row"><label>From<select name=src>{opts}</select></label><label>To<select name=dst>{opts}</select></label>
<label>Expect<select name=expect><option value=none>no communication</option><option value=allow>communication</option></select></label>
<label>Services<input name=services placeholder="any, or tcp/443,udp/53" class="mono"></label></div>
<fieldset><legend>Only during a schedule (optional)</legend><div class="chkgrid">{days}</div>
<div class="row"><label>From<input type=time name=start></label><label>To<input type=time name=end></label></div></fieldset>
<label>Note<input name=note maxlength=200></label><button>Add rule</button></form></details>
<details class="tech"><summary>Start from a template</summary><ul class="small">{tmpl}</ul>
<p class="muted small">Templates create the groups they need (without addresses: add yours) and their rules.</p></details>""" if admin else
              "<p class='muted small'>Admins define groups and rules.</p>")
    rules_card = (f"<section class='card'><div class='card-h'><h2>Groups and expected communication</h2></div>"
                  f"<div class='wrap'><table class='tbl'><tr><th>Group</th><th>Address ranges</th><th></th></tr>{grow or '<tr><td colspan=3 class=muted>No groups yet</td></tr>'}</table></div>"
                  f"<h3>Rules</h3><ul>{prow or '<li class=muted>No rules yet: every pair is “no rule”.</li>'}</ul>{manage}</section>")
    banner = f"<div class='banner'>{e(msg)}</div>" if msg else ""
    if not gs:
        body = (tabs(DEVICE_TABS, "/netmon/segments") + banner + f"<section class='card'>{top}</section>" + intro
                + empty_state("setup", " Define groups of addresses (for example Guest, IoT, Servers, Management) and what communication you "
                              "expect between them, or start from a template below.") + rules_card)
        return page(req, "Segmentation", body, "/netmon/servers", scoped=False, subtitle="Expected vs observed internal communication")
    try:
        m = S.matrix(conn, cfg, ch, s, now - span, now)
    except Exception as ex:
        body = (tabs(DEVICE_TABS, "/netmon/segments") + f"<section class='card'>{top}</section>"
                + empty_state("unavailable", f" Traffic records could not be read ({type(ex).__name__}).") + rules_card)
        return page(req, "Segmentation", body, "/netmon/servers", scoped=False)
    cols = gs + [m["other"]]
    head = "<tr><th scope=col>From ↓ / To →</th>" + "".join(f"<th scope=col>{e(g['name'])}</th>" for g in cols) + "</tr>"
    rows = ""
    for a in cols:
        tds = ""
        for b in cols:
            c = m["cells"].get((a["id"], b["id"]))
            st, pol = S.verdict(a if a["id"] != -1 else None, b if b["id"] != -1 else None, "*", m["policies"])
            exp = ("—" if a["id"] == -1 or b["id"] == -1 else
                   "expected" if st == "expected" else "none expected" if pol and pol["expect"] == "none" else
                   "limited" if pol else "no rule")
            if c and c["n"]:
                state = "bad" if c["unexpected"] else "ok"
                obs = f"{c['n']:,} records" + (f", <b>{c['unexpected']:,} unexpected</b>" if c["unexpected"] else "")
            else:
                state, obs = "na", "not seen"
            blk = f"<br><span class='small'>firewall blocked {c['blocked']:,}</span>" if c and c["blocked"] else ""
            ck = f"{a['id']}:{b['id']}"
            link = f"/netmon/segments?{urlencode({'site': s['id'], 'period': period, 'cell': ck})}#cell"
            tds += (f"<td class='{state}'><span class='small muted'>{e(exp)}</span><br>"
                    + (f"<a href='{e(link)}'>{obs}</a>" if c and (c["n"] or c["blocked"]) else obs) + blk + "</td>")
        rows += f"<tr><th scope=row>{e(a['name'])}</th>{tds}</tr>"
    detail = ""
    if cell and ":" in cell:
        try:
            ka, kb = (int(x) for x in cell.split(":"))
        except ValueError:
            raise HTTPException(400)
        c = m["cells"].get((ka, kb))
        if c:
            lis = "".join(
                f"<li><span class='s1'>{e(cfg.asset_label(x['client']))} → {e(cfg.asset_label(x['server']))} on {e(x['svc'])}</span>"
                f"<span class='s2'>{x['n']:,} records · {human_bytes(x['bytes'])} · last {e(time.strftime('%Y-%m-%d %H:%M', time.gmtime(x['last'])))}Z · "
                f"<b>{e(STATUS[x['status']][0])}</b></span><span class='acts'><a href='/netmon/connections?"
                f"{e(urlencode({'host': x['client'], 'rip': x['server'], 'range': 'custom', 'from': now - span, 'to': now}))}'>View records →</a></span></li>"
                for x in sorted(c["rows"], key=lambda x: (x["status"] != "unexpected", -x["n"])))
            detail = (f"<section class='card' id='cell'><div class='card-h'><h2>{e(c['src']['name'])} → {e(c['dst']['name'])}</h2>"
                      f"<span class='muted small'>top conversations · client inferred from ports</span></div><ul class='sentence-list'>{lis or '<li>none</li>'}</ul>"
                      f"{'<p class=small>The firewall log recorded ' + format(c['blocked'], ',') + ' blocked attempt(s) for this pair.</p>' if c['blocked'] else ''}</section>")
    unseen = [g["name"] for g in gs if g["id"] not in m["seen_src"] and json.loads(g["cidrs"])]
    notes = []
    if unseen:
        notes.append(f"No internal traffic from {', '.join(unseen)} was seen at all in this period: either those devices were quiet, or their "
                     "traffic stays on their own switch/VLAN where the firewall cannot see it.")
    if not m["fw_log"]:
        notes.append("The firewall log is not available, so blocked attempts cannot be shown.")
    if m["own"]:
        notes.append(f"Traffic of the firewall's own address ({', '.join(m['own'])}: proxies, NAT reflection) is not counted as device traffic.")
    if m["truncated"]:
        notes.append(f"Only the {S.MAX_ROWS:,} busiest conversations were analysed.")
    body = f"""{tabs(DEVICE_TABS, '/netmon/segments')}{banner}<section class="card">{top}</section>{off}{intro}
<section class="card"><div class="card-h"><h2>Communication matrix</h2><span class="muted small">{e(s['name'])} · last {e(period)}</span></div>
<div class="wrap"><table class="tbl matrix">{head}{rows}</table></div>
<p class="small">Each cell: what your rules expect (top) and what the firewall saw (bottom). Red = traffic your rules say is unexpected;
“not seen” = no records, which does not prove the path is blocked.</p>{''.join(f"<p class='muted small'>{e(n)}</p>" for n in notes)}</section>
{detail}{rules_card}"""
    return page(req, "Segmentation", body, "/netmon/servers", scoped=False, subtitle="Expected vs observed internal communication")


@app.post("/netmon/segments/groups")
async def seg_group(req: Request):
    u = need(req, "admin")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    s = _site(str(f.get("site", "")))
    try:
        S.save_group(conn, s["id"], str(f.get("name", "")), str(f.get("cidrs", "")), str(f.get("sensitivity", "normal")), u,
                     gid=int(f["gid"]) if str(f.get("gid", "")).isdigit() else None)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(s["id"], "Group saved.")


@app.post("/netmon/segments/groups/{gid}/delete")
async def seg_group_delete(req: Request, gid: int):
    u = need(req, "admin")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    s = _site(str(f.get("site", "")))
    S.delete_group(conn, s["id"], gid, u)
    return _back(s["id"], "Group deleted with its rules.")


@app.post("/netmon/segments/rules")
async def seg_rule(req: Request):
    u = need(req, "admin")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    s = _site(str(f.get("site", "")))
    try:
        sched = parse_schedule(f.getlist("days"), str(f.get("start", "")), str(f.get("end", "")))
        S.save_policy(conn, s["id"], int(f.get("src", 0) or 0), int(f.get("dst", 0) or 0), str(f.get("expect", "")), str(f.get("services", "")),
                      sched, u, note=str(f.get("note", "")))
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(s["id"], "Rule added.")


@app.post("/netmon/segments/rules/{pid}/delete")
async def seg_rule_delete(req: Request, pid: int):
    u = need(req, "admin")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    s = _site(str(f.get("site", "")))
    S.delete_policy(conn, s["id"], pid, u)
    return _back(s["id"], "Rule removed.")


@app.post("/netmon/segments/template")
async def seg_template(req: Request):
    u = need(req, "admin")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    s = _site(str(f.get("site", "")))
    try:
        n = S.apply_template(conn, s["id"], str(f.get("key", "")), u)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(s["id"], f"Template applied: {n} rule(s) added. Add the address ranges of new groups.")
