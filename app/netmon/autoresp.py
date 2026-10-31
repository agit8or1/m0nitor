"""Settings → Auto-response: mode and triggers, netmon's own firewall objects (create / switch on and off),
active automatic blocks and the decision log."""
import json
import time
from urllib.parse import quote

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import block as blk
from . import respond
from .core import audit, get_state, put_setting
from .detect import fmt_ts
from .web import app, cfg, check_csrf, conn, csrf_field, e, need, page, user_of

BASE = "/netmon/settings/response"
MODES = {"off": ("Off", "Nothing is evaluated. Existing automatic blocks still expire on time."),
         "dry_run": ("Dry run", "Triggers and guardrails run and every decision is logged below, but nothing is blocked."),
         "on": ("On", "Addresses that pass every guardrail are added to the auto-block alias for the TTL, then removed.")}
DECISION = {"blocked": ("critical", "■ blocked"), "would_block": ("warning", "◆ would block"), "skipped": ("muted", "○ skipped"),
            "error": ("serious", "✕ error")}


def back(msg, frag=""):
    return RedirectResponse(f"{BASE}?msg={quote(msg)}{frag}", 303)


def fw_card(req, site, admin):
    fw = blk.enforcer(site)
    st = respond.fw_state(conn, site["id"])
    head = f"<div class='card-h'><h2>Firewall objects on {e(site['name'])}</h2><span class='muted small'>{e(fw.vendor)}</span></div>"
    if not isinstance(fw, blk.OPNsense):
        return (f"<section class='card'>{head}<p>pfSense: netmon adds addresses to the alias <code>{e(fw.auto_alias)}</code> only. "
                "Create that Host(s) alias and a floating block rule that uses it yourself; netmon never creates pfSense rules.</p></section>")
    if not fw.enabled:
        return f"<section class='card'>{head}<p class='warnline'>No API key for this firewall (Settings → Firewalls &amp; sites).</p></section>"
    plan = fw.plan(st)
    live = {}
    err = ""
    for key, uuid in (st.get("rules") or {}).items():
        try:
            live[key] = fw.rule(uuid)
        except Exception as ex:
            err = str(ex)[:200]
    rows = ""
    for p in plan:
        if p["kind"] != "rule":
            badge = "<span class='sev s-good'>● exists</span>" if p["exists"] else "<span class='sev s-muted'>○ to create</span>"
            rows += (f"<tr><td>{e(p['kind'])}</td><td><code>{e(p['name'])}</code></td><td class='small'>{e(p.get('detail', ''))}</td>"
                     f"<td>{badge}</td><td></td></tr>")
            continue
        r = live.get(p["key"])
        if not p["exists"]:
            state, ctl = "<span class='sev s-muted'>○ to create</span>", ""
        elif r is None:
            state, ctl = "<span class='sev s-serious'>✕ missing or renamed on the firewall</span>", ""
        else:
            state = "<span class='sev s-good'>● enabled</span>" if r["enabled"] else "<span class='sev s-muted'>○ disabled</span>"
            ctl = (f"<form method=post action='{BASE}/rule/{e(site['id'])}/{e(p['key'])}' class='inline'>{csrf_field(req)}"
                   f"<input type=hidden name=enabled value='{0 if r['enabled'] else 1}'><button>{'Disable' if r['enabled'] else 'Enable'}</button></form>") if admin else ""
        rows += (f"<tr><td>rule</td><td>{e(p['name'])}</td><td class='small'>{e(p['detail'])}</td><td>{state}</td><td>{ctl}</td></tr>")
    missing = [p for p in plan if not p["exists"] or (p["kind"] == "rule" and live.get(p["key"]) is None)]
    setup = ""
    if missing and admin:
        setup = f"""<form method=post action="{BASE}/setup/{e(site['id'])}" class="stackform wide">{csrf_field(req)}
<p>This creates only the objects marked <i>to create</i> (and re-creates netmon rules that were deleted). It edits nothing else: your rules,
aliases and their order stay as they are. Floating quick rules are evaluated before every interface rule, so the four netmon rules
take effect ahead of your WAN rules; their aliases start empty and can hold external addresses only.</p>
<label class="check"><input type=checkbox name=confirm value=1 required> I reviewed the objects above</label>
<div class="row"><button class="primary">Create on {e(site['name'])}</button></div></form>"""
    when = f"Set up {fmt_ts(st['setup_at'])} by {st.get('setup_by')}" if st.get("setup_at") else "Not set up yet"
    return f"""<section class="card" id="fw-{e(site['id'])}">{head}
{f"<div class='banner bad'>Could not read rules: {e(err)}</div>" if err else ''}
<div class="wrap"><table class="tbl"><thead><tr><th>Kind</th><th>Name</th><th>Definition</th><th>State</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
<p class="note">{e(when)}. netmon changes a rule only if its UUID is recorded here and its description still starts with “{blk.OWN_PREFIX}”.
Disabling “manual blocks” rules stops enforcing approved manual blocks; disabling “auto-response” rules stops enforcing automatic ones
(addresses are still added and expire). To switch a rule off, use Disable here rather than deleting it on the firewall: with
“create missing objects” on, a deleted netmon rule is re-created.</p>{setup}</section>"""


@app.get(BASE, response_class=HTMLResponse)
def response_page(req: Request, msg: str = ""):
    from .admin import SETTINGS_TABS, tabs
    u, r = user_of(req)
    admin = r == "admin"
    s = respond.settings(conn)
    last, _ = get_state(conn, "responder", {})
    last = last or {}
    dis = "" if admin else "disabled"
    tr = s["triggers"]
    chk = lambda v: "checked" if v else ""  # noqa: E731
    modes = "".join(f"""<label class="check"><input type=radio name=mode value="{k}" {chk(s['mode'] == k)} {dis}> <b>{v[0]}</b>
<span class="muted small">— {e(v[1])}</span></label>""" for k, v in MODES.items())
    ready = {x["id"]: respond.ready(conn, x) for x in cfg.sites}
    dec = " · ".join(f"{v} {k.replace('_', ' ')}" for k, v in (last.get("decisions") or {}).items())
    status = (f"Last run {fmt_ts(last['ts'])}: {last.get('candidates', 0)} candidate(s){' · ' + dec if dec else ''}"
              f"{' · ' + str(last['expired']) + ' expired' if last.get('expired') else ''}" if last.get("ts") else "Not run yet (starts 90 s after the app).")
    errs = "".join(f"<li>{e(x)}</li>" for x in last.get("errors") or [])
    warn = ""
    if s["mode"] == "on" and not all(ok for ok, _ in ready.values()):
        warn = "<div class='banner warn'>Mode is On, but " + "; ".join(f"{e(cfg.site(k)['name'])}: {e(w)}" for k, (ok, w) in ready.items() if not ok) + ".</div>"
    form = f"""<form method=post action="{BASE}" class="stackform wide">{csrf_field(req)}
<h3>Mode</h3>{modes}
<h3>Triggers <span class="muted small">— scans are never a trigger</span></h3>
<fieldset {dis}><legend><label class="check"><input type=checkbox name=bf_enabled value=1 {chk(tr['bruteforce']['enabled'])}> Brute force against login services</label></legend>
<div class="row"><label>At least <input name=bf_min type=number min=5 value="{tr['bruteforce']['min_attempts']}" class="short"> connections</label>
<label>in <input name=bf_window type=number min=1 max=60 value="{tr['bruteforce']['window_minutes']}" class="short"> min</label>
<label>averaging ≤ <input name=bf_bytes type=number min=100 value="{tr['bruteforce']['max_avg_bytes']}" class="short"> bytes</label></div>
<label>Login ports<input name=bf_ports value="{e(' '.join(map(str, tr['bruteforce']['ports'])))}" class="mono"></label>
<p class="note">Counts connections that the firewall passed to a server (delivered on the LAN side), from one address, to these ports.
Short connections are failed logins; real sessions are larger. IMAP/POP/SMTP-relay ports are left out by default because mail clients reconnect often.</p></fieldset>
<fieldset {dis}><legend><label class="check"><input type=checkbox name=ids_enabled value=1 {chk(tr['ids']['enabled'])}> High-priority IDS signatures</label></legend>
<div class="row"><label>Suricata priority ≤ <input name=ids_priority type=number min=1 max=3 value="{tr['ids']['max_priority']}" class="short"></label>
<label class="check"><input type=checkbox name=ids_noscan value=1 {chk(tr['ids']['exclude_scan'])}> Ignore scan signatures</label></div>
<p class="note">Only when the connection was opened from outside (Suricata's flow initiator is an external address).
A server's own outbound traffic is never auto-blocked.</p></fieldset>
<fieldset {dis}><legend><label class="check"><input type=checkbox name=fl_enabled value=1 {chk(tr['flood']['enabled'])}> Single-source flood</label></legend>
<div class="row"><label>At least <input name=fl_min type=number min=100 value="{tr['flood']['min_flows']}" class="short"> new connections</label>
<label>in <input name=fl_window type=number min=1 max=30 value="{tr['flood']['window_minutes']}" class="short"> min</label>
<label>to at most <input name=fl_ports type=number min=1 max=100 value="{tr['flood']['max_ports']}" class="short"> ports</label></div>
<p class="note">Many connections into a few service ports from one address. Reply traffic (many ports) and scans are excluded. A distributed attack from
many addresses needs upstream (ISP) mitigation; per-address blocks do not stop it.</p></fieldset>
<h3>Limits</h3><fieldset {dis}><div class="row">
<label>Block for <input name=ttl_hours type=number step=any min=1 max=720 value="{s['ttl_hours']}" class="short"> hours</label>
<label>At most <input name=max_per_hour type=number min=1 max=500 value="{s['max_per_hour']}" class="short"> new blocks per hour</label>
<label>At most <input name=max_active type=number min=1 max=5000 value="{s['max_active']}" class="short"> active</label></div>
<label class="check"><input type=checkbox name=kill_states value=1 {chk(s['kill_states'])}> Drop the address's existing connections when blocking (exact address match)</label>
<label class="check"><input type=checkbox name=auto_setup value=1 {chk(s.get('auto_setup', True))}> Create netmon's own firewall objects when they are missing
<span class="muted small">— checked every 10 min while On and before each block; a rule you <i>disable</i> stays disabled, a deleted one is re-created</span></label>
<div class="row"><label>Never block an address with substantial connections (≥ 50 KB) to at least <input name=established_services type=number min=1 max=50 value="{s['established_services']}" class="short"> of our services in the last {s['established_days']} days</label></div>
<label>Allowlist <span class="muted small">— one IP or CIDR per line; # comments allowed</span>
<textarea name=allowlist rows=4 class="mono">{e(chr(10).join(s['allowlist']))}</textarea></label></fieldset>
<p class="note">Always applied as well: the manual-block guardrails (no private, own, protected or broader-than-/{cfg['opnsense']['min_prefix_v4']} ranges),
addresses you named in Inventory, addresses a person un-blocked in the last 7 days, and addresses our servers use as a service.</p>
{'<div class="row"><button class="primary">Save</button></div>' if admin else '<p class="muted small">Only admins can change these settings.</p>'}</form>"""
    active = conn.execute("SELECT * FROM blocks WHERE auto=1 AND status='applied' ORDER BY applied_at DESC LIMIT 200").fetchall()
    now = time.time()
    rm = lambda b: f'<form method=post action="/netmon/block/{b["id"]}/remove" class="inline">{csrf_field(req)}<button>Remove now</button></form>' if admin else ""  # noqa: E731
    arows = "".join(f"""<tr><td><a href="/netmon/block/{b['id']}">#{b['id']}</a></td><td><a class="mono" href="/netmon/connections?rip={e(b['address'])}">{e(b['address'])}</a></td>
<td>{e(respond.TRIGGER_LABEL.get(b['trigger'], b['trigger'] or ''))}</td><td class="small">{e(b['reason'])}</td><td class="num">{e(fmt_ts(b['applied_at']))}</td>
<td class="num" title="{e(fmt_ts(b['expires_at']))}">in {max(0, (b['expires_at'] - now)) / 3600:.1f} h</td>
<td>{rm(b)}</td></tr>""" for b in active)
    logs = conn.execute("SELECT * FROM response_log ORDER BY id DESC LIMIT 150").fetchall()
    lrows = []
    for x in logs:
        cls, txt = DECISION.get(x["decision"], ("muted", x["decision"]))
        ev = json.loads(x["evidence"] or "{}")
        name = cfg.label(x["address"])
        name = f"<div class='sub'>{e(name)}</div>" if name else ""
        link = f"<a href='/netmon/block/{x['block_id']}'>block #{x['block_id']}</a>" if x["block_id"] else ""
        lrows.append(f"<tr><td class='num'>{e(fmt_ts(x['ts']))}</td><td><a class='mono' href='/netmon/connections?rip={e(x['address'])}'>{e(x['address'])}</a>{name}</td>"
                  f"<td>{e(respond.TRIGGER_LABEL.get(x['trigger'], x['trigger']))}</td><td><span class='sev s-{cls}'>{txt}</span></td>"
                  f"<td class='small'>{e(ev.get('title', ''))}<div class='sub'>{e(x['reason'])}</div></td>"
                  f"<td>{link}<details class='tech'><summary>evidence</summary><pre>{e(json.dumps(ev.get('evidence'), indent=1, default=str))}</pre></details></td></tr>")
    sites = "".join(fw_card(req, x, admin) for x in cfg.sites)
    body = f"""{tabs(SETTINGS_TABS, BASE)}{f"<div class='banner'>{e(msg)}</div>" if msg else ''}{warn}
<section class="cards fit">
<div class="kpi"><div class="k">Mode</div><div class="v {'ok' if s['mode'] == 'on' else 'na' if s['mode'] == 'off' else ''}">{MODES[s['mode']][0]}</div><div class="s">{e(MODES[s['mode']][1])}</div></div>
<div class="kpi"><div class="k">Active auto-blocks</div><div class="v">{len(active)}</div><div class="s">expire after {s['ttl_hours']:g} h</div></div>
<div class="kpi"><div class="k">Last 24 h</div><div class="v">{conn.execute("SELECT count(*) FROM blocks WHERE auto=1 AND applied_at > ?", (now - 86400,)).fetchone()[0]}</div>
<div class="s">blocked · {conn.execute("SELECT count(*) FROM response_log WHERE decision='would_block' AND ts > ?", (now - 86400,)).fetchone()[0]} would block (dry run) · {conn.execute("SELECT count(*) FROM response_log WHERE decision='skipped' AND ts > ?", (now - 86400,)).fetchone()[0]} skipped</div></div>
<div class="kpi"><div class="k">Engine</div><div class="v {'ok' if last.get('ts') and now - last['ts'] < 300 else 'na'}">{'● Running' if last.get('ts') and now - last['ts'] < 300 else '○ Waiting'}</div><div class="s">{e(status)}</div></div>
</section>{f"<div class='banner bad'><ul>{errs}</ul></div>" if errs else ''}
{sites}
<section class="card" id="active"><div class="card-h"><h2>Active automatic blocks</h2><a class="small" href="/netmon/blocks">All block requests →</a></div>
<div class="wrap"><table class="tbl"><thead><tr><th>#</th><th>Address</th><th>Trigger</th><th>Evidence</th><th class="num">Blocked</th><th class="num">Expires</th><th></th></tr></thead>
<tbody>{arows or '<tr><td colspan=7 class="state empty">No active automatic blocks</td></tr>'}</tbody></table></div></section>
<section class="card"><div class="card-h"><h2>Settings</h2><span class="muted small">stored in the netmon database</span></div>{form}</section>
<section class="card" id="log"><div class="card-h"><h2>Decisions</h2><span class="muted small">every candidate, with the guardrail that stopped it · one entry per address and trigger per hour</span></div>
{f'<form method=post action="{BASE}/evaluate" class="row">{csrf_field(req)}<button>Evaluate now (dry run)</button><span class="muted small">runs the triggers once without blocking, whatever the mode</span></form>' if admin else ''}
<div class="wrap"><table class="tbl"><thead><tr><th class="num">Time</th><th>Address</th><th>Trigger</th><th>Decision</th><th>Why</th><th></th></tr></thead>
<tbody>{''.join(lrows[:25]) or '<tr><td colspan=6 class="state empty">No candidates yet</td></tr>'}</tbody></table></div>
{f'<details class="more"><summary>Show {len(lrows) - 25} older decisions</summary><div class="wrap"><table class="tbl"><tbody>{"".join(lrows[25:])}</tbody></table></div></details>' if len(lrows) > 25 else ''}</section>"""
    return page(req, "Settings · Auto-response", body, "/netmon/settings", scoped=False)


@app.post(BASE)
async def response_save(req: Request):
    u = need(req, "admin")
    form = await req.form()
    check_csrf(req, form.get("csrf", ""))
    old = respond.settings(conn)["mode"]
    try:
        new = respond.save_settings(conn, {k: form.get(k) for k in form.keys()}, u)
    except ValueError as ex:
        return back(f"Not saved: {ex}")
    note = f" Mode changed from {MODES[old][0]} to {MODES[new['mode']][0]}." if old != new["mode"] else ""
    return back("Saved." + note)


@app.post(BASE + "/setup/{sid}")
async def response_setup(req: Request, sid: str):
    u = need(req, "admin")
    form = await req.form()
    check_csrf(req, form.get("csrf", ""))
    site = cfg.site(sid)
    if not site or form.get("confirm") != "1":
        raise HTTPException(400, "unknown firewall or not confirmed")
    fw = blk.enforcer(site)
    if not isinstance(fw, blk.OPNsense):
        raise HTTPException(400, "setup is OPNsense-only")
    st = respond.fw_state(conn, sid)
    try:
        new, done = fw.setup(st)
    except Exception as ex:
        if getattr(ex, "state", None):
            put_setting(conn, f"response:fw:{sid}", {**ex.state, "setup_at": time.time(), "setup_by": u}, u)
        audit(conn, u, "response_setup_failed", {"site": sid, "error": str(ex)[:300], "done": getattr(ex, "done", [])})
        made = "; ".join(getattr(ex, "done", []) or [])
        return back(f"Setup stopped: {str(ex)[:300]}" + (f" (already created and recorded: {made})" if made else ""), f"#fw-{sid}")
    new.update(setup_at=time.time(), setup_by=u)
    put_setting(conn, f"response:fw:{sid}", new, u)
    audit(conn, u, "response_setup", {"site": sid, "done": done, "objects": new})
    return back(("Created: " + "; ".join(done)) if done else "Everything already existed.", f"#fw-{sid}")


@app.post(BASE + "/rule/{sid}/{key}")
async def response_rule(req: Request, sid: str, key: str):
    u = need(req, "admin")
    form = await req.form()
    check_csrf(req, form.get("csrf", ""))
    site = cfg.site(sid)
    if not site or key not in {k for k, *_ in blk.RULE_SPECS}:
        raise HTTPException(404)
    on = form.get("enabled") == "1"
    try:
        res = blk.enforcer(site).toggle(respond.fw_state(conn, sid), key, on)
    except Exception as ex:
        return back(f"Not changed: {str(ex)[:300]}", f"#fw-{sid}")
    audit(conn, u, "response_rule_toggled", {"site": sid, "rule": key, "enabled": on})
    return back(f"Rule {key} {res.lower()} and applied on {site['name']}.", f"#fw-{sid}")


@app.post(BASE + "/evaluate")
async def response_evaluate(req: Request):
    from .detect import Detector
    from .web import ch, notifier
    u = need(req, "admin")
    form = await req.form()
    check_csrf(req, form.get("csrf", ""))
    r = respond.Responder(cfg, conn, Detector(cfg, ch, conn, notifier), notifier)
    res = r.run_once(force_dry=True)
    audit(conn, u, "response_evaluated", {k: v for k, v in res.items() if k != "ts"})
    dec = ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in res["decisions"].items()) or "no new decisions"
    return back(f"Evaluated: {res['candidates']} candidate(s) — {dec}." + (f" Errors: {'; '.join(res['errors'])[:300]}" if res["errors"] else ""), "#log")
