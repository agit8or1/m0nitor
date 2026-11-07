"""Settings → Status → WAN / VPN quality: current state of each probe, degraded periods with facts and suspected
causes, and (admin) probe configuration. Viewing: viewer."""
import time
from urllib.parse import quote

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import quality as Q
from .admin import SETTINGS_TABS, tabs
from .ux import empty_state, fmt_local, monitored
from .web import ROLES, app, cfg, ch, check_csrf, conn, csrf_field, e, need, page, user_of

PERIODS = {"24h": 86400, "7d": 7 * 86400}
STATE_CLS = {"normal": "s-good", "learning": "s-muted", "degraded": "s-warning", "down": "s-critical", "no data": "s-warning", "paused": "s-muted"}


def _site(site):
    s = cfg.site(site) if site else None
    return s or cfg.sites[0]


def _back(site, msg):
    return RedirectResponse(f"/netmon/quality?site={quote(site)}&msg={quote(msg)}", 303)


def _dur(a, b):
    m = max(1, round((b - a) / 60))
    return f"{m} min" if m < 120 else f"{m / 60:.1f} h"


@app.get("/netmon/quality", response_class=HTMLResponse)
def quality_page(req: Request, site: str = "", period: str = "24h", msg: str = ""):
    u, r = user_of(req)
    admin = ROLES[r] >= ROLES["admin"]
    s = _site(site.split(",")[0])
    span = PERIODS.get(period, 86400)
    now = time.time()
    t0 = now - span
    ps = Q.probes(conn, s["id"])
    banner = f"<div class='banner'>{e(msg)}</div>" if msg else ""
    sitesel = ("<label>Firewall<select name=site>" + "".join(f"<option value='{e(x['id'])}' {'selected' if x['id'] == s['id'] else ''}>{e(x['name'])}</option>"
                                                           for x in cfg.sites) + "</select></label>") if len(cfg.sites) > 1 else ""
    top = (f"<form method=get class='row'>{sitesel}<label>Period<select name=period>"
           + "".join(f"<option {'selected' if k == period else ''}>{k}</option>" for k in PERIODS) + "</select></label><button>Show</button></form>")
    intro = ("<p class='muted small'>Measured from the <b>netmon server</b> (the vantage point), through this firewall. Each round is small: a few "
             "pings, one DNS query or one HTTPS request. netmon never runs bandwidth tests. A degraded period needs two bad rounds in a row. "
             "Facts and suspected causes are kept apart, and the provider is only suspected when a probe to its first hop supports it.</p>")
    off = "" if monitored(s, "probes") else ("<div class='banner warn'>Quality probes are switched off for this firewall (Firewalls & sites → "
                                             "What to monitor): nothing is measured.</div>")
    manage = _manage(req, s, ps) if admin else "<p class='muted small'>Admins add and change probes.</p>"
    if not ps:
        body = (tabs(SETTINGS_TABS, "/netmon/quality") + banner + off + intro
                + empty_state("setup", " No probes yet. Probes are opt-in: nothing is sent until an admin adds them. The recommended set "
                              "below measures the firewall, two internet hosts, DNS and HTTPS.") + manage)
        return page(req, "WAN / VPN quality", body, "/netmon/settings", scoped=False, subtitle="Latency, loss, DNS and HTTPS from the netmon server")
    # current state ------------------------------------------------------------------------------------------------
    rows = []
    for p in ps:
        st = Q.status(conn, p, now)
        pts, _ = Q.series(conn, p["id"], t0, now)
        base = st.get("base") or {}
        usual = f" · usually {base['rtt_ms']:.1f} ms" if base and not base.get("learning") else ""
        rows.append(f"<tr><td><b>{e(p['name'])}</b><div class='muted small'>{e(Q.KINDS[p['kind']])} to <span class=mono>{e(p['target'])}</span>"
                    f"{' (' + e(p['query']) + ')' if p['query'] else ''} · {e(Q.ROLES[p['role']])} · every {p['interval_s']} s</div></td>"
                    f"<td><b class='{STATE_CLS[st['state']]}'>{e(st['state'])}</b>"
                    f"<div class='small'>{e(st.get('values') or '') if st['state'] != 'no data' else ''}{usual}</div>"
                    f"{'<div class=small>' + e(st['text']) + '</div>' if st['state'] not in ('normal',) else ''}</td>"
                    f"<td>{Q.sparkline(p['name'], pts, t0, now) or '<span class=muted>no results in this period</span>'}</td></tr>")
    cur = (f"<section class='card'><div class='card-h'><h2>Now</h2></div><div class='wrap'><table class='tbl'><tr><th scope=col>Probe</th>"
           f"<th scope=col>State</th><th scope=col>Latency over the period (marks: loss or no answer)</th></tr>{''.join(rows)}</table></div></section>")
    # degraded periods -----------------------------------------------------------------------------------------------
    eps = Q.episode_report(conn, cfg, ch, s, t0, now, now)
    if eps:
        lis = "".join(
            f"<li class='qep'><div class='s1'><b>{e(fmt_local(x['start'], s))}</b> – {e(fmt_local(x['end'], s, with_tz=False)[11:])} "
            f"({e(_dur(x['start'], x['end']))}{', ongoing' if x['ongoing'] else ''}): <b>{e(x['probe_name'])}</b> {e(x['summary'])}</div>"
            f"<div class='small'><b>Facts</b><ul>{''.join(f'<li>{e(f)}</li>' for f in x['facts'])}</ul>"
            + (f"<p><b>Suspected cause:</b> {e(x['suspect'])} <span class='muted'>(because {e(x['why'])})</span></p>" if x["suspect"]
               else f"<p class='muted'>No suspected cause: {e(x['why'])}.</p>")
            + "</div></li>" for x in eps)
        epc = f"<section class='card'><div class='card-h'><h2>Degraded periods ({period})</h2></div><ul class='qeps'>{lis}</ul></section>"
    else:
        epc = (f"<section class='card'><div class='card-h'><h2>Degraded periods ({period})</h2></div>"
               "<p>None: no probe had two bad rounds in a row in this period.</p></section>")
    body = tabs(SETTINGS_TABS, "/netmon/quality") + banner + off + f"<section class='card'>{top}</section>" + intro + cur + epc + manage
    return page(req, "WAN / VPN quality", body, "/netmon/settings", scoped=False, subtitle="Latency, loss, DNS and HTTPS from the netmon server")


def _manage(req, s, ps):
    rec = Q.recommended(s)
    have = {(p["kind"], p["target"]) for p in ps}
    rec_new = [x for x in rec if (x["kind"], x["target"]) not in have]
    rec_html = ""
    if rec_new:
        rec_html = (f"<details class='tech' {'open' if not ps else ''}><summary>Recommended probes</summary><p class='small'>Adds these, every 60 s:</p><ul class='small'>"
                    + "".join(f"<li>{e(x['name'])}: {e(Q.KINDS[x['kind']])} to <span class=mono>{e(x['target'])}</span>"
                              f"{' (' + e(x['query']) + ')' if x.get('query') else ''}</li>" for x in rec_new)
                    + f"</ul><form method=post action='/netmon/quality/recommended'>{csrf_field(req)}<input type=hidden name=site value='{e(s['id'])}'>"
                    "<button>Add the recommended probes</button></form><p class='muted small'>To tell a provider problem from others, also add a "
                    "ping to the provider's first hop (the first public address in a traceroute from the firewall) with the role "
                    "“provider's first hop”.</p></details>")
    rows = "".join(
        f"<tr><td>{e(p['name'])}</td><td class='small'>{e(Q.KINDS[p['kind']])} · <span class=mono>{e(p['target'])}</span> · {p['interval_s']} s · "
        f"{p['count']}×, {p['timeout_s']:g} s timeout</td><td>"
        f"<form method=post action='/netmon/quality/{p['id']}/toggle' class='inline'>{csrf_field(req)}<button class='sm'>{'Pause' if p['enabled'] else 'Resume'}</button></form>"
        f"<form method=post action='/netmon/quality/{p['id']}/delete' class='inline' data-confirm='Delete probe {e(p['name'])} and its results?'>{csrf_field(req)}"
        "<button class='sm'>Delete</button></form></td></tr>" for p in ps)
    kinds = "".join(f"<option value={k}>{e(v)}</option>" for k, v in Q.KINDS.items())
    roles = "".join(f"<option value={k} {'selected' if k == 'internet' else ''}>{e(v)}</option>" for k, v in Q.ROLES.items())
    return (f"<section class='card'><div class='card-h'><h2>Probes for {e(s['name'])}</h2></div>"
            + (f"<div class='wrap'><table class='tbl'><tr><th>Name</th><th>What</th><th></th></tr>{rows}</table></div>" if ps else "")
            + rec_html
            + f"""<details class="tech"><summary>Add a probe</summary><form method=post action="/netmon/quality/add" class="stackform">{csrf_field(req)}
<input type=hidden name=site value="{e(s['id'])}"><label>Type<select name=kind>{kinds}</select></label>
<label>Target<input name=target required class=mono placeholder="IP or host name · host:port · resolver IP · https://…"></label>
<label>Name to look up (DNS only)<input name=query placeholder="example.com"></label>
<label>Name<input name=name maxlength=60></label><label>What it measures<select name=role>{roles}</select></label>
<label>Every (seconds)<input name=interval_s type=number min={Q.INTERVAL[0]} max={Q.INTERVAL[1]} value=60></label>
<label>Packets / queries per round<input name=count type=number min={Q.COUNT[0]} max={Q.COUNT[1]} value=5></label>
<label>Timeout (seconds)<input name=timeout_s type=number min={Q.TIMEOUT[0]} max={Q.TIMEOUT[1]} step=0.5 value=2></label>
<button>Add probe</button></form><p class="muted small">At most {Q.MAX_PROBES} probes. Results are kept {Q.RETENTION // 86400} days.</p></details></section>""")


async def _form(req):
    u = need(req, "admin")
    f = await req.form()
    check_csrf(req, str(f.get("csrf", "")))
    return u, f


@app.post("/netmon/quality/add")
async def quality_add(req: Request):
    u, f = await _form(req)
    s = _site(str(f.get("site", "")))
    try:
        Q.add(conn, s["id"], str(f.get("kind", "")), str(f.get("target", "")), str(f.get("name", "")), str(f.get("role", "internet")), u,
              query=str(f.get("query", "")), interval_s=f.get("interval_s", 60), count=f.get("count", 5), timeout_s=f.get("timeout_s", 2))
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return _back(s["id"], "Probe added; the first results appear within a minute.")


@app.post("/netmon/quality/recommended")
async def quality_recommended(req: Request):
    u, f = await _form(req)
    s = _site(str(f.get("site", "")))
    have = {(p["kind"], p["target"]) for p in Q.probes(conn, s["id"])}
    n = 0
    for x in Q.recommended(s):
        if (x["kind"], x["target"]) in have:
            continue
        try:
            Q.add(conn, s["id"], x["kind"], x["target"], x["name"], x["role"], u, query=x.get("query", ""), count=x.get("count", 5),
                  timeout_s=5 if x["kind"] == "https" else 2)
            n += 1
        except ValueError as ex:
            raise HTTPException(400, str(ex))
    return _back(s["id"], f"{n} probe{'s' if n != 1 else ''} added; the first results appear within a minute.")


def _probe(pid):
    r = conn.execute("SELECT * FROM probes WHERE id=? AND site_ok(site)", (pid,)).fetchone()
    if not r:
        raise HTTPException(404)
    return r


@app.post("/netmon/quality/{pid}/toggle")
async def quality_toggle(req: Request, pid: int):
    u, _ = await _form(req)
    p = _probe(pid)
    Q.set_enabled(conn, pid, not p["enabled"], u)
    return _back(p["site"], "Probe resumed." if not p["enabled"] else "Probe paused.")


@app.post("/netmon/quality/{pid}/delete")
async def quality_delete(req: Request, pid: int):
    u, _ = await _form(req)
    p = _probe(pid)
    Q.delete(conn, pid, u)
    return _back(p["site"], "Probe deleted.")
