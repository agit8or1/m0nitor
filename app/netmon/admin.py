"""Settings (notifications, alert rules, maintenance, integrations), account/2FA, firewall & IDS pages."""
import ipaddress
import json
import re
import time
from urllib.parse import quote

import httpx
from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import auth
from .core import apply_overrides, audit, get_setting, get_state, put_setting
from .detect import fmt_ts
from .notify import TYPES
from .views import guard, scope_of
from .web import (ROLES, app, cfg, check_csrf, conn, csrf_field, current, dash, e, need, notifier, page, user_of)

# (name, href, group, admin-only): grouped in this order; admin-only entries are hidden from other roles
SETTINGS_TABS = [("Health", "/netmon/settings", "Status", False), ("Coverage", "/netmon/coverage", "Status", False),
                 ("Firewalls & sites", "/netmon/settings/sites", "Data", False),
                 ("Devices", "/netmon/settings/devices", "Data", False),
                 ("Data sources", "/netmon/settings/integrations", "Data", False),
                 ("Inventory", "/netmon/settings/inventory", "Data", False),
                 ("Alert rules", "/netmon/settings/rules", "Detection & response", False),
                 ("Notifications", "/netmon/settings/notifications", "Detection & response", False),
                 ("Auto-response", "/netmon/settings/response", "Detection & response", False),
                 ("Maintenance", "/netmon/settings/maintenance", "Detection & response", False),
                 ("My account", "/netmon/account", "Access", False), ("Users & 2FA", "/netmon/users", "Access", True),
                 ("Audit log", "/netmon/audit", "Access", True)]
SECURITY_TABS = [("Findings", "/netmon/security"), ("Firewall events", "/netmon/firewall"), ("IDS alerts", "/netmon/ids"),
                 ("Threat intel", "/netmon/threat-intel"), ("Block requests", "/netmon/blocks"), ("Suppressions", "/netmon/exceptions")]


# ---- OPNsense setup tips (menu paths verified on 26.7.7 where marked) ----------------------------------
TIPS = {
    "netflow": ("NetFlow (traffic, map, bandwidth)", """<ol>
<li>Reporting → NetFlow → Capture: <i>Listening interfaces</i> <code>WAN</code> + your LAN (or LAN bridge) interface; <i>WAN interfaces</i> (egress only) <code>WAN</code>; version <code>v9</code>.</li>
<li><i>Destinations</i>: add <code>{MON}:2055</code> (keep any existing destinations).</li>
<li><i>Active timeout</i> <code>120</code> (instead of 1800) so long connections are reported every 2 minutes. Apply.</li></ol>
<p class="sub">Capturing the LAN bridge gives the real internal address of inbound traffic; WAN egress-only avoids double counting. NetFlow only describes traffic pf passed.</p>"""),
    "snmp": ("SNMP WAN counters (near-real-time bandwidth)", """<ol>
<li>System → Firmware → Plugins: <code>os-net-snmp</code>.</li>
<li>Services → Net-SNMP: Enabled ✓, listen on the LAN address only, a read-only community (no write access).</li>
<li>On the monitor: <code>sudo install -o 10001 -g 10001 -m 600 /dev/stdin /opt/netmon/secrets/snmp_community</code>, paste the community, Ctrl-D.</li></ol>
<p class="sub">Port speed is not capacity: set WAN capacity under Settings → Sites to show utilization.</p>"""),
    "syslog": ("Firewall logs (blocked/allowed decisions)", """<ol>
<li>System → Settings → Logging → <i>Remote</i> → +: Enabled ✓ · Transport <code>TCP(4)</code> · Applications <code>filterlog</code>, <code>suricata</code>,
<code>dpinger</code>, <code>wireguard</code>, <code>openvpn</code>, <code>audit</code>, <code>configd.py</code> · Levels: all but debug · Hostname <code>{MON}</code> · Port <code>5514</code> · <i>rfc5424</i> ✓.</li>
<li>OPNsense logs default-deny blocks by default. To see <b>allowed</b> traffic for a rule: Firewall → Rules → edit the rule → <i>Log packets</i> ✓ (only on rules you need — every logged packet is a line).</li>
<li>Within a minute, Settings → Integrations shows “Connected” and Security → Firewall events fills in.</li></ol>
<p class="sub">Only logged rules appear: an absent event is not proof that nothing happened.</p>"""),
    "ids": ("Suricata IDS (alert-only)", """<ol>
<li>Services → Intrusion Detection → Administration → Settings: Enabled ✓ · <b>IPS mode off</b> (alerts only) · Interfaces <code>WAN</code> (optionally the LAN interface).</li>
<li>Same page: <i>Enable syslog alerts</i> ✓ and <i>Enable eve syslog output</i> ✓ (both verified on 26.7.7). Apply.</li>
<li>Download tab: enable rulesets (e.g. <code>ET open/emerging-*</code>) → Download &amp; Update Rules. Schedule tab: daily update.</li>
<li>Make sure <code>suricata</code> is selected in the remote syslog destination (Firewall logs tip).</li></ol>
<p class="sub">Start in alert-only mode and review false positives before considering IPS drops — that is a separate, approved change.</p>"""),
    "blocking": ("Blocking from netmon (approval-gated)", """<ol>
<li>System → Configuration → Backups → Download (backup first).</li>
<li>Firewall → Aliases → +: name <code>netmon_block</code>, type <b>Host(s)</b>, empty content. Apply.</li>
<li>Firewall → Rules → Floating, at the top: <b>Block</b>, Quick ✓, interface <code>WAN</code>, direction in, source <code>netmon_block</code>, Log ✓; and <b>Block</b>,
Quick ✓, your internal interfaces (LAN, VPN), direction in, destination <code>netmon_block</code>, Log ✓. Apply (an empty alias matches nothing).</li>
<li>System → Access → Users → + <code>netmon-block</code> (no shell, not admin) with only the privilege <i>Diagnostics: PF Table IP addresses</i> → API keys → + (downloads <code>apikey.txt</code>).</li>
<li>On the monitor: <code>sudo install -o 10001 -g 10001 -m 600 apikey.txt /opt/netmon/secrets/opnsense_block.key &amp;&amp; shred -u apikey.txt</code>, then restart the app.</li></ol>
<p class="sub">Rollback: remove the entry here, or disable the two floating rules. Existing connections continue until they close.</p>"""),
    "geoip": ("Country (GeoIP) blocking on OPNsense", """<ol>
<li>Firewall → Aliases → GeoIP settings: a GeoIP database source (e.g. a MaxMind GeoLite2 download URL with your licence key) must be configured for country aliases to resolve.</li>
<li>Firewall → Aliases → <code>GeoIP_BLOCK</code> (type GeoIP): review the country list (186 countries today).</li>
<li>Firewall → Rules → WAN: the block rule using <code>GeoIP_BLOCK</code> (sequence 51). The Countries page shows its live state; review the per-country preview before changing it.</li>
<li>Rollback: disable the rule again. Existing states remain until they expire.</li></ol>
<p class="sub">GeoIP is one signal, not a security boundary — VPNs and cloud providers defeat it. Check management, VPN and customer access before enabling.</p>"""),
    "inventory": ("Server names (inventory)", """<ol>
<li>Names come from <code>assets:</code> in <code>/opt/netmon/app/config.yaml</code>, seeded from OPNsense port-forward descriptions (Firewall → NAT → Port Forward → Description).</li>
<li>Give port forwards clear descriptions, or add hosts to <code>assets:</code> (name, role, sensitive) and restart the app.</li>
<li>Exposed services shown here mirror the port-forward list in <code>exposures:</code>; update it when you add or remove forwards on OPNsense.</li></ol>"""),
}


def snmp_rows():
    out = ""
    for x in cfg.sites:
        ok = (get_state(conn, f"snmp:{x['id']}:{x.get('wan_if')}", {})[0] or {}).get("ok")
        out += (f"<tr><td>SNMP WAN counters · {e(x['name'])}</td><td>{status_badge('ok' if ok else 'na')}</td>"
                f"<td>{e(x.get('wan_if') or '—')} every 10 s</td></tr>")
    return out


MONITOR_KEY = "monitor:db"
# lowercase DNS name with at least one dot; no wildcard, no trailing dot, no IP
FQDN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def monitor_settings():
    """This monitor's own identity (Settings → Firewalls & sites → This monitor): the FQDN the UI is served and linked
    under, and the address firewalls send NetFlow/syslog to. Empty values fall back to config.yaml."""
    return {"fqdn": "", "address": "", "via_proxy": False, "proxy_by": "", "proxy_at": None, **(get_setting(conn, MONITOR_KEY, {}) or {})}


def monitor_address():
    """Address the firewall should send NetFlow/syslog to: the setting, else `monitor_address` in config, else the
    host of akvorado_url."""
    from urllib.parse import urlparse
    return str(monitor_settings()["address"] or cfg.get("monitor_address") or urlparse(cfg.get("akvorado_url") or "").hostname
               or "MONITOR-ADDRESS")


def clean_fqdn(v):
    v = (v or "").strip().lower().rstrip(".")
    if v and not FQDN_RE.match(v):
        raise ValueError("FQDN must be a DNS name such as monitor.example.com (letters, digits, hyphens, at least one dot)")
    return v


def monitor_card(req, admin):
    m = monitor_settings()
    addr = monitor_address()
    hs, hdetail = host_status()
    served = ", ".join(["https://" + (f"[{addr}]" if ":" in addr else addr)] + ([f"https://{m['fqdn']}"] if m["fqdn"] else []))
    check = ""
    if m["fqdn"]:
        from . import dnsresolve as dr
        server, _ = dr.resolver_for(cfg.sites[0], dr.settings(conn, cfg.sites[0]["id"]))
        try:
            got = sorted({a for t in ("A", "AAAA") for a, _ in dr.query(m["fqdn"], t, server, 1.0)}) if server else []
            ok = addr in got
            # one of our own addresses with a name (e.g. a reverse proxy's 1:1 NAT): fine if it forwards to this monitor
            via = [f"{cfg.asset_label(a)}" for a in got if cfg.asset_label(a) not in ("", a)]
            if ok:
                verdict = "<span class='sev s-good'>● points at this monitor</span>"
            elif got and m["via_proxy"]:
                verdict = (f"<span class='sev s-good'>● reached through reverse proxy {e(', '.join(via) or ', '.join(got))}</span> "
                           f"(confirmed by {e(m['proxy_by'])} {e(fmt_ts(m['proxy_at']))})")
            elif via:
                verdict = (f"<span class='sev s-warning'>● points at {e(', '.join(via))}</span> — fine if that reverse proxy forwards "
                           f"to https://{e(addr)}; otherwise add a host override (Unbound) or DNS record for {e(addr)}")
            else:
                verdict = (f"<span class='sev s-serious'>◆ does not point at {e(addr)}</span> — add a host override (Unbound) or a "
                           "DNS record so browsers reach it")
            check = f"<li>DNS: {e(m['fqdn'])} → {e(', '.join(got) or 'no address')} on {e(server)} {verdict}</li>"
        except (OSError, ValueError) as ex:
            check = f"<li>DNS: could not check {e(m['fqdn'])} on {e(server)} ({e(type(ex).__name__)})</li>"
    dis = "" if admin else "disabled"
    return f"""<section class="card" id="monitor"><div class="card-h"><h2>This monitor</h2><span class="muted small">its own name and address</span></div>
<ul class="plain small"><li>Web UI served as: <span class="mono">{e(served)}</span> (TLS from Caddy's internal CA)</li>
<li>Links in notifications: <span class="mono">{e(monitor_url())}</span></li>{check}
<li>Host configuration: {e('applied' if hs == 'ok' else 'FAILED' if hs == 'failed' else 'pending')} — {e(hdetail)}</li></ul>
<form method=post action="/netmon/settings/monitor" class="stackform wide">{csrf_field(req)}
<div class="formgrid"><label>FQDN<input name=fqdn value="{e(m['fqdn'])}" maxlength=253 placeholder="e.g. monitor.example.com" class="mono" {dis}></label>
<label>Address firewalls send to<input name=address value="{e(m['address'])}" placeholder="automatic: {e(addr)}" class="mono" {dis}></label></div>
<label class="check"><input type=checkbox name=via_proxy value=1 {'checked' if m['via_proxy'] else ''} {dis}> Reached through a reverse proxy
<span class="muted small">— the FQDN resolves to a proxy that forwards to this monitor</span></label>
<p class="muted small">The FQDN is added to the TLS front end (the IP address keeps working) and used for links in notifications. A previous
FQDN stops being served once you save a new one. The address is what the setup steps tell firewalls to send NetFlow and syslog to.</p>
{'<div class="row"><button class="primary">Save</button></div>' if admin else ''}</form></section>"""


def monitor_url():
    """Base URL for links to this monitor (notifications): https://<FQDN> when set, else akvorado_url."""
    fqdn = monitor_settings()["fqdn"]
    return f"https://{fqdn}" if fqdn else (cfg.get("akvorado_url") or "").rstrip("/")


@app.post("/netmon/settings/monitor")
def save_monitor(req: Request, fqdn: str = Form(""), address: str = Form(""), via_proxy: str = Form(""), csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    try:
        f = clean_fqdn(fqdn)
        a = address.strip()
        if a:
            ip = ipaddress.ip_address(a)
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
                raise ValueError("address must be this monitor's reachable IP address")
            a = str(ip)
        old = monitor_settings()
        vp = via_proxy == "1" and bool(f)
        new = {"fqdn": f, "address": a, "via_proxy": vp,
               **({"proxy_by": old["proxy_by"], "proxy_at": old["proxy_at"]} if vp and old["via_proxy"] else
                  {"proxy_by": u, "proxy_at": time.time()} if vp else {"proxy_by": "", "proxy_at": None})}
        put_setting(conn, MONITOR_KEY, new, u)
        audit(conn, u, "monitor_identity", {"old": old, "new": new})
        sync_sites()   # hands the name to the root helper, which updates the TLS front end
        msg = "Saved. The TLS front end is updated within a few seconds." if f != old["fqdn"] else "Saved."
    except ValueError as ex:
        msg = f"Not saved: {ex}"
    return RedirectResponse(f"/netmon/settings/sites?msg={quote(msg)}#monitor", 303)


def tip_box(key, open_=False):
    title, html_ = TIPS[key]
    html_ = html_.replace("{MON}", e(monitor_address()))
    return (f"<details class='tip-box' id='tip-{key}' {'open' if open_ else ''}><summary>How to set up on OPNsense: {e(title)}</summary>"
            f"<div class='tip-body'>{html_}<p class='sub'><a href='/netmon/settings/integrations#tip-{key}'>All setup tips →</a></p></div></details>")


def tabs(items, active):
    if items and len(items[0]) == 4:   # grouped settings menu
        groups = {}
        for n, h, g, adm in items:
            groups.setdefault(g, []).append(f"<a href='{h}' class='{'on' if h == active else ''}{' adm' if adm else ''}'>{e(n)}</a>")
        return ("<nav class='subtabs grouped' aria-label='Settings'>" + "".join(
            f"<div class='tgrp'><span class='tgl'>{e(g)}</span><div class='tgl-links'>{''.join(links)}</div></div>" for g, links in groups.items()) + "</nav>")
    return "<nav class='subtabs'>" + "".join(f"<a href='{h}' class='{'on' if h == active else ''}'>{e(n)}</a>" for n, h in items) + "</nav>"


# ---- telemetry source status (shared by Settings, Security, Overview) -------------------------
def sources():
    ing, ts = get_state(conn, "ingest", {})
    last = (ing or {}).get("last_line")
    try:
        r = dash.ch.query("""SELECT (SELECT toUInt32(max(received)) FROM netmon.fw_events) AS fw,
                                    (SELECT toUInt32(max(received)) FROM netmon.ids_events) AS ids,
                                    (SELECT toUInt32(max(received)) FROM netmon.sys_events) AS sys,
                                    (SELECT count() FROM netmon.fw_events WHERE ts > now() - INTERVAL 1 DAY AND action = 'block') AS blocks24,
                                    (SELECT count() FROM netmon.ids_events WHERE ts > now() - INTERVAL 1 DAY) AS ids24""")[0]
    except Exception:
        r = {"fw": 0, "ids": 0, "sys": 0, "blocks24": 0, "ids24": 0}

    def st(t, stale=900):
        if not t:
            return "not_connected"
        return "ok" if time.time() - t < stale else "stale"
    return {"ingest": ing or {}, "ingest_last": last,
            "fw": {"state": st(r["fw"]), "last": r["fw"] or None, "blocks24": int(r["blocks24"])},
            "ids": {"state": st(r["ids"], 86400 * 7), "last": r["ids"] or None, "alerts24": int(r["ids24"])},
            "sys": {"state": st(r["sys"], 86400), "last": r["sys"] or None},
            "channels": conn.execute("SELECT count(*) FROM channels WHERE enabled=1").fetchone()[0]}


@app.get("/netmon/api/sources")
def api_sources(req: Request):
    current(req)
    return guard(lambda: {"ok": True, **sources()})


# ---- account & 2FA -------------------------------------------------------------------------
def qr_svg(data: str) -> str:
    import segno
    return segno.make(data, error="m").svg_inline(scale=5, border=2, dark="#0b0b0b", light="#ffffff")


@app.get("/netmon/account", response_class=HTMLResponse)
def account(req: Request, enroll: str = "", msg: str = "", codes: str = ""):
    u, r = user_of(req)
    row = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    required = bool(get_setting(conn, "require_2fa", False))
    parts = []
    if enroll and not row["totp_enabled"]:
        parts.append("<div class='banner warn'><b>Two-factor authentication is required.</b> Set it up below to continue.</div>")
    if msg:
        parts.append(f"<div class='banner'>{e(msg)}</div>")
    if codes:
        cl = "".join(f"<li><code>{e(c)}</code></li>" for c in codes.split(","))
        parts.append(f"<div class='banner warn'><b>Recovery codes — shown once.</b> Store them somewhere safe; each works once.<ul class='codes'>{cl}</ul></div>")
    if row["totp_enabled"]:
        left = len(json.loads(row["recovery"] or "[]"))
        tfa = f"""<p><span class='sev s-good'>● Enabled</span> · {left} recovery codes left</p>
<form method=post action="/netmon/account/2fa/recovery" class="row">{csrf_field(req)}<button>Generate new recovery codes</button></form>
{'' if required else f'''<form method=post action="/netmon/account/2fa/disable" class="row">{csrf_field(req)}
<input type=password name=password placeholder="current password" required autocomplete="current-password">
<input name=code placeholder="6-digit code" required inputmode=numeric> <button>Disable 2FA</button></form>'''}"""
    else:
        secret = row["totp_secret"] or auth.totp_new_secret()
        if not row["totp_secret"]:
            conn.execute("UPDATE users SET totp_secret=? WHERE username=?", (secret, u))
            conn.commit()
        uri = auth.totp_uri(secret, u)
        tfa = f"""<p><span class='sev s-muted'>○ Not enabled</span>{' — required by your administrator' if required else ''}</p>
<div class="enroll"><div class="qr">{qr_svg(uri)}</div><div>
<ol><li>Scan the QR code with an authenticator app (1Password, Bitwarden, Google/Microsoft Authenticator, Aegis…).</li>
<li>Or enter this key manually: <code class="key">{e(' '.join(secret[i:i + 4] for i in range(0, len(secret), 4)))}</code></li>
<li>Enter the current 6-digit code to confirm.</li></ol>
<form method=post action="/netmon/account/2fa/enable" class="row">{csrf_field(req)}
<input name=code placeholder="6-digit code" required inputmode=numeric autocomplete=one-time-code maxlength=8> <button class="primary">Enable 2FA</button></form></div></div>"""
    body = f"""{tabs(SETTINGS_TABS, '/netmon/account')}{''.join(parts)}
<section class="grid2 even"><div class="card"><div class="card-h"><h2>Two-factor authentication (TOTP)</h2></div>{tfa}</div>
<div class="card"><div class="card-h"><h2>Change password</h2></div>
<form method=post action="/netmon/account/password" class="stackform">{csrf_field(req)}
<label>Current password<input type=password name=current required autocomplete="current-password"></label>
<label>New password (12+ characters)<input type=password name=new required minlength=12 autocomplete="new-password"></label>
<button>Change password</button></form>
<p class="muted small">Signed in as <b>{e(u)}</b> ({e(r)}). Changing your password signs out your other sessions.</p></div></section>"""
    return page(req, "Settings · My account", body, "/netmon/settings", scoped=False)


@app.post("/netmon/account/2fa/enable")
def enable_2fa(req: Request, code: str = Form(...), csrf: str = Form("")):
    u, _ = user_of(req)
    check_csrf(req, csrf)
    row = conn.execute("SELECT totp_secret FROM users WHERE username=?", (u,)).fetchone()
    c = auth.totp_check(row["totp_secret"], code)
    if c is None:
        return RedirectResponse("/netmon/account?msg=" + quote("That code did not match. Check the time on your phone and try again."), 303)
    codes, hashes = auth.new_recovery_codes()
    conn.execute("UPDATE users SET totp_enabled=1, totp_last=?, recovery=? WHERE username=?", (c, hashes, u))
    conn.commit()
    audit(conn, u, "2fa_enabled", {})
    return RedirectResponse("/netmon/account?msg=" + quote("Two-factor authentication enabled.") + "&codes=" + quote(",".join(codes)), 303)


@app.post("/netmon/account/2fa/recovery")
def regen_recovery(req: Request, csrf: str = Form("")):
    u, _ = user_of(req)
    check_csrf(req, csrf)
    codes, hashes = auth.new_recovery_codes()
    conn.execute("UPDATE users SET recovery=? WHERE username=? AND totp_enabled=1", (hashes, u))
    conn.commit()
    audit(conn, u, "2fa_recovery_regenerated", {})
    return RedirectResponse("/netmon/account?codes=" + quote(",".join(codes)), 303)


@app.post("/netmon/account/2fa/disable")
def disable_2fa(req: Request, password: str = Form(...), code: str = Form(...), csrf: str = Form("")):
    u, _ = user_of(req)
    check_csrf(req, csrf)
    if get_setting(conn, "require_2fa", False):
        raise HTTPException(403, "2FA is required by policy")
    row = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    if not auth.check_pw(password, row["pw_hash"]) or not auth.verify_second_factor(conn, u, code):
        return RedirectResponse("/netmon/account?msg=" + quote("Password or code incorrect."), 303)
    conn.execute("UPDATE users SET totp_enabled=0, totp_secret=NULL, recovery=NULL WHERE username=?", (u,))
    conn.commit()
    audit(conn, u, "2fa_disabled", {})
    return RedirectResponse("/netmon/account?msg=" + quote("Two-factor authentication disabled."), 303)


@app.post("/netmon/account/password")
def change_password(req: Request, current_pw: str = Form(..., alias="current"), new: str = Form(...), csrf: str = Form("")):
    u, _, sid = current(req)
    check_csrf(req, csrf)
    row = conn.execute("SELECT pw_hash FROM users WHERE username=?", (u,)).fetchone()
    if not auth.check_pw(current_pw, row["pw_hash"]):
        return RedirectResponse("/netmon/account?msg=" + quote("Current password is incorrect."), 303)
    if p := auth.password_problem(new):
        return RedirectResponse("/netmon/account?msg=" + quote(p), 303)
    conn.execute("UPDATE users SET pw_hash=? WHERE username=?", (auth.hash_pw(new), u))
    conn.execute("DELETE FROM sessions WHERE username=? AND token_hash!=?", (u, sid))
    conn.commit()
    audit(conn, u, "password_changed", {})
    return RedirectResponse("/netmon/account?msg=" + quote("Password changed."), 303)


@app.post("/netmon/users/{name}/reset2fa")
def reset_2fa(req: Request, name: str, csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    conn.execute("UPDATE users SET totp_enabled=0, totp_secret=NULL, recovery=NULL WHERE username=?", (name,))
    conn.commit()
    auth.revoke_user_sessions(conn, name)
    audit(conn, u, "2fa_reset", {"user": name})
    return RedirectResponse("/netmon/users?msg=" + quote(f"2FA reset for {name}; they must enroll again"), 303)


@app.post("/netmon/settings/require2fa")
def require_2fa(req: Request, value: str = Form(...), csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    me = conn.execute("SELECT totp_enabled FROM users WHERE username=?", (u,)).fetchone()
    if value == "1" and not me["totp_enabled"]:
        return RedirectResponse("/netmon/users?msg=" + quote("Enable 2FA on your own account first (My account)."), 303)
    put_setting(conn, "require_2fa", value == "1", u)
    audit(conn, u, "require_2fa", {"value": value == "1"})
    return RedirectResponse("/netmon/users?msg=" + quote("2FA is now " + ("required for all users" if value == "1" else "optional")), 303)


# ---- notifications ------------------------------------------------------------------------
SEVS = ("info", "low", "medium", "high")
CATS = (("security", "Security alerts"), ("health", "Monitoring health"), ("response", "Auto-response actions"),
        ("info", "Informational changes"))


@app.get("/netmon/settings/notifications", response_class=HTMLResponse)
def notifications_page(req: Request, msg: str = ""):
    u, r = user_of(req)
    chans = conn.execute("SELECT * FROM channels ORDER BY id").fetchall()
    last = {d["channel_id"]: d for d in conn.execute(
        "SELECT * FROM deliveries WHERE id IN (SELECT max(id) FROM deliveries GROUP BY channel_id)")}
    rows = ""
    for c in chans:
        cats = ", ".join(json.loads(c["categories"]))
        q = f"{c['quiet_start']:02d}–{c['quiet_end']:02d}h" if c["quiet_start"] is not None else "none"
        ld = last.get(c["id"])
        st = (f"<span class='sev s-{'good' if ld['status'] == 'delivered' else 'critical'}'>{e(ld['status'])}</span> "
              f"<span class='muted small'>{e(ld['kind'])} · {e(fmt_ts(ld['ts']))}</span>") if ld else "<span class='muted'>never sent</span>"
        acts = (f"""<form method=post action="/netmon/settings/notifications/{c['id']}/test" class="inline">{csrf_field(req)}<button>Send test</button></form>
<form method=post action="/netmon/settings/notifications/{c['id']}/toggle" class="inline">{csrf_field(req)}<button>{'Disable' if c['enabled'] else 'Enable'}</button></form>
<form method=post action="/netmon/settings/notifications/{c['id']}/delete" class="inline confirm">{csrf_field(req)}<button>Delete</button></form>""" if r == "admin" else "")
        rows += (f"<tr><td><b>{e(c['name'])}</b><div class='sub'>{e(TYPES.get(c['type'], (c['type'],))[0])}</div></td>"
                 f"<td>{'<span class=\"sev s-good\">● on</span>' if c['enabled'] else '<span class=\"sev s-muted\">○ off</span>'}</td>"
                 f"<td>≥ {e(c['min_severity'])}<div class='sub'>{e(cats)}</div></td><td>{e(q)}{' (high still sent)' if c['quiet_start'] is not None and c['quiet_allow_high'] else ''}</td>"
                 f"<td>{c['max_per_hour']}/h{' · daily summary' if c['summary_daily'] else ''}</td><td>{st}</td><td class='acts'>{acts}</td></tr>")
    dl = "".join(f"<tr><td class='num'>{e(fmt_ts(d['ts']))}</td><td>{e(d['channel'])}</td><td>{e(d['kind'])}</td>"
                 f"<td>{('<a href=/netmon/alert/' + str(d['alert_id']) + '>#' + str(d['alert_id']) + '</a>') if d['alert_id'] else '—'}</td>"
                 f"<td><span class='sev s-{'good' if d['status'] == 'delivered' else 'critical' if d['status'] in ('failed', 'error') else 'muted'}'>{e(d['status'])}</span></td>"
                 f"<td>{d['attempts']}</td><td class='muted small'>{e(d['detail'] or '')}</td></tr>"
                 for d in conn.execute("SELECT * FROM deliveries ORDER BY id DESC LIMIT 40"))
    groups = ""
    for t, (label, fields, secrets_) in TYPES.items():
        inputs = "".join(f"<label>{e(lbl)}<input name='f_{t}_{k}' type='{'password' if kind == 'secret' else 'number' if kind == 'number' else 'text'}' "
                         f"{'autocomplete=off' if kind == 'secret' else ''}></label>" for k, lbl, kind in fields)
        groups += f"<fieldset class='chfields' data-type='{t}' hidden><legend>{e(label)}</legend>{inputs}</fieldset>"
    opts = "".join(f"<option value='{t}'>{e(v[0])}</option>" for t, v in TYPES.items())
    sev_opts = "".join(f"<option {'selected' if s == 'medium' else ''}>{s}</option>" for s in SEVS)
    cat_boxes = "".join(f"<label class='cb'><input type=checkbox name=cat value='{k}' {'checked' if k != 'info' else ''}> {e(v)}</label>" for k, v in CATS)
    hour = get_setting(conn, "summary_hour", 8)
    add = f"""<section class="card"><div class="card-h"><h2>Add a channel</h2><span class="muted small">secrets are stored server-side, never shown again, and excluded from logs</span></div>
<form method=post action="/netmon/settings/notifications" class="stackform wide" id="chform">{csrf_field(req)}
<div class="formgrid"><label>Name<input name=name required placeholder="e.g. On-call email"></label>
<label>Type<select name=type id=chtype>{opts}</select></label>
<label>Minimum severity<select name=min_severity>{sev_opts}</select></label>
<label>Max messages per hour<input name=max_per_hour type=number value=20 min=1 max=500></label>
<label>Quiet hours start (0–23, local)<input name=quiet_start type=number min=0 max=23 placeholder="none"></label>
<label>Quiet hours end<input name=quiet_end type=number min=0 max=23 placeholder="none"></label></div>
<div class="row">{cat_boxes}<label class='cb'><input type=checkbox name=quiet_allow_high value=1 checked> High severity ignores quiet hours</label>
<label class='cb'><input type=checkbox name=summary_daily value=1> Daily summary</label></div>
{groups}<div class="row"><button class="primary">Save channel</button><span class="muted small">Then use “Send test” — nothing real is sent until you do.</span></div></form></section>""" if r == "admin" else ""
    body = f"""{tabs(SETTINGS_TABS, '/netmon/settings/notifications')}{f"<div class='banner'>{e(msg)}</div>" if msg else ''}
<section class="card"><div class="card-h"><h2>Channels</h2><span class="muted small">alerts are routed to every enabled channel whose rules match</span></div>
<div class="wrap"><table class="tbl"><thead><tr><th>Channel</th><th>State</th><th>Routes</th><th>Quiet hours</th><th>Limits</th><th>Last delivery</th><th></th></tr></thead>
<tbody>{rows or '<tr><td colspan=7 class="state empty">No channels yet — alerts are only shown in the UI.</td></tr>'}</tbody></table></div>
{f'''<form method=post action="/netmon/settings/summary-hour" class="row">{csrf_field(req)}Daily summary time (local hour, {e(time.strftime('%Z'))}):
<input type=number name=hour min=0 max=23 value="{hour}" style="width:5em"> <button>Save</button></form>''' if r == 'admin' else ''}</section>
{add}
<section class="card"><div class="card-h"><h2>Delivery log</h2><span class="muted small">retries: 4 attempts with backoff · maintenance windows suppress delivery</span></div>
<div class="wrap"><table class="tbl"><thead><tr><th>Time</th><th>Channel</th><th>Kind</th><th>Alert</th><th>Status</th><th>Attempts</th><th>Detail</th></tr></thead><tbody>{dl or '<tr><td colspan=7 class="state empty">Nothing sent yet</td></tr>'}</tbody></table></div></section>
<p class="note">SMS: Twilio sends directly (needs an account and a sending number). The carrier email-to-SMS option uses your SMTP server and
addresses such as <code>number@vtext.com</code>; several US carriers have retired these gateways, so test before relying on it.</p>"""
    return page(req, "Settings · Notifications", body, "/netmon/settings", ("settings.js",), scoped=False)


def _int(v, lo, hi):
    try:
        x = int(v)
    except (TypeError, ValueError):
        return None
    return x if lo <= x <= hi else None


@app.post("/netmon/settings/notifications")
async def add_channel(req: Request):
    u = need(req, "admin")
    form = await req.form()
    check_csrf(req, form.get("csrf", ""))
    t = form.get("type", "")
    if t not in TYPES:
        raise HTTPException(400, "unknown type")
    label, fields, secrets_ = TYPES[t]
    conf = {k: str(form.get(f"f_{t}_{k}", "")).strip() for k, _, _ in fields}
    required = {"email": ["host", "from", "to"], "sms_email": ["host", "from", "to"], "sms_twilio": ["account_sid", "auth_token", "from", "to"],
                "webhook": ["url"], "slack": ["url"], "teams": ["url"], "discord": ["url"], "ntfy": ["server", "topic"],
                "pushover": ["app_token", "user_key"]}[t]
    missing = [k for k in required if not conf.get(k)]
    if missing:
        return RedirectResponse("/netmon/settings/notifications?msg=" + quote(f"Missing: {', '.join(missing)}"), 303)
    for k in ("url", "server"):
        if conf.get(k) and not conf[k].startswith("https://"):
            return RedirectResponse("/netmon/settings/notifications?msg=" + quote(f"{k} must start with https://"), 303)
    cats = [c for c in form.getlist("cat") if c in dict(CATS)] or ["security"]
    qs, qe = _int(form.get("quiet_start"), 0, 23), _int(form.get("quiet_end"), 0, 23)
    conn.execute("INSERT INTO channels(name,type,config,min_severity,categories,quiet_start,quiet_end,quiet_allow_high,summary_daily,"
                 "max_per_hour,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                 (str(form.get("name", t))[:60], t, json.dumps(conf), form.get("min_severity") if form.get("min_severity") in SEVS else "medium",
                  json.dumps(cats), qs if qe is not None else None, qe if qs is not None else None, 1 if form.get("quiet_allow_high") else 0,
                  1 if form.get("summary_daily") else 0, _int(form.get("max_per_hour"), 1, 500) or 20, u, time.time()))
    conn.commit()
    audit(conn, u, "channel_added", {"type": t, "name": str(form.get("name"))[:60]})  # config (with secrets) never audited
    return RedirectResponse("/netmon/settings/notifications?msg=" + quote("Channel saved. Send a test to verify it."), 303)


@app.post("/netmon/settings/notifications/{cid}/{action}")
def channel_action(req: Request, cid: int, action: str, csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    if action == "test":
        notifier.test(cid, u)
        audit(conn, u, "channel_test", {"id": cid})
        msg = "Test queued — refresh in a few seconds to see the result in the delivery log."
    elif action == "toggle":
        conn.execute("UPDATE channels SET enabled = 1 - enabled WHERE id=?", (cid,))
        conn.commit()
        audit(conn, u, "channel_toggled", {"id": cid})
        msg = "Channel updated."
    elif action == "delete":
        conn.execute("DELETE FROM channels WHERE id=?", (cid,))
        conn.commit()
        audit(conn, u, "channel_deleted", {"id": cid})
        msg = "Channel deleted."
    else:
        raise HTTPException(404)
    return RedirectResponse("/netmon/settings/notifications?msg=" + quote(msg), 303)


@app.post("/netmon/settings/summary-hour")
def summary_hour(req: Request, hour: int = Form(...), csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    put_setting(conn, "summary_hour", max(0, min(23, hour)), u)
    return RedirectResponse("/netmon/settings/notifications?msg=" + quote("Summary time saved."), 303)


# ---- alert rules ---------------------------------------------------------------------------
RULE_DOCS = {
    "new_dest_country": "A server starts talking to a country it has not used in the baseline window.",
    "new_dest_asn": "A server starts talking to a network (ASN) it has not used before.",
    "unexpected_inbound": "Internet traffic reaches an internal port that no port forward explains.",
    "outbound_volume": "Outbound bytes from a source exceed its usual volume for this hour.",
    "fanout": "One source contacts many destinations or ports (scanning pattern).",
    "beaconing": "Connections to the same destination at very regular intervals.",
    "ids_alert": "Suricata signature alerts forwarded from OPNsense.",
    "fw_blocked_outbound": "An internal host is repeatedly blocked by the firewall.",
    "fw_blocked_scan": "Repeated blocked inbound attempts from one source (informational).",
    "exporter_silence": "No NetFlow received from the firewall.",
    "syslog_silence": "No firewall/IDS log lines received.",
    "disk_usage": "Monitor VM disk usage threshold.",
    "device_auth_failures": "Repeated failed logins reported by a device's own log (firewall, router, switch).",
    "vpn_tunnel_down": "A device reports a VPN tunnel or session down.",
    "interface_down": "A device reports an interface/link down.",
    "routing_neighbor_down": "A device reports a BGP/OSPF neighbor down.",
    "ha_failover": "A device reports a high-availability role change (failover).",
    "config_change": "A device reports a configuration change (who, when, what).",
    "device_silence": "An additional device that was sending logs stopped.",
}
DETECTOR_KEYS = [("interval_seconds", "Run detector every (s)", 60, 3600), ("window_minutes", "Evaluation window (min)", 10, 1440),
                 ("baseline_days", "Baseline length (days)", 3, 60), ("min_learning_days", "Novelty rules start after (days)", 0, 30),
                 ("cooldown_minutes", "Repeat cooldown (min)", 5, 10080)]


@app.get("/netmon/settings/rules", response_class=HTMLResponse)
def rules_page(req: Request, msg: str = ""):
    u, r = user_of(req)
    apply_overrides(cfg, conn)
    admin = r == "admin"
    rows = ""
    for name, rc in cfg["rules"].items():
        fields = ""
        for k, v in rc.items():
            if k == "enabled":
                continue
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                fields += f"<label class='inl'>{e(k.replace('_', ' '))}<input name='{e(name)}.{e(k)}' type=number step=any value='{e(v)}' {'disabled' if not admin else ''}></label>"
            elif isinstance(v, list):
                fields += f"<label class='inl'>{e(k.replace('_', ' '))}<input name='{e(name)}.{e(k)}' value='{e(','.join(map(str, v)))}' {'disabled' if not admin else ''}></label>"
        rows += (f"<tr><td><label class='cb'><input type=checkbox name='{e(name)}.enabled' value=1 {'checked' if rc.get('enabled') else ''} {'disabled' if not admin else ''}> "
                 f"<b>{e(name)}</b></label><div class='sub'>{e(RULE_DOCS.get(name, ''))}</div></td><td class='fields'>{fields}</td></tr>")
    det = "".join(f"<label>{e(lbl)}<input name='detector.{k}' type=number value='{e(cfg['detector'][k])}' min={lo} max={hi} {'disabled' if not admin else ''}></label>"
                  for k, lbl, lo, hi in DETECTOR_KEYS)
    ov = get_setting(conn, "override:rules", {}) or {}
    body = f"""{tabs(SETTINGS_TABS, '/netmon/settings/rules')}{f"<div class='banner'>{e(msg)}</div>" if msg else ''}
<form method=post action="/netmon/settings/rules">{csrf_field(req)}
<section class="card"><div class="card-h"><h2>Detector</h2><span class="muted small">baseline = observed history, never automatic approval</span></div><div class="formgrid">{det}</div></section>
<section class="card"><div class="card-h"><h2>Detection rules</h2><span class="muted small">{len(ov)} rule(s) changed from config.yaml defaults</span></div>
<div class="wrap"><table class="tbl rules"><thead><tr><th>Rule</th><th>Thresholds</th></tr></thead><tbody>{rows}</tbody></table></div>
{'<div class="row"><button class="primary">Save rules</button></div>' if admin else '<p class="muted">Only admins can change rules.</p>'}</section></form>
{f'''<form method=post action="/netmon/settings/rules/reset" class="row">{csrf_field(req)}<button>Reset all to config.yaml defaults</button></form>''' if admin else ''}
<p class="note">Changes apply on the next detector run. Use Suppressions for specific known-good traffic and Maintenance windows for planned work.</p>"""
    return page(req, "Settings · Alert rules", body, "/netmon/settings", scoped=False)


@app.post("/netmon/settings/rules")
async def save_rules(req: Request):
    u = need(req, "admin")
    form = await req.form()
    check_csrf(req, form.get("csrf", ""))
    base = cfg._base if hasattr(cfg, "_base") else {"rules": cfg["rules"], "detector": cfg["detector"]}
    rules_ov, det_ov = {}, {}
    for name, rc in base["rules"].items():
        new = {}
        for k, v in rc.items():
            key = f"{name}.{k}"
            if k == "enabled":
                val = key in form
            elif isinstance(v, bool):
                continue
            elif isinstance(v, (int, float)):
                try:
                    val = type(v)(float(form.get(key, v)))
                except ValueError:
                    continue
                if val < 0:
                    continue
            elif isinstance(v, list):
                try:
                    val = [int(x) for x in str(form.get(key, "")).split(",") if x.strip()]
                except ValueError:
                    continue
            else:
                continue
            if val != v:
                new[k] = val
        if new:
            rules_ov[name] = new
    for k, _, lo, hi in DETECTOR_KEYS:
        try:
            val = int(form.get(f"detector.{k}", base["detector"][k]))
        except ValueError:
            continue
        val = max(lo, min(hi, val))
        if val != base["detector"][k]:
            det_ov[k] = val
    put_setting(conn, "override:rules", rules_ov, u)
    put_setting(conn, "override:detector", det_ov, u)
    apply_overrides(cfg, conn)
    audit(conn, u, "rules_saved", {"rules": rules_ov, "detector": det_ov})
    return RedirectResponse("/netmon/settings/rules?msg=" + quote("Saved. Applies on the next detector run."), 303)


@app.post("/netmon/settings/rules/reset")
def reset_rules(req: Request, csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    put_setting(conn, "override:rules", {}, u)
    put_setting(conn, "override:detector", {}, u)
    apply_overrides(cfg, conn)
    audit(conn, u, "rules_reset", {})
    return RedirectResponse("/netmon/settings/rules?msg=" + quote("Rules reset to config.yaml defaults."), 303)


# ---- maintenance windows -------------------------------------------------------------------
@app.get("/netmon/settings/maintenance", response_class=HTMLResponse)
def maintenance_page(req: Request, msg: str = ""):
    u, r = user_of(req)
    now = time.time()
    rows = ""
    for m in conn.execute("SELECT * FROM maintenance ORDER BY start_ts DESC LIMIT 100"):
        state = ("<span class='sev s-warning'>◐ active</span>" if m["enabled"] and m["start_ts"] <= now <= m["end_ts"] else
                 "scheduled" if m["enabled"] and m["start_ts"] > now else "ended" if m["enabled"] else "cancelled")
        cancel = (f"<form method=post action='/netmon/settings/maintenance/{m['id']}/cancel' class=inline>{csrf_field(req)}<button>Cancel</button></form>"
                  if m["enabled"] and m["end_ts"] > now and ROLES[r] >= 1 else "")
        rows += (f"<tr><td class='num'>{e(fmt_ts(m['start_ts']))}</td><td class='num'>{e(fmt_ts(m['end_ts']))}</td>"
                 f"<td>{e(cfg.asset_label(m['asset']) if m['asset'] != '*' else 'all servers')}</td><td>{e(m['rule'] if m['rule'] != '*' else 'all rules')}</td>"
                 f"<td>{e(m['reason'])}</td><td>{e(m['created_by'])}</td><td>{state}</td><td>{cancel}</td></tr>")
    assets = "".join(f"<option value='{e(ip)}'>{e(a['name'])} ({e(ip)})</option>" for ip, a in cfg.get("assets", {}).items())
    rules = "".join(f"<option>{e(k)}</option>" for k in cfg["rules"])
    form = f"""<section class="card"><div class="card-h"><h2>Schedule a window</h2><span class="muted small">times in your browser's local time</span></div>
<form method=post action="/netmon/settings/maintenance" class="stackform wide" id="mwform">{csrf_field(req)}
<div class="formgrid"><label>Start<input type=datetime-local name=start_l required></label><label>End<input type=datetime-local name=end_l required></label>
<label>Server<select name=asset><option value="*">All servers</option>{assets}</select></label>
<label>Rule<select name=rule><option value="*">All rules</option>{rules}</select></label>
<label class="span2">Reason<input name=reason required placeholder="e.g. PBS full backup / kernel patching"></label></div>
<input type=hidden name=start><input type=hidden name=end><button class="primary">Schedule</button></form></section>""" if ROLES[r] >= 1 else ""
    body = f"""{tabs(SETTINGS_TABS, '/netmon/settings/maintenance')}{f"<div class='banner'>{e(msg)}</div>" if msg else ''}
<p class="muted">During a window, findings are still recorded (marked “maintenance”) but notifications are not sent.</p>{form}
<section class="card"><div class="wrap"><table class="tbl"><thead><tr><th>Start</th><th>End</th><th>Server</th><th>Rule</th><th>Reason</th><th>By</th><th>State</th><th></th></tr></thead>
<tbody>{rows or '<tr><td colspan=8 class="state empty">No maintenance windows</td></tr>'}</tbody></table></div></section>"""
    return page(req, "Settings · Maintenance", body, "/netmon/settings", ("settings.js",), scoped=False)


@app.post("/netmon/settings/maintenance")
def add_maintenance(req: Request, start: str = Form(...), end: str = Form(...), asset: str = Form("*"), rule: str = Form("*"),
                    reason: str = Form(...), csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    try:
        s, t = float(start), float(end)
    except ValueError:
        raise HTTPException(400, "bad time")
    if t <= s or t - s > 14 * 86400:
        return RedirectResponse("/netmon/settings/maintenance?msg=" + quote("End must be after start and within 14 days."), 303)
    if asset != "*" and asset not in cfg.get("assets", {}):
        raise HTTPException(400)
    if rule != "*" and rule not in cfg["rules"]:
        raise HTTPException(400)
    conn.execute("INSERT INTO maintenance(start_ts,end_ts,asset,rule,reason,created_by,created_at) VALUES (?,?,?,?,?,?,?)",
                 (s, t, asset, rule, reason.strip()[:200], u, time.time()))
    conn.commit()
    audit(conn, u, "maintenance_added", {"start": s, "end": t, "asset": asset, "rule": rule})
    return RedirectResponse("/netmon/settings/maintenance?msg=" + quote("Window scheduled."), 303)


@app.post("/netmon/settings/maintenance/{mid}/cancel")
def cancel_maintenance(req: Request, mid: int, csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    conn.execute("UPDATE maintenance SET enabled=0 WHERE id=?", (mid,))
    conn.commit()
    audit(conn, u, "maintenance_cancelled", {"id": mid})
    return RedirectResponse("/netmon/settings/maintenance", 303)


# ---- integrations / firewall setup ---------------------------------------------------------
def status_badge(state, ok="Connected", na="Not connected", stale="Stale"):
    return {"ok": f"<span class='sev s-good'>● {ok}</span>", "stale": f"<span class='sev s-warning'>◐ {stale}</span>"}.get(
        state, f"<span class='sev s-muted'>○ {na}</span>")


@app.get("/netmon/settings/integrations", response_class=HTMLResponse)
def integrations_page(req: Request):
    user_of(req)
    s = sources()
    ing = s["ingest"]
    at = cfg["exporter_active_timeout"]
    body = f"""{tabs(SETTINGS_TABS, '/netmon/settings/integrations')}
<section class="card"><div class="card-h"><h2>Telemetry sources</h2></div><table class="tbl">
<tr><th>Source</th><th>Status</th><th>Detail</th></tr>
<tr><td>NetFlow v9 (traffic)</td><td>{status_badge('ok')}</td><td>active timeout {at} s {'— <b>recommended 120 s</b>, see step 1' if at > 300 else ''}</td></tr>
{snmp_rows()}
<tr><td>Firewall logs (filterlog)</td><td>{status_badge(s['fw']['state'])}</td><td>{f"last {fmt_ts(s['fw']['last'])} · {s['fw']['blocks24']:,} blocks in 24 h" if s['fw']['last'] else 'waiting for OPNsense remote syslog (step 2)'}</td></tr>
<tr><td>Suricata IDS alerts</td><td>{status_badge(s['ids']['state'], stale='No recent alerts')}</td><td>{f"last {fmt_ts(s['ids']['last'])} · {s['ids']['alerts24']} in 24 h" if s['ids']['last'] else 'Suricata not enabled on OPNsense (step 3)'}</td></tr>
<tr><td>Gateway / VPN / config events</td><td>{status_badge(s['sys']['state'])}</td><td>{f"last {fmt_ts(s['sys']['last'])}" if s['sys']['last'] else 'via the same remote syslog destination'}</td></tr>
<tr><td>Syslog receiver (rsyslog, TCP 5514)</td><td>{status_badge('ok' if ing.get('lines') else 'na', na='Listening — nothing received yet')}</td>
<td>{ing.get('lines', 0):,} lines parsed · {ing.get('errors', 0)} errors · unparsed {e(json.dumps(ing.get('unparsed', {})))}{(' · ' + e(ing.get('error'))) if ing.get('error') else ''}</td></tr>
</table></section>
<section class="card"><div class="card-h"><h2>OPNsense setup tips</h2><span class="muted small">steps to do in the OPNsense GUI</span></div>
{''.join(tip_box(k, open_=(k == 'syslog' and not s['fw']['last']) or (k == 'ids' and not s['ids']['last'])) for k in TIPS)}
<p class="note">Transport: TCP, ideally on a directly attached management network. OPNsense also supports TLS(4) for remote syslog; that needs a CA trusted on both sides and can be added later.</p></section>
"""
    return page(req, "Settings · Data sources", body, "/netmon/settings", scoped=False)


# ---- firewall events & IDS -------------------------------------------------------------------
def fw_where(sc):
    """Time + site scope for the syslog tables (rows are tagged with the sending firewall's site id)."""
    return "ts >= toDateTime({t0:UInt32}) AND ts < toDateTime({t1:UInt32}) AND has({fsites:Array(String)}, site)"


def fw_params(sc):
    return {"t0": sc.start, "t1": sc.end, "fsites": [x["id"] for x in sc.sites],
            "flan": [(x["id"], x["lan_if"]) for x in sc.sites if x.get("lan_if")]}


@app.get("/netmon/api/firewall")
def api_firewall(req: Request, page_: int = 1, action: str = "block"):
    current(req)
    sc = scope_of(req)
    action = action if action in ("block", "pass", "all") else "block"

    def run():
        p = {**fw_params(sc), "b": sc.bucket, "a": action}
        q = dash.ch.query
        tot = q(f"SELECT action, dir, iface, count() AS n FROM netmon.fw_events WHERE {fw_where(sc)} GROUP BY action, dir, iface ORDER BY n DESC", p)
        ts = q(f"""SELECT toUInt32(toStartOfInterval(ts, INTERVAL {{b:UInt32}} SECOND)) AS t, countIf(action = 'block') AS blocked,
                   countIf(action = 'pass') AS passed FROM netmon.fw_events WHERE {fw_where(sc)} GROUP BY t ORDER BY t""", p)
        act = "" if action == "all" else "AND action = {a:String}"
        srcs = q(f"""SELECT replaceOne(IPv6NumToString(src), '::ffff:', '') AS ip, count() AS n, uniq(dport) AS ports, uniq(dst) AS targets
                    FROM netmon.fw_events WHERE {fw_where(sc)} {act} GROUP BY src ORDER BY n DESC LIMIT 15""", p)
        ports = q(f"""SELECT proto, dport, count() AS n, uniq(src) AS sources FROM netmon.fw_events WHERE {fw_where(sc)} {act}
                     GROUP BY proto, dport ORDER BY n DESC LIMIT 15""", p)
        lanblk = q(f"""SELECT replaceOne(IPv6NumToString(src), '::ffff:', '') AS ip, count() AS n, uniq(dst) AS dsts, groupUniqArray(5)(dport) AS ports
                      FROM netmon.fw_events WHERE {fw_where(sc)} AND action = 'block' AND has({{flan:Array(Tuple(String, String))}}, (site, iface)) AND dir = 'in'
                      GROUP BY src ORDER BY n DESC LIMIT 15""", p)
        per = 50
        recent = q(f"""SELECT toUnixTimestamp64Milli(ts) AS ms, action, dir, iface, proto, replaceOne(IPv6NumToString(src), '::ffff:', '') AS src,
                       sport, replaceOne(IPv6NumToString(dst), '::ffff:', '') AS dst, dport, rulenr, rid, reason, tcpflags, length
                       FROM netmon.fw_events WHERE {fw_where(sc)} {act} ORDER BY ts DESC LIMIT {per} OFFSET {(max(1, page_) - 1) * per}""", p)
        for row in srcs + lanblk:
            a = cfg.asset(row["ip"])
            row["name"] = a["name"] if a["name"] != row["ip"] else ""
        return {"ok": True, "scope": {"start": sc.start, "end": sc.end, "bucket": sc.bucket, "describe": sc.describe()},
                "sources": sources(), "totals": tot, "series": ts, "top_sources": srcs, "top_ports": ports, "lan_blocked": lanblk,
                "recent": recent, "page": max(1, page_), "action": action}
    return guard(run)


@app.get("/netmon/api/ids")
def api_ids(req: Request):
    current(req)
    sc = scope_of(req)

    def run():
        p = fw_params(sc)
        q = dash.ch.query
        sigs = q(f"""SELECT sig_id, any(signature) AS signature, any(category) AS category, min(severity) AS severity, count() AS hits,
                    uniq(src) AS sources, groupUniqArray(3)(action) AS actions, toUInt32(max(ts)) AS last
                    FROM netmon.ids_events WHERE {fw_where(sc)} GROUP BY sig_id ORDER BY severity, hits DESC LIMIT 50""", p)
        recent = q(f"""SELECT toUnixTimestamp64Milli(ts) AS ms, sig_id, signature, category, severity, action, proto,
                      replaceOne(IPv6NumToString(src), '::ffff:', '') AS src, sport, replaceOne(IPv6NumToString(dst), '::ffff:', '') AS dst,
                      dport, iface FROM netmon.ids_events WHERE {fw_where(sc)} ORDER BY ts DESC LIMIT 100""", p)
        for x in recent:
            x["src_name"] = cfg.label(x["src"])
        return {"ok": True, "scope": {"start": sc.start, "end": sc.end, "describe": sc.describe()}, "sources": sources(),
                "signatures": sigs, "recent": recent}
    return guard(run)


@app.get("/netmon/firewall", response_class=HTMLResponse)
def firewall_page(req: Request):
    s = sources()
    body = f"""{tabs(SECURITY_TABS, '/netmon/firewall')}{tip_box('syslog', open_=not s['fw']['last'])}<div id="fwstate"></div>
<section class="cards fit" id="cards"></section>
<section class="card"><div class="card-h"><h2>Firewall decisions over time</h2><div class="legend" id="fwlegend"></div></div><div id="fwts" class="chart"></div>
<p class="note">From OPNsense filter logs. Blocks come from the default-deny rule and any block rules with logging; passes appear only for rules that log them.</p></section>
<section class="quad">
<div class="card"><div class="card-h"><h2>Top blocked sources</h2></div><div id="t-src"></div></div>
<div class="card"><div class="card-h"><h2>Top blocked ports</h2></div><div id="t-ports"></div></div>
<div class="card"><div class="card-h"><h2>Internal hosts blocked (outbound)</h2></div><div id="t-lan"></div></div>
<div class="card"><div class="card-h"><h2>By interface &amp; direction</h2></div><div id="t-tot"></div></div></section>
<section class="card"><div class="card-h"><h2>Recent events</h2><div class="seg" id="fwact"><button data-v="block">Blocked</button><button data-v="pass">Allowed (logged)</button><button data-v="all">All</button></div></div>
<div id="t-recent"></div><div class="pager" id="pager"></div></section>"""
    return page(req, "Security · Firewall events", body, "/netmon/security", ("d3.min.js", "firewall.js"))


@app.get("/netmon/ids", response_class=HTMLResponse)
def ids_page(req: Request):
    s = sources()
    body = f"""{tabs(SECURITY_TABS, '/netmon/ids')}{tip_box('ids', open_=not s['ids']['last'])}<div id="idsstate"></div>
<section class="card"><div class="card-h"><h2>Signatures</h2><span class="muted small">Suricata on OPNsense · a signature match is evidence of a pattern, not proof of compromise</span></div><div id="t-sigs"></div></section>
<section class="card"><div class="card-h"><h2>Recent alerts</h2></div><div id="t-recent"></div></section>"""
    return page(req, "Security · IDS alerts", body, "/netmon/security", ("ids.js",))


# ---- firewalls (sites) ----------------------------------------------------------------------
import hashlib
import os

from .core import DATA_DIR, IFNAME, SITE_ID, VENDORS, apply_sites
from . import block as blk
from . import devices, vendors

HOST_JSON = os.path.join(DATA_DIR, "host-sites.json")
HOST_STATUS = os.path.join(DATA_DIR, "host-sites.status.json")
SECRETS = os.path.join(DATA_DIR, "secrets")


def _ip_or_none(v):
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def export_host_sites():
    """Hand the sender list to the root helper (netmon-apply-sites.path). Written only when it changes."""
    doc = {"version": 1, "sites": [{"id": x["id"], "exporter": x["exporter"], "flow_mode": x["flow_mode"], "wan_if": x["wan_if"],
                                    "exporter_ip": x.get("exporter_ip") or None, "syslog_source": x.get("syslog_source") or None,
                                    "ifindexes": {str(k): v for k, v in (x.get("ifindexes") or {}).items()}} for x in cfg.sites],
           "devices": devices.host_entries(cfg),
           "monitor": {"fqdn": monitor_settings()["fqdn"] or None, "address": _ip_or_none(monitor_address())}}
    text = json.dumps(doc, indent=1, sort_keys=True)
    try:
        if open(HOST_JSON).read() == text:
            return
    except OSError:
        pass
    tmp = HOST_JSON + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, HOST_JSON)


def host_status():
    """Has the root helper applied the current list? -> (state, detail)."""
    try:
        want = hashlib.sha256(open(HOST_JSON, "rb").read()).hexdigest()
    except OSError:
        return "pending", "not exported yet"
    try:
        st = json.load(open(HOST_STATUS))
    except (OSError, ValueError):
        return "pending", "waiting for netmon-apply-sites (systemd path unit) to run"
    if st.get("hash") != want:
        return "pending", "change not applied yet (usually takes a few seconds)"
    if not st.get("ok"):
        return "failed", st.get("error") or "failed"
    return "ok", f"applied {fmt_ts(st['applied_at'])}: " + "; ".join(st.get("actions") or [])


def sync_sites():
    apply_sites(cfg, conn)
    devices.apply_devices(cfg, conn)
    export_host_sites()


sync_sites()


def write_secret(name, value):
    os.makedirs(SECRETS, mode=0o700, exist_ok=True)
    path = os.path.join(SECRETS, name)
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value.strip() + "\n")
    os.replace(path + ".tmp", path)
    return path


def site_health():
    """Last NetFlow / syslog arrival per site, plus SNMP and blocking state."""
    exp = [x["exporter"] for x in cfg.sites]
    try:
        flows = {r["e"]: r["t"] for r in dash.ch.query(
            "SELECT ExporterName AS e, toUInt32(max(TimeReceived)) AS t FROM flows WHERE ExporterName IN {exps:Array(String)} "
            "AND TimeReceived > now() - INTERVAL 7 DAY GROUP BY e", {"exps": exp})}
        logs = {r["s"]: r["t"] for r in dash.ch.query(
            "SELECT site AS s, toUInt32(max(m)) AS t FROM (SELECT site, max(received) AS m FROM netmon.fw_events GROUP BY site "
            "UNION ALL SELECT site, max(received) FROM netmon.sys_events GROUP BY site UNION ALL SELECT site, max(received) FROM netmon.ids_events GROUP BY site) GROUP BY s")}
        extra = {(r["k"], r["s"]): r["t"] for r in dash.ch.query(
            "SELECT 'ids' AS k, site AS s, toUInt32(max(received)) AS t FROM netmon.ids_events GROUP BY site "
            "UNION ALL SELECT 'dns', site, toUInt32(max(received)) FROM netmon.dns_events WHERE startsWith(source, 'unbound') GROUP BY site", {})}
    except Exception:
        flows, logs, extra = {}, {}, {}
    out = {}
    for x in cfg.sites:
        sn = x.get("snmp") or {}
        st = [get_state(conn, f"snmp:{x['id']}:{n}", None)[0] for n in (sn.get("interfaces") or {})]
        out[x["id"]] = {"flows": flows.get(x["exporter"]) or None, "logs": logs.get(x["id"]) or None,
                        "ids": extra.get(("ids", x["id"])) or None, "dns": extra.get(("dns", x["id"])) or None,
                        "snmp": None if not sn else ("ok" if st and all(v and v.get("ok") for v in st) else
                                                       (next((v.get("error") for v in st if v and v.get("error")), None) or "no sample yet")),
                        "block": blk.enforcer(x).enabled}
    return out


def dns_note(site):
    from . import dnsresolve as dr
    d = dr.settings(conn, site["id"])
    if not d["fw_mode"]:
        return ""
    note = f" · {e(d['fw_note'])}" if d["fw_note"] else ""
    return (f"<div class='muted'>Firewall: Unbound query logging {e(dr.FW_MODES[d['fw_mode']])} · recorded by {e(d['noted_by'])} "
            f"{e(fmt_ts(d['noted_at']))}{note}</div>")


def dns_card(req, site, admin):
    """DNS for one firewall: what is set up on the firewall (operator's record) and how netmon names remote addresses."""
    from . import dnsresolve as dr
    d = dr.settings(conn, site["id"])
    server, how = dr.resolver_for(site, d)
    st = ((get_state(conn, "dnsnames:status", None)[0] or {}).get(site["id"])) or {}
    hour = st.get("hour", [])
    err = f" · last error: {st['error']}" if st.get("error") else ""
    stat = (f"Last hour: {sum(h[1] for h in hour):,} names resolved, {sum(h[2] for h in hour):,} addresses, "
            f"{sum(h[3] for h in hour):,} lookups failed{err}." if hour else "Not run yet (starts a minute after the app).")
    dis = "" if admin else "disabled"
    modes = "".join(f"<option value='{k}' {'selected' if k == d['fw_mode'] else ''}>{e(v)}</option>" for k, v in dr.FW_MODES.items())
    recorded = f"Recorded by {e(d['noted_by'])} {e(fmt_ts(d['noted_at']))}. " if d["noted_at"] else ""
    save = '<div class="row"><button class="primary">Save DNS settings</button></div>' if admin else ""
    return f"""<details {'' if d['fw_mode'] else 'open'}><summary>DNS: query log &amp; remote names (FQDN)</summary>
<form method=post action="/netmon/settings/sites/{e(site['id'])}/dns" class="stackform wide">{csrf_field(req)}
<h3>On the firewall</h3>
<div class="formgrid"><label>Unbound query logging<select name=fw_mode {dis}>{modes}</select></label>
<label>Note<input name=fw_note value="{e(d['fw_note'])}" maxlength=300 placeholder="e.g. Services → Unbound DNS → Advanced → Log Queries; Logging → Remote: Unbound" {dis}></label></div>
<p class="muted small">{recorded}A record of the firewall-side setting; what actually arrives is the "DNS query log" line above.</p>
<h3>Names for remote addresses</h3>
<label class="check"><input type=checkbox name=enabled value=1 {'checked' if d['enabled'] else ''} {dis}> Resolve looked-up names to label connections with their FQDN</label>
<label>Resolver<input name=resolver value="{e(d['resolver'])}" placeholder="automatic: {e(server or 'none')}" class="mono" {dis}></label>
<p class="muted small">Now using <span class="mono">{e(server or 'none')}</span> ({e(how)}). The query log carries names, not answers: netmon asks the
same resolver for each A/AAAA name a host looked up, and its cache normally returns the answer the host got. Connections then show the
name under the remote address (≈ = only another host looked it up). {e(stat)}</p>
{save}</form></details>"""


def ago_txt(t):
    if not t:
        return None
    d = time.time() - t
    return f"{int(d)} s ago" if d < 120 else f"{int(d / 60)} min ago" if d < 7200 else f"{d / 3600:.1f} h ago" if d < 172800 else f"{d / 86400:.0f} days ago"


def site_setup(x):
    """Vendor-specific setup steps with this site's values filled in."""
    mon = e(monitor_address())
    if x["vendor"] not in ("opnsense", "pfsense"):
        p = vendors.profile(x["vendor"])
        return (f"<p class='small'>{e(p['notes'])}</p><pre class='setup'>{e(vendors.setup_text(x['vendor'], monitor_address()))}</pre>"
                f"<p class='muted small'>Profile status {p['status']}. Live protocol status and parser coverage: "
                f"<a href='/netmon/settings/devices/{e(x['id'])}'>Settings → Devices</a>. In routed mode the WAN/LAN ifIndex values "
                f"decide traffic direction: read them from the device (SNMP ifIndex / ifName).</p>")
    if x["vendor"] == "pfsense":
        return f"""<ol class="steps">
<li><b>NetFlow</b> — System → Package Manager → install <code>softflowd</code>. Services → softflowd: Enable ✓ · Interface <b>WAN only</b>
(<code>{e(x['wan_if'])}</code>; capturing LAN too would count traffic twice) · Destination <code>{mon}:2055</code> · NetFlow version <code>9</code> ·
Flow tracking <code>full</code> · maximum flow lifetime <code>120</code> s if offered. softflowd reports one interface for both directions,
so direction is derived from this site's networks: keep <i>Internal / public networks</i> below complete.</li>
<li><b>Firewall logs</b> — Status → System Logs → Settings → Remote Logging: Enable ✓ · Remote log server <code>{mon}:5514</code> ·
Contents: <i>Firewall Events</i> (and <i>System Events</i>) · Log Message Format <code>syslog (RFC 5424)</code> recommended. pfSense sends UDP; both formats are parsed.
Also tick <i>Log packets matched from the default pass rules</i> (Settings tab) so inbound/outbound direction can be verified from state creation.</li>
<li><b>Suricata (optional)</b> — Services → Suricata → interface → Logs: EVE JSON log ✓, EVE output type <code>SYSLOG</code>; make sure the remote syslog
contents include it (<i>Everything</i>).</li>
<li><b>Bandwidth counters (optional)</b> — Services → SNMP: Enable ✓, read-only community, bind to the LAN address. Find the WAN index with
<code>snmpwalk -v2c -c COMMUNITY {e(x.get('snmp', {}).get('host') or 'FIREWALL')} 1.3.6.1.2.1.31.1.1.1.1</code> and enter it below.</li>
<li><b>Blocking (optional)</b> — install the pfSense REST API package (pfrest.org) · System → REST API: enable, auth <code>API Key</code> ·
create a dedicated user with only <code>api-v2-firewall-aliases-get</code> and <code>api-v2-firewall-alias-patch</code>, generate its key, paste it below ·
Firewall → Aliases: add Host alias <code>{e((x.get('block') or {}).get('block_alias', 'netmon_block'))}</code> · add block rules that use it (docs/BLOCKING.md).</li>
<li><b>Path to the monitor</b> — a remote firewall should reach <code>{mon}</code> through a site-to-site VPN. The NetFlow and syslog source address
the monitor sees must match the addresses entered here; only those are let through.</li></ol>"""
    return f"""<ol class="steps">
<li><b>NetFlow</b> — Reporting → NetFlow: Listening interfaces <b>WAN and LAN</b> · WAN interfaces <b>WAN</b> · Version <code>v9</code> ·
Destination <code>{mon}:2055</code> · active timeout <code>120</code> s. Read interface indexes with <code>netstat -inW</code> (Link#N) and enter WAN/LAN below.</li>
<li><b>Firewall logs</b> — System → Settings → Logging → Remote → +: Transport <code>TCP(4)</code> · Applications <code>filterlog</code>, <code>suricata</code> ·
Hostname <code>{mon}</code> · Port <code>5514</code> · RFC 5424 ✓.</li>
<li><b>Bandwidth counters (optional)</b> — Plugins: <code>os-net-snmp</code>; Services → Net-SNMP: read-only community on the LAN address; WAN ifIndex = Link#N.</li>
<li><b>Blocking (optional)</b> — API key for a user with only <i>Diagnostics: PF Table IP addresses</i>; alias <code>{e((x.get('block') or {}).get('block_alias', 'netmon_block'))}</code>; rules per docs/BLOCKING.md.</li>
<li><b>Path to the monitor</b> — remote firewalls reach <code>{mon}</code> through a site-to-site VPN; enter the source addresses the monitor sees.</li></ol>"""


def conn_form(req, x=None):
    """Add/edit form for a UI-managed firewall's connection settings."""
    x = x or {"vendor": "opnsense", "block": {}, "snmp": {}, "location": {}}
    b, sn = x.get("block") or {}, x.get("snmp") or {}
    ifx = {v["name"]: k for k, v in (x.get("ifindexes") or {}).items()}
    snidx = next(iter((sn.get("interfaces") or {}).values()), "")
    v = lambda k: e(x.get(k) if x.get(k) is not None else "")  # noqa: E731
    nets = lambda k: e(", ".join(x.get(k) or []))  # noqa: E731
    edit = "id" in x
    vend = "".join(f"<option value={k} {'selected' if x['vendor'] == k else ''}>{e(m['label'])}</option>" for k, m in VENDORS.items())
    action = f"/netmon/settings/sites/{e(x['id'])}/connection" if edit else "/netmon/settings/sites/add"
    return f"""<form method=post action="{action}" class="stackform wide fwform">{csrf_field(req)}
<div class="formgrid">
<label>Vendor<select name=vendor class="fw-vendor" {'disabled' if edit else ''}>{vend}</select></label>
<label>Site id (lowercase, permanent)<input name=sid value="{v('id')}" pattern="[a-z0-9][a-z0-9-]{{0,23}}" required {'disabled' if edit else ''} placeholder="e.g. branch1"></label>
<label>Display name<input name=name value="{v('name')}" maxlength=60 required placeholder="e.g. Branch 1 · pfSense"></label>
<label>NetFlow source IP (as seen here)<input name=exporter_ip value="{v('exporter_ip')}" required placeholder="10.20.0.1"></label>
<label>Syslog source IP (blank = same)<input name=syslog_source value="{e(x.get('syslog_source') if x.get('syslog_source') != x.get('exporter_ip') else '')}" placeholder="same as NetFlow source"></label>
<label>WAN interface name<input name=wan_if value="{v('wan_if')}" pattern="[A-Za-z0-9_.-]{{1,15}}" required placeholder="igb0 / ix0 / vtnet0"></label>
<label>WAN ifindex<input name=wan_idx type=number min=1 max=65535 value="{e(ifx.get(x.get('wan_if'), ''))}" placeholder="OPNsense: required"></label>
<label class="fw-routed">LAN interface name<input name=lan_if value="{v('lan_if')}" pattern="[A-Za-z0-9_.-]{{0,15}}" placeholder="bridge0 / igb1"></label>
<label class="fw-routed">LAN ifindex<input name=lan_idx type=number min=1 max=65535 value="{e(ifx.get(x.get('lan_if'), ''))}"></label>
<label>Internal networks (CIDR, comma-separated)<input name=internal_nets value="{nets('internal_nets')}" placeholder="10.20.0.0/24"></label>
<label>Public networks / WAN addresses<input name=public_nets value="{nets('public_nets')}" placeholder="203.0.113.8/29"></label>
<label>Shared outbound NAT address(es)<input name=nat value="{nets('outbound_nat_ips')}" placeholder="203.0.113.9"></label>
<label>WAN download capacity, Mb/s<input name=down type=number min=1 max=1000000 value="{v('wan_down_mbps')}" placeholder="contracted, not port speed"></label>
<label>WAN upload capacity, Mb/s<input name=up type=number min=1 max=1000000 value="{v('wan_up_mbps')}"></label>
</div>
<fieldset><legend>Bandwidth counters (SNMP, optional)</legend><div class="formgrid">
<label>SNMP host<input name=snmp_host value="{e(sn.get('host', ''))}" placeholder="firewall LAN address"></label>
<label>WAN ifIndex (SNMP)<input name=snmp_idx type=number min=1 max=65535 value="{e(snidx)}"></label>
<label>Read-only community<input name=snmp_comm type=password autocomplete=off placeholder="{'stored — leave blank to keep' if sn.get('community_file') else ''}"></label></div></fieldset>
<fieldset><legend>Blocking (optional)</legend><div class="formgrid">
<label>API base URL (https)<input name=block_url value="{e(b.get('base_url', ''))}" placeholder="https://10.20.0.1"></label>
<label>TLS name (if the cert is for a hostname)<input name=block_tls value="{e(b.get('tls_server_name', ''))}" placeholder="fw.example.net"></label>
<label>Alias<input name=block_alias value="{e(b.get('block_alias', 'netmon_block'))}" pattern="[A-Za-z0-9_]{{1,31}}"></label>
<label>API key <span class="muted">(OPNsense key:secret · pfSense key)</span><input name=block_key type=password autocomplete=off placeholder="{'stored — leave blank to keep' if b.get('key_file') else ''}"></label></div></fieldset>
<div class="row"><button class="primary">{'Save connection settings' if edit else 'Add firewall'}</button></div></form>"""


@app.post("/netmon/settings/sites/{sid}/dns")
def save_site_dns(req: Request, sid: str, fw_mode: str = Form(""), fw_note: str = Form(""), enabled: str = Form(""),
                  resolver: str = Form(""), csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    if not cfg.site(sid):
        raise HTTPException(404)
    from . import dnsresolve as dr
    try:
        d = dr.save_settings(conn, sid, {"fw_mode": fw_mode, "fw_note": fw_note, "enabled": enabled == "1", "resolver": resolver}, u)
        audit(conn, u, "site_dns_settings", {"site": sid, **{k: d[k] for k in ("fw_mode", "fw_note", "enabled", "resolver")}})
        msg = "DNS settings saved."
    except ValueError as ex:
        msg = f"Not saved: {ex}"
    return RedirectResponse(f"/netmon/settings/sites?msg={quote(msg)}#site-{quote(sid)}", 303)


@app.get("/netmon/settings/sites", response_class=HTMLResponse)
def sites_page(req: Request, msg: str = ""):
    from .dash import META
    from .views import site_locations
    u, r = user_of(req)
    admin = r == "admin"
    locs = {l["id"]: l for l in site_locations()}
    countries = sorted(((m["name"], cc) for cc, m in META.items()), key=lambda x: x[0])
    health = site_health()
    hs, hdetail = host_status()
    cards = ""
    for s in cfg.sites:
        loc = s.get("location") or {}
        h = health.get(s["id"], {})
        copts = "".join(f"<option value='{cc}' {'selected' if cc == loc.get('country') else ''}>{e(n)}</option>" for n, cc in countries)
        cur = locs.get(s["id"])
        dis = "" if admin else "disabled"
        badge = lambda ok, good, bad: f"<span class='sev s-{'good' if ok else 'muted'}'>{'●' if ok else '○'} {e(good if ok else bad)}</span>"  # noqa: E731
        status = f"""<ul class="plain small fwstat">
<li>NetFlow: {badge(h.get('flows'), f"last flow {ago_txt(h.get('flows'))}", 'nothing received yet')}</li>
<li>Syslog: {badge(h.get('logs'), f"last line {ago_txt(h.get('logs'))}", 'nothing received yet')}</li>
<li>IDS (Suricata EVE): {badge(h.get('ids'), f"last alert {ago_txt(h.get('ids'))}", 'nothing received yet')}</li>
<li>DNS query log: {badge(h.get('dns'), f"last query {ago_txt(h.get('dns'))}", 'nothing received yet')}{dns_note(s)}</li>
<li>Counters: {badge(h.get('snmp') == 'ok', 'SNMP polling', 'not set up' if h.get('snmp') is None else f"SNMP: {h.get('snmp')}")}</li>
<li>Blocking: {badge(h.get('block'), f"API key set · alias {blk.enforcer(s).alias}", 'not set up')}</li></ul>"""
        exp_ip = f" ({e(s['exporter_ip'])})" if s.get("exporter_ip") else ""
        lan_txt = f" · LAN {e(s['lan_if'])}" if s.get("lan_if") else ""
        how = "interfaces" if s["flow_mode"] == "routed" else "addresses (WAN capture)"
        tech = (f"{e(VENDORS.get(s['vendor'], {}).get('label', s['vendor']))} · exporter <code>{e(s['exporter'])}</code>{exp_ip}"
                f" · WAN {e(s['wan_if'])}{lan_txt} · {how} decide direction")
        cards += f"""<section class="card" id="site-{e(s['id'])}"><div class="card-h"><h2>{e(s['name'])}</h2><span class="muted small">{tech}</span></div>
<div class="grid2 even"><div>{status}</div><div class="meters one" data-capacity="{e(s['id'])}"></div></div>
<form method=post action="/netmon/settings/sites/{e(s['id'])}" class="stackform wide">{csrf_field(req)}
<h3>Location &amp; capacity</h3>
{"""<div class="geocode"><label>Find by address<span class="row"><input class="geo-q" type=search maxlength=200 placeholder="street, city, postcode or place name" autocomplete="off">
<button type=button class="geo-go">Look up</button></span></label><div class="geo-res" aria-live="polite"></div></div>""" if admin else ''}
<div class="formgrid"><label>Display name<input name=name value="{e(s['name'])}" maxlength=60 required {dis}></label>
<label>Location label (shown on the map)<input name=label value="{e(loc.get('label', ''))}" maxlength=60 placeholder="e.g. Ashburn DC, rack 12" {dis}></label>
<label>Latitude (−90…90)<input name=lat type=number step=any min=-90 max=90 value="{'' if loc.get('lat') is None else loc['lat']}" placeholder="exact site latitude" {dis}></label>
<label>Longitude (−180…180)<input name=lon type=number step=any min=-180 max=180 value="{'' if loc.get('lon') is None else loc['lon']}" placeholder="exact site longitude" {dis}></label>
<label>Country (fallback when lat/lon empty)<select name=country {dis}><option value="">— none —</option>{copts}</select></label>
<label>WAN download capacity, Mb/s<input name=down type=number min=1 max=1000000 value="{e(s.get('wan_down_mbps') or '')}" placeholder="contracted — not port speed" {dis}></label>
<label>WAN upload capacity, Mb/s<input name=up type=number min=1 max=1000000 value="{e(s.get('wan_up_mbps') or '')}" placeholder="contracted — not port speed" {dis}></label></div>
<p class="muted small">Map position now: {e(f"{cur['lat']:.4f}, {cur['lon']:.4f} — {cur['source']}") if cur else 'not set (no marker or arcs)'}.
Look up sends only the address you type to OpenStreetMap Nominatim, and only when you click it.</p>
{'<div class="row"><button class="primary">Save</button></div>' if admin else ''}</form>
{f"<details><summary>Connection settings</summary>{conn_form(req, s)}" + (f"<form method=post action='/netmon/settings/sites/{e(s['id'])}/delete' class='row confirm'>{csrf_field(req)}<button>Delete</button></form>" if len(cfg.sites) > 1 else "") + "</details>" if admin else ''}
{dns_card(req, s, admin)}
<details><summary>Setup steps on the {e(VENDORS.get(s['vendor'], {}).get('label', ''))} firewall</summary>{site_setup(s)}</details></section>"""
    hostbox = (f"<div class='banner {'' if hs == 'ok' else 'bad' if hs == 'failed' else 'warn'}'><b>Host access lists:</b> "
               f"{'applied' if hs == 'ok' else 'FAILED' if hs == 'failed' else 'pending'} — {e(hdetail)}</div>")
    add = (f"""<section class="card" id="add"><div class="card-h"><h2>Add a firewall</h2><span class="muted small">any profile · each firewall is its own site · routers and switches: Settings → Devices</span></div>
{conn_form(req)}<p class="muted small">Saving lets this firewall's NetFlow (UDP 2055) and syslog (5514 TCP+UDP) source through the monitor's host firewall,
registers it with Akvorado (collector restarts for a few seconds) and starts per-site detection, dashboards, logs and blocking.
Asset names and expected exposures are global: if two sites use the same private range, give their hosts distinct names.</p></section>""" if admin else "")
    body = f"""{tabs(SETTINGS_TABS, '/netmon/settings/sites')}{f"<div class='banner'>{e(msg)}</div>" if msg else ''}{hostbox}{monitor_card(req, admin)}{cards}{add}"""
    return page(req, "Settings · Firewalls & sites", body, "/netmon/settings", ("settings.js",), scoped=False)


_geo_last = [0.0]


@app.post("/netmon/api/geocode")
def api_geocode(req: Request, q: str = Form(...), csrf: str = Form("")):
    """Address -> candidate coordinates via OpenStreetMap Nominatim (admin only, on explicit request, 1 req/s per policy)."""
    check_csrf(req, csrf)
    u = need(req, "admin")
    q = " ".join(q.split())[:200]
    if len(q) < 3:
        return JSONResponse({"ok": False, "error": "Type at least 3 characters."})
    wait = _geo_last[0] + 1.1 - time.time()
    if wait > 0:
        time.sleep(wait)
    _geo_last[0] = time.time()
    try:
        r = httpx.get("https://nominatim.openstreetmap.org/search", timeout=10,
                      params={"q": q, "format": "jsonv2", "limit": 5, "addressdetails": 1},
                      headers={"User-Agent": "netmon-site-locator/1.0 (self-hosted OPNsense monitor)", "Accept-Language": "en"})
        r.raise_for_status()
        rows = r.json()
    except Exception as ex:  # network, HTTP or JSON error
        return JSONResponse({"ok": False, "error": f"Lookup failed: {type(ex).__name__}. Enter coordinates manually."})
    audit(conn, u, "geocode", q)
    out = [{"name": str(x.get("display_name", ""))[:200], "lat": round(float(x["lat"]), 5), "lon": round(float(x["lon"]), 5),
            "country": str((x.get("address") or {}).get("country_code", "")).upper()[:2],
            "label": str((x.get("address") or {}).get("city") or (x.get("address") or {}).get("town") or x.get("name") or "")[:60]}
           for x in rows if "lat" in x and "lon" in x]
    return JSONResponse({"ok": True, "results": out})


def _num(v, lo, hi, what="value"):
    if v is None or str(v).strip() == "":
        return None
    try:
        x = float(v)
    except ValueError:
        raise HTTPException(400, f"invalid {what}")
    if not lo <= x <= hi:
        raise HTTPException(400, f"{what} out of range")
    return x


def db_sites():
    return get_setting(conn, "sites:db", []) or []


def put_sites(sites, user):
    put_setting(conn, "sites:db", sites, user)
    sync_sites()


@app.post("/netmon/settings/sites/{sid}")
def save_site(req: Request, sid: str, name: str = Form(...), label: str = Form(""), lat: str = Form(""), lon: str = Form(""),
              country: str = Form(""), down: str = Form(""), up: str = Form(""), csrf: str = Form("")):
    from .dash import META
    u = need(req, "admin")
    check_csrf(req, csrf)
    sites = db_sites()
    x = next((s for s in sites if s["id"] == sid), None)
    if not x:
        raise HTTPException(404)
    la, lo_ = _num(lat, -90, 90, "latitude"), _num(lon, -180, 180, "longitude")
    if (la is None) != (lo_ is None):
        return RedirectResponse("/netmon/settings/sites?msg=" + quote("Enter both latitude and longitude, or neither."), 303)
    if country and country not in META:
        raise HTTPException(400, "unknown country")
    dn, upv = _num(down, 1, 1_000_000, "capacity"), _num(up, 1, 1_000_000, "capacity")
    x.update(name=name.strip()[:60] or sid, location={"lat": la, "lon": lo_, "country": country or None, "label": label.strip()[:60]},
             wan_down_mbps=int(dn) if dn else None, wan_up_mbps=int(upv) if upv else None)
    x.pop("wan_capacity_mbps", None)
    put_sites(sites, u)
    audit(conn, u, "site_updated", {"site": sid, "name": x["name"], "location": x["location"],
                                    "wan_down_mbps": x["wan_down_mbps"], "wan_up_mbps": x["wan_up_mbps"]})
    return RedirectResponse("/netmon/settings/sites?msg=" + quote("Saved. Map and capacity meters use the new values immediately.")
                            + f"#site-{sid}", 303)


def _ip(v, what, required=False):
    v = (v or "").strip()
    if not v:
        if required:
            raise ValueError(f"{what} is required")
        return ""
    a = ipaddress.ip_address(v)
    if a.is_unspecified or a.is_loopback or a.is_multicast or a.is_link_local:
        raise ValueError(f"{what}: {a} is not usable")
    return str(a)


def _cidrs(v, what):
    out = []
    for t in re.split(r"[\s,]+", (v or "").strip()):
        if t:
            try:
                out.append(str(ipaddress.ip_network(t, strict=False)))
            except ValueError:
                raise ValueError(f"{what}: {t} is not a CIDR")
    return out


def build_site(form, prev=None):
    """Validate the add/edit form into a site dict (raises ValueError with a user-facing message)."""
    prev = prev or {}
    vendor = prev.get("vendor") or form.get("vendor", "")
    if vendor not in VENDORS:
        raise ValueError("choose a firewall profile")
    sid = prev.get("id") or form.get("sid", "").strip()
    if not re.match(SITE_ID, sid):
        raise ValueError("site id: lowercase letters, digits and '-', up to 24 characters")
    if not prev and cfg.site(sid):
        raise ValueError(f"site id {sid} already exists")
    name = form.get("name", "").strip()[:60]
    if not name:
        raise ValueError("display name is required")
    exp_ip = _ip(form.get("exporter_ip"), "NetFlow source IP", True)
    sys_ip = _ip(form.get("syslog_source"), "syslog source IP") or exp_ip
    for x in cfg.sites:
        if x["id"] != sid and exp_ip in (x.get("exporter_ip"), x.get("syslog_source")):
            raise ValueError(f"{exp_ip} is already used by {x['name']}")
    mode = VENDORS[vendor]["flow_mode"]
    wan, lan = form.get("wan_if", "").strip(), form.get("lan_if", "").strip()
    if not re.match(IFNAME, wan):
        raise ValueError("WAN interface name is required (e.g. igb0)")
    if lan and not re.match(IFNAME, lan):
        raise ValueError("LAN interface name: letters, digits, . _ - only")
    vlabel = VENDORS[vendor]["label"]
    if mode == "routed":
        if not lan:
            raise ValueError(f"{vlabel}: enter the LAN interface name (flows are split by interface)")
    else:
        lan = ""
    wi, li = _num(form.get("wan_idx"), 1, 65535, "WAN ifindex"), _num(form.get("lan_idx"), 1, 65535, "LAN ifindex")
    if mode == "routed" and not (wi and li):
        raise ValueError(f"{vlabel}: enter the WAN and LAN ifIndex (SNMP ifIndex; OPNsense: netstat -inW, Link#N)")
    ifx = {}
    if wi:
        ifx[int(wi)] = {"name": wan, "description": "WAN", "speed": 0}
    if li and lan:
        ifx[int(li)] = {"name": lan, "description": "LAN", "speed": 0}
    internal, public = _cidrs(form.get("internal_nets"), "internal networks"), _cidrs(form.get("public_nets"), "public networks")
    if mode == "capture" and not (internal or public):
        raise ValueError("pfSense: enter this site's internal and/or public networks — direction is decided by address")
    nat = [str(ipaddress.ip_address(t)) for t in re.split(r"[\s,]+", form.get("nat", "").strip()) if t]
    dn, upv = _num(form.get("down"), 1, 1_000_000, "capacity"), _num(form.get("up"), 1, 1_000_000, "capacity")
    keep = {k: v for k, v in (prev.get("ifindexes") or {}).items() if v.get("name") not in (wan, lan, prev.get("wan_if"), prev.get("lan_if"))}
    ifx = {**keep, **{str(k): v for k, v in ifx.items()}}
    site = {"id": sid, "name": name, "vendor": vendor, "flow_mode": mode, "exporter": prev.get("exporter") or f"{vendor}-{sid}",
            "exporter_ip": exp_ip, "syslog_source": sys_ip, "wan_if": wan, "lan_if": lan, "ifindexes": ifx,
            "internal_nets": internal, "public_nets": public, "outbound_nat_ips": nat, "active_timeout": prev.get("active_timeout", 120),
            "wan_down_mbps": int(dn) if dn else None, "wan_up_mbps": int(upv) if upv else None,
            "location": prev.get("location") or {}}
    # blocking
    b = dict(prev.get("block") or {})
    url = form.get("block_url", "").strip()
    if url and not vendors.profile(vendor)["response"]:
        raise ValueError(f"blocking is not implemented for {vlabel}: leave the API fields empty (monitoring works without write access)")
    if url:
        if not re.match(r"^https://[A-Za-z0-9.\-\[\]:]+(:\d+)?/?$", url):
            raise ValueError("API base URL must be https://host[:port]")
        tls = form.get("block_tls", "").strip()
        if tls and not re.match(r"^[A-Za-z0-9.-]{1,253}$", tls):
            raise ValueError("TLS name must be a hostname")
        alias = form.get("block_alias", "").strip() or "netmon_block"
        if not re.match(r"^[A-Za-z0-9_]{1,31}$", alias):
            raise ValueError("alias: letters, digits and _ only")
        b.update(base_url=url.rstrip("/"), tls_server_name=tls, block_alias=alias)
        if form.get("block_key", "").strip():
            b["key_file"] = write_secret(f"{sid}-block.key", form["block_key"])
    else:
        b = {}
    site["block"] = b
    # SNMP
    sn = dict(prev.get("snmp") or {})
    host = form.get("snmp_host", "").strip()
    if host:
        idx = _num(form.get("snmp_idx"), 1, 65535, "SNMP ifIndex") or wi
        if not idx:
            raise ValueError("SNMP: enter the WAN ifIndex")
        sn.update(host=_ip(host, "SNMP host"), interfaces={wan: int(idx)}, interval_seconds=10)
        if form.get("snmp_comm", "").strip():
            sn["community_file"] = write_secret(f"{sid}-snmp", form["snmp_comm"])
        if not sn.get("community_file"):
            raise ValueError("SNMP: enter the read-only community")
    else:
        sn = {}
    site["snmp"] = sn
    return site


@app.post("/netmon/settings/sites/add")
async def add_site(req: Request):
    u = need(req, "admin")
    form = dict(await req.form())
    check_csrf(req, form.get("csrf", ""))
    try:
        site = build_site(form)
    except ValueError as ex:
        return RedirectResponse("/netmon/settings/sites?msg=" + quote(f"Not added: {ex}") + "#add", 303)
    put_sites(db_sites() + [site], u)
    audit(conn, u, "site_added", {k: site[k] for k in ("id", "name", "vendor", "exporter_ip", "syslog_source")})
    return RedirectResponse("/netmon/settings/sites?msg=" + quote(f"Added {site['name']}. Follow its setup steps below; status turns green when data arrives.")
                            + f"#site-{site['id']}", 303)


@app.post("/netmon/settings/sites/{sid}/connection")
async def edit_site(req: Request, sid: str):
    u = need(req, "admin")
    form = dict(await req.form())
    check_csrf(req, form.get("csrf", ""))
    sites = db_sites()
    prev = next((x for x in sites if x["id"] == sid), None)
    if not prev:
        raise HTTPException(404)
    try:
        site = build_site(form, prev)
    except ValueError as ex:
        return RedirectResponse("/netmon/settings/sites?msg=" + quote(f"Not saved: {ex}") + f"#site-{sid}", 303)
    put_sites([site if x["id"] == sid else x for x in sites], u)
    audit(conn, u, "site_connection_updated", {k: site[k] for k in ("id", "exporter_ip", "syslog_source", "wan_if", "lan_if")})
    return RedirectResponse("/netmon/settings/sites?msg=" + quote("Saved.") + f"#site-{sid}", 303)


@app.post("/netmon/settings/sites/{sid}/delete")
def delete_site(req: Request, sid: str, csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    sites = db_sites()
    if not any(x["id"] == sid for x in sites):
        raise HTTPException(404)
    if len(sites) == 1:
        return RedirectResponse("/netmon/settings/sites?msg=" + quote("The last firewall cannot be deleted."), 303)
    put_sites([x for x in sites if x["id"] != sid], u)
    for f in (f"{sid}-block.key", f"{sid}-snmp"):
        try:
            os.remove(os.path.join(SECRETS, f))
        except OSError:
            pass
    audit(conn, u, "site_deleted", {"site": sid})
    return RedirectResponse("/netmon/settings/sites?msg=" + quote(f"Deleted {sid}. Its senders are removed from the host access lists; "
                                                                  "past alerts and data stay."), 303)
