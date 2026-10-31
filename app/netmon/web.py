"""netmon web UI: login, dashboard, alerts, blocks, exceptions, users, audit.

Identity comes from a server-side session cookie. Caddy calls /auth/verify
(forward_auth) before proxying to Akvorado, and receives Remote-User back.
"""
import hashlib
import hmac
import html
import ipaddress
import json
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from . import auth, threatradar
from . import block as blk
from .core import (DATA_DIR, EXPECTED_KEY, ClickHouse, ThreadLocalDB, audit, db_connect, expected_devices, expected_match, get_setting, get_state,
                   load_config, put_setting, set_state)
from .dash import Dash
from .detect import Detector, exception_matches, fmt_ts, human_bytes
from .notify import Notifier
from .counters import Poller, init as counters_init

cfg = load_config()
ch = ClickHouse(cfg["clickhouse_url"])
BRAND = str(cfg.get("brand") or "netmon")      # product name in the header and page titles
conn = ThreadLocalDB()
auth.init(conn)
counters_init(conn)
auth.bootstrap_admin(conn, os.environ.get("NETMON_ADMIN_PASSWORD_FILE", "/run/secrets/admin_password"))
notifier = Notifier(cfg, conn, cfg["akvorado_url"])
det = Detector(cfg, ch, conn, notifier)
dash = Dash(cfg, ch)


def enforcement():
    """(connected, total) firewalls with a working blocking API key."""
    return sum(blk.enforcer(x).enabled for x in cfg.sites), len(cfg.sites)


def site_name(sid):
    x = cfg.site(sid) if sid else None
    return x["name"] if x else (sid or "—")


def site_checks(req_sites=None, name="sites"):
    """Firewall checkboxes for a block request (default: every firewall)."""
    return "".join(f"<label class='chk'><input type=checkbox name={name} value='{e(x['id'])}' "
                   f"{'checked' if not req_sites or x['id'] in req_sites else ''}> {e(x['name'])}"
                   f"{'' if blk.enforcer(x).enabled else ' <span class=muted>(no API key)</span>'}</label>" for x in cfg.sites)
@asynccontextmanager
async def _lifespan(_app):
    start()   # background threads (detector, ingest, health); defined below
    yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)
app.mount("/netmon/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


def _asset_version() -> str:
    """Changes whenever any static file changes, so a deploy never runs new pages against cached old scripts."""
    d = os.path.join(os.path.dirname(__file__), "static")
    h = hashlib.sha256()
    for f in sorted(os.listdir(d)):
        st = os.stat(os.path.join(d, f))
        h.update(f"{f}:{st.st_size}:{st.st_mtime_ns}".encode())
    return h.hexdigest()[:10]


ASSET_V = _asset_version()
from . import __version__ as VERSION   # noqa: E402
CHANGELOG = os.path.join(os.path.dirname(os.path.dirname(__file__)), "CHANGELOG.md")


@app.middleware("http")
async def static_revalidate(request: Request, call_next):
    resp = await call_next(request)
    if request.url.path.startswith("/netmon/static/"):
        resp.headers["Cache-Control"] = "no-cache"  # always revalidate (cheap: ETag -> 304)
    return resp

_key_path = os.path.join(DATA_DIR, "csrf.key")
if not os.path.exists(_key_path):
    with open(os.open(_key_path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
        f.write(secrets.token_hex(32))
CSRF_KEY = open(_key_path).read().strip().encode()

ROLES = auth.ROLES
e = lambda v: html.escape("" if v is None else str(v), quote=True)  # noqa: E731
SEV_STATUS = {"critical": "critical", "high": "critical", "medium": "serious", "low": "warning", "info": "muted"}
SEV_ICON = {"critical": "▲", "high": "▲", "medium": "◆", "low": "●", "info": "○"}


class LoginRequired(Exception):
    pass


class MustEnroll(Exception):
    pass


@app.exception_handler(MustEnroll)
def _enroll_redirect(req: Request, exc):
    if req.url.path.startswith("/netmon/api/"):
        return JSONResponse({"error": "two-factor enrollment required"}, status_code=403)
    return RedirectResponse("/netmon/account?enroll=1", 303)


@app.exception_handler(LoginRequired)
def _login_redirect(req: Request, exc):
    if req.url.path.startswith("/netmon/api/"):
        return JSONResponse({"error": "login required"}, status_code=401)
    return RedirectResponse("/login?next=" + quote(req.url.path), 303)


@app.exception_handler(HTTPException)
async def _http_error(req: Request, exc: HTTPException):
    """Browser form posts get a readable page with a way back; API calls and everything else keep FastAPI's JSON."""
    if req.method == "POST" and not req.url.path.startswith("/netmon/api/") and exc.status_code in (400, 403, 404):
        parts = req.url.path.rstrip("/").split("/")  # no Referer (no-referrer policy): go back to the section page
        back = "/".join(parts[:4]) if req.url.path.startswith("/netmon/settings/") else "/".join(parts[:3]) or "/netmon/"
        back = html.escape(back, quote=True)
        hint = ("Your form was out of date (for example after signing in again in another tab). Reload the page and try again."
                if "CSRF" in str(exc.detail) else "")
        body = f"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Not saved</title><link rel=stylesheet href="/netmon/static/app.css?v={ASSET_V}"><script src="/netmon/static/theme.js?v={ASSET_V}"></script><main class="loginbox"><h1>Not saved</h1>
<p>{html.escape(str(exc.detail))}.</p><p class="muted">{hint}</p><p><a href="{back}">Back to the page</a></p></main>"""
        return HTMLResponse(body, status_code=exc.status_code, headers=SECURITY_HEADERS)
    from fastapi.exception_handlers import http_exception_handler
    return await http_exception_handler(req, exc)


@app.exception_handler(RequestValidationError)
async def _validation_error(req: Request, exc: RequestValidationError):
    """A missing or empty required form field stays a plain 400 as before the FastAPI 0.16x upgrade; type errors keep 422."""
    errs = exc.errors()
    if errs and all(e.get("type") == "missing" for e in errs):
        fields = sorted({str(e.get("loc", ["", "?"])[-1]) for e in errs})
        return await _http_error(req, HTTPException(400, "missing field: " + ", ".join(fields)))
    from fastapi.exception_handlers import request_validation_exception_handler
    return await request_validation_exception_handler(req, exc)


def client_ip(req: Request) -> str:
    # Caddy (host network, loopback) sets X-Forwarded-For; the app only listens on 127.0.0.1.
    return (req.headers.get("x-forwarded-for", "").split(",")[0].strip() or
            (req.client.host if req.client else "?"))


ENROLL_OK = ("/netmon/account", "/logout", "/netmon/static")


def must_enroll(user: str) -> bool:
    if not get_setting(conn, "require_2fa", False):
        return False
    r = conn.execute("SELECT totp_enabled FROM users WHERE username=?", (user,)).fetchone()
    return not (r and r["totp_enabled"])


def current(req: Request):
    s = auth.session_user(conn, req.cookies.get(auth.SESSION_COOKIE))
    if not s:
        raise LoginRequired()
    if must_enroll(s[0]) and not req.url.path.startswith(ENROLL_OK):
        raise MustEnroll()
    return s  # (user, role, session_hash)


def user_of(req: Request):
    u, r, _ = current(req)
    return u, r


def need(req: Request, role: str) -> str:
    u, r = user_of(req)
    if ROLES[r] < ROLES[role]:
        raise HTTPException(403, f"requires role {role}")
    return u


def csrf_token(req_or_sid) -> str:
    sid = req_or_sid if isinstance(req_or_sid, str) else current(req_or_sid)[2]
    return hmac.new(CSRF_KEY, sid.encode(), hashlib.sha256).hexdigest()


def check_csrf(req: Request, token: str):
    origin = req.headers.get("origin")
    if origin and origin.split("://", 1)[-1] != req.headers.get("host"):
        print(f"WARNING csrf: origin {origin!r} != host {req.headers.get('host')!r} on {req.url.path}", flush=True)
        raise HTTPException(403, "cross-origin request refused")
    if not hmac.compare_digest(token or "", csrf_token(req)):
        print(f"WARNING csrf: {'missing' if not token else 'stale/invalid'} token on {req.url.path}", flush=True)
        raise HTTPException(403, "invalid CSRF token")


def csrf_field(req):
    return f'<input type="hidden" name="csrf" value="{csrf_token(req)}">'


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                               "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",  # not no-referrer: browsers then send "Origin: null" on form POSTs, failing check_csrf
}

NAV = [("Overview", "/", "viewer"), ("Wallboards", "/netmon/wallboards", "viewer"), ("Servers", "/netmon/servers", "viewer"),
       ("Connections", "/netmon/connections", "viewer"), ("Countries", "/netmon/countries", "viewer"),
       ("Security", "/netmon/security", "viewer"), ("Investigations", "/netmon/investigations", "viewer"),
       ("Settings", "/netmon/settings", "viewer")]


def scopebar():
    sites = "".join(f'<option value="{e(x["id"])}">{e(x["name"])}</option>' for x in cfg["sites"])
    ranges = "".join(f'<button data-range="{k}">{k}</button>' for k in ("15m", "1h", "6h", "24h", "7d", "custom"))
    return f"""<div class="scopebar" id="scopebar">
<select id="site" aria-label="Site"><option value="all">All sites</option>{sites}</select>
<div class="seg" id="range" role="group" aria-label="Time range">{ranges}</div>
<span id="custom" class="custom" hidden><input type="datetime-local" id="from" aria-label="From"> – <input type="datetime-local" id="to" aria-label="To"> <button id="apply">Apply</button></span>
<button id="live" class="live" aria-pressed="true">❚❚ Pause</button>
<span id="fresh" class="pill">…</span>
<form action="/netmon/search" class="search" role="search"><input name="q" id="q" placeholder="Search server, IP, country, service, ASN" aria-label="Search"></form>
</div><div id="chips" class="chips"></div>"""


def page(req, title, body, active="", scripts=(), wide=True, scoped=True, subtitle=""):
    u, r = user_of(req)
    nav = "".join(f'<a href="{href}" class="{"on" if href == active else ""}">{e(name)}</a>'
                  for name, href, role in NAV if ROLES[r] >= ROLES[role])
    scr = "".join(f'<script src="/netmon/static/{s}?v={ASSET_V}"></script>' for s in scripts)
    return HTMLResponse(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)} · {e(BRAND)}</title>
<meta name="nm-csrf" content="{e(csrf_token(req))}"><meta name="nm-role" content="{e(r)}">
<link rel="stylesheet" href="/netmon/static/app.css?v={ASSET_V}"><script src="/netmon/static/theme.js?v={ASSET_V}"></script></head><body class="role-{e(r)}">
<header class="appbar"><a class="brand" href="/"><span class="logo">◎</span> {e(BRAND)}</a><a class="ver" href="/netmon/changelog" title="Version — what changed">v{VERSION}</a>
<nav class="mainnav">{nav}<a href="/visualize" target="_blank" rel="noopener" class="ext" title="Akvorado: raw flow exploration">Advanced flow explorer ↗</a></nav>
<div class="who"><select class="themebtn" data-theme-toggle aria-label="Color theme" title="Color theme"><option value="auto">◐ System</option><option value="light">☀ Light</option><option value="dark">☾ Dark</option></select> <span>{e(u)}</span> <small>{e(r)}</small>
<form method="post" action="/logout" class="inline">{csrf_field(req)}<button class="link">Sign out</button></form></div></header>
<main class="{'wide' if wide else ''}">
<div class="titlerow"><h1>{e(title)}</h1>{f'<span class="muted">{e(subtitle)}</span>' if subtitle else ''}<span id="scopedesc" class="muted small"></span></div>
{scopebar() if scoped else '<div id="fresh" class="pill solo">…</div>'}
{body}<p class="attrib muted small">Country and ASN data: <a href="https://ipinfo.io" rel="noopener">IP address data powered by IPinfo</a>
(CC BY-SA 4.0) · map: Natural Earth · <a href="/netmon/coverage">what is visible</a> · <a href="/netmon/changelog">v{VERSION}</a></p></main><script src="/netmon/static/common.js?v={ASSET_V}"></script>{scr}</body></html>""", headers=SECURITY_HEADERS)


def sev(s):
    st = SEV_STATUS.get(s, "muted")
    return f'<span class="sev s-{st}">{SEV_ICON.get(s, "○")} {e(s)}</span>'


# ---- auth -------------------------------------------------------------------
LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in · {brand}</title>
<link rel="stylesheet" href="/netmon/static/app.css?v={ASSET_V}"><script src="/netmon/static/theme.js?v={ASSET_V}"></script></head><body class="login"><select class="themebtn" data-theme-toggle aria-label="Color theme" title="Color theme"><option value="auto">◐ System</option><option value="light">☀ Light</option><option value="dark">☾ Dark</option></select>
<form method="post" action="/login" class="loginbox">
<div class="brand big"><span class="logo">◎</span> {brand} <span class="ver">v{version}</span></div>
<p class="muted">Network monitoring for {exporter}</p>
{error}
<label>Username<input name="username" autocomplete="username" required autofocus></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<input type="hidden" name="next" value="{next}">
<button class="primary">Sign in</button>
<p class="muted small">Access is logged. Sessions expire after 2 h idle / 12 h.</p></form></body></html>"""


# post-login destinations: this app and the Akvorado console. Anything else (stale bookmarks, scanners probing
# /wp-admin etc.) lands on the overview instead of Akvorado's "Not found!".
NEXT_PREFIXES = ("/netmon/", "/visualize", "/docs", "/api/v0/console")  # plus "/" (overview)


def safe_next(n: str) -> str:
    ok = n.startswith("/") and not n.startswith("//") and "\\" not in n
    if n in ("/netmon", "/netmon/"):
        return "/"
    return n if ok and (n == "/" or n.startswith(NEXT_PREFIXES)) else "/"


@app.get("/login", response_class=HTMLResponse)
def login_page(next: str = "/", error: str = ""):
    msg = {"bad": "Invalid username or password.", "slow": "Too many attempts. Try again in 15 minutes."}.get(error, "")
    return HTMLResponse(LOGIN_HTML.format(ASSET_V=ASSET_V, version=VERSION, brand=e(BRAND), exporter=e(cfg["exporter"]), next=e(safe_next(next)),
                                          error=f'<div class="err">{e(msg)}</div>' if msg else ""),
                        headers=SECURITY_HEADERS)


def _issue_session(req, username, nxt, method):
    token = auth.create_session(conn, username, client_ip(req), req.headers.get("user-agent", ""))
    audit(conn, username, "login", {"ip": client_ip(req), "method": method})
    r = RedirectResponse(nxt, 303)
    r.set_cookie(auth.SESSION_COOKIE, token, max_age=auth.SESSION_TTL, httponly=True, secure=True, samesite="lax", path="/")
    r.delete_cookie("netmon_mfa", path="/login")
    return r


@app.post("/login")
def login_post(req: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/netmon/")):
    ip, nxt = client_ip(req), safe_next(next)
    username = username.strip()[:64]
    if auth.throttled(conn, ip, username):
        audit(conn, username or "?", "login_throttled", {"ip": ip})
        return RedirectResponse(f"/login?error=slow&next={quote(nxt)}", 303)
    row = auth.check_password(conn, username, password, ip)
    if not row:
        audit(conn, username or "?", "login_failed", {"ip": ip})
        return RedirectResponse(f"/login?error=bad&next={quote(nxt)}", 303)
    if row["totp_enabled"]:
        tok = auth.start_mfa(conn, username, ip, nxt)
        r = RedirectResponse("/login/2fa", 303)
        r.set_cookie("netmon_mfa", tok, max_age=300, httponly=True, secure=True, samesite="strict", path="/login")
        return r
    return _issue_session(req, username, nxt, "password")


MFA_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Two-factor · {brand}</title>
<link rel="stylesheet" href="/netmon/static/app.css?v={ASSET_V}"><script src="/netmon/static/theme.js?v={ASSET_V}"></script></head><body class="login"><select class="themebtn" data-theme-toggle aria-label="Color theme" title="Color theme"><option value="auto">◐ System</option><option value="light">☀ Light</option><option value="dark">☾ Dark</option></select>
<form method="post" action="/login/2fa" class="loginbox">
<div class="brand big"><span class="logo">◎</span> {brand} <span class="ver">v{version}</span></div>
<p class="muted">Enter the 6-digit code from your authenticator app for <b>{user}</b>, or a recovery code.</p>{error}
<label>Code<input name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus maxlength="16"></label>
<button class="primary">Verify</button><p class="muted small"><a href="/login">Start over</a></p></form></body></html>"""


@app.get("/login/2fa", response_class=HTMLResponse)
def mfa_page(req: Request, error: str = ""):
    p = auth.pending_mfa(conn, req.cookies.get("netmon_mfa"))
    if not p:
        return RedirectResponse("/login", 303)
    msg = {"bad": "That code is not valid.", "slow": "Too many attempts. Start over in 15 minutes."}.get(error, "")
    return HTMLResponse(MFA_HTML.format(ASSET_V=ASSET_V, version=VERSION, brand=e(BRAND), user=e(p["username"]), error=f'<div class="err">{e(msg)}</div>' if msg else ""),
                        headers=SECURITY_HEADERS)


@app.post("/login/2fa")
def mfa_post(req: Request, code: str = Form(...)):
    tok = req.cookies.get("netmon_mfa")
    p = auth.pending_mfa(conn, tok)
    if not p:
        return RedirectResponse("/login", 303)
    ip = client_ip(req)
    if auth.throttled(conn, ip, p["username"]):
        auth.finish_mfa(conn, tok)
        return RedirectResponse("/login?error=slow", 303)
    method = auth.verify_second_factor(conn, p["username"], code)
    if not method:
        auth.record_failure(conn, ip, p["username"])
        audit(conn, p["username"], "mfa_failed", {"ip": ip})
        return RedirectResponse("/login/2fa?error=bad", 303)
    auth.finish_mfa(conn, tok)
    if method == "recovery":
        audit(conn, p["username"], "recovery_code_used", {"ip": ip})
    return _issue_session(req, p["username"], p["next"] or "/", f"password+{method}")


@app.post("/logout")
def logout_post(req: Request, csrf: str = Form("")):
    u, _, _ = current(req)
    check_csrf(req, csrf)
    auth.logout(conn, req.cookies.get(auth.SESSION_COOKIE))
    audit(conn, u, "logout", {})
    r = RedirectResponse("/login", 303)
    r.delete_cookie(auth.SESSION_COOKIE, path="/")
    return r


@app.get("/auth/verify")
def verify(req: Request):
    """Caddy forward_auth target for Akvorado. 200 + Remote-User, else redirect to login."""
    s = auth.session_user(conn, req.cookies.get(auth.SESSION_COOKIE))
    if not s:
        uri = req.headers.get("x-forwarded-uri", "/")
        return RedirectResponse("/login?next=" + quote(safe_next(uri)), 302)
    if must_enroll(s[0]):
        return RedirectResponse("/netmon/account?enroll=1", 302)
    return Response(status_code=200, headers={"Remote-User": s[0]})


@app.get("/netmon/changelog", response_class=HTMLResponse)
def changelog_page(req: Request):
    """What changed in each version (CHANGELOG.md shipped in the image)."""
    current(req)
    try:
        text = open(CHANGELOG, encoding="utf-8").read()
    except OSError:
        text = "CHANGELOG.md is not in this build."
    return page(req, "Changelog", f'<section class="card"><pre class="changelog">{e(text)}</pre></section>', subtitle=f"running v{VERSION}", scoped=False)


@app.get("/netmon/healthz")
def healthz():
    st, ts = get_state(conn, "detector", {})
    ok = bool(ts and time.time() - ts < 3 * cfg["detector"]["interval_seconds"])
    return JSONResponse({"detector_ok": ok, "last_run": ts, "version": VERSION}, status_code=200 if ok else 503)


def detector_status():
    st, ts = get_state(conn, "detector", {})
    return {"last_run": ts, "learning_days": (st or {}).get("learning_days", 0),
            "baseline_days": cfg["detector"]["baseline_days"], "errors": (st or {}).get("errors", [])}


def internal_ip(ip: str) -> str:
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(400, "bad ip")
    if not cfg.is_internal(ip):
        raise HTTPException(400, "not an internal address")
    return ip


CATEGORY = {"new_dest_country": "info", "new_dest_asn": "info", "fw_blocked_scan": "info", "ids_alert": "security",
            "fw_blocked_outbound": "security", "syslog_silence": "health", "unexpected_inbound": "security",
            "outbound_volume": "security", "fanout": "security", "beaconing": "security",
            "exporter_silence": "health", "disk_usage": "health", "detector_error": "health", "source_health": "health", "dns_bypass": "info", "dns_anomaly": "security", "test": "test",
            "auto_block": "response"}
RULE_LABEL = {"new_dest_country": "New country", "new_dest_asn": "New network (ASN)",
              "unexpected_inbound": "Unexpected inbound service", "outbound_volume": "Outbound volume above baseline",
              "fanout": "Scanning / fan-out", "beaconing": "Periodic connections (beacon-like)",
              "source_health": "Monitoring source health", "dns_bypass": "Uses external DNS resolvers", "dns_anomaly": "DNS anomaly", "exporter_silence": "Telemetry stopped", "disk_usage": "Disk space", "detector_error": "Detector error",
              "test": "Test alert", "ids_alert": "IDS signature (Suricata)", "fw_blocked_outbound": "Outbound blocked by firewall",
              "fw_blocked_scan": "Blocked inbound scanning", "syslog_silence": "Firewall log feed stopped",
              "auto_block": "Auto-response block"}


@app.get("/netmon/alerts")
def alerts_redirect():
    return RedirectResponse("/netmon/security", 301)


DIRECTION = {"inbound": "⬇ Inbound", "outbound": "⬆ Outbound", "internal": "↔ Internal",
             "both": "⇅ Both directions", "transit": "Transit"}


def direction_badge(a):
    d = a["direction"] if "direction" in a.keys() else None
    if not d:
        return ""
    ok = a["direction_verified"]
    return (f"<span class='dir dir-{e(d)}{'' if ok else ' unverified'}' title='{e(a['direction_basis'] or '')}'>"
            f"{e(DIRECTION.get(d, d))}<small>{'✓ verified' if ok else '? unverified'}</small></span>")


def ongoing(a, traffic=False):
    """Is this finding still happening? From local evidence only: re-detections by the detector (count,
    first/last seen) and, with traffic=True, flows with the finding's named endpoints in the last 15 minutes."""
    now = time.time()
    interval = cfg["detector"]["interval_seconds"]
    days = conn.execute("SELECT count(DISTINCT date(ts, 'unixepoch')) FROM audit WHERE action='alert_created' AND detail LIKE ?",
                        (f'%"key": "{a["key"]}"%',)).fetchone()[0] if "key" in a.keys() else 0
    span_h = (a["last_seen"] - a["first_seen"]) / 3600
    out = {"first_seen": fmt_ts(a["first_seen"]), "last_seen": fmt_ts(a["last_seen"]), "detections": a["count"],
           "span_hours": round(span_h, 1), "days_seen": max(days, 1), "recent_flows": None, "recent_window_min": 15}
    if a["status"] == "closed":
        out["state"], out["label"] = "closed", f"Closed · last detected {fmt_ts(a['last_seen'])}"
    elif now - a["last_seen"] <= 3 * interval:
        out["state"], out["label"] = "active", f"Active: re-detected {a['count']}× over {span_h:.1f} h, last {int((now - a['last_seen']) / 60)} min ago"
    else:
        out["state"], out["label"] = "quiet", f"Not re-detected since {fmt_ts(a['last_seen'])} ({a['count']}× over {span_h:.1f} h)"
    if traffic and a["status"] != "closed":
        peers = candidate_peers(a)
        if peers:
            try:
                sc = dash.scope(range_key="15m")
                from .dash import REMOTE_IP
                n = dash.q(sc, f"SELECT count() AS n FROM flows WHERE {dash.where(sc)} AND has({{p:Array(String)}}, {REMOTE_IP})",
                           {"p": peers[:200]})[0]["n"]
                out["recent_flows"] = int(n)
                if n and out["state"] == "quiet":
                    out["state"], out["label"] = "traffic", f"{out['label']}; traffic with its endpoints continues ({int(n):,} flow records in 15 min)"
            except Exception:
                pass
    if out["state"] in ("active", "quiet") and a["count"] > 1 and span_h >= 1:
        out["label"] += " · recurring"
    return out


def ai_scores(aid):
    rows = conn.execute("SELECT id, ts, model, result FROM investigations WHERE kind='alert' AND target=? ORDER BY id", (str(aid),)).fetchall()
    out = []
    for r in rows:
        try:
            sc = json.loads(r["result"] or "{}").get("threat_score")
        except ValueError:
            sc = None
        if sc is not None:
            out.append({"id": r["id"], "ts": r["ts"], "model": r["model"], "score": sc})
    return out


def score_chip(score):
    band = "critical" if score >= 81 else "serious" if score >= 61 else "warning" if score >= 41 else "muted"
    return (f"<span class='aiscore s-{band}' title='AI estimate (0-100) that this is a legitimate threat; evidence-limited'>"
            f"AI threat {score}</span>")


def lan_hosts(a):
    """Return-path attribution stored with a shared-NAT finding (see Detector.nat_hosts); [] if none."""
    for ev in json.loads(a["evidence"] or "[]"):
        if isinstance(ev, dict) and "lan_hosts" in ev:
            return ev
    return None


def lan_hosts_text(a):
    ev = lan_hosts(a)
    if not ev:
        return ""
    total = sum(h["destinations"] for h in ev["lan_hosts"]) + ev.get("dsts_ambiguous", 0) + ev.get("dsts_no_reply", 0)
    if not ev["lan_hosts"]:
        return f"no LAN host identified: none of {total:,} destinations replied to a single host"
    top = ", ".join(f"{cfg.asset_label(h['host'])}{' [expected]' if h.get('expected') else ''} ({h['destinations']:,} of {total:,} destinations)"
                    for h in ev["lan_hosts"][:3])
    return f"likely LAN host{'s' if len(ev['lan_hosts']) > 1 else ''}: {top}" + \
        (f"; {ev['dsts_no_reply']:,} never replied (not attributable)" if ev.get("dsts_no_reply") else "")


def expected_button(req, ip, back):
    return (f"<form method=post action='/netmon/expected' class='inline'>{csrf_field(req)}<input type=hidden name=target value='{e(ip)}'>"
            f"<input type=hidden name=back value='{e(back)}'><input name=reason required maxlength=200 placeholder='why it is legitimate' class='sm'>"
            f"<button class='sm' title='Exclude this device from findings (Security → Suppressions)'>Mark expected</button></form>")


def lan_hosts_dd(a, req=None, can_edit=False):
    ev = lan_hosts(a)
    if not ev:
        return ""
    exp = expected_devices(conn)
    back = f"/netmon/alert/{a['id']}"
    links = "".join(f"<li><a href='/netmon/servers/{quote(h['host'])}'>{e(cfg.asset_label(h['host']))}</a> — {h['destinations']:,} destinations "
                    f"({h['share_pct']}%) "
                    + ("<span class='tag'>expected device</span>" if expected_match(exp, h["host"]) else
                       expected_button(req, h["host"], back) if can_edit and req else "") + "</li>" for h in ev["lan_hosts"])
    return (f"<div class='small'><b>Behind the NAT address</b> (return path):<ul>{links or '<li>no single host identified</li>'}</ul>"
            f"<span class='muted'>{ev.get('dsts_ambiguous', 0):,} destinations replied to several hosts · {ev.get('dsts_no_reply', 0):,} never replied "
            f"— unanswered probes cannot be attributed from flow records.</span></div>")


def ack_form(req, a, back):
    """Per-card triage on the Security list: Ack on open findings, Unack (back to open) on acked ones."""
    if a["status"] not in ("open", "acked"):
        return ""
    to, label, tip = (("acked", "Ack", "Acknowledge: moves it to the acked tab") if a["status"] == "open" else
                      ("open", "Unack", "Unacknowledge: moves it back to the open tab"))
    return (f"<form method=post action='/netmon/alert/{a['id']}/status' class='inline ack'>{csrf_field(req)}{back_field(back)}"
            f"<input type=hidden name=list value=1><input type=hidden name=status value={to}>"
            f"<button class='sm' title='{tip}'>{label}</button></form>")


def finding_card(a, ack=""):
    nxt = (json.loads(a["next_steps"] or "[]") or [""])[0]
    asset = cfg.asset_label(a["asset"]) if a["asset"] else "—"
    link = f"/netmon/servers/{quote(a['asset'])}" if a["asset"] and _is_internal_safe(a["asset"]) else ""
    return f"""<article class="finding f-{SEV_STATUS.get(a['severity'], 'muted')}">
<div class="fh">{sev(a['severity'])}{direction_badge(a)}<span class="muted small">{(e(site_name(a['site'])) + ' · ') if len(cfg.sites) > 1 and 'site' in a.keys() else ''}confidence {e(a['confidence'])} · {e(RULE_LABEL.get(a['rule'], a['rule']))}
 · {e(a['count'])}× · last {e(fmt_ts(a['last_seen']))}</span>{score_chip(sc[-1]['score']) if (sc := ai_scores(a['id'])) else ''}<span class="tag">{e(ongoing(a)['state'] if a['status'] != 'closed' else 'closed')}</span><span class="tag">{e(a['status'])}</span>{ack}</div>
<a class="ft" href="/netmon/alert/{a['id']}">{e(a['title'])}</a>
<div class="fg"><div><span class="k">Server</span>{f'<a href="{link}">{e(asset)}</a>' if link else e(asset)}{f'<div class="small">{e(lh)}</div>' if (lh := lan_hosts_text(a)) else ''}</div>
<div><span class="k">Why it differs from normal</span>{e(a['baseline'])}</div>
<div><span class="k">Next step</span>{e(nxt)}</div></div></article>"""


@app.get("/netmon/security", response_class=HTMLResponse)
def security_page(req: Request, status: str = "open"):
    u, r = user_of(req)
    if status not in ("open", "acked", "closed", "all"):
        status = "open"
    where = "WHERE status=? AND test=0" if status != "all" else "WHERE test=0"
    rows = conn.execute(f"SELECT * FROM alerts {where} ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                        f"WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC LIMIT 300",
                        (status,) if status != "all" else ()).fetchall()
    groups = {"security": [], "response": [], "info": [], "health": []}
    for a in rows:
        groups.setdefault(CATEGORY.get(a["rule"], "security"), []).append(a)
    st = detector_status()
    learn = (f"<div class='banner warn'><b>Baseline still learning:</b> {st['learning_days'] * 24:.1f} hours of {st['baseline_days']} days collected. "
             f"New-country/new-network changes start at day {cfg['detector']['min_learning_days']} and stay low-confidence until the baseline completes. "
             f"Volume, scanning, beaconing and exposure checks run now.</div>" if st["learning_days"] < st["baseline_days"] else "")
    status_tabs = "".join(f"<a class='{'on' if s == status else ''}' href='/netmon/security?status={s}'>{s}</a>"
                   for s in ("open", "acked", "closed", "all"))
    from .admin import sources as _src
    S = _src()
    fwcard = (f"<div class='v'>{S['fw']['blocks24']:,}</div><div class='s'>firewall events → · last {e(fmt_ts(S['fw']['last']))}</div>"
              if S["fw"]["last"] else "<div class='v na'>Firewall logs not connected</div><div class='s'>blocked counts unavailable — not zero · set up →</div>")
    idscard = (f"<div class='v'>{S['ids']['alerts24']:,}</div><div class='s'>IDS alerts → · last {e(fmt_ts(S['ids']['last']))}</div>"
               if S["ids"]["last"] else "<div class='v na'>Not connected</div><div class='s'>enable Suricata (alert-only) · set up →</div>")
    sources = f"""<section class="cards fit">
<a class="kpi link" href="/netmon/settings/rules"><div class="k">Flow-based detection</div><div class="v ok">● Running</div><div class="s">every {cfg['detector']['interval_seconds'] // 60} min · last {e(fmt_ts(st['last_run'])) if st['last_run'] else 'never'}</div></a>
<a class="kpi link" href="/netmon/firewall"><div class="k">Firewall blocks (24 h)</div>{fwcard}</a>
<a class="kpi link" href="/netmon/ids"><div class="k">Suricata IDS (24 h)</div>{idscard}</a>
<a class="kpi link" href="/netmon/settings/integrations"><div class="k">Threat intelligence</div><div class="v na">No feeds configured</div><div class="s">add licensed feeds in config</div></a>
<a class="kpi link" href="/netmon/blocks"><div class="k">Enforcement</div><div class="v {'ok' if enforcement()[0] else 'na'}">{f"{enforcement()[0]} of {enforcement()[1]} firewalls" if enforcement()[0] else 'Not set up'}</div><div class="s">block requests →</div></a>
</section>"""
    can_ack, back = ROLES[r] >= ROLES["analyst"], f"/netmon/security?status={status}"
    # Ack all covers every open finding (the list shows at most 300), up to the newest one at page load
    n_open, max_id = conn.execute("SELECT count(*), max(id) FROM alerts WHERE status='open' AND test=0").fetchone()
    ack_all = (f"<form method=post action='/netmon/alerts/ack' class='inline' data-confirm='Acknowledge all {n_open:,} open findings?'>"
               f"{csrf_field(req)}{back_field(back)}<input type=hidden name=max_id value='{max_id}'>"
               f"<button title='Acknowledge every open finding, including any beyond the 300 listed'>Ack all ({n_open:,})</button></form>"
               if can_ack and status == "open" and n_open else "")
    # Unack all on the acked tab: everything acked before the page loaded (acks made since then stay acked)
    n_acked = conn.execute("SELECT count(*) FROM alerts WHERE status='acked' AND test=0").fetchone()[0]
    if can_ack and status == "acked" and n_acked:
        ack_all = (f"<form method=post action='/netmon/alerts/unack' class='inline' data-confirm='Move all {n_acked:,} acked findings back to open?'>"
                   f"{csrf_field(req)}{back_field(back)}<input type=hidden name=asof value='{time.time():.3f}'>"
                   f"<button title='Move every acked finding back to the open tab'>Unack all ({n_acked:,})</button></form>")

    def sec(title, desc, items, empty):
        cards = "".join(finding_card(a, ack_form(req, a, back) if can_ack else "")
                        for a in items) or f"<p class='empty'>{e(empty)}</p>"
        return f"<section class='card'><div class='card-h'><h2>{e(title)} <span class='count'>{len(items)}</span></h2><span class='muted small'>{e(desc)}</span></div>{cards}</section>"
    test_btn = (f"<form method=post action='/netmon/test-alert' class='inline'>{csrf_field(req)}"
                f"<button>Create clearly-marked TEST alert</button></form>") if r == "admin" else ""
    from .admin import SECURITY_TABS, tabs
    body = (tabs(SECURITY_TABS, "/netmon/security") + learn + sources + f"<div class='toolbar'><div class='seg links'>{status_tabs}</div>{ack_all}{test_btn}</div>" +
            sec("Security alerts", "credible suspicious behavior, with evidence", groups["security"], "No security alerts in this view") +
            sec("Auto-response actions", "addresses netmon blocked automatically, with the evidence and expiry", groups["response"], "No automatic blocks in this view") +
            sec("Informational changes", "new countries or networks — not malicious by themselves", groups["info"], "No informational changes") +
            sec("Monitoring health", "telemetry and system problems", groups["health"], "Monitoring is healthy"))
    return page(req, "Security", body, "/netmon/security", (), scoped=False,
                subtitle="Findings from flow metadata. Country is never treated as malicious by itself.")


EV_LABELS = {"src": "Source", "dst": "Destination", "dsts": "Distinct destinations", "max_ports": "Most ports on one destination (traceroute probes excluded)",
             "flows": "Flow records", "top_dst": "Top destination", "top_dsts": "Top destinations", "sample_ports": "Example destination ports (up to 10, across all destinations)", "distinct_ports": "Distinct destination ports (all destinations)",
             "top_dst_ports": "Ports contacted on top destination", "dsts_ambiguous": "Destinations that replied to several LAN hosts",
             "dsts_no_reply": "Destinations that never replied (not attributable)",
             "dsts_expected": "Destinations explained by expected devices (not counted)", "expected_hosts": "Expected devices involved", "lan_hosts_basis": "LAN host attribution basis", "top_dst_traceroute": "Traceroute probes to top destination",
             "ports": "Ports", "port": "Port", "peers": "Remote peers", "sample_peers": "Sample remote peers", "peer": "Remote peer",
             "bytes": "Bytes", "packets": "Packets", "count": "Count", "proto": "Protocol", "country": "Country", "asn": "Network (ASN)",
             "interval": "Interval (s)", "jitter": "Interval jitter", "first": "First seen", "last": "Last seen", "baseline": "Baseline"}
PORT_NAMES = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
              123: "ntp", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog", 587: "smtp submission",
              853: "dns-over-tls", 993: "imaps", 995: "pop3s", 1194: "openvpn", 1433: "mssql", 3306: "mysql", 3389: "rdp", 3478: "stun/turn",
              5060: "sip", 5222: "xmpp", 5228: "google push", 5432: "postgresql", 5900: "vnc", 6881: "bittorrent", 8006: "proxmox",
              8080: "http-alt", 8443: "https-alt", 51820: "wireguard"}


def port_label(p):
    try:
        p = int(p)
    except (TypeError, ValueError):
        return e(p)
    name = PORT_NAMES.get(p) or ("traceroute (UDP)" if 33434 <= p <= 33534 else "")
    return f"<span class='chip static'>{p}{f' <span class=muted>{e(name)}</span>' if name else ''}</span>"


def evidence_table(evs):
    out = ""
    for ev in evs if isinstance(evs, list) else [evs]:
        if not isinstance(ev, dict):
            continue
        rows = ""
        for k, v in ev.items():
            if k in ("dsts_expected", "expected_hosts") and not v:
                continue      # nothing excluded: no row
            label = EV_LABELS.get(k, k.replace("_", " ").capitalize())
            if "port" in k and isinstance(v, (list, int)):
                vals = sorted(v, key=lambda x: int(x) if str(x).isdigit() else 0) if isinstance(v, list) else [v]
                cell = f"<div class='chiplist'>{''.join(port_label(x) for x in vals)}</div>"
            elif k == "lan_hosts":
                label = "LAN hosts behind the NAT address"
                cell = ", ".join(f"{e(cfg.asset_label(h['host']))}: {h['destinations']:,} ({h['share_pct']}%)" for h in v) or "none identified"
            elif isinstance(v, list):
                cell = e(", ".join(map(str, v)))
            elif isinstance(v, (int, float)) and not isinstance(v, bool) and k not in ("asn", "port"):
                cell = f"<span class='num'>{v:,}</span>" if isinstance(v, int) else e(v)
            else:
                cell = e(v)
            rows += f"<tr><th>{e(label)}</th><td>{cell}</td></tr>"
        out += f"<div class='wrap'><table class='tbl kv'>{rows}</table></div>"
    return out or "<p class='muted'>No structured evidence</p>"


def candidate_peers(a):
    out = []
    for ev in json.loads(a["evidence"] or "[]"):
        for k in ("peers", "sample_peers", "top_dsts", "peer", "top_dst"):
            v = ev.get(k) if isinstance(ev, dict) else None
            for ip in (v if isinstance(v, list) else [v] if v else []):
                try:
                    blk.validate_target(cfg, str(ip))
                    out.append(str(ip))
                except blk.BlockError:
                    pass
    return list(dict.fromkeys(out))[:20]


def list_return(req: Request) -> str:
    """Where triage should land afterwards: the list the finding was opened from (same-origin Referer), else Security."""
    from urllib.parse import urlsplit
    ref = urlsplit(req.headers.get("referer", ""))
    path = ref.path + (f"?{ref.query}" if ref.query else "")
    if ref.netloc != req.headers.get("host", "") or not ref.path or ref.path.startswith("/netmon/alert/"):
        return "/netmon/security"
    return safe_next(path)


def back_field(back: str) -> str:
    return f'<input type="hidden" name="back" value="{e(back)}">'


@app.get("/netmon/alert/{aid}", response_class=HTMLResponse)
def alert_view(req: Request, aid: int, back: str = ""):
    u, r = user_of(req)
    a = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    if not a:
        raise HTTPException(404)
    q = json.loads(a["query"] or "{}")
    lis = lambda xs: "".join(f"<li>{e(x)}</li>" for x in json.loads(xs or "[]"))  # noqa: E731
    back = safe_next(back) if back else list_return(req)
    actions = ""
    if ROLES[r] >= ROLES["analyst"]:
        actions += f"""<div class="card"><div class="card-h"><h2>Triage</h2></div>
<form method=post action="/netmon/alert/{aid}/status" class="row">{csrf_field(req)}{back_field(back)}
<select name=status><option>acked</option><option>closed</option><option>open</option></select> <button>Set status</button></form>
</div>{normal_card(req, a, back)}"""
        peers = candidate_peers(a)
        if peers:
            opts = "".join(f"<option>{e(p)}</option>" for p in peers)
            actions += f"""<div class="card"><div class="card-h"><h2>Request block</h2></div>
<p class="muted small">Creates a pending request with an impact preview. An admin must approve it before anything changes on OPNsense.</p>
<form method=post action="/netmon/blocks" class="row">{csrf_field(req)}<input type=hidden name=alert_id value="{aid}">
<select name=address>{opts}</select> <input name=reason placeholder="reason" required size=40>
<span class="chks">Block on: {site_checks([a['site']] if a['site'] else None)}</span> <button>Preview block</button></form></div>"""
    link = f"/netmon/servers/{quote(a['asset'])}" if a["asset"] and _is_internal_safe(a["asset"]) else ""
    evs = json.loads(a["evidence"] or "[]")
    og, scores = ongoing(a, traffic=True), ai_scores(aid)
    can_ai = ROLES[r] >= ROLES["analyst"]
    from .views import ai as _ai
    last = conn.execute("SELECT id, ts, user, model, result, usage FROM investigations WHERE kind='alert' AND target=? ORDER BY id DESC LIMIT 1",
                        (str(aid),)).fetchone()
    saved = (json.dumps({"id": last["id"], "ts": last["ts"], "user": last["user"], "model": last["model"],
                         "result": json.loads(last["result"] or "{}"), "usage": json.loads(last["usage"] or "{}")}).replace("</", "<\\/")
             if last else "")
    ai_box = (f"""<div class="card" id="aibox" data-aid="{aid}" data-enabled="{'1' if _ai.enabled else '0'}" data-model="{e(_ai.ac.get('model', ''))}">
<div class="card-h"><h2>AI analysis</h2><div class="panelctl"><span class="muted small">{'model ' + e(_ai.ac.get('model', '')) + f' · {_ai.used_today()} of {_ai.ac.get("daily_request_limit")} requests today' if _ai.enabled else 'not configured — <a href="/netmon/investigations">set up</a>'}</span>
<button id="aigo" class="{'' if last else 'primary'}">{'Re-analyze' if last else 'Analyze with AI'}</button></div></div>
<p class="muted small">Builds minimized, pseudonymized evidence for this finding. You review it before anything is sent; AI never changes the firewall.</p>
<div id="aipreview"></div><div id="airesult"></div>{f'<script type="application/json" id="aisaved">{saved}</script>' if saved else ''}<input type="hidden" id="csrf" value="{e(csrf_token(req))}"></div>""" if can_ai else "")
    body = f"""<div class="card"><div class="fh">{sev(a['severity'])} <span class="muted">confidence {e(a['confidence'])} ·
{e(RULE_LABEL.get(a['rule'], a['rule']))} · {e(CATEGORY.get(a['rule'], 'security'))} · status {e(a['status'])}{(' · acked by ' + e(a['acked_by'])) if a['acked_by'] else ''}</span></div>
<h2 class="title">{e(a['title'])}</h2>
<dl class="facts"><dt>Firewall</dt><dd>{e(site_name(a['site']))}</dd><dt>Direction</dt><dd>{direction_badge(a) or '—'} <span class="muted small">{e(a['direction_basis'] or 'not applicable')}</span></dd>
<dt>Affected server</dt><dd>{f'<a href="{link}">{e(cfg.asset_label(a["asset"]))}</a>' if link else e(cfg.asset_label(a['asset']) if a['asset'] else '—')}{lan_hosts_dd(a, req, ROLES[r] >= ROLES["analyst"])}</dd>
<dt>Time window</dt><dd>{e(fmt_ts(a['window_start']))} → {e(fmt_ts(a['window_end']))}</dd>
<dt>Seen</dt><dd>{e(a['count'])}× ({e(fmt_ts(a['first_seen']))} → {e(fmt_ts(a['last_seen']))})</dd>
<dt>Ongoing?</dt><dd><span class="tag og-{e(og['state'])}">{e(og['state'])}</span> {e(og['label'])}
 <span class="muted small">(re-detections by the detector{'; flows with the named endpoints in the last 15 min: ' + format(og['recent_flows'], ',') if og['recent_flows'] is not None else ''})</span></dd>
<dt>AI threat score</dt><dd>{(score_chip(scores[-1]['score']) + ' <span class="muted small">' + ' → '.join(f"<a href='/netmon/investigations/{x['id']}' title='{e(fmt_ts(x['ts']))} · {e(x['model'])}'>{x['score']}</a>" for x in scores) + ' (history, oldest first)</span>') if scores else '<span class="muted">not analyzed yet</span>'}</dd>
<dt>Why it differs from normal</dt><dd>{e(a['baseline'])}</dd>
<dt>Notification</dt><dd>{e(a['notify_status'] or 'not sent (no destination configured)')}</dd></dl>
<div class="grid2 even"><div><h3>Other possible explanations</h3><ul>{lis(a['alternatives'])}</ul></div>
<div><h3>Next investigation steps</h3><ul>{lis(a['next_steps'])}</ul>
<p>{'<a class="btn" href="#aibox">Analyze with AI ↓</a> ' if can_ai else ''}<a class="btn" href="/visualize" target="_blank" rel="noopener">Open flow explorer</a></p></div></div></div>
<section class="card" id="ftraffic" data-aid="{aid}"><div class="card-h"><h2>Traffic behind this finding</h2>
<div class="panelctl"><span class="muted small" id="ftscope"></span><div class="seg" id="mapdir" role="group" aria-label="Direction"><button data-v="both">Both</button><button data-v="in">Inbound</button><button data-v="out">Outbound</button></div>
<details class="info"><summary aria-label="About this view" title="About this view">i</summary><div class="pop" id="mapnote"></div></details></div></div>
<div class="grid2"><div><div id="map" class="map"></div><div class="legend" id="maplegend"></div></div>
<div><h3 class="grp">Destination ports</h3><div id="ft-ports" class="wrap"></div></div></div>
<h3 class="grp">Remote endpoints (to and from)</h3><div id="ft-remotes" class="wrap"></div></section>
<div class="card"><div class="card-h"><h2>Evidence</h2><span class="muted small">values from flow records; strings are untrusted telemetry</span></div>
{evidence_table(evs)}</div>
{ai_box}
<div class="card"><div class="card-h"><h2>Technical details</h2></div>
<details><summary>Technical details: raw evidence, Akvorado filter and triggering query</summary>
<pre>{e(json.dumps(evs, indent=1))}</pre><h3>Akvorado filter</h3><pre>{e(a['akvorado_filter'])}</pre>
<pre>{e(q.get('sql'))}</pre><pre>{e(json.dumps(q.get('params')))}</pre></details></div>
{actions}"""
    return page(req, f"Finding #{aid}", body, "/netmon/security", ("d3.min.js", "topojson-client.min.js", "map.js", "finding.js"), scoped=False)


def _is_internal_safe(ip):
    try:
        return cfg.is_internal(ip)
    except ValueError:
        return False


def normal_card(req, a, back="/netmon/security"):
    """'This is normal' on a finding: stop it (or everything for the address) from triggering again, and close the
    matching findings already raised. Suppression only: the traffic is not marked trusted anywhere else."""
    label = cfg.asset_label(a["asset"]) if a["asset"] else ""
    shared = a["asset"] in cfg.get("outbound_nat_ips", [])
    rule = e(RULE_LABEL.get(a["rule"], a["rule"]))
    opt = lambda v, text, checked=False: (f"<label class='check'><input type=radio name=scope value={v} {'checked' if checked else ''}> {text}</label>")  # noqa: E731
    scopes = (opt("rule", f"Any <b>{rule}</b> finding for <b>{e(label or a['asset'])}</b>", True)
              + (opt("exact", f"Only this exact finding (<span class='mono'>{e(a['subject'])}</span>)") if a["subject"] not in ("", "*") else "")
              + ("" if shared or not a["asset"] else
                 opt("device", f"Every finding for <span class='mono'>{e(a['asset'])}</span> (expected device)")))
    note = ("<p class='muted small'>This is the shared NAT address, used by every LAN host: suppress the finding type here, or mark the "
            "individual LAN hosts expected in the attribution above.</p>" if shared else "")
    return f"""<div class="card" id="normal"><div class="card-h"><h2>This is normal</h2></div>
<form method=post action="/netmon/alert/{a['id']}/normal" class="stackform">{csrf_field(req)}{back_field(back)}
<p class="muted small">Stops future triggers and closes the matching findings already raised. It only suppresses findings: the traffic is not
marked trusted anywhere else, and you can undo it under Security → Suppressions.</p>{note}
<fieldset><legend>Don't alert again for</legend>{scopes}</fieldset>
<label>Reason<input name=reason required maxlength=200 placeholder="e.g. crawler: fan-out is what this server does"></label>
<label>Expires after (days)<input name=expires_days inputmode=numeric maxlength=5 placeholder="never" class="short"></label>
<label class="check"><input type=checkbox name=close value=1 checked> Close matching open findings now</label>
<div class="row"><button class="primary">Don't alert again</button></div></form>
<details class="tech"><summary>Advanced exception (any rule / asset / subject pattern)</summary>
<form method=post action="/netmon/exceptions" class="row">{csrf_field(req)}
<input name=rule value="{e(a['rule'])}" size=18> <input name=asset value="{e(a['asset'])}" size=16>
<input name=subject value="{e(a['subject'])}" size=18> <input name=owner placeholder="owner" required size=10>
<input name=reason placeholder="reason" required size=24> <input name=expires_days placeholder="expires (days)" size=8>
<button>Add exception</button></form></details></div>"""


@app.post("/netmon/alert/{aid}/normal")
def alert_normal(req: Request, aid: int, scope: str = Form(...), reason: str = Form(...), expires_days: str = Form(""),
                 close: str = Form(""), back: str = Form(""), csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    a = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    if not a:
        raise HTTPException(404)
    reason = " ".join(reason.split())[:200]
    if not reason:
        raise HTTPException(400, "reason required")
    try:
        exp = time.time() + float(expires_days) * 86400 if expires_days.strip() else None
    except ValueError:
        raise HTTPException(400, "expires must be a number of days")
    now = time.time()
    if scope in ("rule", "exact"):
        exc = {"rule": a["rule"], "asset": a["asset"], "subject": "*" if scope == "rule" else a["subject"],
               "enabled": 1, "expires_at": exp}
        conn.execute("INSERT INTO exceptions(rule,asset,subject,owner,reason,created_by,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?)",
                     (exc["rule"], exc["asset"], exc["subject"], u, f"{reason} (from finding #{aid})", u, now, exp))
        audit(conn, u, "exception_added", {"rule": exc["rule"], "asset": exc["asset"], "subject": exc["subject"], "expires": exp, "alert": aid})
        hit = lambda x: exception_matches(exc, x["rule"], x["asset"], x["subject"], now)  # noqa: E731
    elif scope == "device":
        try:
            ip = str(ipaddress.ip_address(a["asset"]))
        except ValueError:
            raise HTTPException(400, "this finding has no single address to mark expected")
        if ip in cfg.get("outbound_nat_ips", []):
            raise HTTPException(400, "that is the shared NAT address (every LAN host) — mark the individual devices instead")
        d = get_setting(conn, EXPECTED_KEY, {}) or {}
        d[ip] = {"reason": f"{reason} (from finding #{aid})", "by": u, "ts": now, "expires_at": exp}
        put_setting(conn, EXPECTED_KEY, d, u)
        audit(conn, u, "expected_device_added", {"target": ip, "reason": d[ip]["reason"], "expires": exp, "alert": aid})
        hit = lambda x: x["asset"] == ip  # noqa: E731
    else:
        raise HTTPException(400, "unknown scope")
    closed = []
    if close:
        for x in conn.execute("SELECT id, rule, asset, subject FROM alerts WHERE status IN ('open','acked') AND test=0").fetchall():
            if x["id"] == aid or hit(x):
                conn.execute("UPDATE alerts SET status='closed', acked_by=?, acked_at=? WHERE id=?", (u, now, x["id"]))
                closed.append(x["id"])
        if closed:
            audit(conn, u, "alert_status", {"ids": closed, "status": "closed", "reason": "marked normal"})
    conn.commit()
    # closed: back to the list it came from (it is gone from there now); otherwise stay on the finding
    return RedirectResponse(safe_next(back) if closed and back else f"/netmon/alert/{aid}", 303)


@app.post("/netmon/alert/{aid}/status")
def alert_status(req: Request, aid: int, status: str = Form(...), back: str = Form(""), list: str = Form(""),
                 csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    if status not in ("open", "acked", "closed"):
        raise HTTPException(400)
    # reopening clears "acked by" (the audit log keeps who acked and who reopened)
    conn.execute("UPDATE alerts SET status=?, acked_by=?, acked_at=? WHERE id=?",
                 (status, None, None, aid) if status == "open" else (status, u, time.time(), aid))
    conn.commit()
    audit(conn, u, "alert_status", {"id": aid, "status": status})
    if "application/json" in req.headers.get("accept", ""):   # list buttons (fetch): no page to go to
        return JSONResponse({"ok": True, "id": aid, "status": status})
    # acked/closed drop off the open lists, so return to the list rather than leaving the user on the finding;
    # reopening from the finding page stays there, from a list button (Unack) it returns to that list
    return RedirectResponse(safe_next(back) if back and (status != "open" or list) else f"/netmon/alert/{aid}", 303)


@app.post("/netmon/alerts/ack")
def alerts_ack(req: Request, max_id: int = Form(...), back: str = Form(""), csrf: str = Form("")):
    """Ack all: acknowledges every open finding up to the newest one when the page loaded (ids only grow), so findings
    raised after that stay open. Not limited to the rows the page lists."""
    u = need(req, "analyst")
    check_csrf(req, csrf)
    acked = [x[0] for x in conn.execute("SELECT id FROM alerts WHERE status='open' AND test=0 AND id<=?", (max_id,)).fetchall()]
    if acked:
        conn.executemany("UPDATE alerts SET status='acked', acked_by=?, acked_at=? WHERE id=?", [(u, time.time(), i) for i in acked])
        conn.commit()
        audit(conn, u, "alert_status", {"ids": acked, "status": "acked", "reason": "ack all"})
    return RedirectResponse(safe_next(back) if back else "/netmon/security", 303)


@app.post("/netmon/alerts/unack")
def alerts_unack(req: Request, asof: float = Form(...), back: str = Form(""), csrf: str = Form("")):
    """Unack all: moves every finding acked before the page loaded (acked_at <= asof) back to open."""
    u = need(req, "analyst")
    check_csrf(req, csrf)
    ids = [x[0] for x in conn.execute("SELECT id FROM alerts WHERE status='acked' AND test=0 AND (acked_at IS NULL OR acked_at<=?)",
                                      (asof,)).fetchall()]
    if ids:
        conn.executemany("UPDATE alerts SET status='open', acked_by=NULL, acked_at=NULL WHERE id=?", [(i,) for i in ids])
        conn.commit()
        audit(conn, u, "alert_status", {"ids": ids, "status": "open", "reason": "unack all"})
    return RedirectResponse(safe_next(back) if back else "/netmon/security?status=acked", 303)


@app.post("/netmon/test-alert")
def test_alert(req: Request, csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    now = time.time()
    cur = conn.execute(
        "INSERT INTO alerts(key,rule,severity,confidence,asset,subject,title,first_seen,last_seen,window_start,window_end,"
        "evidence,query,baseline,alternatives,next_steps,akvorado_filter,test) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
        (f"test|{now}", "test", "info", "high", "monitor", "test", f"TEST ALERT requested by {u} — not a real event",
         now, now, now, now, "[]", "{}", "n/a", "[]", '["Close this alert"]', ""))
    conn.commit()
    audit(conn, u, "test_alert", {"id": cur.lastrowid, "webhook": notifier.enabled})
    threading.Thread(target=notifier.alert, args=(cur.lastrowid, True), daemon=True).start()
    return RedirectResponse(f"/netmon/alert/{cur.lastrowid}", 303)


# ---- exceptions ---------------------------------------------------------------
@app.get("/netmon/exceptions", response_class=HTMLResponse)
def exceptions(req: Request):
    u, r = user_of(req)
    rows = conn.execute("SELECT * FROM exceptions ORDER BY id DESC").fetchall()
    trs = "".join(
        f"<tr><td>{x['id']}</td><td><code>{e(x['rule'])}</code></td><td>{e(x['asset'])}</td><td>{e(x['subject'])}</td><td>{e(x['owner'])}</td>"
        f"<td>{e(x['reason'])}</td><td>{e(x['created_by'])}</td><td>{e(fmt_ts(x['expires_at'])) if x['expires_at'] else 'never'}</td>"
        f"<td>{'yes' if x['enabled'] else 'no'}</td><td>"
        + (f"<form method=post action='/netmon/exceptions/{x['id']}/disable'>{csrf_field(req)}<button>Disable</button></form>"
           if x["enabled"] and ROLES[r] >= 1 else "") + "</td></tr>" for x in rows)
    from .admin import SECURITY_TABS, tabs
    exp = get_setting(conn, EXPECTED_KEY, {}) or {}
    now = time.time()
    etr = "".join(
        f"<tr><td class='mono'>{e(t)}</td><td>{e(cfg.asset_label(t) if '/' not in t else t)}</td><td>{e(v.get('reason'))}</td><td>{e(v.get('by'))}</td>"
        f"<td>{e(fmt_ts(v['ts']))}</td><td>{e(fmt_ts(v['expires_at'])) if v.get('expires_at') else 'never'}"
        f"{' <span class=tag>expired</span>' if v.get('expires_at') and v['expires_at'] < now else ''}</td><td>"
        + (f"<form method=post action='/netmon/expected/remove' class='inline'>{csrf_field(req)}<input type=hidden name=target value='{e(t)}'>"
           f"<button>Remove</button></form>" if ROLES[r] >= 1 else "") + "</td></tr>" for t, v in sorted(exp.items()))
    add = (f"""<form method=post action="/netmon/expected" class="row">{csrf_field(req)}
<label>IP or CIDR<input name=target required class="mono" placeholder="10.0.0.21 or 10.0.0.32/28"></label>
<label class="span2">Why it is legitimate<input name=reason required maxlength=200 placeholder="e.g. contact crawler for the CRM"></label>
<label>Expires after (days)<input name=expires_days inputmode=numeric placeholder="never"></label><button class="primary">Add expected device</button></form>"""
           if ROLES[r] >= 1 else "")
    expected_card = (f"""<section class="card"><div class="card-h"><h2>Expected devices</h2><span class="muted small">legitimate traffic by your decision · excluded from findings</span></div>
<p class="muted small">Findings about these addresses are not raised. Behind a shared NAT address, destinations that replied to these devices are not
counted towards fan-out, and other findings are dropped when every named peer replied only to them. Destinations that never replied cannot be
attributed and still count. Traffic is still recorded and shown on every page. Changes are audited.</p>
<div class="wrap"><table class="tbl"><tr><th>Address</th><th>Name</th><th>Reason</th><th>By</th><th>Added</th><th>Expires</th><th></th></tr>
{etr or '<tr><td colspan=7 class=muted>No expected devices</td></tr>'}</table></div>{add}</section>""")
    return page(req, "Suppressions", tabs(SECURITY_TABS, "/netmon/exceptions") + expected_card + "<h2 class='grp'>Alert suppressions</h2><p class='muted'>Exceptions suppress alerts; they do not make traffic trusted. "
                "Use * for any rule/asset/subject; subject may be a CIDR. Add them from an alert.</p><div class='card wrap'><table class='tbl'><tr><th>#</th><th>Rule</th>"
                "<th>Asset</th><th>Subject</th><th>Owner</th><th>Reason</th><th>By</th><th>Expires</th><th>Active</th><th></th></tr>"
                f"{trs or '<tr><td colspan=10 class=muted>No exceptions</td></tr>'}</table></div>", "/netmon/security", scoped=False)


@app.post("/netmon/exceptions")
def add_exception(req: Request, rule: str = Form(...), asset: str = Form(...), subject: str = Form(...),
                  owner: str = Form(...), reason: str = Form(...), expires_days: str = Form(""), csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    if not owner.strip() or not reason.strip():
        raise HTTPException(400, "owner and reason required")
    try:
        exp = time.time() + float(expires_days) * 86400 if expires_days.strip() else None
    except ValueError:
        raise HTTPException(400, "expires must be a number of days")
    vals = [s.strip()[:200] for s in (rule, asset, subject, owner, reason)]
    conn.execute("INSERT INTO exceptions(rule,asset,subject,owner,reason,created_by,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?)",
                 (*vals, u, time.time(), exp))
    conn.commit()
    audit(conn, u, "exception_added", {"rule": vals[0], "asset": vals[1], "subject": vals[2], "expires": exp})
    return RedirectResponse("/netmon/exceptions", 303)


@app.post("/netmon/expected")
def add_expected(req: Request, target: str = Form(...), reason: str = Form(...), expires_days: str = Form(""), back: str = Form(""),
                 csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    try:
        n = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        raise HTTPException(400, "not an IP address or CIDR")
    if n.prefixlen < (24 if n.version == 4 else 48):
        raise HTTPException(400, "range too broad (at most a /24 or /48)")
    if str(n.network_address) in cfg.get("outbound_nat_ips", []) and n.prefixlen == n.max_prefixlen:
        raise HTTPException(400, "that is the shared NAT address (every LAN host) — mark the individual devices instead")
    if not reason.strip():
        raise HTTPException(400, "reason required")
    try:
        exp = time.time() + float(expires_days) * 86400 if expires_days.strip() else None
    except ValueError:
        raise HTTPException(400, "expires must be a number of days")
    t = str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n)
    d = get_setting(conn, EXPECTED_KEY, {}) or {}
    d[t] = {"reason": reason.strip()[:200], "by": u, "ts": time.time(), "expires_at": exp}
    put_setting(conn, EXPECTED_KEY, d, u)
    audit(conn, u, "expected_device_added", {"target": t, "reason": d[t]["reason"], "expires": exp})
    return RedirectResponse(safe_next(back) if back else "/netmon/exceptions", 303)


@app.post("/netmon/expected/remove")
def remove_expected(req: Request, target: str = Form(...), csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    d = get_setting(conn, EXPECTED_KEY, {}) or {}
    if d.pop(target, None) is not None:
        put_setting(conn, EXPECTED_KEY, d, u)
        audit(conn, u, "expected_device_removed", {"target": target})
    return RedirectResponse("/netmon/exceptions", 303)


@app.post("/netmon/exceptions/{xid}/disable")
def disable_exception(req: Request, xid: int, csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    conn.execute("UPDATE exceptions SET enabled=0 WHERE id=?", (xid,))
    conn.commit()
    audit(conn, u, "exception_disabled", {"id": xid})
    return RedirectResponse("/netmon/exceptions", 303)


# ---- blocks ---------------------------------------------------------------------
@app.get("/netmon/blocks", response_class=HTMLResponse)
def blocks(req: Request):
    u, r = user_of(req)
    rows = conn.execute("SELECT * FROM blocks ORDER BY id DESC LIMIT 300").fetchall()
    now = time.time()

    def kind(b):
        if not b["auto"]:
            return "manual"
        left = f" · expires in {max(0, b['expires_at'] - now) / 3600:.1f} h" if b["status"] == "applied" and b["expires_at"] else ""
        return f"<span class='tag'>auto</span> {e(b['trigger'] or '')}{left}"
    trs = "".join(f"<tr><td><a href='/netmon/block/{b['id']}'>#{b['id']}</a></td><td><code>{e(b['address'])}</code></td>"
                  f"<td>{e(site_name(b['site']))}</td><td>{kind(b)}</td><td>{e(b['status'])}</td>"
                  f"<td>{e(b['reason'])}</td><td>{e(b['requested_by'])}</td><td>{e(b['approved_by'] or '')}</td>"
                  f"<td class='num'>{e(fmt_ts(b['requested_at']))}</td></tr>" for b in rows)
    form = (f"<div class=card><div class='card-h'><h2>Request block</h2></div><form method=post action='/netmon/blocks' class='row'>{csrf_field(req)}"
            f"<input name=address placeholder='IP or CIDR' required> <input name=reason placeholder=reason required size=40> "
            f"<span class='chks'>Block on: {site_checks()}</span> <button>Preview</button></form></div>") if ROLES[r] >= 1 else ""
    from .admin import SECURITY_TABS, tabs, tip_box
    con, tot = enforcement()
    fws = "".join(f"<li>{e(x['name'])} ({e(blk.enforcer(x).vendor)}) — alias <code>{e(blk.enforcer(x).alias)}</code>: "
                  f"<b>{'API key configured' if blk.enforcer(x).enabled else 'not set up — requests can be previewed but not applied'}</b></li>"
                  for x in cfg.sites)
    return page(req, "Block requests", tabs(SECURITY_TABS, "/netmon/blocks") + tip_box("blocking", open_=not con) + f"""<div class="banner {'' if con else 'warn'}">Enforcement happens on each firewall through its own alias ({con} of {tot} connected):
<ul>{fws}</ul>A request creates one block per selected firewall; each needs a preview and explicit admin approval.
Automatic blocks (<a href="/netmon/settings/response">Settings → Auto-response</a>) go into a separate alias and expire on their own.</div>
{form}<div class="card wrap"><table class="tbl"><tr><th>#</th><th>Address</th><th>Firewall</th><th>Type</th><th>Status</th><th>Reason</th><th>Requested</th><th>Approved</th><th>When</th></tr>
{trs or '<tr><td colspan=9 class=muted>No block requests</td></tr>'}</table></div>""", "/netmon/security", scoped=False)


@app.post("/netmon/blocks")
def request_block(req: Request, address: str = Form(...), reason: str = Form(...), alert_id: str = Form(""),
                  sites: list[str] = Form([]), csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    try:
        if not sites:
            raise blk.BlockError("choose at least one firewall")
        bid = blk.request_block(conn, det, u, address, reason, int(alert_id) if alert_id.isdigit() else None, sites)
    except blk.BlockError as ex:
        return page(req, "Block refused", f"<div class='banner bad'>{e(address)}: {e(ex)}</div>", "/netmon/security", scoped=False)
    return RedirectResponse(f"/netmon/block/{bid}", 303)


@app.get("/netmon/block/{bid}", response_class=HTMLResponse)
def block_view(req: Request, bid: int):
    u, r = user_of(req)
    b = conn.execute("SELECT * FROM blocks WHERE id=?", (bid,)).fetchone()
    if not b:
        raise HTTPException(404)
    try:
        bsite = blk.site_of_block(cfg, b)
    except blk.BlockError as ex:
        return page(req, f"Block #{bid}", f"<div class='banner bad'>{e(ex)}</div>", "/netmon/security", scoped=False)
    fw = blk.enforcer(bsite)
    pv = blk.preview(cfg, b["address"], bsite, b["alias"])
    imp = json.loads(b["impact"] or "[]")
    trs = "".join(f"<tr><td>{e(i['dir'])}</td><td>{e(i['asset'])}</td><td>{e(i['ports'])}</td><td class='num'>{e(i['flows'])}</td>"
                  f"<td class='num'>{e(human_bytes(i['bytes']))}</td><td class='num'>{e(fmt_ts(i['last']))}</td></tr>" for i in imp)
    act = ""
    if r == "admin" and b["status"] == "pending":
        act = f"""<div class="card danger"><div class="card-h"><h2>Approve and apply on {e(bsite['name'])} ({e(fw.vendor)})</h2></div>
<form method=post action="/netmon/block/{bid}/apply" class="row">{csrf_field(req)}
Type the address to confirm: <input name=confirm required> <button class="primary" {'disabled' if not fw.enabled else ''}>Apply block</button>
{'' if fw.enabled else '<span class="muted small">disabled: enforcement not set up</span>'}</form>
<form method=post action="/netmon/block/{bid}/remove" class="row">{csrf_field(req)}<button>Reject request</button></form></div>"""
    elif r == "admin" and b["status"] == "applied":
        act = f"""<div class="card"><form method=post action="/netmon/block/{bid}/remove">{csrf_field(req)}
<button>Remove block (rollback)</button></form></div>"""
    return page(req, f"Block #{bid}: {b['address']}", f"""<div class="card"><dl class="facts">
<dt>Firewall</dt><dd>{e(bsite['name'])} ({e(fw.vendor)})</dd><dt>Status</dt><dd>{e(b['status'])}</dd><dt>Requested</dt><dd>{e(b['requested_by'])} at {e(fmt_ts(b['requested_at']))}</dd>
<dt>Reason</dt><dd>{e(b['reason'])}</dd><dt>Result</dt><dd>{e(b['result'] or '—')}</dd></dl>
<h3>Exact change</h3><pre>{e(pv['api_call'])}</pre><p>{e(pv['effect'])}</p>
<h3>Existing connections</h3><p>{e(pv['existing_states'])}</p><h3>Rollback</h3><p>{e(pv['rollback'])}</p></div>
<div class="card"><div class="card-h"><h2>Traffic with this address in the last 7 days</h2><span class="muted small">what the block would have affected</span></div>
<div class=wrap><table class="tbl"><tr><th>Direction</th><th>Our side</th><th>Ports</th><th>Flows</th><th>Bytes</th><th>Last</th></tr>
{trs or '<tr><td colspan=6 class=muted>No observed traffic</td></tr>'}</table></div></div>{act}""", "/netmon/security", scoped=False)


@app.post("/netmon/block/{bid}/apply")
def block_apply(req: Request, bid: int, confirm: str = Form(...), csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    b = conn.execute("SELECT address FROM blocks WHERE id=?", (bid,)).fetchone()
    if not b or confirm.strip() != b["address"]:
        raise HTTPException(400, "confirmation does not match address")
    try:
        blk.apply_block(conn, cfg, u, bid)
    except blk.BlockError as ex:
        return page(req, "Block failed", f"<div class='banner bad'>{e(ex)}</div>", "/netmon/security", scoped=False)
    return RedirectResponse(f"/netmon/block/{bid}", 303)


@app.post("/netmon/block/{bid}/remove")
def block_remove(req: Request, bid: int, csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    try:
        blk.remove_block(conn, cfg, u, bid)
    except blk.BlockError as ex:
        return page(req, "Remove failed", f"<div class='banner bad'>{e(ex)}</div>", "/netmon/security", scoped=False)
    return RedirectResponse(f"/netmon/block/{bid}", 303)


# ---- users & audit ----------------------------------------------------------
@app.get("/netmon/users", response_class=HTMLResponse)
def users_page(req: Request, msg: str = ""):
    need(req, "admin")
    rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    opts = lambda cur: "".join(f"<option {'selected' if k == cur else ''}>{k}</option>" for k in ROLES)  # noqa: E731
    trs = "".join(f"""<tr><td>{e(x['username'])}</td><td>
<form method=post action="/netmon/users/{quote(x['username'])}/role" class="inline">{csrf_field(req)}<select name=role>{opts(x['role'])}</select> <button>Save</button></form></td>
<td>{'disabled' if x['disabled'] else 'active'}</td>
<td>{'<span class="sev s-good">● on</span>' if x['totp_enabled'] else '<span class="sev s-muted">○ off</span>'}</td>
<td class='num'>{e(fmt_ts(x['last_login'])) if x['last_login'] else '—'}</td><td>
<form method=post action="/netmon/users/{quote(x['username'])}/reset2fa" class="inline">{csrf_field(req)}<button {'disabled' if not x['totp_enabled'] else ''}>Reset 2FA</button></form>
<form method=post action="/netmon/users/{quote(x['username'])}/password" class="inline">{csrf_field(req)}<input name=password type=password placeholder="new password (12+)" autocomplete="new-password"> <button>Set</button></form>
<form method=post action="/netmon/users/{quote(x['username'])}/toggle" class="inline">{csrf_field(req)}<button>{'Enable' if x['disabled'] else 'Disable'}</button></form></td></tr>"""
                  for x in rows)
    note = f"<div class='banner'>{e(msg)}</div>" if msg else ""
    req2 = bool(get_setting(conn, "require_2fa", False))
    from .admin import SETTINGS_TABS, tabs
    return page(req, "Settings · Users & 2FA", f"""{tabs(SETTINGS_TABS, '/netmon/users')}{note}<div class="card"><div class="card-h"><h2>Add user</h2></div>
<form method=post action="/netmon/users" class="row">{csrf_field(req)}<input name=username placeholder=username required pattern="[A-Za-z0-9._-]{{2,32}}">
<select name=role>{opts('viewer')}</select> <input name=password type=password placeholder="password (12+ chars)" required autocomplete="new-password"> <button>Add</button></form>
<p class="muted small">viewer: read only · analyst: triage, exceptions, block requests · admin: approve blocks, users, audit.</p></div>
<div class="card"><div class="card-h"><h2>Two-factor policy</h2></div>
<form method=post action="/netmon/settings/require2fa" class="row">{csrf_field(req)}
<input type=hidden name=value value="{'0' if req2 else '1'}">
<span>{'<span class="sev s-good">● Required for all users</span>' if req2 else '<span class="sev s-muted">○ Optional</span>'}</span>
<button>{'Make optional' if req2 else 'Require 2FA for all users'}</button>
<span class="muted small">Users without 2FA are sent to enrollment at their next request. Enroll yourself first under My account.</span></form></div>
<div class="card wrap"><table class="tbl"><tr><th>User</th><th>Role</th><th>State</th><th>2FA</th><th>Last login</th><th></th></tr>{trs}</table></div>""", "/netmon/settings", scoped=False)


def _user_change(req, csrf):
    u = need(req, "admin")
    check_csrf(req, csrf)
    return u


@app.post("/netmon/users")
def add_user(req: Request, username: str = Form(...), role: str = Form(...), password: str = Form(...), csrf: str = Form("")):
    u = _user_change(req, csrf)
    import re
    if not re.fullmatch(r"[A-Za-z0-9._-]{2,32}", username) or role not in ROLES:
        raise HTTPException(400, "bad username or role")
    if p := auth.password_problem(password):
        return RedirectResponse("/netmon/users?msg=" + quote(p), 303)
    try:
        conn.execute("INSERT INTO users(username,pw_hash,role,created_at) VALUES (?,?,?,?)",
                     (username, auth.hash_pw(password), role, time.time()))
        conn.commit()
    except Exception:
        return RedirectResponse("/netmon/users?msg=" + quote("user already exists"), 303)
    audit(conn, u, "user_added", {"user": username, "role": role})
    return RedirectResponse("/netmon/users?msg=" + quote(f"added {username}"), 303)


def _admins_left(excluding: str) -> int:
    return conn.execute("SELECT count(*) FROM users WHERE role='admin' AND disabled=0 AND username!=?",
                        (excluding,)).fetchone()[0]


@app.post("/netmon/users/{name}/role")
def set_role(req: Request, name: str, role: str = Form(...), csrf: str = Form("")):
    u = _user_change(req, csrf)
    if role not in ROLES:
        raise HTTPException(400)
    if role != "admin" and not _admins_left(name):
        return RedirectResponse("/netmon/users?msg=" + quote("cannot remove the last admin"), 303)
    conn.execute("UPDATE users SET role=? WHERE username=?", (role, name))
    conn.commit()
    auth.revoke_user_sessions(conn, name) if name != u else None
    audit(conn, u, "user_role", {"user": name, "role": role})
    return RedirectResponse("/netmon/users?msg=" + quote(f"{name} is now {role}"), 303)


@app.post("/netmon/users/{name}/password")
def set_password(req: Request, name: str, password: str = Form(...), csrf: str = Form("")):
    u = _user_change(req, csrf)
    if p := auth.password_problem(password):
        return RedirectResponse("/netmon/users?msg=" + quote(p), 303)
    conn.execute("UPDATE users SET pw_hash=? WHERE username=?", (auth.hash_pw(password), name))
    conn.commit()
    if name != u:
        auth.revoke_user_sessions(conn, name)
    audit(conn, u, "user_password_set", {"user": name})
    return RedirectResponse("/netmon/users?msg=" + quote(f"password updated for {name}"), 303)


@app.post("/netmon/users/{name}/toggle")
def toggle_user(req: Request, name: str, csrf: str = Form("")):
    u = _user_change(req, csrf)
    row = conn.execute("SELECT disabled FROM users WHERE username=?", (name,)).fetchone()
    if not row:
        raise HTTPException(404)
    if not row["disabled"] and (name == u or not _admins_left(name)):
        return RedirectResponse("/netmon/users?msg=" + quote("cannot disable yourself or the last admin"), 303)
    conn.execute("UPDATE users SET disabled=? WHERE username=?", (0 if row["disabled"] else 1, name))
    conn.commit()
    auth.revoke_user_sessions(conn, name)
    audit(conn, u, "user_toggled", {"user": name, "disabled": not row["disabled"]})
    return RedirectResponse("/netmon/users", 303)


@app.get("/netmon/audit", response_class=HTMLResponse)
def audit_view(req: Request):
    need(req, "admin")
    rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 500").fetchall()
    trs = "".join(f"<tr><td class='num'>{e(fmt_ts(x['ts']))}</td><td>{e(x['user'])}</td><td><code>{e(x['action'])}</code></td><td><code>{e(x['detail'])}</code></td></tr>"
                  for x in rows)
    from .admin import SETTINGS_TABS, tabs
    return page(req, "Settings · Audit log", tabs(SETTINGS_TABS, "/netmon/audit") + f"<p class='muted'>Append-only (database triggers refuse updates and deletes).</p><div class='card wrap'><table class='tbl'><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th></tr>{trs}</table></div>", "/netmon/settings", scoped=False)


def responder_loop():
    """Auto-response every 60 s, in its own thread and DB connection; state for the settings page."""
    from .respond import Responder
    rconn = db_connect()
    r = Responder(cfg, rconn, Detector(cfg, ch, rconn, notifier), notifier)
    time.sleep(90)  # let the detector and ingest settle after boot
    from .inventory import sync_vips
    last_vip = 0
    while True:
        if time.time() - last_vip > 3600:
            last_vip = time.time()
            try:
                sync_vips()
            except Exception as ex:
                print(f"vip sync failed: {ex}", flush=True)
        try:
            threatradar.refresh(rconn)   # self-limiting: only fetches when the interval is due
        except Exception as ex:
            print(f"threat intel refresh failed: {ex}", flush=True)
        try:
            from . import geocity
            geocity.refresh(rconn)   # monthly city database for map placement; self-limiting like threat intel
        except Exception as ex:
            print(f"city geo refresh failed: {ex}", flush=True)
        try:
            set_state(rconn, "responder", r.run_once())
        except Exception as ex:
            set_state(rconn, "responder", {"ts": time.time(), "errors": [f"fatal: {str(ex)[:300]}"]})
        time.sleep(60)


def detector_loop():
    dconn = db_connect()
    d = Detector(cfg, ch, dconn, notifier)
    for _ in range(60):  # at boot ClickHouse can lag the app; wait up to ~5 min before the first run
        try:
            ch.query("SELECT 1", {})
            break
        except Exception:
            time.sleep(5)
    while True:
        failed = False
        try:
            d.run_once()
            failed = bool((get_state(dconn, "detector", {})[0] or {}).get("errors"))
        except Exception as ex:  # keep the loop alive; error is surfaced via state
            set_state(dconn, "detector", {"last_run": time.time(), "errors": [f"fatal: {ex}"]})
            failed = True
        # retry transient failures (e.g. ClickHouse restarting) quickly instead of a full interval
        time.sleep(min(30, cfg["detector"]["interval_seconds"]) if failed else cfg["detector"]["interval_seconds"])


HEALTH = []


def health_loop():
    """Source health every 60 s in its own DB connection (Coverage page + health alerts)."""
    from .health import Health
    from .views import blocks
    hconn = db_connect()
    h = Health(cfg, ch, hconn, notifier, geo=blocks().geo)
    HEALTH.append(h)
    h.loop(60)


def start():
    if os.environ.get("NETMON_DETECTOR", "1") == "1":
        from .logingest import Ingest
        notifier.start()
        threading.Thread(target=detector_loop, daemon=True).start()
        threading.Thread(target=responder_loop, daemon=True).start()
        Poller(cfg).start()
        Ingest(cfg, cfg["clickhouse_url"]).start()
        from .dnsresolve import NameResolver
        NameResolver(cfg, ch, cfg["clickhouse_url"]).start()   # FQDNs for remote addresses from the DNS query log
        threading.Thread(target=health_loop, daemon=True).start()
        from .zeek import ZEEK_DIR, ZeekIngest
        if os.path.isdir(ZEEK_DIR):   # optional sensor: only when its log directory is mounted
            ZeekIngest(cfg, cfg["clickhouse_url"]).start()


from . import views  # noqa: E402,F401  (registers data pages and APIs)
from . import admin  # noqa: E402,F401  (settings, notifications, account/2FA, firewall/IDS pages)
from . import wallboards  # noqa: E402,F401
from . import inventory  # noqa: E402,F401  (server names and external address labels)
from . import autoresp  # noqa: E402,F401  (auto-response settings, firewall setup, decision log)
from . import coverage  # noqa: E402,F401  (coverage & source health)
from . import intel  # noqa: E402,F401  (threat intel: ExploitHound Threat Radar)
