"""Devices: every firewall, router or switch that sends telemetry, its profile, and what is actually arriving.

Two kinds, one model:
  primary   the firewall that defines a site (Settings -> Firewalls & sites). Its flows are the site's WAN accounting
            boundary (core.flow_predicates); its blocks feed the site's firewall views. Any vendor profile.
  additional devices attached to a site (setting devices:db): routers, switches, secondary firewalls, sensors. Their
            flows get their own exporter name and are never added to the site's WAN totals (no double counting);
            their logs are owned by the device (column `device`) and normalized by the vendor parser.

Status shown here is evidence only: "active" means data from that device arrived recently; a capability the profile
does not document is "unknown", and a protocol nothing arrived on is "no data" - never zero, never green.
"""
import ipaddress
import json
import re
import time

import httpx
from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import secretbox, vendors
from .core import IFNAME, SITE_ID, audit, get_setting, get_state, put_setting

DEV_KEY = "devices:db"
FLOW_KINDS = ("netflow_v5", "netflow_v9", "ipfix", "sflow")
FLOW_LABEL = {"netflow_v5": "NetFlow v5", "netflow_v9": "NetFlow v9", "ipfix": "IPFIX", "sflow": "sFlow"}
ACTIVE_S = 900          # data within 15 min = active
_METRICS = {"t": 0, "inlet": "", "outlet": ""}


# ---- registry ---------------------------------------------------------------------------------------------------
def primary(s):
    return {"id": s["id"], "site": s["id"], "name": s["name"], "vendor": s.get("vendor", "opnsense"), "primary": True,
            "exporter": s.get("exporter", ""), "exporter_ip": s.get("exporter_ip") or None,
            "syslog_source": s.get("syslog_source") or None, "wan_if": s.get("wan_if", ""), "lan_if": s.get("lan_if", ""),
            "wan_zones": s.get("wan_zones") or [], "snmp": s.get("snmp") or {}, "model": s.get("model", ""),
            "firmware": s.get("firmware", ""), "flows": ["netflow_v9"] if s.get("exporter_ip") else [],
            "syslog": bool(s.get("syslog_source")), "role": "firewall", "block": s.get("block") or {}}


def additional(cfg):
    sites = {s["id"] for s in cfg.sites}
    return [{**d, "primary": False, "exporter": d["id"]} for d in (cfg.raw.get("devices") or []) if d.get("site") in sites]


def all_devices(cfg):
    return [primary(s) for s in cfg.sites] + additional(cfg)


def device(cfg, did):
    return next((d for d in all_devices(cfg) if d["id"] == did), None)


def sender_map(cfg):
    """syslog source address -> owning device. One sender belongs to exactly one device (enforced on save)."""
    out = {}
    for d in all_devices(cfg):
        if d.get("syslog_source"):
            out.setdefault(d["syslog_source"], d)
    return out


def apply_devices(cfg, conn):
    cfg.raw["devices"] = get_setting(conn, DEV_KEY, []) or []


def host_entries(cfg):
    """For the root helper (host-sites.json): additional senders only."""
    return [{"id": d["id"], "site": d["site"], "exporter_ip": d.get("exporter_ip"), "syslog_source": d.get("syslog_source"),
             "sflow": "sflow" in (d.get("flows") or [])} for d in additional(cfg)]


# ---- evidence: what actually arrives ------------------------------------------------------------------------------
RE_METRIC = re.compile(r'^(\w+)\{([^}]*)\} ([0-9.eE+\-]+|NaN)$')
RE_LABEL = re.compile(r'(\w+)="([^"]*)"')


def _metrics(url):
    try:
        return httpx.get(url, timeout=3).text
    except Exception:
        return ""


def flow_metrics(cfg):
    """Akvorado's own counters per exporter: packets per listener, NetFlow versions, templates (per observation domain),
    sFlow datagrams, decoder errors. Cached 15 s. {exporter_ip: {...}}"""
    now = time.time()
    if now - _METRICS["t"] > 15:
        base = cfg.get("akvorado_internal_url", "http://traefik:8081")
        _METRICS.update(t=now, inlet=_metrics(base + "/api/v0/inlet/metrics"), outlet=_metrics(base + "/api/v0/outlet/metrics"))
    out = {}

    def ent(addr):
        a = addr.replace("::ffff:", "")
        return out.setdefault(a, {"packets": {}, "versions": set(), "templates": set(), "sflow": 0, "errors": {}})
    for line in (_METRICS["inlet"] + "\n" + _METRICS["outlet"]).splitlines():
        m = RE_METRIC.match(line)
        if not m:
            continue
        name, lab, val = m.group(1), dict(RE_LABEL.findall(m.group(2))), m.group(3)
        if "exporter" not in lab or val == "NaN":
            continue
        v = float(val)
        x = ent(lab["exporter"])
        if name == "akvorado_inlet_flow_input_udp_packets_total":
            port = lab.get("listener", "").lstrip(":")
            x["packets"][port] = x["packets"].get(port, 0) + v
        elif name == "akvorado_outlet_flow_decoder_netflow_packets_total" and v > 0:
            x["versions"].add({"5": "netflow_v5", "9": "netflow_v9", "10": "ipfix"}.get(lab.get("version", ""), "netflow_" + lab.get("version", "?")))
        elif name == "akvorado_outlet_flow_decoder_netflow_templates_total":
            x["templates"].add((lab.get("obs_domain_id", ""), lab.get("template_id", "")))
        elif name.startswith("akvorado_outlet_flow_decoder_sflow") and name.endswith("_total") and v > 0:
            x["sflow"] += v
            x["versions"].add("sflow")
        elif "error" in name and v > 0:
            x["errors"][lab.get("error") or name.replace("akvorado_", "")] = v
    return out


def flow_activity(ch):
    """Last hour of flows per exporter address, with field coverage (share of flows that carry each field)."""
    try:
        rows = ch.query("""SELECT replaceOne(IPv6NumToString(ExporterAddress), '::ffff:', '') AS addr, any(ExporterName) AS name,
            toUInt32(max(TimeReceived)) AS last, count() AS flows, groupUniqArray(5)(SamplingRate) AS rates,
            round(countIf(InIfName != '') / count(), 3) AS in_if, round(countIf(OutIfName != '') / count(), 3) AS out_if,
            round(countIf(FlowDirection != 0) / count(), 3) AS direction, round(countIf(EType = 34525) / count(), 3) AS ipv6,
            round(countIf(SrcAS != 0 OR DstAS != 0) / count(), 3) AS asn
            FROM flows WHERE TimeReceived > now() - INTERVAL 1 HOUR GROUP BY addr""", {})
    except Exception:
        return None   # unknown (ClickHouse unreachable), not "no flows"
    return {r["addr"]: r for r in rows}


def log_activity(ch):
    """Last syslog-derived row per device (7 days) across the event tables. Rows without a device (written before
    devices existed) belong to the site firewall, whose device id is the site id."""
    dev = "if(device = '', site, device)"
    try:
        rows = ch.query(f"""SELECT dv AS d, toUInt32(max(m)) AS t FROM (
            SELECT {dev} AS dv, max(received) AS m FROM netmon.fw_events WHERE received > now() - INTERVAL 7 DAY GROUP BY dv
            UNION ALL SELECT {dev} AS dv, max(received) FROM netmon.sys_events WHERE received > now() - INTERVAL 7 DAY GROUP BY dv
            UNION ALL SELECT {dev} AS dv, max(received) FROM netmon.ids_events WHERE received > now() - INTERVAL 7 DAY GROUP BY dv
            UNION ALL SELECT {dev} AS dv, max(received) FROM netmon.auth_events WHERE received > now() - INTERVAL 7 DAY GROUP BY dv
            UNION ALL SELECT {dev} AS dv, max(received) FROM netmon.events WHERE received > now() - INTERVAL 7 DAY GROUP BY dv)
            WHERE d != '' GROUP BY d""", {})
    except Exception:
        return None
    return {r["d"]: r["t"] for r in rows}


def status_of(cfg, conn, ch, d, flows=None, logs=None, metrics=None):
    """Per-protocol supported / configured / active, with the evidence behind 'active'."""
    p = vendors.profile(d["vendor"])
    now = time.time()
    flows = flow_activity(ch) if flows is None else flows
    logs = log_activity(ch) if logs is None else logs
    metrics = flow_metrics(cfg) if metrics is None else metrics
    fa = (flows or {}).get(d.get("exporter_ip") or "") if flows is not None else None
    fm = metrics.get(d.get("exporter_ip") or "", {})
    ing = ((get_state(conn, "ingest", {})[0] or {}).get("devices") or {}).get(d["id"]) or {}
    rows = []
    recent = bool(fa and now - fa["last"] < ACTIVE_S)
    conf_flows = [k for k in FLOW_KINDS if k in (d.get("flows") or [])]
    for k in FLOW_KINDS:
        seen = k in fm.get("versions", set())
        if flows is None:
            active, ev = None, ""
        elif metrics:            # Akvorado's decoder counters say which protocol arrived
            active, ev = seen and recent, (f"decoded from {d['exporter_ip']}" if seen else "")
        elif recent and conf_flows == [k]:   # counters unavailable: flows arrive, and this is the only protocol set up
            active, ev = True, f"flows from {d['exporter_ip']} (protocol not confirmed: collector counters unavailable)"
        elif recent and k in conf_flows:     # several set up: which one is arriving is unknown
            active, ev = None, "flows arrive; protocol unknown (collector counters unavailable)"
        else:
            active, ev = False, ""
        rows.append({"protocol": FLOW_LABEL[k], "supported": p["flows"][k], "configured": k in conf_flows,
                     "active": active, "evidence": ev})
    last_log = (logs or {}).get(d["id"]) if logs is not None else None
    if d.get("primary") and not last_log:
        last_log = ing.get("last")
    sl = d.get("syslog_transport", "")
    rows.append({"protocol": "Syslog", "supported": any(p["syslog"].values()), "configured": bool(d.get("syslog_source")),
                 "active": bool(last_log and now - last_log < ACTIVE_S) if logs is not None or last_log else None,
                 "evidence": f"last line {int(now - last_log)} s ago" if last_log else "", "transport": sl})
    sn = d.get("snmp") or {}
    names = list((sn.get("interfaces") or {}).keys())
    st = [get_state(conn, f"snmp:{d['id']}:{n}", None)[0] for n in names]
    rows.append({"protocol": f"SNMP {sn.get('version', 'v2c')}" if sn else "SNMP", "supported": p["snmp"]["v3"] or p["snmp"]["v2c"],
                 "configured": bool(sn), "active": bool(st and all(x and x.get("ok") for x in st)) if sn else None,
                 "evidence": next((x.get("error") for x in st if x and x.get("error")), "") if sn else ""})
    rows.append({"protocol": "Enforcement (blocking)", "supported": bool(p["response"]), "configured": bool((d.get("block") or {}).get("key_file")),
                 "active": None, "evidence": "" if p["response"] else "not implemented for this vendor"})
    warn = []
    if d.get("syslog_source") and d.get("syslog_transport") == "udp":
        warn.append("Syslog over UDP is unauthenticated and unencrypted; lines can be lost or spoofed from the sender's address. "
                    + ("Prefer TLS (RFC 5425) or TCP." if p["syslog"]["tls"] or p["syslog"]["tcp"] else "This device offers no other transport."))
    if sn and sn.get("version", "v2c") == "v2c":
        warn.append("SNMPv2c sends the community in clear text. " + ("Prefer SNMPv3 authPriv." if p["snmp"]["v3"] else ""))
    if d.get("exporter_ip"):
        warn.append("NetFlow/IPFIX/sFlow are unauthenticated UDP: only registered exporter addresses are accepted by the host firewall.")
    return {"rows": rows, "flows": fa, "metrics": {**fm, "versions": sorted(fm.get("versions", ())),
                                                   "templates": sorted(fm.get("templates", ()))} if fm else {},
            "ingest": ing, "warnings": warn, "profile": p}


# ---- validation ---------------------------------------------------------------------------------------------------
def _ip(v, what, required=False):
    v = (v or "").strip()
    if not v:
        if required:
            raise ValueError(f"{what} is required")
        return None
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        raise ValueError(f"{what}: {v} is not an IP address")
    if a.is_unspecified or a.is_loopback or a.is_multicast or a.is_link_local:
        raise ValueError(f"{what}: {v} is not a usable sender address")
    return str(a)


def build_device(cfg, form, prev=None):
    prev = prev or {}
    did = prev.get("id") or (form.get("did") or "").strip()
    if not re.match(SITE_ID, did):
        raise ValueError("device id: lowercase letters, digits and '-', up to 24 characters")
    taken = {s["id"] for s in cfg.sites} | {s.get("exporter") for s in cfg.sites}
    if not prev and (did in taken or any(d["id"] == did for d in additional(cfg))):
        raise ValueError(f"id {did} is already used")
    site = (form.get("site") or prev.get("site") or "").strip()
    if not cfg.site(site):
        raise ValueError("choose the site this device belongs to")
    vendor = (form.get("vendor") or "generic").strip()
    if vendor not in vendors.PROFILES:
        raise ValueError("unknown device profile")
    name = (form.get("name") or "").strip()[:60]
    if not name:
        raise ValueError("display name is required")
    exp, sys_ip = _ip(form.get("exporter_ip"), "flow source IP"), _ip(form.get("syslog_source"), "syslog source IP")
    if not exp and not sys_ip:
        raise ValueError("enter a flow source IP, a syslog source IP, or both")
    for other in all_devices(cfg):
        if other["id"] == did:
            continue
        for ipv, what in ((exp, "flow"), (sys_ip, "syslog")):
            if ipv and ipv in (other.get("exporter_ip"), other.get("syslog_source")):
                raise ValueError(f"{what} source {ipv} already belongs to {other['name']}: one sender, one device")
    flows = [k for k in FLOW_KINDS if form.get(f"flow_{k}")]
    if flows and not exp:
        raise ValueError("flow protocols are selected but no flow source IP is set")
    p = vendors.profile(vendor)
    bad = [FLOW_LABEL[k] for k in flows if p["flows"][k] is False]
    if bad:
        raise ValueError(f"{p['name']} does not offer {', '.join(bad)}")
    transport = form.get("syslog_transport", "udp")
    if transport not in vendors.SYSLOG_TRANSPORTS:
        raise ValueError("bad syslog transport")
    if transport == "tls":
        raise ValueError("TLS syslog (RFC 5425) is not available on this monitor yet; use TCP")
    wan = (form.get("wan_if") or "").strip()
    if wan and not re.match(IFNAME, wan):
        raise ValueError("WAN interface name: letters, digits, . _ - only")
    zones = [z for z in re.split(r"[\s,]+", (form.get("wan_zones") or "").strip()) if z]
    if any(not re.match(r"^[A-Za-z0-9_.-]{1,32}$", z) for z in zones):
        raise ValueError("WAN zones: names of letters, digits, . _ -")
    obs = (form.get("observation_domain") or "").strip()
    if obs and not (obs.isdigit() and int(obs) < 2 ** 32):
        raise ValueError("observation domain: a number")
    d = {"id": did, "site": site, "name": name, "vendor": vendor, "model": (form.get("model") or "").strip()[:60],
         "firmware": (form.get("firmware") or "").strip()[:40], "exporter_ip": exp, "syslog_source": sys_ip,
         "syslog_transport": transport if sys_ip else "", "flows": flows, "observation_domain": int(obs) if obs else None,
         "wan_if": wan, "wan_zones": zones, "notes": (form.get("notes") or "").strip()[:300],
         "device_tz_utc": bool(form.get("device_tz_utc"))}
    d["snmp"] = build_snmp(form, prev.get("snmp") or {}, did)
    return d


SNMP_AUTH = ("SHA", "SHA-256", "SHA-512")
SNMP_PRIV = ("AES", "AES-256")


def build_snmp(form, prev, did):
    from .admin import write_secret
    host = (form.get("snmp_host") or "").strip()
    if not host:
        return {}
    ver = form.get("snmp_version", "v3")
    sn = {"host": _ip(host, "SNMP host"), "version": ver, "interval_seconds": 10}
    ifs = {}
    for part in re.split(r"[\s,]+", (form.get("snmp_ifs") or "").strip()):
        if not part:
            continue
        name, _, idx = part.partition("=")
        if not re.match(IFNAME, name) or not idx.isdigit() or not 1 <= int(idx) <= 2 ** 31:
            raise ValueError("SNMP interfaces: name=ifIndex, comma-separated (e.g. wan=1,lan=2)")
        ifs[name] = int(idx)
    if not ifs:
        raise ValueError("SNMP: list at least one interface as name=ifIndex")
    sn["interfaces"] = ifs
    if ver == "v2c":
        sn["community_file"] = prev.get("community_file") if prev.get("version", "v2c") == "v2c" else None
        if (form.get("snmp_community") or "").strip():
            sn["community_file"] = write_secret(f"{did}-snmp", form["snmp_community"])
        if not sn["community_file"]:
            raise ValueError("SNMPv2c: enter the read-only community")
        return sn
    if ver != "v3":
        raise ValueError("SNMP version: v3 or v2c")
    user = (form.get("snmp_user") or "").strip()
    if not re.match(r"^[A-Za-z0-9_.@-]{1,32}$", user):
        raise ValueError("SNMPv3: user name required (letters, digits, _ . @ -)")
    ap, pp = form.get("snmp_auth_proto", "SHA"), form.get("snmp_priv_proto", "AES")
    if ap not in SNMP_AUTH or pp not in SNMP_PRIV:
        raise ValueError("SNMPv3: authPriv with SHA-family authentication and AES privacy only")
    old = {}
    if prev.get("v3_file"):
        try:
            old = json.loads(secretbox.read_file(prev["v3_file"]) or "{}")
        except (OSError, ValueError):
            old = {}
    a, pr = (form.get("snmp_auth_pass") or "").strip() or old.get("auth"), (form.get("snmp_priv_pass") or "").strip() or old.get("priv")
    if not a or not pr or len(a) < 8 or len(pr) < 8:
        raise ValueError("SNMPv3 authPriv: authentication and privacy passphrases (8+ characters) are required")
    sn.update(user=user, auth_proto=ap, priv_proto=pp,
              v3_file=write_secret(f"{did}-snmpv3.json", json.dumps({"auth": a, "priv": pr})))
    return sn


# ---- pages --------------------------------------------------------------------------------------------------------
def register(app):
    from .admin import SETTINGS_TABS, ago_txt, export_host_sites, host_status, monitor_address, tabs
    from .web import cfg, check_csrf, conn, csrf_field, dash, e, need, page, user_of

    def cap_badge(v):
        return {True: "<span class='sev s-good'>yes</span>", False: "<span class='sev s-muted'>no</span>"}.get(v, "<span class='sev s-medium'>unknown</span>")

    def act_badge(row):
        if not row["configured"] and not row["active"]:
            return "<span class='muted'>—</span>"
        if row["active"] is None:
            return "<span class='sev s-muted'>unknown</span>"
        return "<span class='sev s-good'>● active</span>" if row["active"] else "<span class='sev s-high'>○ no data</span>"

    def status_table(st):
        tr = "".join(f"<tr><td>{e(r['protocol'])}</td><td>{cap_badge(r['supported'])}</td><td>{'yes' if r['configured'] else '—'}</td>"
                     f"<td>{act_badge(r)}</td><td class='muted small'>{e(r['evidence'])}</td></tr>" for r in st["rows"])
        return (f"<table class='tbl'><thead><tr><th>Protocol</th><th>Supported by profile</th><th>Configured</th><th>Receiving</th>"
                f"<th>Evidence</th></tr></thead><tbody>{tr}</tbody></table>")

    def status_pill(p):
        cls = {"VERIFIED": "good", "PARTIAL": "medium", "GENERIC": "muted", "UNSUPPORTED": "high"}[p["status"]]
        return f"<span class='sev s-{cls}' title='{e(STATUS_HELP[p['status']])}'>{p['status']}</span>"

    def profile_options(sel):
        return "".join(f"<option value='{k}' {'selected' if k == sel else ''}>{e(p['name'])} — {p['status']}</option>"
                       for k, p in vendors.PROFILES.items())

    def dev_form(req, d=None):
        d = d or {"vendor": "generic", "flows": [], "snmp": {}}
        sn = d.get("snmp") or {}
        v = lambda k: e(d.get(k) if d.get(k) is not None else "")  # noqa: E731
        sites = "".join(f"<option value='{e(s['id'])}' {'selected' if s['id'] == d.get('site') else ''}>{e(s['name'])}</option>" for s in cfg.sites)
        edit = "id" in d
        flows = "".join(f"<label class='check'><input type=checkbox name=flow_{k} value=1 {'checked' if k in (d.get('flows') or []) else ''}> {FLOW_LABEL[k]}</label>"
                        for k in FLOW_KINDS)
        tr = "".join(f"<option value={t} {'selected' if t == (d.get('syslog_transport') or 'udp') else ''}>{t.upper()}</option>" for t in ("udp", "tcp"))
        ifs = ", ".join(f"{k}={i}" for k, i in (sn.get("interfaces") or {}).items())
        action = f"/netmon/settings/devices/{e(d['id'])}" if edit else "/netmon/settings/devices/add"
        return f"""<form method=post action="{action}" class="stackform wide">{csrf_field(req)}
<div class="formgrid">
<label>Profile (vendor / family)<select name=vendor>{profile_options(d['vendor'])}</select></label>
<label>Device id (lowercase, permanent)<input name=did value="{v('id')}" pattern="[a-z0-9][a-z0-9-]{{0,23}}" required {'disabled' if edit else ''} placeholder="e.g. core-sw1"></label>
<label>Display name<input name=name value="{v('name')}" maxlength=60 required placeholder="e.g. Core switch"></label>
<label>Site<select name=site>{sites}</select></label>
<label>Model (optional)<input name=model value="{v('model')}" maxlength=60></label>
<label>Firmware (optional)<input name=firmware value="{v('firmware')}" maxlength=40></label>
<label>Flow source IP (as seen here)<input name=exporter_ip value="{v('exporter_ip')}" placeholder="blank = no flows"></label>
<label>IPFIX observation domain (optional)<input name=observation_domain value="{v('observation_domain')}" inputmode=numeric></label>
<label>Syslog source IP<input name=syslog_source value="{v('syslog_source')}" placeholder="blank = no syslog"></label>
<label>Syslog transport<select name=syslog_transport>{tr}</select></label>
<label>WAN interface (optional)<input name=wan_if value="{v('wan_if')}" placeholder="for in/out direction of logged traffic"></label>
<label>WAN zones (optional)<input name=wan_zones value="{e(', '.join(d.get('wan_zones') or []))}" placeholder="e.g. untrust, outside"></label>
</div>
<fieldset><legend>Flow protocols the device is set to send</legend>{flows}</fieldset>
<label class="check"><input type=checkbox name=device_tz_utc value=1 {'checked' if d.get('device_tz_utc') else ''}> Device clock is UTC (use the timestamps inside its log lines; otherwise receipt time is used)</label>
<fieldset><legend>SNMP (optional, read-only)</legend><div class="formgrid">
<label>SNMP host<input name=snmp_host value="{e(sn.get('host', ''))}" placeholder="blank = no SNMP"></label>
<label>Version<select name=snmp_version><option value=v3 {'selected' if sn.get('version', 'v3') == 'v3' else ''}>v3 authPriv (recommended)</option><option value=v2c {'selected' if sn.get('version') == 'v2c' else ''}>v2c (community, clear text)</option></select></label>
<label>Interfaces (name=ifIndex, …)<input name=snmp_ifs value="{e(ifs)}" placeholder="wan=1, lan=2"></label>
<label>v3 user<input name=snmp_user value="{e(sn.get('user', ''))}" autocomplete=off></label>
<label>v3 auth<select name=snmp_auth_proto>{''.join(f"<option {'selected' if a == sn.get('auth_proto') else ''}>{a}</option>" for a in SNMP_AUTH)}</select></label>
<label>v3 auth passphrase<input name=snmp_auth_pass type=password autocomplete=new-password placeholder="{'unchanged' if sn.get('v3_file') else ''}"></label>
<label>v3 privacy<select name=snmp_priv_proto>{''.join(f"<option {'selected' if a == sn.get('priv_proto') else ''}>{a}</option>" for a in SNMP_PRIV)}</select></label>
<label>v3 privacy passphrase<input name=snmp_priv_pass type=password autocomplete=new-password placeholder="{'unchanged' if sn.get('v3_file') else ''}"></label>
<label>v2c community<input name=snmp_community type=password autocomplete=new-password placeholder="{'unchanged' if sn.get('community_file') else ''}"></label>
</div><p class="muted small">Credentials are written to the monitor's secrets directory (mode 600) and never shown again, logged or exported.</p></fieldset>
<label>Notes<input name=notes value="{v('notes')}" maxlength=300></label>
<div class="row"><button class="primary">{'Save' if edit else 'Add device'}</button></div></form>"""

    def common(req):
        hs, hdetail = host_status()
        return (f"<div class='banner {'' if hs == 'ok' else 'bad' if hs == 'failed' else 'warn'}'><b>Host access lists:</b> "
                f"{'applied' if hs == 'ok' else 'FAILED' if hs == 'failed' else 'pending'} — {e(hdetail)}</div>")

    @app.get("/netmon/settings/devices", response_class=HTMLResponse)
    def devices_page(req: Request, msg: str = ""):
        u, r = user_of(req)
        admin = r == "admin"
        flows, logs, metrics = flow_activity(dash.ch), log_activity(dash.ch), flow_metrics(cfg)
        rows = ""
        for d in all_devices(cfg):
            st = status_of(cfg, conn, dash.ch, d, flows, logs, metrics)
            p = st["profile"]
            proto = " ".join(f"<span title='{e(x['evidence'] or '')}'>{e(x['protocol'])} {act_badge(x)}</span>" for x in st["rows"]
                             if x["configured"] or x["active"])
            ing = st["ingest"]
            cov = (f"{ing.get('parsed', 0):,} parsed · {ing.get('unparsed', 0):,} unrecognized" if ing.get("lines") else "—")
            site = cfg.site(d["site"]) or {}
            rows += (f"<tr><td><a href='/netmon/settings/devices/{e(d['id'])}'><b>{e(d['name'])}</b></a><div class='muted small'>"
                     f"{'site firewall' if d['primary'] else 'additional device'} · {e(site.get('name', d['site']))}</div></td>"
                     f"<td>{e(p['name'])} {status_pill(p)}</td><td class='small'>{proto or '<span class=muted>nothing configured</span>'}</td>"
                     f"<td class='small'>{cov}</td></tr>")
        unreg = ""
        if flows:
            known = {d.get("exporter_ip") for d in all_devices(cfg)}
            extra = [a for a in flows if a not in known]
            if extra:
                unreg = ("<div class='banner warn'>Flows from exporter addresses that are not registered here: "
                         + ", ".join(f"<code>{e(a)}</code>" for a in sorted(extra)) + ". Add them as devices so their traffic is attributed.</div>")
        add = (f"<section class='card' id='add'><div class='card-h'><h2>Add a device</h2><span class='muted small'>router, switch, "
               f"secondary firewall or any exporter — attached to a site</span></div>{dev_form(req)}"
               "<p class='muted small'>A site's own firewall is added under Settings → Firewalls &amp; sites (it defines the site's WAN "
               "boundary). Additional devices keep their own flows and logs: their traffic is shown per device and never added to the "
               "site's WAN totals, so nothing is counted twice.</p></section>") if admin else ""
        body = f"""{tabs(SETTINGS_TABS, '/netmon/settings/devices')}{f"<div class='banner'>{e(msg)}</div>" if msg else ''}{common(req)}{unreg}
<section class="card"><div class="card-h"><h2>Devices</h2><span class="muted small">"Receiving" is evidence from the last 15 minutes; unknown is not zero</span></div>
<table class="tbl"><thead><tr><th>Device</th><th>Profile</th><th>Telemetry</th><th>Syslog parser coverage (since start)</th></tr></thead><tbody>{rows}</tbody></table>
<p class="muted small">Profile status: VERIFIED = validated on a real device; PARTIAL = vendor parser tested with synthetic fixtures from the vendor's documented format;
GENERIC = flows, SNMP and generic syslog only. See <a href="https://github.com/agit8or1/m0nitor/blob/main/docs/vendors.md">docs/vendors.md</a>.</p></section>{add}"""
        return page(req, "Settings · Devices", body, "/netmon/settings", scoped=False)

    @app.get("/netmon/settings/devices/{did}", response_class=HTMLResponse)
    def device_page(req: Request, did: str, msg: str = ""):
        u, r = user_of(req)
        admin = r == "admin"
        d = device(cfg, did)
        if not d:
            raise HTTPException(404, "no such device")
        st = status_of(cfg, conn, dash.ch, d)
        p, ing, fa, fm = st["profile"], st["ingest"], st["flows"], st["metrics"]
        mon = monitor_address()
        warn = "".join(f"<li>{e(w)}</li>" for w in st["warnings"])
        if fa:
            fl = (f"<ul class='plain small'><li>Exporter address seen: <code>{e(fa['addr'])}</code> (name {e(fa['name'])})</li>"
                  f"<li>Last flow {e(ago_txt(fa['last']))} · {fa['flows']:,} flows in the last hour</li>"
                  f"<li>Sampling rates seen: {e(', '.join(str(x) for x in fa['rates']))} (counts are multiplied by the sampling rate)</li>"
                  f"<li>Field coverage: input interface {fa['in_if']:.0%}, output interface {fa['out_if']:.0%}, direction {fa['direction']:.0%}, "
                  f"IPv6 {fa['ipv6']:.0%}, AS numbers {fa['asn']:.0%}</li></ul>")
        elif st["flows"] is None and d.get("exporter_ip"):
            fl = "<p class='muted'>No flows from this address in the last hour.</p>"
        else:
            fl = "<p class='muted'>No flow source configured.</p>"
        if fm:
            pk = ", ".join(f"UDP {k}: {int(v):,} packets" for k, v in sorted(fm.get("packets", {}).items()))
            tm = ", ".join(f"domain {o} template {t}" for o, t in fm.get("templates", []))
            er = ", ".join(f"{k}: {int(v):,}" for k, v in fm.get("errors", {}).items())
            fl += (f"<ul class='plain small'><li>Collector counters (since collector start): {e(pk or '—')}</li>"
                   f"<li>Decoded as: {e(', '.join(FLOW_LABEL.get(v, v) for v in fm.get('versions', [])) or '—')}</li>"
                   f"<li>Templates: {e(tm or 'none (NetFlow v5 and sFlow have none)')}</li><li>Decoder errors: {e(er or 'none')}</li></ul>")
        cats = ", ".join(f"{k}: {v:,}" for k, v in sorted((ing.get("cats") or {}).items()))
        sample = ing.get("sample")
        logs = (f"<ul class='plain small'><li>Lines: {ing.get('lines', 0):,} · parsed {ing.get('parsed', 0):,} · unrecognized (kept as system events) "
                f"{ing.get('unparsed', 0):,} · recognized, not stored {ing.get('skipped', 0):,}</li><li>Actual source address: <code>{e(ing.get('sender', '—'))}</code> · "
                f"last line {e(ago_txt(ing.get('last')) or '—')}</li><li>Stored as: {e(cats or '—')}</li>"
                + (f"<li>Sample normalized event: <code>{e(json.dumps(sample)[:400])}</code></li>" if sample else "")
                + (f"<li>Sample unrecognized line: <code>{e(ing.get('sample_unparsed', ''))}</code></li>" if ing.get("sample_unparsed") else "")
                + "</ul>") if ing.get("lines") else "<p class='muted'>No syslog lines from this device since the app started.</p>"
        edit = ""
        if admin and not d["primary"]:
            edit = (f"<details><summary>Edit</summary>{dev_form(req, d)}</details>"
                    f"<form method=post action='/netmon/settings/devices/{e(d['id'])}/delete' class='row confirm'>{csrf_field(req)}"
                    f"<button>Delete device</button></form>")
        elif d["primary"]:
            edit = f"<p class='muted small'>This is the site firewall: edit it under <a href='/netmon/settings/sites#site-{e(d['id'])}'>Firewalls &amp; sites</a>.</p>"
        snmp_btn = (f"<form method=post action='/netmon/settings/devices/{e(d['id'])}/snmp-test' class='row'>{csrf_field(req)}"
                    f"<button>Test SNMP now</button></form>") if admin and d.get("snmp") else ""
        body = f"""{tabs(SETTINGS_TABS, '/netmon/settings/devices')}{f"<div class='banner'>{e(msg)}</div>" if msg else ''}
<section class="card"><div class="card-h"><h2>{e(d['name'])}</h2><span class="muted small">{e(p['name'])} {status_pill(p)} ·
{'site firewall' if d['primary'] else 'additional device'} · {e(d.get('model') or '')} {e(d.get('firmware') or '')}</span></div>
<p class="small">{e(p['notes'])}</p>{status_table(st)}
{f"<ul class='small warnlist'>{warn}</ul>" if warn else ''}
<p class="muted small"><a href="/netmon/settings/devices/{e(d['id'])}">Refresh</a> to test again: every value above is read live from the collector and the database.</p></section>
<section class="card"><div class="card-h"><h2>Hardware &amp; capacity</h2><a href="/netmon/settings/devices/{e(d['id'])}/hardware">Open →</a></div>
<p class="small">CPU, memory, interfaces and storage discovered over SNMP (HOST-RESOURCES-MIB, IF-MIB, vendor MIBs), manual values, and how much
more telemetry this device can export.</p></section>
<section class="grid2 even"><div class="card"><div class="card-h"><h2>Flows</h2></div>{fl}</div>
<div class="card"><div class="card-h"><h2>Syslog</h2></div>{logs}{snmp_btn}</div></section>
<section class="card"><div class="card-h"><h2>Device-side setup</h2><span class="muted small">example; check your firmware's documentation</span></div>
<pre class="setup">{e(vendors.setup_text(d['vendor'], mon))}</pre></section>
<section class="card">{edit}</section>"""
        return page(req, f"Settings · Devices · {d['name']}", body, "/netmon/settings", scoped=False)

    async def _save(req, did=None):
        u = need(req, "admin")
        form = dict(await req.form())
        check_csrf(req, form.get("csrf", ""))
        devs = get_setting(conn, DEV_KEY, []) or []
        prev = next((x for x in devs if x["id"] == did), None) if did else None
        if did and not prev:
            raise HTTPException(404, "no such device")
        try:
            d = build_device(cfg, form, prev)
        except ValueError as ex:
            back = f"/netmon/settings/devices/{did}" if did else "/netmon/settings/devices"
            return RedirectResponse(back + "?msg=" + _q(f"Not saved: {ex}") + ("" if did else "#add"), 303)
        devs = [x for x in devs if x["id"] != d["id"]] + [d]
        put_setting(conn, DEV_KEY, devs, u)
        apply_devices(cfg, conn)
        export_host_sites()
        audit(conn, u, "device_saved", {k: d[k] for k in ("id", "site", "vendor", "exporter_ip", "syslog_source", "flows")})
        return RedirectResponse(f"/netmon/settings/devices/{d['id']}?msg=" + _q("Saved. The host access lists update within seconds; "
                                                                               "status turns active when data arrives."), 303)

    @app.post("/netmon/settings/devices/add")
    async def add_device(req: Request):
        return await _save(req)

    @app.post("/netmon/settings/devices/{did}")
    async def edit_device(req: Request, did: str):
        return await _save(req, did)

    @app.post("/netmon/settings/devices/{did}/delete")
    def delete_device(req: Request, did: str, csrf: str = Form("")):
        u = need(req, "admin")
        check_csrf(req, csrf)
        devs = get_setting(conn, DEV_KEY, []) or []
        if not any(x["id"] == did for x in devs):
            raise HTTPException(404, "no such additional device")
        put_setting(conn, DEV_KEY, [x for x in devs if x["id"] != did], u)
        apply_devices(cfg, conn)
        export_host_sites()
        audit(conn, u, "device_deleted", {"id": did})
        return RedirectResponse("/netmon/settings/devices?msg=" + _q(f"Deleted {did}. Its stored events stay until retention."), 303)

    @app.post("/netmon/settings/devices/{did}/snmp-test")
    def snmp_test(req: Request, did: str, csrf: str = Form("")):
        need(req, "admin")
        check_csrf(req, csrf)
        d = device(cfg, did)
        if not d or not d.get("snmp"):
            raise HTTPException(404, "no SNMP configured")
        from .counters import snmp_get
        try:
            descr, up = snmp_get(d["snmp"]["host"], d["snmp"], [".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0"])
            res = f"SNMP OK: {descr[:120]} (uptime {up})"
        except Exception as ex:
            res = f"SNMP failed: {str(ex)[:200]}"
        return RedirectResponse(f"/netmon/settings/devices/{did}?msg=" + _q(res), 303)

    @app.get("/netmon/api/devices")
    def api_devices(req: Request):
        need(req, "viewer")
        flows, logs, metrics = flow_activity(dash.ch), log_activity(dash.ch), flow_metrics(cfg)
        out = []
        for d in all_devices(cfg):
            st = status_of(cfg, conn, dash.ch, d, flows, logs, metrics)
            out.append({"id": d["id"], "site": d["site"], "name": d["name"], "vendor": d["vendor"], "primary": d["primary"],
                        "status": st["profile"]["status"], "decisions": st["profile"]["decisions"], "protocols": st["rows"],
                        "warnings": st["warnings"]})
        return JSONResponse(out)


def _q(s):
    from urllib.parse import quote
    return quote(s)


STATUS_HELP = {"VERIFIED": "validated against a real device", "PARTIAL": "vendor parser tested with synthetic fixtures; not yet validated on hardware",
               "GENERIC": "flows, SNMP and generic syslog only", "UNSUPPORTED": "not usable"}
