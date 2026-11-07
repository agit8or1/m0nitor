"""Shared building blocks for the investigation pages, so every feature looks and reads the same way:

  summary → affected device → evidence → next action

- Devices are named by their friendly name first; IP and site are secondary (identity.label).
- Confidence is always shown as a word and a badge (never colour alone), with the reason in plain language.
- Empty states say *why* there is nothing: setup incomplete, still learning, nothing matched, telemetry unavailable,
  or a source stopped reporting, and give the next step.
- Per-firewall monitoring choices (site["monitor"]): what netmon checks and alerts on for each firewall.
"""
import html
import json
import time
from urllib.parse import quote, urlencode
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

e = lambda v: html.escape("" if v is None else str(v), quote=True)  # noqa: E731

# Investigate hub (one main-nav entry) and the device-related tabs under Internal devices
INVESTIGATE_TABS = [("Incidents", "/netmon/incidents"), ("What changed", "/netmon/changes"), ("Search", "/netmon/search/flows"),
                    ("Threat hunt", "/netmon/hunt"), ("Test detections", "/netmon/detections/test"),
                    ("AI analysis", "/netmon/investigations")]
DEVICE_TABS = [("Devices", "/netmon/servers"), ("Applications", "/netmon/apps"), ("Segmentation", "/netmon/segments"),
               ("Identity review", "/netmon/identities")]

# ---- per-firewall monitoring choices --------------------------------------------------------------------------
# key: (label, what it controls). Default: everything on. Switching a source off does not stop the firewall sending it:
# netmon stops checking, alerting and warning about it for that firewall ("not monitored by choice", never "missing").
MONITOR_OPTIONS = {
    "flows": ("Traffic (NetFlow)", "flow-based detection (new destinations, volume, scanning, beacon-like connections, exposure) and the 'telemetry stopped' check"),
    "syslog": ("Firewall log", "firewall block/pass events and the 'log feed stopped' check"),
    "ids": ("IDS alerts (Suricata)", "IDS findings"),
    "dns": ("DNS query log", "DNS findings and DNS coverage checks"),
    "snmp": ("Interface counters (SNMP)", "counter-based bandwidth and capacity checks"),
    "device_events": ("Device events", "VPN/interface/routing/HA state changes, configuration changes and failed logins reported by the device"),
    "discovery_arp": ("Discovery: ARP table", "device identity and inventory from the firewall's IPv4 ARP table"),
    "discovery_ndp": ("Discovery: NDP table", "device identity for IPv6 from the firewall's neighbour table"),
    "discovery_dhcp": ("Discovery: DHCP leases", "device identity from DHCP leases (address, MAC, hostname)"),
    "probes": ("WAN / VPN quality probes", "active latency, loss, DNS and HTTPS checks configured for this firewall"),
    "segmentation": ("Segmentation checks", "comparing observed internal traffic with your communication rules"),
}


def monitored(site, key):
    """Does the user want `key` monitored for this firewall? (default yes)"""
    if not site:
        return True
    return bool((site.get("monitor") or {}).get(key, True))


# ---- time ---------------------------------------------------------------------------------------------------
def site_tz(site):
    try:
        return ZoneInfo((site or {}).get("tz") or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def fmt_local(ts, site=None, with_tz=True):
    if not ts:
        return "—"
    from datetime import datetime
    d = datetime.fromtimestamp(float(ts), site_tz(site))
    return d.strftime("%Y-%m-%d %H:%M") + (f" {d.tzname()}" if with_tz else "")


def ago(ts, now=None):
    if not ts:
        return "never"
    s = (now or time.time()) - float(ts)
    if s < 90:
        return f"{int(s)} s ago"
    if s < 5400:
        return f"{int(s / 60)} min ago"
    if s < 172800:
        return f"{s / 3600:.1f} h ago"
    return f"{int(s / 86400)} d ago"


# ---- rendering --------------------------------------------------------------------------------------------
CONF_WORD = {"high": "high confidence", "medium": "medium confidence", "low": "low confidence", "unknown": "unknown"}


def conf_badge(level, why=""):
    level = level if level in CONF_WORD else "unknown"
    return f"<span class='conf c-{level}' title='{e(why)}'>{e(CONF_WORD[level])}</span>"


def device_html(lab, link=True, show_conf=False):
    """Friendly name first, IP and site secondary. `lab` from identity.label()."""
    name, ip = lab.get("name") or lab.get("ip"), lab.get("ip", "")
    sub = " · ".join(x for x in (ip if name != ip else "", lab.get("site_name") or "") if x)
    inner = f"<span class='devname'>{e(name)}</span>" + (f"<span class='devsub'>{e(sub)}</span>" if sub else "")
    if link and ip:
        q = f"?site={quote(lab['site'])}" if lab.get("site") else ""
        inner = f"<a href='/netmon/servers/{quote(ip)}{q}'>{inner}</a>" if lab.get("internal", True) else inner
    if show_conf and lab.get("confidence") not in (None, "high"):
        inner += " " + conf_badge(lab.get("confidence"), lab.get("explain", ""))
    return inner


EMPTY_KINDS = {
    "setup": ("Setup is not complete", "es-setup"),
    "learning": ("Still learning", "es-learning"),
    "nomatch": ("Nothing matched", ""),
    "unavailable": ("The data needed is not available", "es-setup"),
    "stopped": ("A source stopped reporting", "es-stopped"),
    "disabled": ("Not monitored for this firewall (your choice)", ""),
}


def empty_state(kind, msg, next_href="", next_label=""):
    title, cls = EMPTY_KINDS.get(kind, ("Nothing to show", ""))
    nxt = f" <a href='{e(next_href)}'>{e(next_label or 'Next step')} →</a>" if next_href else ""
    return f"<div class='empty-state {cls}' role='status'><b>{e(title)}</b>{e(msg)}{nxt}</div>"


def evidence_details(summary, obj, open_=False):
    """Raw evidence / queries behind an expandable section."""
    body = obj if isinstance(obj, str) else json.dumps(obj, indent=1, default=str)
    return f"<details class='tech' {'open' if open_ else ''}><summary>{e(summary)}</summary><pre>{e(body)}</pre></details>"


def _routes():
    try:
        from .web import app
        return {getattr(r, "path", "") for r in app.routes}
    except Exception:
        return set()


def tabs(items, active):
    known = _routes()
    items = [(n, h) for n, h in items if not known or h in known]   # only sections this version has
    return "<nav class='subtabs' aria-label='Sections'>" + "".join(
        f"<a href='{h}' class='{'on' if h == active else ''}' {'aria-current=page' if h == active else ''}>{e(n)}</a>" for n, h in items) + "</nav>"


def link(path, **params):
    q = urlencode({k: v for k, v in params.items() if v not in (None, "")})
    return path + (f"?{q}" if q else "")


def sentence_item(s1, s2="", actions=(), sev=""):
    acts = "".join(f"<a href='{e(h)}'>{e(t)}</a>" for t, h in actions if h)
    return (f"<li class='{e(sev)}'><span class='s1'>{s1}</span>" + (f"<span class='s2'>{s2}</span>" if s2 else "")
            + (f"<span class='acts'>{acts}</span>" if acts else "") + "</li>")


def ratio_text(cur, prev):
    """'3×', '+40%', '−60%'; prev == 0 -> 'new'."""
    if not prev:
        return "new" if cur else "no change"
    r = cur / prev
    if r >= 2:
        return f"{r:.1f}×".replace(".0×", "×")
    pct = (r - 1) * 100
    return f"{'+' if pct >= 0 else '−'}{abs(pct):.0f}%"
