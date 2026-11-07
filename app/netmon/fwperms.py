"""Firewall API permissions netmon needs, per feature, with a read-only live check.

OPNsense privilege names and the endpoints they cover were taken from Core's ACL.xml files (verified on 26.7.7). Each
probe is a read-only call that is covered by exactly the privilege it checks, so a pass proves that privilege (write
calls of the same feature use the same privilege). Nothing here changes the firewall."""
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse

# (privilege, features, endpoints netmon calls, probe (method, path, form data), required?)
OPNSENSE = [
    ("Diagnostics: PF Table IP addresses", "Manual blocks and auto-response: add/remove addresses in the netmon_block and netmon_auto aliases",
     "api/firewall/alias_util/*", ("GET", "/api/firewall/alias_util/aliases", None), "blocking"),
    ("Firewall: Alias: Edit", "Create the netmon_block / netmon_auto aliases once (Settings → Auto-response → Create)",
     "api/firewall/alias/search_item, add_item, reconfigure", ("GET", "/api/firewall/alias/get", None), "blocking setup"),
    ("Firewall: Categories", "Create the netmon category that tags netmon's rules and aliases",
     "api/firewall/category/search_item, add_item", ("GET", "/api/firewall/category/get", None), "blocking setup"),
    ("Firewall: Rules [new]", "Create, check and repair netmon's 4 floating block rules (enable/disable switch); read the GeoIP block policy shown on Countries",
     "api/firewall/filter/search_rule, add_rule, get_rule, toggle_rule, apply", ("POST", "/api/firewall/filter/search_rule", {"rowCount": "1"}), "blocking setup, GeoIP policy"),
    ("Diagnostics: Show States", "Drop existing connections of an address when it is blocked (otherwise established states survive the block)",
     "api/diagnostics/firewall/query_states, del_state", ("POST", "/api/diagnostics/firewall/query_states", {"rowCount": "1"}), "optional"),
    ("Firewall: NAT: 1:1", "Attribute outbound traffic of servers with their own public address (1:1 NAT sync, hourly)",
     "api/firewall/one_to_one/search_rule", ("GET", "/api/firewall/one_to_one/search_rule", None), "recommended"),
    ("Interfaces: Virtual IPs: Settings", "Name the firewall's public addresses (virtual IP labels, hourly)",
     "api/interfaces/vip_settings/search_item", ("GET", "/api/interfaces/vip_settings/search_item", None), "recommended"),
    ("Diagnostics: ARP Table", "Inventory auto-discovery: MAC address, vendor and hostname of internal devices (every 15 min)",
     "api/diagnostics/interface/search_arp (the legacy getArp is not covered by this privilege)",
     ("GET", "/api/diagnostics/interface/search_arp", {"rowCount": "1"}), "recommended"),
    ("Diagnostics: NDP Table", "Device identity for IPv6: which MAC address uses which IPv6 address (every 15 min)",
     "api/diagnostics/interface/search_ndp", ("GET", "/api/diagnostics/interface/search_ndp", {"rowCount": "1"}), "optional"),
    ("Services: ISC DHCPv4: Leases", "Device identity: DHCP leases (address, MAC, hostname, lease times) from the ISC DHCP server. "
     "The privilege also allows deleting leases; netmon only reads them",
     "api/dhcpv4/leases/search_lease", ("GET", "/api/dhcpv4/leases/search_lease", {"rowCount": "1"}), "optional"),
    ("Services: DHCP: Kea(v4)", "Device identity: DHCP leases from the Kea DHCP server (only if you use Kea). The privilege also covers "
     "Kea's settings; netmon only reads leases",
     "api/kea/leases4/search", ("GET", "/api/kea/leases4/search", {"rowCount": "1"}), "optional"),
]

# URL patterns each privilege covers (OPNsense ACL.xml), to name the missing privilege when a call is refused (HTTP 403)
PATTERNS = [
    ("Diagnostics: PF Table IP addresses", ("/api/firewall/alias_util/",)),
    ("Firewall: Alias: Edit", ("/api/firewall/alias/",)),
    ("Firewall: Categories", ("/api/firewall/category/",)),
    ("Firewall: Rules [new]", ("/api/firewall/filter/",)),
    ("Diagnostics: Show States", ("/api/diagnostics/firewall/query_states", "/api/diagnostics/firewall/del_state")),
    ("Firewall: NAT: 1:1", ("/api/firewall/one_to_one/",)),
    ("Interfaces: Virtual IPs: Settings", ("/api/interfaces/vip_settings/",)),
    ("Diagnostics: ARP Table", ("/api/diagnostics/interface/search_arp", "/api/diagnostics/interface/get_arp",
                                "/api/diagnostics/interface/getArp")),
    ("Diagnostics: NDP Table", ("/api/diagnostics/interface/search_ndp", "/api/diagnostics/interface/get_ndp")),
    ("Services: ISC DHCPv4: Leases", ("/api/dhcpv4/leases/",)),
    ("Services: DHCP: Kea(v4)", ("/api/kea/leases4/", "/api/kea/dhcpv4/")),
]


def privilege_for(path):
    """The OPNsense privilege that covers an API path, or ''."""
    path = "/" + str(path or "").lstrip("/")
    for name, prefixes in PATTERNS:
        if path.startswith(prefixes):
            return name
    return ""


def missing_text(path):
    """Plain-language 403 explanation naming the privilege to grant."""
    p = privilege_for(path)
    return (f"the firewall's API user is missing the privilege \"{p}\". Grant it in OPNsense System → Access → Users → (API user) → "
            f"Effective Privileges (all privileges netmon uses: Settings → Firewall permissions)" if p else
            "the firewall's API user is not allowed to call this endpoint (Settings → Firewall permissions lists what netmon needs)")


def missing_html(e, msg):
    """Render an error string; when it names a missing privilege, add the fix and a link to the permissions page."""
    msg = str(msg or "")
    p = next((n for n, _ in PATTERNS if f'"{n}"' in msg), "")
    if not p:
        return f"<span class='warnline'>{e(msg)}</span>"
    return (f"<span class='warnline'>Missing firewall permission: <b>{e(p)}</b>.</span> <span class='small'>Grant it to the API user in "
            f"OPNsense <i>System → Access → Users → (API user) → Effective Privileges</i>. "
            f"<a href='/netmon/settings/permissions?check=1'>Check all permissions →</a></span>")

PFSENSE = [   # pfSense-pkg-RESTAPI v2 privileges
    ("api-v2-firewall-aliases-get", "Find the netmon_block alias"),
    ("api-v2-firewall-alias-patch", "Replace the alias address list (one address added or removed)"),
]


def probe(site):
    """[(row, 'ok' | 'denied' | 'error: ...')] for one OPNsense site; None if the site has no usable API."""
    from . import block as blk
    fw = blk.enforcer(site)
    if not isinstance(fw, blk.OPNsense) or not fw.enabled:
        return None
    out = []
    for row in OPNSENSE:
        m, path, data = row[3]
        try:
            fw._call(m, path, data=data if m == "POST" else None, params=data if m == "GET" else None)
            out.append((row, "ok"))
        except Exception as ex:
            msg = str(ex)
            out.append((row, "denied" if "403" in msg else f"error: {msg[:100]}"))
    return out


def table_html(e, results=None):
    res = {r[0][0]: r[1] for r in (results or [])}

    def st(name):
        s = res.get(name)
        if s is None:
            return ""
        if s == "ok":
            return "<td><span class='sev s-ok'>✓ granted</span></td>"
        if s == "denied":
            return "<td><span class='sev s-serious'>✗ missing</span></td>"
        return f"<td class='small warnline'>{e(s)}</td>"
    head = "<th>Privilege</th><th>Needed for</th><th>Used for</th><th>API endpoints</th>" + ("<th>This account</th>" if results else "")
    rows = "".join(f"<tr><td><b>{e(p)}</b></td><td class='small'>{e(req)}</td><td class='small'>{e(f)}</td><td class='small mono'>{e(ep)}</td>{st(p)}</tr>"
                   for p, f, ep, _, req in OPNSENSE)
    return f"<div class='wrap'><table class='tbl'><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table></div>"


def register(app, cfg, need, page, e, tabs_fn, tabs_list):
    @app.get("/netmon/settings/permissions", response_class=HTMLResponse)
    def permissions_page(req: Request, check: str = ""):
        need(req, "analyst")
        sections = []
        for site in cfg.sites:
            vendor = site.get("vendor", "opnsense")
            if vendor == "pfsense":
                rows = "".join(f"<tr><td><code>{e(p)}</code></td><td class='small'>{e(f)}</td></tr>" for p, f in PFSENSE)
                sections.append(f"<h3>{e(site['name'])} · pfSense (REST API package)</h3><div class='wrap'><table class='tbl'><thead><tr>"
                                f"<th>Privilege</th><th>Used for</th></tr></thead><tbody>{rows}</tbody></table></div>")
                continue
            results = None
            note = ""
            if check:
                try:
                    results = probe(site)
                except HTTPException:
                    raise
                except Exception as ex:
                    note = f"<p class='warnline'>Check failed: {e(str(ex)[:160])}</p>"
                if results is None and not note:
                    note = "<p class='muted small'>No API key configured for this firewall (Settings → Firewalls &amp; sites → Connection settings).</p>"
            missing = [r[0][0] for r in (results or []) if r[1] != "ok"]
            summary = ("" if results is None else
                       "<p class='ok'>All privileges granted.</p>" if not missing else
                       f"<p class='warnline'>Missing: {e(', '.join(missing))}. The features listed for them do not work until granted.</p>")
            sections.append(f"<h3>{e(site['name'])} · OPNsense</h3>{note}{summary}{table_html(e, results)}")
        body = f"""{tabs_fn(tabs_list, "/netmon/settings/permissions")}
<section class="card"><div class="card-h"><h2>Firewall API permissions</h2>
<a class="small" href="/netmon/settings/permissions?check=1">Check this account now →</a></div>
<p class="note">netmon talks to each firewall through one API user (Settings → Firewalls &amp; sites → Connection settings). Give that user
only the privileges below, in OPNsense <b>System → Access → Users → (user) → Effective Privileges</b>, then create an API key for it.
Do not add it to the admins group and do not grant "All pages". Monitoring itself (NetFlow, syslog, SNMP) needs no API access at all;
without an API user netmon still monitors, it just cannot block or sync names. The check calls one read-only endpoint per privilege;
it never changes the firewall.</p>
{''.join(sections)}
<p class="note">"Needed for": <b>blocking</b> = manual blocks and auto-response; <b>blocking setup</b> = creating netmon's own aliases, category and
floating rules (once, plus automatic repair); <b>recommended</b> = name and inventory sync; <b>optional</b> = dropping existing connections on block.
Full guide: docs/opnsense-permissions.md in the repository.</p></section>"""
        return page(req, "Settings · Firewall permissions", body, "/netmon/settings", scoped=False)
