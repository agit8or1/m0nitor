"""Inventory auto-discovery: every internal address that shows up gets an Inventory entry on its own.

Sources, each used only for what it proves:
  traffic    internal addresses that received traffic from the internet in the last 24 h (inbound records are exact for
             one LAN host, even behind the shared NAT). Proves the address exists and is in use; nothing about its type.
  ARP table  each OPNsense firewall's ARP table (API privilege "Diagnostics: ARP Table"): MAC address, the vendor the
             firewall resolves for it, and the hostname it knows. The vendor is looked up in the IEEE registry
             (devtypes.vendor_of; the firewall's answer is the fallback). A virtualization MAC prefix proves a virtual
             NIC ("virtual machine"); a short list of single-purpose vendors (camera, printer, VoIP, NAS makers) sets
             that type; any other vendor sets no type (a Dell MAC can be a server, a switch or a management card).

Never overwrites what a person set: new addresses are added with source "auto"; on existing entries only empty fields
(type, MAC, vendor) are filled. Editing an entry by hand makes it a manual entry (inventory.save)."""
import ipaddress
import re
import time

from .core import audit, get_setting, get_state, put_setting, set_state
from .devtypes import type_from_hostname, type_from_mac, vendor_of

KEY = "discovery"           # setting: {"enabled": bool}
STATE = "discovery"         # state: last run summary
INTERVAL = 900

NAME_OK = re.compile(r"^[\w.:;/+()&@#=~-]{1,64}$")


def enabled(conn):
    return (get_setting(conn, KEY, {}) or {}).get("enabled", True)


def norm_mac(m):
    m = str(m or "").strip().lower().replace("-", ":")
    return m if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", m) else ""


def traffic_ips(cfg, dash):
    """{ip: last_seen} for internal addresses that received internet traffic in the last 24 h."""
    sc = dash.scope(range_key="24h")
    rows = dash.q(sc, f"""SELECT replaceOne(IPv6NumToString(DstAddr), '::ffff:', '') AS ip, toUnixTimestamp(max(TimeReceived)) AS last
        FROM flows WHERE {dash.where(sc)} AND INB AND TOLAN GROUP BY ip ORDER BY ip LIMIT 5000""", ttl=600)
    return {r["ip"]: int(r["last"]) for r in rows if _usable(cfg, r["ip"])}


def _usable(cfg, ip):
    try:
        a = ipaddress.ip_address(ip)
        if not cfg.is_internal(ip) or a.is_multicast or a.is_unspecified:
            return False
    except ValueError:
        return False
    for n in cfg.internal_nets:   # network and broadcast addresses are not devices
        if a in n and n.num_addresses > 2 and a in (n.network_address, n.broadcast_address):
            return False
    return True


def _arp_call(fw):
    """Current OPNsense: search_arp (grid endpoint, all rows). Older releases only have getArp; the same privilege
    ("Diagnostics: ARP Table") may cover only one of them, so try the current one first."""
    try:
        return fw._call("GET", "/api/diagnostics/interface/search_arp", params={"rowCount": "-1", "current": "1"})
    except Exception as first:
        try:
            return fw._call("GET", "/api/diagnostics/interface/getArp")
        except Exception:
            raise first


def arp_rows(cfg):
    """({ip: {mac, vendor, hostname, site}}, {site: "ok (N)" | error}) from every OPNsense site's ARP table."""
    from . import block as blk
    out, status = {}, {}
    for site in cfg.sites:
        fw = blk.enforcer(site)
        if not isinstance(fw, blk.OPNsense) or not fw.enabled:
            continue
        try:
            rows = _arp_call(fw)
        except Exception as ex:
            msg = str(ex)
            status[site["id"]] = ("no permission: give the netmon API user the privilege \"Diagnostics: ARP Table\""
                                  if "403" in msg else f"error: {msg[:120]}")
            continue
        rows = rows if isinstance(rows, list) else rows.get("rows", [])
        n = 0
        for r in rows:
            ip, mac = str(r.get("ip", "")).strip(), norm_mac(r.get("mac"))
            if not mac or not _usable(cfg, ip) or r.get("permanent") in (True, "true", "1"):   # permanent = the firewall's own
                continue
            out[ip] = {"mac": mac, "vendor": (vendor_of(mac) or str(r.get("manufacturer") or "").strip())[:64],
                       "hostname": str(r.get("hostname") or "").strip().rstrip(".")[:64], "site": site["id"]}
            n += 1
        status[site["id"]] = f"ok ({n} entries)"
    return out, status


def merge(db, seen, arp, now):
    """Pure merge of discovery results into assets:db. Returns (db, added, filled)."""
    added, filled = [], []
    for ip in sorted(set(seen) | set(arp), key=ipaddress.ip_address):
        a = arp.get(ip, {})
        kind, why = type_from_mac(a.get("mac"), a.get("vendor", ""))
        if not kind:
            kind, why = type_from_hostname(a.get("hostname"))
        cur = db.get(ip)
        if cur is None:
            host = a.get("hostname", "")
            e = {"name": host if host and NAME_OK.match(host) else ip, "role": "", "sensitive": False, "source": "auto",
                 "discovered": now, "notes": "auto-discovered from " + ("the ARP table" if a else "traffic")
                 + (f"; type from {why}" if kind else "")}
            if kind:
                e["kind"], e["kind_source"] = kind, why
            for k in ("mac", "vendor"):
                if a.get(k):
                    e[k] = a[k]
            db[ip] = e
            added.append(ip)
            continue
        ch = {}
        for k in ("mac", "vendor"):
            if a.get(k) and not cur.get(k):
                ch[k] = a[k]
        if kind and not cur.get("kind"):
            ch["kind"], ch["kind_source"] = kind, why
        if ch:
            cur.update(ch)
            filled.append({"ip": ip, **ch})
    for ip, cur in db.items():   # vendor for MACs recorded before the lookup existed (or entered by hand)
        if cur.get("mac") and not cur.get("vendor"):
            v = vendor_of(cur["mac"])
            if v:
                cur["vendor"] = v
                filled.append({"ip": ip, "vendor": v})
    for ip in seen:
        if ip in db and db[ip].get("source") == "auto":
            db[ip]["last_seen"] = max(int(seen[ip]), int(db[ip].get("last_seen", 0)))
    return db, added, filled


def run(cfg, conn, dash, user="discovery"):
    """One discovery pass. Returns the summary also stored in state 'discovery'."""
    from .core import apply_assets
    now = int(time.time())
    seen, err = {}, None
    try:
        seen = traffic_ips(cfg, dash)
    except Exception as ex:
        err = f"traffic: {type(ex).__name__}"
    arp, arp_status = arp_rows(cfg)
    db = get_setting(conn, "assets:db", {}) or {}
    db, added, filled = merge(db, seen, arp, now)
    if added or filled or seen:
        put_setting(conn, "assets:db", db, user)
        apply_assets(cfg, conn)
    if added or filled:
        audit(conn, user, "inventory_discovered", {"added": added, "filled": filled})
    summary = {"ts": now, "traffic_ips": len(seen), "arp_ips": len(arp), "arp": arp_status, "added": added,
               "filled": len(filled), "error": err}
    set_state(conn, STATE, summary)
    return summary


def last(conn):
    s, _ = get_state(conn, STATE, {})
    return s or {}
