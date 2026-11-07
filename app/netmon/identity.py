"""Persistent device identity: which device owned an address at a given time, per site.

Evidence is time-stamped and kept per site, so overlapping private ranges at different sites never mix:

  mac       a network card address the firewall reported (ARP / NDP table, DHCP lease). The strongest key we have.
            Randomized ("private") MACs are recognised by the locally-administered bit and kept, but marked weak:
            the same phone or laptop may come back with a new one.
  ip        an address interval (first_seen .. last_seen) owned by one identity. A new MAC on the same IP opens a new
            interval for another identity; the old interval stays as it was, so older events keep their owner.
  hostname  what the firewall or DHCP server calls it. Evidence only: never used to merge devices.
  dhcp      a lease (IP, MAC, hostname, start/end) from the firewall's DHCP server.

Rules (deliberately conservative):
  - Devices are never merged automatically on hostname, vendor or a reused IP. Hostname matches, a MAC seen at
    two sites and devices that moved address become *suggestions* a person reviews (accept / dismiss).
  - Traffic without a MAC proves only that an address is in use. It extends an interval that was confirmed recently;
    after a gap it is attached to the previous owner as *inferred* (shown as "probably"), never as certain.
  - An address-only identity (no MAC yet) takes the MAC the first time the firewall reports one for that address.
  - Merges and splits move evidence rows and remember where each row came from, so both can be undone. Every change
    is written to identity_events and the audit log.
"""
import ipaddress
import json
import time

from .core import audit

CONFIRM_GAP = 86400          # traffic within a day of the last MAC confirmation extends the interval as confirmed
SLACK = 3600                 # attribution tolerance around an interval (discovery runs every 15 min)
EXTRAPOLATE = 86400          # after an interval ends, "probably" the same owner for up to a day, then unknown
BASIS_TEXT = {
    "mac": "identified by its network card address (MAC), which the firewall reported",
    "random-mac": "identified by a randomized (private) MAC address; the device may appear later with a new one",
    "ip-only": "only its IP address is known; if another device takes this address later the two cannot be told apart "
               "until the firewall reports a MAC address",
    "manual": "created or confirmed by a person",
}


def norm_mac(m):
    m = str(m or "").strip().lower().replace("-", ":")
    parts = m.split(":")
    if len(parts) != 6 or not all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts):
        return ""
    return "" if m in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else m


def randomized(mac):
    """Locally administered (second-least-significant bit of the first octet): privacy/random MACs, many VMs."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def norm_ip(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip().split("%")[0])
    except ValueError:
        return ""
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(a)


def _event(conn, iid, user, action, detail, ts=None):
    conn.execute("INSERT INTO identity_events(identity_id,ts,user,action,detail) VALUES (?,?,?,?,?)",
                 (iid, ts or time.time(), user, action, json.dumps(detail, default=str)))


def resolve(conn, iid):
    """Follow merges to the identity that is active now."""
    seen = set()
    while iid and iid not in seen:
        seen.add(iid)
        r = conn.execute("SELECT id, status, merged_into FROM identities WHERE id=?", (iid,)).fetchone()
        if not r or r["status"] != "merged" or not r["merged_into"]:
            return iid
        iid = r["merged_into"]
    return iid


def _new_identity(conn, site, basis, ts, user="discovery", note=""):
    cur = conn.execute("INSERT INTO identities(site,basis,created_at,updated_at,note) VALUES (?,?,?,?,?)", (site, basis, ts, ts, note))
    _event(conn, cur.lastrowid, user, "created", {"basis": basis, "note": note}, ts)
    return cur.lastrowid


def _latest(conn, site, kind, value):
    return conn.execute("SELECT * FROM identity_evidence WHERE site=? AND kind=? AND value=? ORDER BY last_seen DESC, id DESC LIMIT 1",
                        (site, kind, value)).fetchone()


def _touch(conn, iid, site, kind, value, ts, source, inferred=0, detail=None, gap=CONFIRM_GAP):
    """Extend this identity's latest row for (kind, value) when it is recent, else open a new interval."""
    r = conn.execute("SELECT * FROM identity_evidence WHERE identity_id=? AND site=? AND kind=? AND value=? ORDER BY last_seen DESC LIMIT 1",
                     (iid, site, kind, value)).fetchone()
    if r and ts - r["last_seen"] <= gap and ts >= r["first_seen"] - gap:
        # a confirmed observation upgrades an inferred interval; an inferred one never downgrades a confirmed one
        conn.execute("UPDATE identity_evidence SET last_seen=max(last_seen,?), first_seen=min(first_seen,?), inferred=?, "
                     "source=CASE WHEN ?=0 THEN ? ELSE source END WHERE id=?",
                     (ts, ts, min(r["inferred"], inferred), inferred, source, r["id"]))
        return r["id"]
    cur = conn.execute("INSERT INTO identity_evidence(identity_id,site,kind,value,first_seen,last_seen,source,inferred,detail) "
                       "VALUES (?,?,?,?,?,?,?,?,?)", (iid, site, kind, value, ts, ts, source, inferred,
                                                      json.dumps(detail) if detail else None))
    return cur.lastrowid


def _suggest(conn, site, kind, a, b, detail, ts):
    a, b = (a, b) if b is None or a < b else (b, a)
    exists = conn.execute("SELECT 1 FROM identity_suggestions WHERE site=? AND kind=? AND a=? AND coalesce(b,0)=coalesce(?,0)",
                          (site, kind, a, b)).fetchone()
    if not exists:
        conn.execute("INSERT INTO identity_suggestions(site,kind,a,b,detail,created_at) VALUES (?,?,?,?,?,?)",
                     (site, kind, a, b, json.dumps(detail), ts))


def observe(conn, site, ts, ip="", mac="", hostname="", source="arp", lease=None):
    """Record one observation. Returns the identity id it was attributed to (None when nothing usable was given).
    Does not commit: callers batch a whole discovery pass and commit once."""
    ip, mac = norm_ip(ip), norm_mac(mac)
    hostname = str(hostname or "").strip().rstrip(".")[:64]
    if not ip and not mac:
        return None
    if mac:
        r = _latest(conn, site, "mac", mac)
        iid = resolve(conn, r["identity_id"]) if r else None
        if iid is None and ip:
            # address-only identity that owns this IP right now (no MAC yet): it gets this MAC
            cur = _latest(conn, site, "ip", ip)
            if cur and ts - cur["last_seen"] <= CONFIRM_GAP:
                owner = resolve(conn, cur["identity_id"])
                has_mac = conn.execute("SELECT 1 FROM identity_evidence WHERE identity_id=? AND kind='mac' LIMIT 1", (owner,)).fetchone()
                if not has_mac:
                    iid = owner
                    conn.execute("UPDATE identities SET basis=?, updated_at=? WHERE id=? AND basis='ip-only'",
                                 ("random-mac" if randomized(mac) else "mac", ts, iid))
                    _event(conn, iid, "discovery", "mac_learned", {"mac": mac, "ip": ip, "source": source}, ts)
        if iid is None:
            iid = _new_identity(conn, site, "random-mac" if randomized(mac) else "mac", ts)
            other = conn.execute("SELECT DISTINCT identity_id FROM identity_evidence WHERE kind='mac' AND value=? AND site!=?",
                                 (mac, site)).fetchall()
            for o in other:   # the same MAC at another site: a moved device, a migrated VM or a copied MAC — a person decides
                _suggest(conn, site, "same_mac_other_site", iid, resolve(conn, o["identity_id"]), {"mac": mac}, ts)
        _touch(conn, iid, site, "mac", mac, ts, source)
        if ip:
            prev = _latest(conn, site, "ip", ip)
            if prev and resolve(conn, prev["identity_id"]) != iid and prev["last_seen"] >= ts - CONFIRM_GAP:
                _event(conn, iid, "discovery", "address_taken_over", {"ip": ip, "previous_identity": resolve(conn, prev["identity_id"]),
                                                                       "mac": mac, "source": source}, ts)
            other = conn.execute("SELECT value, last_seen FROM identity_evidence WHERE identity_id=? AND kind='ip' AND value!=? "
                                 "ORDER BY last_seen DESC LIMIT 1", (iid, ip)).fetchone()
            new_row = not conn.execute("SELECT 1 FROM identity_evidence WHERE identity_id=? AND kind='ip' AND value=?", (iid, ip)).fetchone()
            _touch(conn, iid, site, "ip", ip, ts, source)
            if other and new_row:
                if other["last_seen"] >= ts - SLACK:   # both addresses in use at once: a second address, not a move
                    _event(conn, iid, "discovery", "address_added", {"also": other["value"], "new": ip, "mac": mac}, ts)
                else:
                    _event(conn, iid, "discovery", "address_changed", {"from": other["value"], "to": ip, "mac": mac}, ts)
                    _suggest(conn, site, "moved", iid, None, {"from": other["value"], "to": ip, "mac": mac}, ts)
    else:
        prev = _latest(conn, site, "ip", ip)
        if prev is None:
            iid = _new_identity(conn, site, "ip-only", ts)
            _touch(conn, iid, site, "ip", ip, ts, source)
        else:
            iid = resolve(conn, prev["identity_id"])
            # recent confirmation: same interval; otherwise the owner is only probable (inferred) until a MAC confirms it
            _touch(conn, iid, site, "ip", ip, ts, source, inferred=0 if ts - prev["last_seen"] <= CONFIRM_GAP else 1)
    if hostname:
        _touch(conn, iid, site, "hostname", hostname.lower(), ts, source)
        for o in conn.execute("SELECT DISTINCT identity_id FROM identity_evidence WHERE site=? AND kind='hostname' AND value=? AND identity_id!=?",
                              (site, hostname.lower(), iid)).fetchall():
            oid = resolve(conn, o["identity_id"])
            if oid != iid and not _generic_hostname(hostname):
                _suggest(conn, site, "same_hostname", iid, oid, {"hostname": hostname}, ts)
    if lease:
        _touch(conn, iid, site, "dhcp", ip or mac, ts, source, detail=lease)
    conn.execute("UPDATE identities SET updated_at=? WHERE id=?", (ts, iid))
    return iid


GENERIC = {"localhost", "ubuntu", "debian", "android", "iphone", "ipad", "raspberrypi", "dev", "test", "server", "host",
           "desktop", "laptop", "unknown", "espressif", "router", "switch", "printer"}


def _generic_hostname(h):
    """Factory-default names say nothing about which device it is (two 'ubuntu' VMs are not one machine)."""
    h = h.lower().split(".")[0]
    return h in GENERIC or h.startswith(("android-", "desktop-", "iphone", "galaxy-", "esp-", "esp32", "dhcp-"))


# ---- attribution --------------------------------------------------------------------------------------
def owner_at(conn, site, ip, ts):
    """Who had `ip` at site `site` at time `ts`. Returns
    {identity, confidence: high|medium|low|unknown, ambiguous: [ids], explain: str}."""
    ip = norm_ip(ip)
    if not ip:
        return {"identity": None, "confidence": "unknown", "ambiguous": [], "explain": "not an IP address"}
    rows = conn.execute("SELECT * FROM identity_evidence WHERE site=? AND kind='ip' AND value=? ORDER BY first_seen", (site, ip)).fetchall()
    cover = [r for r in rows if r["first_seen"] - SLACK <= ts <= r["last_seen"] + SLACK]
    owners = sorted({resolve(conn, r["identity_id"]) for r in cover})
    if len(owners) > 1:
        return {"identity": None, "confidence": "low", "ambiguous": owners,
                "explain": f"{len(owners)} devices used {ip} around that time (address changed hands, or duplicate addresses); "
                           "the event cannot be tied to one of them"}
    if owners:
        r = max(cover, key=lambda x: x["last_seen"])
        basis = _basis(conn, owners[0])
        conf = "low" if r["inferred"] or basis == "ip-only" else "medium" if basis == "random-mac" else "high"
        why = ("seen on this address again after a gap without a MAC confirmation, so the owner is probable, not certain"
               if r["inferred"] else BASIS_TEXT.get(basis, ""))
        return {"identity": owners[0], "confidence": conf, "ambiguous": [], "explain": why}
    before = [r for r in rows if r["last_seen"] < ts]
    if before and ts - before[-1]["last_seen"] <= EXTRAPOLATE:
        return {"identity": resolve(conn, before[-1]["identity_id"]), "confidence": "low", "ambiguous": [],
                "explain": f"last confirmed on {ip} {int((ts - before[-1]['last_seen']) / 3600)} h before the event; probably the same device"}
    return {"identity": None, "confidence": "unknown", "ambiguous": [],
            "explain": "no device was recorded on this address at that time" if rows else "this address has no recorded owner yet"}


def _basis(conn, iid):
    r = conn.execute("SELECT basis FROM identities WHERE id=?", (iid,)).fetchone()
    return r["basis"] if r else ""


def evidence(conn, iid):
    """Evidence rows of an identity (including rows merged into it), newest first."""
    return [dict(r) for r in conn.execute("SELECT * FROM identity_evidence WHERE identity_id=? ORDER BY kind, last_seen DESC", (iid,))]


def current_ip(conn, iid):
    r = conn.execute("SELECT value FROM identity_evidence WHERE identity_id=? AND kind='ip' ORDER BY last_seen DESC LIMIT 1", (iid,)).fetchone()
    return r["value"] if r else ""


def name_of(conn, cfg, iid):
    """Friendly name: the name a person gave the identity, else the Inventory name of its current address, else its
    hostname, else the address."""
    r = conn.execute("SELECT name FROM identities WHERE id=?", (iid,)).fetchone()
    if r and r["name"]:
        return r["name"]
    ip = current_ip(conn, iid)
    # a real name from any of its addresses, newest first (auto-discovered entries are named after their own IP)
    for x in conn.execute("SELECT value, max(last_seen) AS t FROM identity_evidence WHERE identity_id=? AND kind='ip' "
                          "GROUP BY value ORDER BY t DESC LIMIT 8", (iid,)):
        lab = cfg.label(x["value"])
        if lab and lab != x["value"]:
            return lab
    h = conn.execute("SELECT value FROM identity_evidence WHERE identity_id=? AND kind='hostname' ORDER BY last_seen DESC LIMIT 1", (iid,)).fetchone()
    return h["value"] if h else (ip or f"device #{iid}")


def sites_for_ip(cfg, ip):
    """Sites whose internal networks contain ip (more than one = overlapping private ranges)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return []
    out = []
    for s in cfg.sites:
        nets = [ipaddress.ip_network(str(n), strict=False) for n in s.get("internal_nets", [])]
        if any(a in n for n in nets):
            out.append(s["id"])
    if not out and cfg.is_internal(ip):
        out = [s["id"] for s in cfg.sites] if len(cfg.sites) == 1 else []
    return out


def label(conn, cfg, ip, site=None, ts=None):
    """Display record for an address: {name, ip, site, site_name, identity, confidence, explain}. The friendly name is
    first, IP and site are secondary. With ts, the owner at that time (historical attribution)."""
    ip = norm_ip(ip) or str(ip)
    if site is None:
        cand = sites_for_ip(cfg, ip)
        site = cand[0] if len(cand) == 1 else None
    s = cfg.site(site) if site else None
    out = {"ip": ip, "site": site, "site_name": s["name"] if s else "", "identity": None, "confidence": "unknown",
           "explain": "", "name": cfg.label(ip) or ip}
    if site and _usable_ip(cfg, ip):
        o = owner_at(conn, site, ip, ts or time.time())
        out.update(identity=o["identity"], confidence=o["confidence"], explain=o["explain"], ambiguous=o["ambiguous"])
        if o["identity"]:
            out["name"] = name_of(conn, cfg, o["identity"])
    return out


def _usable_ip(cfg, ip):
    try:
        return cfg.is_internal(ip)
    except ValueError:
        return False


# ---- review: merge, separate, rename, suggestions -----------------------------------------------------
def merge(conn, keep, gone, user, reason=""):
    """Merge identity `gone` into `keep` (same site only). Evidence rows remember their original identity for undo."""
    keep, gone = resolve(conn, keep), resolve(conn, gone)
    a = conn.execute("SELECT * FROM identities WHERE id=?", (keep,)).fetchone()
    b = conn.execute("SELECT * FROM identities WHERE id=?", (gone,)).fetchone()
    if not a or not b or keep == gone:
        raise ValueError("pick two different devices")
    if a["site"] != b["site"]:
        raise ValueError("devices at different sites are kept separate (their addresses can overlap)")
    now = time.time()
    n = conn.execute("UPDATE identity_evidence SET original_identity=coalesce(original_identity, identity_id), identity_id=? WHERE identity_id=?",
                     (keep, gone)).rowcount
    conn.execute("UPDATE identities SET status='merged', merged_into=?, updated_at=? WHERE id=?", (keep, now, gone))
    if not a["name"] and b["name"]:
        conn.execute("UPDATE identities SET name=? WHERE id=?", (b["name"], keep))
    if a["basis"] == "ip-only" and b["basis"] != "ip-only":
        conn.execute("UPDATE identities SET basis=? WHERE id=?", (b["basis"], keep))
    conn.execute("UPDATE alerts SET identity_id=? WHERE identity_id=?", (keep, gone))
    for iid in (keep, gone):
        _event(conn, iid, user, "merged", {"kept": keep, "merged": gone, "rows": n, "reason": reason}, now)
    conn.execute("UPDATE identity_suggestions SET status='accepted', decided_by=?, decided_at=? WHERE status='open' AND "
                 "((a=? AND b=?) OR (a=? AND b=?))", (user, now, keep, gone, gone, keep))
    conn.commit()
    audit(conn, user, "identity_merged", {"kept": keep, "merged": gone, "rows": n, "reason": reason})
    return n


def unmerge(conn, gone, user):
    """Undo a merge: rows that came from `gone` go back to it and it is active again."""
    b = conn.execute("SELECT * FROM identities WHERE id=?", (gone,)).fetchone()
    if not b or b["status"] != "merged":
        raise ValueError("that device was not merged")
    now = time.time()
    n = conn.execute("UPDATE identity_evidence SET identity_id=?, original_identity=NULL WHERE original_identity=?", (gone, gone)).rowcount
    conn.execute("UPDATE identities SET status='active', merged_into=NULL, updated_at=? WHERE id=?", (now, gone))
    _event(conn, gone, user, "unmerged", {"from": b["merged_into"], "rows": n}, now)
    _event(conn, b["merged_into"], user, "unmerged", {"restored": gone, "rows": n}, now)
    conn.commit()
    audit(conn, user, "identity_unmerged", {"restored": gone, "from": b["merged_into"], "rows": n})
    return n


def separate(conn, iid, row_ids, user, reason=""):
    """Move the chosen evidence rows of `iid` to a new identity (e.g. two machines that shared one record)."""
    iid = resolve(conn, iid)
    me = conn.execute("SELECT * FROM identities WHERE id=?", (iid,)).fetchone()
    rows = [r for r in evidence(conn, iid) if r["id"] in set(row_ids)]
    if not me or not rows or len(rows) == len(evidence(conn, iid)):
        raise ValueError("choose some, but not all, of the device's addresses to separate")
    now = time.time()
    has_mac = [r for r in rows if r["kind"] == "mac"]
    basis = ("random-mac" if randomized(has_mac[0]["value"]) else "mac") if has_mac else "ip-only"
    new = _new_identity(conn, me["site"], basis, now, user, note=f"separated from device #{iid}")
    conn.executemany("UPDATE identity_evidence SET identity_id=?, original_identity=coalesce(original_identity, ?) WHERE id=?",
                     [(new, iid, r["id"]) for r in rows])
    _event(conn, iid, user, "separated", {"new": new, "rows": [r["id"] for r in rows], "reason": reason}, now)
    conn.commit()
    audit(conn, user, "identity_separated", {"from": iid, "new": new, "rows": [r["id"] for r in rows], "reason": reason})
    return new


def rename(conn, iid, name, user):
    iid = resolve(conn, iid)
    name = " ".join(str(name or "").split())[:64]
    conn.execute("UPDATE identities SET name=?, basis=CASE WHEN basis='ip-only' THEN basis ELSE basis END, updated_at=? WHERE id=?",
                 (name or None, time.time(), iid))
    _event(conn, iid, user, "renamed", {"name": name})
    conn.commit()
    audit(conn, user, "identity_renamed", {"id": iid, "name": name})


def decide(conn, sid, status, user):
    if status not in ("accepted", "dismissed"):
        raise ValueError("bad decision")
    conn.execute("UPDATE identity_suggestions SET status=?, decided_by=?, decided_at=? WHERE id=?", (status, user, time.time(), sid))
    conn.commit()
    audit(conn, user, "identity_suggestion", {"id": sid, "status": status})


SUGGESTION_TEXT = {
    "same_hostname": "Both devices reported the hostname “{hostname}”. That can be one machine with two network cards, a "
                     "device that got a new network card, or two machines that happen to share a name.",
    "same_mac_other_site": "The MAC address {mac} was seen at two sites. That can be a device that moved, a migrated virtual "
                           "machine, or a copied MAC. Devices at different sites stay separate.",
    "moved": "This device (MAC {mac}) moved from {from} to {to}. Names in Inventory are kept per address, so the old name "
             "stays on {from}.",
}


def suggestion_text(kind, detail):
    try:
        return SUGGESTION_TEXT.get(kind, kind).format(**detail)
    except (KeyError, IndexError):
        return kind


def ingest_discovery(conn, seen_by_site, arp, ndp=None, leases=None, ts=None):
    """Feed one discovery pass: {site: {ip: last_seen}} from traffic, ARP / NDP rows {ip: {mac, hostname, site}}, DHCP
    lease rows [{ip, mac, hostname, site, starts, ends, type}]. Returns counts."""
    ts = ts or time.time()
    n = {"arp": 0, "ndp": 0, "dhcp": 0, "traffic": 0}
    for src, rows in (("arp", arp or {}), ("ndp", ndp or {})):
        for ip, a in rows.items():
            if observe(conn, a["site"], ts, ip=ip, mac=a.get("mac"), hostname=a.get("hostname"), source=src):
                n[src] += 1
    for lz in leases or []:
        lease = {k: lz.get(k) for k in ("starts", "ends", "type") if lz.get(k)}
        if observe(conn, lz["site"], ts, ip=lz.get("ip"), mac=lz.get("mac"), hostname=lz.get("hostname"), source="dhcp", lease=lease):
            n["dhcp"] += 1
    macs = {(a["site"], ip) for rows in (arp or {}, ndp or {}) for ip, a in rows.items()}
    for site, ips in (seen_by_site or {}).items():
        for ip, last in ips.items():
            if (site, ip) not in macs:   # already confirmed with a MAC this pass
                observe(conn, site, min(float(last), ts), ip=ip, source="traffic")
                n["traffic"] += 1
    conn.commit()
    return n
