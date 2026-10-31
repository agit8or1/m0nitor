"""Operator pages (Overview, Servers, Connections, Countries, Search, Investigations, Settings) and their APIs.

All APIs require a session, take the same scope parameters, and run bounded
server-side aggregations; the browser never receives raw flow datasets.
"""
import ipaddress
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor

from fastapi import Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from urllib.parse import quote

from . import counters, geocity
from .ai import AI
from .core import audit, get_state
from .dash import META, cname
from .detect import fmt_ts
from .web import (CATEGORY, RULE_LABEL, ROLES, app, cfg, lan_hosts_text, check_csrf, conn, csrf_field, csrf_token, current, dash, detector_status, e, enforcement,
                  internal_ip, need, page, user_of)

ai = AI(cfg, conn)
POOL = ThreadPoolExecutor(max_workers=8)
conn.executescript("""CREATE TABLE IF NOT EXISTS investigations (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, user TEXT NOT NULL, kind TEXT NOT NULL, target TEXT,
  digest TEXT, model TEXT, result TEXT, usage TEXT)""")
_previews = {}  # digest -> (ts, user, preview); in-memory, 15 min


def scope_of(req: Request, **over):
    p = dict(req.query_params)
    p.update(over)
    try:
        return dash.scope(site=p.get("site", "all"), range_key=p.get("range", "15m"), start=p.get("from"), end=p.get("to"),
                          cc=p.get("cc", ""), host=p.get("host", ""), asn=p.get("asn", ""), port=p.get("port", ""),
                          rip=p.get("rip", ""))
    except ValueError as ex:
        raise HTTPException(400, str(ex))


def guard(fn):
    try:
        return fn()
    except HTTPException:
        raise
    except Exception as ex:
        return JSONResponse({"ok": False, "error": str(ex)[:400]}, status_code=503)


def open_alerts():
    return [dict(a) for a in conn.execute("SELECT * FROM alerts WHERE status='open' AND test=0")]


def alert_summary():
    out = {"security": {"high": 0, "medium": 0, "low": 0}, "info": 0, "health": 0}
    for a in open_alerts():
        cat = CATEGORY.get(a["rule"], "security")
        if cat == "security":
            k = "high" if a["severity"] in ("high", "critical") else "medium" if a["severity"] == "medium" else "low"
            out["security"][k] += 1
        elif cat in ("info", "health"):
            out[cat] += 1
    return out


def _internal(ip):
    """True when `ip` is an internal server address (has a server page); NAT/public subjects do not."""
    try:
        return bool(ip) and cfg.is_internal(ip)
    except ValueError:
        return False


def alert_brief(a):
    nxt = (json.loads(a["next_steps"] or "[]") or [""])[0]
    return {"id": a["id"], "severity": a["severity"], "confidence": a["confidence"], "title": a["title"],
            "rule": RULE_LABEL.get(a["rule"], a["rule"]), "category": CATEGORY.get(a["rule"], "security"),
            "asset": a["asset"], "asset_label": cfg.asset_label(a["asset"]) if a["asset"] else "",
            "asset_internal": _internal(a["asset"]),
            "last_seen": a["last_seen"], "count": a["count"], "why": a["baseline"], "next": nxt,
            "direction": a["direction"], "direction_verified": bool(a["direction_verified"]), "direction_basis": a["direction_basis"],
            "site": a["site"], "lan_hosts": lan_hosts_text(a), "status": a["status"]}


_alert_cc = {"t": 0, "v": {}}


def alert_countries():
    """Countries of remote addresses named in open security/info alerts (from observed flows)."""
    # cache keyed on the open-finding set too, so ack/unack/close shows on the map at the next refresh
    fp = tuple(conn.execute("SELECT count(*), coalesce(sum(id), 0), coalesce(max(last_seen), 0) FROM alerts WHERE status='open' AND test=0").fetchone())
    if time.time() - _alert_cc["t"] < 60 and _alert_cc.get("fp") == fp:
        return _alert_cc["v"]
    by_cc, ips, meta = {}, {}, {}
    for a in open_alerts():
        cat = CATEGORY.get(a["rule"], "security")
        if a["rule"] == "new_dest_country":
            d = by_cc.setdefault(a["subject"], {"security": 0, "info": 0, "ids": []})
            d["info"] += 1
            d["ids"].append(a["id"])
            continue
        if cat != "security" or a["severity"] in ("low", "info") or a["confidence"] == "low":
            continue  # red map markers need a credible (medium+ severity and confidence) finding
        meta[a["id"]] = {"id": a["id"], "title": a["title"], "severity": a["severity"], "last_seen": a["last_seen"],
                         "asset": a["asset"] or "", "asset_label": cfg.asset_label(a["asset"]) if a["asset"] else ""}
        for ev in json.loads(a["evidence"] or "[]"):
            if isinstance(ev, dict):
                for k in ("peers", "sample_peers", "peer", "top_dst", "top_dsts"):
                    v = ev.get(k)
                    for ip in (v if isinstance(v, list) else [v] if v else []):
                        ips.setdefault(str(ip), set()).add(a["id"])
    if ips:
        sc = dash.scope(range_key="7d")
        rows = dash.q(sc, """SELECT replaceOne(IPv6NumToString(SrcAddr), '::ffff:', '') AS ip, any(SrcCountry) AS cc FROM flows
                             WHERE TimeReceived > now() - INTERVAL 7 DAY AND has({ips:Array(String)}, replaceOne(IPv6NumToString(SrcAddr), '::ffff:', ''))
                             GROUP BY ip""", {"ips": sorted(ips)}, ttl=60)
        for r in rows:
            r["cc"] = (r["cc"] or "").strip("\x00")
            if r["cc"]:
                d = by_cc.setdefault(r["cc"], {"security": 0, "info": 0, "ids": []})
                # per-finding detail for the map marker tooltip: which endpoints in this country the finding names
                its = {x["id"]: x for x in d.setdefault("items", [])}
                for aid in ips[r["ip"]]:
                    it = its.setdefault(aid, {**meta[aid], "endpoints": []})
                    if r["ip"] not in it["endpoints"]:
                        it["endpoints"].append(r["ip"])
                d["items"] = sorted(its.values(), key=lambda x: -x["last_seen"])
                d.setdefault("sec_ids", [])
                d["sec_ids"] = sorted(set(d["sec_ids"]) | ips[r["ip"]])
                d["ids"] = sorted(set(d["ids"]) | ips[r["ip"]])
                d["security"] = len(d["sec_ids"])
    _alert_cc.update(t=time.time(), v=by_cc, fp=fp)
    return by_cc


def counter_series(sc):
    """Interface-counter series for the scope's sites (site-wide WAN; not affected by country/server filters)."""
    out = []
    for s in sc.sites:
        sn = s.get("snmp")
        if not sn:
            continue
        for name in sn["interfaces"]:
            st, ts = get_state(conn, f"snmp:{s['id']}:{name}", {})
            b = counters.bucketed(conn, s["id"], name, sc.start, sc.end, sc.bucket, sn["interval_seconds"])
            b.update(site=s["id"], iface=name, ok=bool(st and st.get("ok")), error=(st or {}).get("error"),
                     polled=ts, port_speed_mbps=(st or {}).get("speed_mbps"), capacity_mbps=s.get("wan_down_mbps"),
                     down_mbps=s.get("wan_down_mbps"), up_mbps=s.get("wan_up_mbps"), site_name=s["name"],
                     interval=sn["interval_seconds"])
            out.append(b)
    return out


def capacity_status():
    """Current WAN use against contracted capacity, per firewall.

    Interface counters (SNMP) when polled within 3 intervals; otherwise a flow-record estimate over the
    last 5 minutes, which understates long transfers (they are exported at the active timeout)."""
    now = time.time()
    out, need_flows = [], []
    for s in cfg.sites:
        row = {"id": s["id"], "name": s["name"], "vendor": s["vendor"], "down_mbps": s.get("wan_down_mbps"),
               "up_mbps": s.get("wan_up_mbps"), "in_bps": None, "out_bps": None, "peak_in_bps": None, "peak_out_bps": None,
               "source": None, "at": None}
        sn = s.get("snmp") or {}
        ifs = sn.get("interfaces") or {}
        if ifs:
            name = s["wan_if"] if s["wan_if"] in ifs else next(iter(ifs))
            iv = sn.get("interval_seconds", 10)
            b = counters.bucketed(conn, s["id"], name, now - 3600, now, 60, iv)
            c = b["current"]
            if c and now - c["t"] < 3 * iv:
                row.update(in_bps=c["in_bps"], out_bps=c["out_bps"], peak_in_bps=b["peak_in_bps"], peak_out_bps=b["peak_out_bps"],
                           source=f"WAN interface {name} counters (SNMP, {iv} s)", at=c["t"])
        if row["source"] is None:
            need_flows.append(row)
        out.append(row)
    if need_flows:
        sc = dash.scope(range_key="15m")
        exp = {x["exporter"]: x["id"] for x in cfg.sites}
        rows = dash.q(sc, "SELECT ExporterName AS e, sumIf(Bytes, INB) AS ib, sumIf(Bytes, OUTB) AS ob FROM flows "
                          "WHERE has({exps:Array(String)}, ExporterName) AND TimeReceived >= now() - 360 AND TimeReceived < now() - 60 "
                          "GROUP BY e", ttl=10)
        got = {exp.get(r["e"]): r for r in rows}
        for row in need_flows:
            r = got.get(row["id"])
            if r:
                row.update(in_bps=r["ib"] * 8 / 300, out_bps=r["ob"] * 8 / 300, at=now - 60,
                           source="flow-record estimate, last 5 min (understates long transfers)")
    return out


def site_locations():
    out = []
    for s in cfg["sites"]:
        loc = s.get("location", {})
        name = loc.get("label") or s["name"]
        if loc.get("lat") is not None and loc.get("lon") is not None:
            out.append({"id": s["id"], "name": name, "lat": loc["lat"], "lon": loc["lon"], "cc": loc.get("country") or "",
                        "source": "location configured in Settings"})
        elif loc.get("country") in META:
            ll = META[loc["country"]]["ll"]
            out.append({"id": s["id"], "name": name, "lat": ll[0], "lon": ll[1], "cc": loc["country"],
                        "source": f"{cname(loc['country'])} country centroid (exact location not set — Settings → Sites)"})
    return out


def home_regions(sc, sites, countries):
    """The site's own country has no meaningful country-centroid arc, so its busiest endpoints are placed by region
    (city-level GeoIP). `covered` = share of that country's bytes the located endpoints carry; the rest stays a ring."""
    home = sites[0] if sites else None
    cc = home and home.get("cc")
    tot = next((c["in_b"] + c["out_b"] for c in countries if c["cc"] == cc), 0) if cc else 0
    if not tot:
        return {"cc": cc or "", "regions": [], "covered": 0, "geo": geocity.GEO.provenance()}
    rows = dash.top_remotes(sc, cc)
    # city database puts the address in another country: typically anycast CDNs (one address, many locations)
    disputed = sum(r["in_b"] + r["out_b"] for r in rows if (g := geocity.GEO.loc(r["ip"])) and g["cc"] != cc)
    regs = geocity.regions(rows)
    return {"cc": cc, "regions": regs, "covered": min(1, sum(r["in_b"] + r["out_b"] for r in regs) / tot),
            "disputed": min(1, disputed / tot), "geo": geocity.GEO.provenance()}


def named_novelty(sc):
    rows = dash.server_novelty(sc)
    asn = [{"asn": int(r["v"])} for r in rows if r["kind"] == "asn"]
    dash._names(asn, "asn", "name", sc)
    names = {str(a["asn"]): a["name"] for a in asn}
    return [{**r, "label": cname(r["v"]) if r["kind"] == "country" else (names.get(r["v"]) or f"AS{r['v']}"),
             "sub": r["v"] if r["kind"] == "country" else f"AS{r['v']}"} for r in rows]


# ---- APIs ----------------------------------------------------------------------------------
@app.get("/netmon/api/live")
def api_live(req: Request):
    current(req)

    def run():
        sc = dash.scope(range_key="15m")
        cs = counter_series(dash.scope(range_key="15m"))
        cur = [{"site": c["site"], "iface": c["iface"], "ok": c["ok"], "current": c["current"], "polled": c["polled"]} for c in cs]
        return {"ok": True, "collection": dash.collection(sc), "counters": cur, "now": time.time(),
                "alerts": alert_summary(), "detector": detector_status(), "capacity": capacity_status(),
                "active_timeout": cfg["exporter_active_timeout"]}
    return guard(run)


@app.get("/netmon/api/overview")
def api_overview(req: Request):
    current(req)
    sc = scope_of(req)

    def run():
        coll = dash.collection(sc)
        alerts = [alert_brief(a) for a in conn.execute(
            "SELECT * FROM alerts WHERE status='open' AND test=0 ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC LIMIT 40")]
        alerts.sort(key=lambda a: {"security": 0, "health": 1, "info": 2}.get(a["category"], 3))
        jobs = {"summary": lambda: dash.summary(sc), "flow_series": lambda: dash.flow_series(sc, coll),
                "countries": lambda: dash.countries(sc), "srv": lambda: dash.servers(sc, limit=200),
                "orgs": lambda: dash.orgs(sc, 10), "services": lambda: dash.services(sc, 8),
                "recent": lambda: dash.conversations(sc, page=1, per=24, sort="time"), "alert_countries": alert_countries}
        r = {k: f.result() for k, f in {k: POOL.submit(fn) for k, fn in jobs.items()}.items()}
        srv = r.pop("srv")
        from .admin import sources
        sel = {s["id"] for s in sc.sites}
        locs = [l for l in site_locations() if l["id"] in sel]
        return {"ok": True, "scope": scope_json(sc), "collection": coll, **r, "counters": counter_series(sc), "sources": sources(),
                "sites": locs, "home": home_regions(sc, locs, r["countries"]), "alerts": alerts[:12], "alert_summary": alert_summary(),
                "blocked": geo_blocked(),
                "servers": srv["servers"][:10], "server_count": len(srv["servers"]), "unattributed_nat_tx": srv["unattributed_nat_tx"]}
    return guard(run)


def scope_json(sc):
    return {"start": sc.start, "end": sc.end, "span": sc.span, "bucket": sc.bucket, "range": sc.range_key,
            "sites": [s["id"] for s in sc.sites], "cc": sc.cc, "cc_name": cname(sc.cc) if sc.cc else "", "host": sc.host,
            "host_name": cfg.asset_label(sc.host) if sc.host else "", "asn": sc.asn, "port": sc.port, "rip": sc.rip,
            "describe": sc.describe()}


PEER_KEYS = ("peers", "sample_peers", "top_dst", "top_dsts", "peer", "dst", "remote")


@app.get("/netmon/api/alert/{aid}/traffic")
def api_alert_traffic(req: Request, aid: int):
    """Traffic behind one finding over its own evidence window: to/from whom, which countries, which ports."""
    current(req)
    a = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    if not a:
        raise HTTPException(404)

    def run():
        evs = [x for x in json.loads(a["evidence"] or "[]") if isinstance(x, dict)]
        peers, subj = [], a["asset"] or next((str(x["src"]) for x in evs if x.get("src")), "")
        for ev in evs:
            for k in PEER_KEYS:
                val = ev.get(k)
                for ip in (val if isinstance(val, list) else [val] if val else []):
                    try:
                        ipaddress.ip_address(str(ip))
                        peers.append(str(ip))
                    except ValueError:
                        pass
        try:
            ipaddress.ip_address(subj)
        except ValueError:
            subj = ""
        t1 = int(a["window_end"] or a["last_seen"]) + 60
        t0 = min(int(a["window_start"] or a["first_seen"]), t1 - 600)
        sc = dash.scope(site=a["site"] or "all", range_key="custom", start=t0, end=t1)
        d = dash.finding_traffic(sc, subj, sorted(set(peers))[:200])
        named = set(peers)
        geocity.locate(d["remotes"])
        # named endpoints with no flows (e.g. a scan the firewall blocked: blocked packets create no flow records)
        seen = {r["ip"] for r in d["remotes"]}
        d["evidence_only"] = []
        for ip in sorted(named - seen)[:40]:
            cc = blocks().geo.cc(ip) or "??"
            ev = next((x for x in evs if ip in (x.get("peer"), x.get("s"), x.get("src"))), {})
            d["evidence_only"].append({"ip": ip, "cc": cc, "cc_name": cname(cc), "events": int(ev.get("events") or 0),
                                       "blocked": a["rule"].startswith("fw_blocked"), "name": cfg.label(ip)})
        geocity.locate(d["evidence_only"])
        rd = dash.rdns.wait([r["ip"] for r in d["remotes"] + d["evidence_only"]])
        for r in d["remotes"] + d["evidence_only"]:
            r["rdns"] = rd.get(r["ip"])
        marks = {}
        for r in d["remotes"]:
            if r["ip"] in named and r["cc"] != "??":
                m = marks.setdefault(r["cc"], {"security": 1, "info": 0, "items": [{"id": a["id"], "title": a["title"], "severity": a["severity"],
                                                                                    "last_seen": a["last_seen"], "asset": a["asset"] or "",
                                                                                    "asset_label": cfg.asset_label(a["asset"]) if a["asset"] else "", "endpoints": []}]})
                m["items"][0]["endpoints"].append(r["ip"])
        sel = {s["id"] for s in sc.sites}
        finding = {"id": a["id"], "title": a["title"], "severity": a["severity"], "last_seen": a["last_seen"], "asset": a["asset"] or "",
                   "asset_label": cfg.asset_label(a["asset"]) if a["asset"] else "", "security": CATEGORY.get(a["rule"], "security") == "security"}
        return {"ok": True, **d, "finding": finding, "geo": geocity.GEO.provenance(), "subject": subj, "subject_label": cfg.asset_label(subj) if subj else "", "peers": sorted(named),
                "scope": scope_json(sc), "sites": [x for x in site_locations() if x["id"] in sel],
                "alert_countries": marks if CATEGORY.get(a["rule"], "security") == "security" else {}}
    return guard(run)


@app.get("/netmon/api/servers")
def api_servers(req: Request, page_: int = Query(1, alias="page"), sort: str = "total", per: int = 50):
    current(req)
    sc = scope_of(req)

    def run():
        d = dash.servers(sc, limit=500)
        rows = d["servers"]
        key = {"total": lambda h: h["rx"] + h["tx"], "in": lambda h: h["rx"], "out": lambda h: h["tx"],
               "last": lambda h: h["last"] or 0, "countries": lambda h: h["countries"]}.get(sort, lambda h: h["rx"] + h["tx"])
        rows.sort(key=key, reverse=True)
        counts = {}
        for a in open_alerts():
            counts[a["asset"]] = counts.get(a["asset"], 0) + 1
        assets = cfg.get("assets", {})
        for h in rows:
            h["alerts"] = counts.get(h["ip"], 0)
            h["aliases"] = (assets.get(h["ip"]) or {}).get("aliases", [])
        per_ = max(10, min(per, 200))
        p = max(1, page_)
        shown = rows[(p - 1) * per_: p * per_]
        for h in shown:
            h["public"] = cfg.binat_ext(h["ip"])
        rd = dash.rdns.wait([h["ip"] for h in shown] + [x for h in shown for x in h["public"]] +
                            [h["top_remote"] for h in shown if h.get("top_remote")], timeout=2.0)
        for h in shown:
            h["rdns"] = rd.get(h["ip"])
            h["public"] = [{"ip": x, "fw": cfg.fw_label(x), "rdns": rd.get(x)} for x in h["public"]]
            h["top_remote_rdns"] = rd.get(h["top_remote"]) if h.get("top_remote") else None
        return {"ok": True, "scope": scope_json(sc), "rows": shown, "total": len(rows),
                "page": p, "per": per_, "unattributed_nat_tx": d["unattributed_nat_tx"]}
    return guard(run)


@app.get("/netmon/api/server")
def api_server(req: Request, ip: str):
    current(req)
    ip = internal_ip(ip)
    sc = scope_of(req, host=ip)

    def run():
        coll = dash.collection(sc)
        alerts = [alert_brief(a) for a in conn.execute("SELECT * FROM alerts WHERE asset=? AND test=0 ORDER BY last_seen DESC LIMIT 30", (ip,))]
        a = cfg.asset(ip)
        exps = [x for x in cfg.exposures if x.ip == ip]
        pub = cfg.binat_ext(ip)
        rd = dash.rdns.wait([ip] + pub + [x.public_ip for x in exps], timeout=2.0)
        # the server's own addresses: LAN, then the public 1:1 NAT address(es) it is reached on at the WAN
        addrs = [{"ip": ip, "kind": "LAN", "rdns": rd.get(ip)}] + \
                [{"ip": x, "kind": cfg.fw_label(x) or "1:1 NAT", "rdns": rd.get(x)} for x in pub]
        return {"ok": True, "scope": scope_json(sc), "ip": ip, "asset": a, "collection": coll, "addresses": addrs,
                "exposures": [{"proto": x.proto, "ports": f"{x.lo}" + (f"-{x.hi}" if x.hi != x.lo else ""), "public_ip": x.public_ip,
                               "public_fw": cfg.fw_label(x.public_ip), "rdns": rd.get(x.public_ip)} for x in exps],
                "summary": dash.summary(sc), "flow_series": dash.flow_series(sc, coll), "countries": dash.countries(sc, 30),
                "orgs": dash.orgs(sc, 12), "services": dash.services(sc, 12), "novelty": named_novelty(sc),
                "baseline_days": detector_status()["learning_days"],
                "conversations": dash.conversations(sc, page=1, per=25), "alerts": alerts, "ai_enabled": ai.enabled}
    return guard(run)


@app.get("/netmon/api/connections")
def api_connections(req: Request, page_: int = Query(1, alias="page"), sort: str = "bytes", dir: str = "", proto: str = ""):
    current(req)
    sc = scope_of(req)
    dir = dir if dir in ("in", "out", "unknown") else ""
    proto = proto if proto in ("tcp", "udp", "icmp", "other") else ""
    return guard(lambda: {"ok": True, "scope": scope_json(sc), "filters": {"dir": dir, "proto": proto},
                          **dash.conversations(sc, page=max(1, page_), per=50, sort="time" if sort == "time" else "bytes",
                                               direction=dir, proto=proto)})


@app.get("/netmon/api/countries")
def api_countries(req: Request):
    current(req)
    sc = scope_of(req)

    def run():
        coll = dash.collection(sc)
        pol = set(geo_policy()["countries"])
        rows = dash.countries(sc)
        geo = geo_policy()
        for r in rows:
            r["in_policy"] = r["cc"] in pol
            r["blocked_in"], r["blocked_out"] = r["cc"] in geo["blocked_in"], r["cc"] in geo["blocked_out"]
        return {"ok": True, "scope": scope_json(sc), "collection": coll, "countries": rows, "summary": dash.summary(sc),
                "alert_countries": alert_countries(), "sites": site_locations(), "home": home_regions(sc, site_locations(), rows), "policy": policy_json(),
                "policy_sites": policy_sites(sc.sites), "blocks": block_stats(sc)}
    return guard(run)


_BLOCKS = []


def blocks():
    if not _BLOCKS:
        from . import block as blk
        from .geoblocks import Blocks
        _BLOCKS.append(Blocks(cfg, dash.ch, geo_policy, blk.enforcer))
    return _BLOCKS[0]


def block_stats(sc):
    """Logged firewall block events per country for the scope (never fails the page: errors come back as a state)."""
    try:
        return blocks().public(blocks().stats(sc.sites, sc.start, sc.end))
    except Exception as ex:
        return {"state": "error", "error": str(ex)[:200], "countries": {}, "coverage": []}


def policy_sites(sites):
    """The GeoIP block policy of each firewall in scope, so the map can say "Mixed policy" when they differ."""
    out = []
    for s in sites:
        try:
            v = geo_policy(s)
        except Exception as ex:
            v = {"unknown": True, "error": str(ex)[:160], "blocked_in": {}, "blocked_out": {}, "rules": []}
        out.append({"site": s["id"], "name": s["name"], "unknown": bool(v.get("unknown")), "live": bool(v.get("live")),
                    "verified_at": v.get("verified_at"), "blocked_in": sorted(v["blocked_in"]), "blocked_out": sorted(v["blocked_out"]),
                    "rules": [{"interface": r.get("interface"), "sequence": r.get("sequence"), "side": r.get("side"), "description": r.get("description", "")}
                              for r in v.get("rules", []) if r.get("blocks")]})
    return out


@app.get("/netmon/api/country/{cc}/blocks")
def api_country_blocks(req: Request, cc: str):
    current(req)
    cc = cc.upper()
    if cc not in META:
        raise HTTPException(400, "unknown country code")
    sc = scope_of(req, cc="")

    def run():
        ev = blocks().events(sc.sites, sc.start, sc.end, cc)
        rows = ev.get("rows") or []
        rd = dash.rdns.wait([r[k] for r in rows for k in ("src", "dst") if r.get(k)], timeout=2.0)
        for r in rows:   # reverse DNS, and the firewall's own addresses named as WAN / WAN alias
            for k in ("src", "dst"):
                if r.get(k):
                    r[f"{k}_rdns"], r[f"{k}_fw"] = rd.get(r[k]), cfg.fw_label(r[k])
        return {"ok": True, "scope": scope_json(sc), "cc": cc, "name": cname(cc),
                "stats": {k: x for k, x in block_stats(sc).items() if k != "countries"}, **ev}
    return guard(run)


_GEO = {}   # site id -> {"t", "v"}
_GEO_LOCK = __import__("threading").Lock()


def geo_policy(site=None):
    """GeoIP alias contents and every filter rule that references it, read live from one OPNsense site (default: the
    first; read-only API calls, cached 5 min). Falls back to the last good read, then (first site only) to the
    config.yaml snapshot; a site whose policy cannot be read at all is marked unknown."""
    from . import block as blk
    site = site or cfg.sites[0]
    first = site["id"] == cfg.sites[0]["id"]
    skey = "geoip_policy" if first else f"geoip_policy:{site['id']}"
    with _GEO_LOCK:
        hit = _GEO.get(site["id"])
        if hit and time.time() - hit["t"] < 300:
            return hit["v"]
        alias = cfg.get("geoip_policy", {}).get("alias", "GeoIP_BLOCK")
        try:
            fw = blk.enforcer(site)
            if not isinstance(fw, blk.OPNsense) or not fw.enabled:
                raise blk.BlockError("no OPNsense API key configured")
            geo = [x for x in fw._call("GET", "/api/firewall/alias/search_item", params={"rowCount": "-1"}).get("rows", [])
                   if x.get("type") == "geoip"]
            if not geo:
                raise blk.BlockError("no GeoIP alias on the firewall")
            aliases = []
            for a in geo:
                rules = []
                for x in fw._call("POST", "/api/firewall/filter/search_rule", data={"searchPhrase": a["name"], "rowCount": "-1"}).get("rows", []):
                    for s in ("source", "destination"):
                        if a["name"] in str(x.get(f"{s}_net", "")).split(","):
                            rules.append({"uuid": x.get("uuid", ""), "enabled": x.get("enabled") == "1", "action": x.get("action"), "direction": x.get("direction"),
                                          "interface": x.get("%interface") or x.get("interface"), "sequence": x.get("sequence"),
                                          "description": x.get("description", ""), "side": s, "negated": x.get(f"{s}_not") == "1"})
                aliases.append({"name": a["name"], "enabled": a.get("enabled") == "1", "rules": rules,
                                "countries": [c for c in a.get("content", "").split() if c]})
            prim = next((a for a in aliases if a["name"] == alias), aliases[0])
            v = {"alias": prim["name"], "alias_enabled": prim["enabled"], "countries": prim["countries"], "rules": prim["rules"],
                 "aliases": aliases, "live": True, "verified_at": time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime()),
                 "source": f"read live from {site['name']} (OPNsense API, read-only)"}
            from .core import set_state
            set_state(conn, skey, v)
        except Exception as ex:
            v, _ = get_state(conn, skey, None)
            if v:
                v = {**v, "live": False, "error": str(ex)[:200], "source": f"last successful read (firewall unreachable now: {str(ex)[:120]})"}
            elif not first:
                v = {"alias": alias, "alias_enabled": False, "countries": [], "rules": [], "aliases": [], "live": False, "unknown": True,
                     "error": str(ex)[:200], "verified_at": None, "source": f"policy of {site['name']} could not be read: {str(ex)[:120]}"}
            else:
                p = cfg.get("geoip_policy", {})
                r = p.get("rule", {})
                rules = [{**r, "side": "source", "negated": False, "description": ""}] if r else []
                v = {"alias": alias, "alias_enabled": True, "countries": p.get("countries", []), "live": False, "error": str(ex)[:200],
                     "rules": rules, "aliases": [{"name": alias, "enabled": True, "rules": rules, "countries": p.get("countries", [])}],
                     "verified_at": p.get("verified_at"), "source": "config.yaml snapshot (firewall not reachable)"}
        # a country is blocked in a direction when an enabled alias sits on an enabled block/reject rule:
        # alias as source = traffic from that country (inbound); as destination = traffic to it (outbound)
        blocked = {"in": {}, "out": {}}
        for a in v["aliases"]:
            for r in a["rules"]:
                r["blocks"] = a["enabled"] and r["enabled"] and r["action"] in ("block", "reject") and not r["negated"]
                if r["blocks"]:
                    d = "in" if r["side"] == "source" else "out"
                    for c in a["countries"]:
                        blocked[d].setdefault(c, []).append(f"{a['name']} · {r['interface']} rule {r['sequence']}")
        v["blocked_in"], v["blocked_out"] = blocked["in"], blocked["out"]
        on = [r for r in v["rules"] if r.get("blocks")]
        v["enforced"] = bool(v["alias_enabled"] and on)
        v["note"] = (f"{len(on)} enabled block rule(s) reference {alias}." if v["enforced"] else
                     f"The alias {alias} is disabled." if not v["alias_enabled"] else
                     f"No rule references {alias}." if not v["rules"] else
                     f"Every rule referencing {alias} is disabled, so these countries are not blocked.")
        v["rule"] = (on or v["rules"] or [{}])[0]
        v["count"] = len(v["countries"])
        v["site"], v["site_name"] = site["id"], site["name"]
        _GEO[site["id"]] = {"t": time.time(), "v": v}
        return v


def geo_blocked():
    try:
        v = geo_policy()
        return {"in": sorted(v["blocked_in"]), "out": sorted(v["blocked_out"])}
    except Exception:
        return None


def policy_json():
    v = geo_policy()
    return {**{k: x for k, x in v.items() if k not in ("countries", "aliases", "blocked_in", "blocked_out")},
            "aliases": [{k: x for k, x in a.items() if k != "countries"} | {"count": len(a["countries"])} for a in v["aliases"]],
            "blocked_in": sorted(v["blocked_in"]), "blocked_out": sorted(v["blocked_out"])}


@app.get("/netmon/api/country")
def api_country(req: Request, cc: str):
    current(req)
    cc = cc.upper()
    if cc not in META and cc != "??":
        raise HTTPException(400, "unknown country code")
    sc = scope_of(req, cc=cc)

    def run():
        coll = dash.collection(sc)
        ids = alert_countries().get(cc, {}).get("ids", [])
        findings = [alert_brief(a) for a in conn.execute(
            f"SELECT * FROM alerts WHERE id IN ({','.join('?' * len(ids))}) ORDER BY last_seen DESC", ids)] if ids else []
        pol = geo_policy()
        jobs = {"summary": lambda: dash.summary(sc), "flow_series": lambda: dash.flow_series(sc, coll),
                "servers": lambda: dash.servers(sc, 50)["servers"][:20], "orgs": lambda: dash.orgs(sc, 12),
                "conversations": lambda: dash.conversations(sc, page=1, per=25)}
        r = {k: f.result() for k, f in {k: POOL.submit(fn) for k, fn in jobs.items()}.items()}
        return {"ok": True, "scope": scope_json(sc), "cc": cc, "name": cname(cc), "collection": coll, **r, "findings": findings,
                "policy": {**policy_json(), "listed": cc in pol.get("countries", []),
                           "in": pol["blocked_in"].get(cc, []), "out": pol["blocked_out"].get(cc, [])}}
    return guard(run)


_PREVIEW7 = {}   # (cc, sites) -> (ts, preview): the 7-day block preview is heavy for busy countries; 10 min cache


@app.get("/netmon/api/country/{cc}/preview")
def api_country_preview(req: Request, cc: str):
    """What a block of this country would have affected over the last 7 days (loaded after the page; cached)."""
    current(req)
    cc = cc.upper()
    if cc not in META and cc != "??":
        raise HTTPException(400, "unknown country code")
    sc7 = scope_of(req, cc=cc, range="7d", **{"from": "", "to": ""})

    def run():
        key = (cc, tuple(s["id"] for s in sc7.sites))
        hit = _PREVIEW7.get(key)
        if hit and time.time() - hit[0] < 600:
            return {"ok": True, **hit[1]}
        jobs = {"servers": lambda: dash.servers(sc7, limit=100)["servers"][:15], "services": lambda: dash.services(sc7, 15),
                "summary": lambda: dash.summary(sc7)}
        pv = {"cc": cc, "name": cname(cc), "computed": time.time(), **{k: f.result() for k, f in {k: POOL.submit(fn) for k, fn in jobs.items()}.items()}}
        _PREVIEW7[key] = (time.time(), pv)
        return {"ok": True, **pv}
    return guard(run)


def prefix_range(q):
    """'203.0.113', '203.0.11', '203.0.113.' or a CIDR -> (network to scan, text prefix or ''), else None.
    At least two complete octets (or a /16 or narrower CIDR) so the scan stays bounded."""
    import ipaddress
    import re
    if "/" in q:
        try:
            n = ipaddress.ip_network(q, strict=False)
        except ValueError:
            return None
        return (n, "") if n.version == 4 and n.prefixlen >= 16 or n.version == 6 and n.prefixlen >= 48 else None
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){1,3}\.?", q):
        return None
    parts = q.rstrip(".").split(".")
    if any(int(x) > 255 for x in parts):
        return None
    full = parts if q.endswith(".") else parts[:-1]
    if len(full) < 2:
        return None
    full = full[:3]
    n = ipaddress.ip_network(".".join(full + ["0"] * (4 - len(full))) + f"/{8 * len(full)}")
    return n, ("" if q.endswith(".") or len(full) == len(parts) else q)


def address_prefix_matches(q):
    """Addresses seen in the last 7 days (flows, auto-response decisions, blocks) inside a partial IP or CIDR."""
    rng = prefix_range(q)
    if not rng:
        return []
    net, pre = rng
    out, seen = [], set()
    try:
        sc = dash.scope(range_key="7d")
        rows = dash.q(sc, """
            SELECT ip, sum(b) AS bytes, sum(n) AS flows, toUInt32(max(l)) AS last FROM (
              SELECT replaceOne(IPv6NumToString(if(INB, SrcAddr, DstAddr)), '::ffff:', '') AS ip, Bytes AS b, 1 AS n, TimeReceived AS l
              FROM flows WHERE has({exps:Array(String)}, ExporterName) AND TimeReceived > now() - INTERVAL 7 DAY AND (INB OR OUTB))
            WHERE isIPAddressInRange(ip, {net:String}) AND startsWith(ip, {pre:String})
            GROUP BY ip ORDER BY bytes DESC LIMIT 15""", {"net": str(net), "pre": pre}, ttl=120)
        for r in rows:
            seen.add(r["ip"])
            name = cfg.label(r["ip"])
            out.append({"type": "Server" if cfg.is_internal(r["ip"]) else "Remote IP", "label": f"{name} ({r['ip']})" if name else r["ip"],
                        "ip": r["ip"], "name": name,
                        "sub": f"{int(r['flows']):,} flows · last seen {fmt_ts(int(r['last']))}",
                        "href": f"/netmon/servers/{r['ip']}" if cfg.is_internal(r["ip"]) else f"/netmon/connections?rip={r['ip']}"})
    except Exception:
        pass
    import ipaddress
    for x in conn.execute("SELECT address, max(ts) AS ts, group_concat(DISTINCT decision) AS d FROM response_log GROUP BY address ORDER BY ts DESC LIMIT 2000"):
        try:
            hit = ipaddress.ip_address(x["address"]) in net and x["address"].startswith(pre)
        except ValueError:
            continue
        if hit:
            out.append({"type": "Auto-response", "label": x["address"], "sub": f"decisions: {x['d'].replace('_', ' ')} · {fmt_ts(x['ts'])}",
                        "href": "/netmon/settings/response#log"})
    for b in conn.execute("SELECT id, address, status, auto FROM blocks ORDER BY id DESC LIMIT 2000"):
        try:
            hit = ipaddress.ip_network(b["address"], strict=False).overlaps(net) and (not pre or b["address"].startswith(pre))
        except ValueError:
            continue
        if hit:
            out.append({"type": "Block", "label": f"#{b['id']} {b['address']}", "sub": f"{'automatic' if b['auto'] else 'manual'} · {b['status']}",
                        "href": f"/netmon/block/{b['id']}"})
    if not out:
        out.append({"type": "Remote IP", "label": f"No traffic from {q}* in the last 7 days", "sub": f"searched {net}", "href": "/netmon/connections"})
    return out


@app.get("/netmon/api/search")
def api_search(req: Request, q: str = ""):
    current(req)
    q = q.strip()[:64]
    if len(q) < 2:
        return {"ok": True, "results": []}
    ql, res = q.lower(), []
    for ip, a in cfg.get("assets", {}).items():
        if ql in ip or ql in a["name"].lower() or ql in a.get("role", "").lower() or any(ql in x.lower() for x in a.get("aliases", [])):
            res.append({"type": "Server", "label": a["name"], "sub": " · ".join(x for x in (ip, a.get("role"), ", ".join(a.get("aliases", []))) if x),
                        "href": f"/netmon/servers/{ip}"})
    for ip, a in cfg.get("labels", {}).items():
        if ql in ip or ql in a["name"].lower() or ql in a.get("notes", "").lower() or any(ql in x.lower() for x in a.get("aliases", [])):
            res.append({"type": "Remote IP", "label": a["name"], "ip": ip, "name": a["name"], "sub": "your label", "href": f"/netmon/connections?rip={ip}"})
    for cc, m in META.items():
        if ql == cc.lower() or ql in m["name"].lower():
            res.append({"type": "Country", "label": m["name"], "sub": cc, "href": f"/netmon/countries/{cc}"})
    for x in cfg.exposures:
        if q.isdigit() and x.lo <= int(q) <= x.hi:
            res.append({"type": "Service", "label": f"{x.proto}/{q} on {cfg.asset(x.ip)['name']}", "sub": "port forward",
                        "href": f"/netmon/servers/{x.ip}"})
    if q.isdigit():
        res.append({"type": "Service", "label": f"Connections on port {q}", "sub": "all servers", "href": f"/netmon/connections?port={q}"})
    import ipaddress
    try:
        ip = str(ipaddress.ip_address(q))
        if cfg.is_internal(ip):
            res.append({"type": "Server", "label": cfg.asset_label(ip), "sub": "internal address", "href": f"/netmon/servers/{ip}"})
        else:
            res.append({"type": "Remote IP", "label": cfg.label(ip) or ip, "ip": ip, "name": cfg.label(ip), "sub": "connections with this address",
                        "href": f"/netmon/connections?rip={ip}"})
    except ValueError:
        res += address_prefix_matches(q)
    asq = q.upper().removeprefix("AS")
    try:
        sc = dash.scope(range_key="7d")
        if asq.isdigit():
            rows = dash.q(sc, "SELECT toUInt32({a:UInt32}) AS asn, dictGetOrDefault('asns', 'name', toUInt64({a:UInt32}), '') AS name",
                          {"a": int(asq)}, ttl=3600)
        else:
            rows = dash.q(sc, """SELECT asn, dictGetOrDefault('asns', 'name', toUInt64(asn), '') AS name FROM
                          (SELECT DISTINCT if(INB, SrcAS, DstAS) AS asn FROM flows_1h0m0s WHERE has({exps:Array(String)}, ExporterName)
                           AND TimeReceived > now() - INTERVAL 30 DAY AND (INB OR OUTB))
                          WHERE positionCaseInsensitive(name, {s:String}) > 0 LIMIT 8""", {"s": q}, ttl=600)
        for r in rows:
            res.append({"type": "Organization", "label": r["name"] or f"AS{r['asn']}", "sub": f"AS{r['asn']}",
                        "href": f"/netmon/connections?asn={r['asn']}"})
    except Exception:
        pass
    return {"ok": True, "results": res[:40]}


# ---- pages ---------------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
@app.get("/netmon/", response_class=HTMLResponse)
def overview(req: Request):
    info = lambda nid, label: (f'<details class="info"><summary aria-label="{label}" title="{label}">i</summary>'  # noqa: E731
                               f'<div class="pop" id="{nid}"></div></details>')
    body = f"""
<section class="cards" id="cards" aria-live="polite"></section>
<section class="mainrow">
 <div class="card map-card"><div class="card-h"><h2>Where traffic goes</h2>
  <div class="panelctl"><div class="seg" id="mapdir" role="group" aria-label="Direction"><button data-v="both">Both</button><button data-v="in">Inbound</button><button data-v="out">Outbound</button></div>
  <select id="mapshade" aria-label="Shade countries by"><option value="bytes">Shade: bytes</option><option value="flows">Shade: flows</option><option value="alerts">Shade: findings</option><option value="blocked">Shade: GeoIP blocked</option></select>
  <button id="zoomin" aria-label="Zoom in">+</button><button id="zoomout" aria-label="Zoom out">−</button><button id="zoomreset">Reset</button>{info("mapnote", "About this map")}</div></div>
  <div id="map" class="map"></div><div class="legend" id="maplegend"></div></div>
 <div class="card sec-card"><div class="card-h"><h2>Security activity</h2><a href="/netmon/security" class="small">View all alerts →</a></div><div id="secpanel"></div></div>
</section>
<section class="card"><div class="card-h"><h2>WAN bandwidth</h2><div class="panelctl"><div class="legend" id="bwlegend"></div>
 <div class="seg" id="bwsrc" role="group" aria-label="Bandwidth source"><button data-v="counters">Interface counters</button><button data-v="flows">Flow-estimated</button></div>{info("bwnote", "About this chart")}</div></div>
 <div id="bwstats" class="bwsum"></div><div id="bw" class="chart"></div><div id="capacity" class="utilbar" aria-live="polite"></div></section>
<section class="quad">
 <div class="card"><div class="card-h"><h2>Top servers</h2><a href="/netmon/servers" class="small" data-keep>View all →</a></div><div id="t-servers"></div></div>
 <div class="card"><div class="card-h"><h2>Top organizations</h2><span class="muted small">remote networks (ASN)</span></div><div id="t-orgs"></div></div>
 <div class="card"><div class="card-h"><h2>Top countries</h2><a href="/netmon/countries" class="small" data-keep>View all →</a></div><div id="t-countries"></div></div>
 <div class="card"><div class="card-h"><h2>Top services</h2><a href="/netmon/connections" class="small" data-keep>View all →</a></div><div id="t-services"></div></div>
</section>
<section class="card"><div class="card-h"><h2>Recent connections</h2><div class="panelctl"><div class="pager compact" id="recentpager"></div>
 <a href="/netmon/connections" class="small" data-keep>View all connections →</a></div></div><div id="t-recent"></div></section>"""
    return page(req, "Network overview", body, "/", ("d3.min.js", "topojson-client.min.js", "map.js", "overview.js"))


@app.get("/netmon/servers", response_class=HTMLResponse)
def servers_page(req: Request):
    from .admin import tip_box
    body = f"""<section class="card"><div class="card-h"><h2>Internal servers</h2><span class="muted small" id="srvnote"></span></div>
<div class="wrap"><table class="tbl sortable" id="srv"><thead><tr><th data-sort="name">Name</th><th>Internal IP</th><th data-sort="in" class="num">Inbound rate</th>
<th data-sort="out" class="num">Outbound rate</th><th data-sort="total" class="num">Total transfer</th><th>Top remote</th><th data-sort="countries" class="num">Countries</th>
<th class="num">Alerts</th><th data-sort="last" class="num">Last seen</th></tr></thead><tbody></tbody></table></div><div class="pager" id="pager"></div>
<p class="note">Inbound = Internet → server (exact, after de-NAT). Outbound = server → Internet, only where a port-forward reply maps uniquely to the server;
traffic the server sends through the shared NAT address is shown separately and cannot be attributed from flows. Rates = transfer ÷ selected window (flow-estimated).</p>{tip_box("inventory")}</section>"""
    return page(req, "Servers", body, "/netmon/servers", ("servers.js",))


@app.get("/netmon/servers/{ip}", response_class=HTMLResponse)
def server_page(req: Request, ip: str, msg: str = ""):
    ip = internal_ip(ip)
    a = cfg.asset(ip)
    title = f"{a['name']}" if a["name"] != ip else ip
    body = f"""<div id="srvhead" data-ip="{e(ip)}"></div><section class="cards fit" id="cards"></section>
<section class="card"><div class="card-h"><h2>Bandwidth history</h2><div class="legend" id="bwlegend"></div></div><div id="bwstats" class="bwstats"></div><div id="bw" class="chart"></div><div class="note" id="bwnote"></div></section>
<section class="quad">
<div class="card"><div class="card-h"><h2>Countries</h2></div><div id="t-countries"></div></div>
<div class="card"><div class="card-h"><h2>Organizations</h2></div><div id="t-orgs"></div></div>
<div class="card"><div class="card-h"><h2>Services &amp; protocols</h2></div><div id="t-services"></div></div>
<div class="card"><div class="card-h"><h2>New or unusual</h2><span class="muted small">vs previous 14 days</span></div><div id="t-novel"></div></div>
</section>
<section class="grid2"><div class="card"><div class="card-h"><h2>Related alerts</h2></div><div id="t-alerts"></div></div>
<div class="card"><div class="card-h"><h2>Exposure &amp; AI</h2></div><div id="t-exposure"></div></div></section>
<section class="card"><div class="card-h"><h2>Connections</h2><a class="small" href="/netmon/connections?host={e(ip)}" data-keep>All for this server →</a></div><div id="t-conv"></div></section>
{name_card(req, ip, f"/netmon/servers/{ip}#srvname", msg)}"""
    aka = (cfg.get("assets", {}).get(ip) or {}).get("aliases", [])
    return page(req, title, body, "/netmon/servers", ("d3.min.js", "server.js"), subtitle=f"{ip} · {a.get('role') or 'unknown'}" + (f" · aka {', '.join(aka)}" if aka else ""))


def name_card(req, ip, back, msg=""):
    """Name / label editor for one address: servers editable by admins, external labels by analysts."""
    from .inventory import name_form
    _, r = user_of(req)
    internal = cfg.is_internal(ip)
    a = (cfg.get("assets", {}) if internal else cfg.get("labels", {})).get(ip) or {}
    ok = ROLES[r] >= ROLES["admin" if internal else "analyst"]
    what = "Name &amp; role" if internal else "Your label for this address"
    banner = f"<div class='banner'>{e(msg)}</div>" if msg else ""
    if ok:
        inner = name_form(req, ip, back)
    else:
        inner = f"<p>{e(a.get('name') or 'Not named')}{(' · ' + e(a['notes'])) if a.get('notes') else ''}</p><p class='muted small'>Only {'admins' if internal else 'analysts'} can edit names.</p>"
    return f"""<section class="card" id="srvname"><div class="card-h"><h2>{what}</h2><a class="small" href="/netmon/settings/inventory">All names →</a></div>{banner}{inner}</section>"""


@app.get("/netmon/connections", response_class=HTMLResponse)
def connections_page(req: Request, rip: str = "", msg: str = ""):
    body = """<section class="card"><div class="card-h"><h2>Observed conversations</h2>
<div class="seg" id="convsort"><button data-v="bytes">Largest</button><button data-v="time">Most recent</button></div></div>
<form class="convfilters" id="convf" autocomplete="off">
 <div class="seg" id="convdir" role="group" aria-label="Direction"><button type="button" data-v="">All directions</button><button type="button" data-v="in">⬇ Inbound to server</button><button type="button" data-v="out">⬆ Outbound from server</button><button type="button" data-v="unknown">Unknown</button></div>
 <label>Protocol <select name="proto"><option value="">All</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="other">Other</option></select></label>
 <label>Port <input name="port" inputmode="numeric" pattern="[0-9]*" maxlength="5" placeholder="any" class="short"></label>
 <label>Server <input name="host" placeholder="internal IP" class="mono"></label>
 <label>Remote IP <input name="rip" placeholder="any" class="mono"></label>
 <button type="submit">Apply</button><button type="button" class="ghost" id="convclear">Clear filters</button>
 <span class="chips" id="convchips"></span>
</form>
<p class="note" id="convnote"></p><div id="conv"></div><div class="pager" id="pager"></div></section>"""
    import ipaddress
    try:
        rip = str(ipaddress.ip_address(rip)) if rip else ""
    except ValueError:
        rip = ""
    if rip and not cfg.is_internal(rip):
        body += name_card(req, rip, f"/netmon/connections?rip={rip}#srvname", msg)
    return page(req, "Connections", body, "/netmon/connections", ("connections.js",))


@app.get("/netmon/countries", response_class=HTMLResponse)
def countries_page(req: Request):
    from .admin import tip_box
    body = f"""<section class="card" id="blocked"><div class="card-h"><h2>Blocked countries</h2><span class="muted small" id="blknote"></span></div>
<div class="mapctl"><select id="blkshade" aria-label="Shade the blocked-countries map by"><option value="blocked">Shade: configured GeoIP policy</option><option value="blocks">Shade: logged block events</option><option value="bytes">Shade: observed traffic</option></select></div>
<div id="blkmap" class="map"></div><div class="legend" id="blklegend"></div><div class="note" id="blkcov"></div>
<div id="blklists"></div></section>
<section class="mainrow"><div class="card map-card free"><div class="card-h"><h2>Traffic by country</h2>
<div class="mapctl"><div class="seg" id="mapdir"><button data-v="both">Both</button><button data-v="in">Inbound</button><button data-v="out">Outbound</button></div>
<select id="mapshade"><option value="bytes">Shade: bytes</option><option value="flows">Shade: flows</option><option value="alerts">Shade: findings</option><option value="blocked">Shade: GeoIP policy</option><option value="blocks">Shade: logged block events</option></select>
<button id="zoomin">+</button><button id="zoomout">−</button><button id="zoomreset">Reset</button></div></div><div id="map" class="map"></div><div class="legend" id="maplegend"></div><div id="mapnote" class="note"></div></div>
<div class="card sec-card"><div class="card-h"><h2>GeoIP policy on OPNsense</h2></div><div id="policy"></div>{tip_box("geoip")}</div></section>
<section class="card"><div class="card-h"><h2>All countries</h2><div class="seg" id="ctfilter" role="group" aria-label="Filter"><button data-v="all" class="on">All</button><button data-v="in">Blocked inbound</button><button data-v="out">Blocked outbound</button><button data-v="open">Not blocked</button></div><span class="muted small" id="ctnote"></span></div><div class="wrap"><table class="tbl" id="ct"><thead><tr><th>Country</th>
<th class="num">Inbound</th><th class="num">Outbound</th><th class="num">Flows</th><th class="num">Servers</th><th>Top organization</th><th>Alerts</th><th>GeoIP block</th></tr></thead><tbody></tbody></table></div></section>"""
    return page(req, "Countries", body, "/netmon/countries", ("d3.min.js", "topojson-client.min.js", "map.js", "countries.js"))


@app.get("/netmon/countries/{cc}", response_class=HTMLResponse)
def country_page(req: Request, cc: str):
    cc = cc.upper()
    if cc not in META and cc != "??":
        raise HTTPException(404)
    body = f"""<div id="cthead" data-cc="{e(cc)}"></div><section class="cards fit" id="cards"></section>
<section class="card"><div class="card-h"><h2>Traffic over time</h2><div class="legend" id="bwlegend"></div></div><div id="bw" class="chart"></div><div class="note" id="bwnote"></div></section>
<section class="quad"><div class="card"><div class="card-h"><h2>Related servers</h2></div><div id="t-servers"></div></div>
<div class="card"><div class="card-h"><h2>Organizations</h2></div><div id="t-orgs"></div></div>
<div class="card"><div class="card-h"><h2>Findings</h2></div><div id="t-findings"></div></div>
<div class="card"><div class="card-h"><h2>Blocking policy</h2></div><div id="t-policy"></div></div></section>
<section class="card"><div class="card-h"><h2>If this country were blocked: traffic affected in the last 7 days</h2></div><div id="t-preview"></div></section>
<section class="card" id="blocks"><div class="card-h"><h2>Logged firewall blocks</h2><span class="muted small" id="blkstate"></span></div><div id="t-blocks"></div></section>
<section class="card"><div class="card-h"><h2>Connections</h2><a class="small" href="/netmon/connections?cc={e(cc)}" data-keep>All →</a></div><div id="t-conv"></div></section>"""
    return page(req, cname(cc), body, "/netmon/countries", ("d3.min.js", "country.js"), subtitle=f"country {cc} · GeoIP registration, not operator location")


@app.get("/netmon/search", response_class=HTMLResponse)
def search_page(req: Request, q: str = ""):
    body = f"""<section class="card"><div class="card-h"><h2>Results for “{e(q)}”</h2></div><div id="results" data-q="{e(q)}"></div></section>"""
    return page(req, "Search", body, "", ("search.js",))


# ---- investigations (AI) ------------------------------------------------------------------
def asset_context(ip):
    """What kind of address the finding is about - decisive for calibration (a shared NAT aggregates many hosts)."""
    if not ip:
        return {"kind": "none"}
    if ip in cfg.get("outbound_nat_ips", []):
        return {"kind": "shared outbound NAT address", "note": "Traffic of many internal hosts (and the firewall itself) leaves through "
                "this one address, so per-address counts aggregate all of them; it is not a single machine."}
    if ip in cfg.binat:
        return {"kind": "1:1 NAT address of one internal host"}
    try:
        internal = cfg.is_internal(ip)
    except ValueError:
        internal = False
    a = cfg.asset(ip) if internal else {}
    return {"kind": "internal server" if internal else "public address", "role": a.get("role", "unknown"),
            "sensitive": bool(a.get("sensitive"))}


def ai_evidence(req, kind, target):
    if kind == "server":
        ip = internal_ip(target)
        sc = scope_of(req, host=ip)
        coll = dash.collection(sc)
        conv = dash.conversations(sc, page=1, per=20)["rows"]
        return f"Analyze server {ip} over {sc.describe()}", {
            "scope": [scope_json(sc) | {"server": ip}], "summary": [dash.summary(sc)],
            "countries": [{k: c[k] for k in ("cc", "name", "in_b", "out_b", "flows", "servers", "top_asname")} for c in dash.countries(sc, 12)],
            "organizations": dash.orgs(sc, 10), "new_or_unusual": dash.server_novelty(sc)[:30],
            "conversations": [{k: r[k] for k in ("remote", "cc", "asname", "proto", "service", "direction", "evidence", "rx", "flows", "last")} for r in conv],
            "alerts": [{k: a[k] for k in ("title", "rule", "severity", "confidence", "why")} for a in
                       (alert_brief(x) for x in conn.execute("SELECT * FROM alerts WHERE asset=? AND test=0 ORDER BY last_seen DESC LIMIT 10", (ip,)))],
            "collection": [{"first_flow": coll["first"], "last_flow": coll["last"], "active_timeout_s": cfg["exporter_active_timeout"]}]}
    if kind == "alert":
        a = conn.execute("SELECT * FROM alerts WHERE id=?", (int(target),)).fetchone()
        if not a:
            raise HTTPException(404)
        ev = json.loads(a["evidence"] or "[]")
        from .web import ongoing
        og = ongoing(a, traffic=True)
        return f"Explain why finding #{a['id']} was flagged, score how likely it is a legitimate threat, and suggest investigation steps", {
            "finding": [{"title": a["title"], "rule": a["rule"], "severity": a["severity"], "confidence": a["confidence"],
                         "window": [fmt_ts(a["window_start"]), fmt_ts(a["window_end"])], "baseline": a["baseline"],
                         "alternatives": json.loads(a["alternatives"] or "[]")}],
            "evidence": ev[:5],
            "activity": [{k: og[k] for k in ("state", "label", "first_seen", "last_seen", "detections", "span_hours", "days_seen",
                                             "recent_flows", "recent_window_min")}],
            "asset_context": [asset_context(a["asset"])]}
    if kind == "country":
        cc = target.upper()
        if cc not in META:
            raise HTTPException(400)
        sc = scope_of(req, cc=cc)
        return f"Summarize traffic with {cname(cc)} over {sc.describe()}", {
            "scope": [scope_json(sc)], "summary": [dash.summary(sc)],
            "servers": [{k: s[k] for k in ("ip", "name", "rx", "tx", "peers")} for s in dash.servers(sc, 20)["servers"][:15]],
            "organizations": dash.orgs(sc, 10),
            "conversations": [{k: r[k] for k in ("server", "remote", "asname", "service", "direction", "rx", "flows")} for r in dash.conversations(sc, per=15)["rows"]]}
    if kind == "window":
        sc = scope_of(req)
        return f"Summarize unusual traffic over {sc.describe()}", {
            "scope": [scope_json(sc)], "summary": [dash.summary(sc)],
            "servers": [{k: s[k] for k in ("ip", "name", "rx", "tx", "peers", "countries")} for s in dash.servers(sc, 20)["servers"][:15]],
            "countries": [{k: c[k] for k in ("cc", "name", "in_b", "out_b", "servers")} for c in dash.countries(sc, 15)],
            "organizations": dash.orgs(sc, 10),
            "open_alerts": [{k: a[k] for k in ("title", "rule", "severity", "confidence")} for a in map(alert_brief, open_alerts()[:20])]}
    raise HTTPException(400, "unknown analysis type")


@app.get("/netmon/investigations", response_class=HTMLResponse)
def investigations_page(req: Request, kind: str = "", target: str = "", msg: str = ""):
    u, r = user_of(req)
    hist = conn.execute("SELECT * FROM investigations ORDER BY id DESC LIMIT 20").fetchall()
    rows = "".join(f"<tr><td class='num'>{e(fmt_ts(h['ts']))}</td><td>{e(h['user'])}</td><td>{e(h['kind'])}</td><td>{e(h['target'])}</td>"
                   f"<td><a href='/netmon/investigations/{h['id']}'>view</a></td></tr>" for h in hist)
    state = (f"<div class='banner'>AI analysis is <b>configured</b> · model <code>{e(ai.ac.get('model'))}</code> · "
             f"{ai.used_today()} of {ai.ac.get('daily_request_limit')} requests used today. Nothing is sent until you review the evidence preview.</div>"
             if ai.enabled else
             """<div class='banner warn'><b>AI analysis is not configured.</b> Everything else works without it.
Paste an OpenAI API key below (project-scoped, with a spend limit) — it is checked with OpenAI and active immediately.
You can still build and review evidence previews.</div>""")
    if msg:
        state = f"<div class='banner'>{e(msg)}</div>" + state
    ac = ai.ac
    if r == "admin":
        state += f"""<section class="card"><div class="card-h"><h2>AI settings</h2><span class="muted small">stored in the netmon database · key in /opt/netmon/data/secrets (0600)</span></div>
<form method=post action="/netmon/settings/ai" class="stackform wide">{csrf_field(req)}<div class="formgrid">
<label>OpenAI API key<input name=key type=password autocomplete=off placeholder="{'key saved — leave blank to keep' if ai.enabled else 'sk-…'}"></label>
<label>Model<input name=model value="{e(ac.get('model', 'gpt-5-nano'))}" pattern="[A-Za-z0-9._:-]{{1,64}}" required></label>
<label>Requests per day<input name=daily type=number min=1 max=1000 value="{e(ac.get('daily_request_limit', 25))}"></label>
<label>Max output tokens<input name=tokens type=number min=200 max=8000 value="{e(ac.get('max_output_tokens', 4000))}"></label></div>
<div class="row"><button class="primary">{'Save' if ai.enabled else 'Check key and enable'}</button></div></form>
{f"<form method=post action='/netmon/settings/ai/remove-key' class='row confirm'>{csrf_field(req)}<button>Delete</button> <span class='muted small'>removes the stored key and disables AI analysis</span></form>" if ai.enabled else ''}</section>"""
    kinds = "".join(f"<option value='{k}' {'selected' if k == kind else ''}>{v}</option>" for k, v in
                    (("server", "A server"), ("alert", "A security finding"), ("country", "A country"), ("window", "The selected time window")))
    body = f"""{state}<section class="card"><div class="card-h"><h2>New analysis</h2><span class="muted small">uses the time range/site selected above</span></div>
<form id="aiform" class="row"><select name="kind" id="aikind">{kinds}</select>
<input name="target" id="aitarget" value="{e(target)}" placeholder="server IP, finding #, or country code" size="28">
<button type="submit">Preview evidence</button></form>
<div id="aipreview"></div><div id="airesult"></div></section>
<section class="card"><div class="card-h"><h2>Previous analyses</h2></div><table class="tbl"><tr><th>Time</th><th>By</th><th>Type</th><th>Target</th><th></th></tr>
{rows or '<tr><td colspan=5 class=muted>None yet</td></tr>'}</table></section>
<input type="hidden" id="csrf" value="{e(csrf_token(req))}"><input type="hidden" id="aienabled" value="{'1' if ai.enabled else '0'}">"""
    return page(req, "Investigations", body, "/netmon/investigations", ("investigations.js",),
                subtitle="Manual, preview-first AI analysis. AI never changes the firewall.")


@app.get("/netmon/api/ai/preview")
def api_ai_preview(req: Request, kind: str, target: str = ""):
    u = need(req, "analyst")

    def run():
        prompt, payload = ai_evidence(req, kind, target)
        pv = ai.build(prompt, payload)
        _previews.update({k: v for k, v in _previews.items() if time.time() - v[0] < 900})
        _previews[pv["digest"]] = (time.time(), u, pv, kind, target)
        return {"ok": True, "digest": pv["digest"], "model": pv["model"], "chars": pv["chars"], "categories": pv["categories"],
                "pseudonyms": pv["pseudonyms"], "body": json.loads(pv["body"]), "enabled": ai.enabled,
                "note": "This is exactly what would be sent. Internal addresses and server names are replaced by host-N; "
                        "the mapping stays on this server."}
    return guard(run)


@app.post("/netmon/api/ai/send")
def api_ai_send(req: Request, digest: str = Form(...), csrf: str = Form("")):
    u = need(req, "analyst")
    check_csrf(req, csrf)
    hit = _previews.get(digest)
    if not hit or hit[1] != u or time.time() - hit[0] > 900:
        raise HTTPException(400, "preview expired; build it again")
    _, _, pv, kind, target = hit
    try:
        result, usage = ai.send(u, pv)
    except Exception as ex:
        return JSONResponse({"ok": False, "error": str(ex)[:300]}, status_code=400)
    cur = conn.execute("INSERT INTO investigations(ts,user,kind,target,digest,model,result,usage) VALUES (?,?,?,?,?,?,?,?)",
                       (time.time(), u, kind, target, digest, pv["model"], json.dumps(result), json.dumps(usage)))
    conn.commit()
    return {"ok": True, "id": cur.lastrowid, "result": result, "usage": usage}


@app.get("/netmon/investigations/{iid}", response_class=HTMLResponse)
def investigation_view(req: Request, iid: int):
    user_of(req)
    h = conn.execute("SELECT * FROM investigations WHERE id=?", (iid,)).fetchone()
    if not h:
        raise HTTPException(404)
    res = json.loads(h["result"] or "{}")
    ev = "".join(f"<li><code>{e(x.get('evidence_id'))}</code> {e(x.get('observation'))}</li>" for x in res.get("evidence", []))
    hy = "".join(f"<li><b>{e(x.get('likelihood'))}</b> — {e(x.get('hypothesis'))} <span class='muted small'>({e(', '.join(x.get('supporting_evidence_ids', [])))})</span></li>"
                 for x in res.get("hypotheses", []))
    rec = "".join(f"<li>{e(x)}</li>" for x in res.get("recommendations", []) if str(x).strip())
    body = f"""<div class="card"><p class="muted">{e(fmt_ts(h['ts']))} · {e(h['user'])} · {e(h['kind'])} {e(h['target'])} · model {e(h['model'])}</p>
{(f"<div class='scorebox'><b>AI threat score: {int(res['threat_score'])} / 100</b><div class='scorebar'><span style='width:{int(res['threat_score'])}%'></span></div><p class='small'>{e(res.get('score_rationale', ''))}</p>"
  + (f"<p class='small'><a href='/netmon/alert/{e(h['target'])}'>Finding #{e(h['target'])}</a> — score history and ongoing status are on the finding.</p>" if h['kind'] == 'alert' else '') + "</div>") if res.get('threat_score') is not None else ''}
<h3>Summary</h3><p>{e(res.get('summary'))}</p><h3>Evidence cited</h3><ul>{ev}</ul><h3>Hypotheses</h3><ul>{hy}</ul>
<h3>Uncertainty</h3><p>{e(res.get('uncertainty'))}</p><h3>Recommended next steps</h3><ul>{rec}</ul>
<p class="note">AI output is advisory. It cannot change the firewall; blocks require the separate reviewed workflow.</p></div>"""
    return page(req, f"Investigation #{iid}", body, "/netmon/investigations", scoped=False)


# ---- settings -----------------------------------------------------------------------------
@app.get("/netmon/settings", response_class=HTMLResponse)
def settings_page(req: Request):
    u, r = user_of(req)
    sc = dash.scope(range_key="15m")
    try:
        coll = dash.collection(sc)
        ch_ok, ch_err = True, ""
    except Exception as ex:
        coll, ch_ok, ch_err = {"first": None, "last": None, "age": None, "flows_5m": 0}, False, str(ex)[:200]
    st = detector_status()
    disk = os.statvfs("/data")
    disk_pct = 100 * (1 - disk.f_bavail / disk.f_blocks)
    snmp_rows = ""
    for s in cfg["sites"]:
        for name in (s.get("snmp") or {}).get("interfaces", {}):
            v, ts = get_state(conn, f"snmp:{s['id']}:{name}", {})
            ok = v and v.get("ok")
            snmp_rows += (f"<tr><td>{e(s['name'])}</td><td>{e(name)}</td><td>{sev_ok(ok)}</td>"
                          f"<td class='num'>{e(fmt_ts(ts)) if ts else 'never'}</td><td>{e((v or {}).get('speed_mbps', '—'))} Mb/s port speed</td>"
                          f"<td>{e((v or {}).get('error') or '')}</td></tr>")
    age = coll["age"]
    from .admin import SETTINGS_TABS, sources, tabs
    S = sources()
    body = tabs(SETTINGS_TABS, "/netmon/settings") + f"""<section class="grid2 even"><div class="card"><div class="card-h"><h2>Collection health</h2></div><table class="tbl">
<tr><td>Flow records (NetFlow v9)</td><td>{sev_ok(ch_ok and age is not None and age < 300)}</td><td>last {e(f'{age:.0f} s ago' if age is not None else 'never')} · {coll['flows_5m']} in 5 min · since {e(fmt_ts(coll['first'])) if coll['first'] else '—'}</td></tr>
<tr><td>Export delay</td><td>{sev_ok(None, 'Recommended change') if cfg['exporter_active_timeout'] > 300 else sev_ok(True)}</td><td>short flows ≤ ~15 s (inactive timeout); long connections are reported every {cfg['exporter_active_timeout'] // 60} min (active timeout).
{'Not a failure, but long transfers show up late and as spikes — set OPNsense NetFlow active timeout to 120 s (<a href="/netmon/settings/integrations">how</a>).' if cfg['exporter_active_timeout'] > 300 else ''}</td></tr>
<tr><td>ClickHouse</td><td>{sev_ok(ch_ok)}</td><td>{e(ch_err or 'reachable (read-only queries)')}</td></tr>
<tr><td>Detector</td><td>{sev_ok(not st['errors'] and st['last_run'] and time.time() - st['last_run'] < 900)}</td><td>last run {e(fmt_ts(st['last_run'])) if st['last_run'] else 'never'} · baseline {st['learning_days']:.1f}/{st['baseline_days']} days {e('; '.join(st['errors']))}</td></tr>
<tr><td>Disk (monitor VM)</td><td>{sev_ok(disk_pct < 85)}</td><td>{disk_pct:.0f}% used</td></tr>
<tr><td>Firewall logs</td><td>{src_badge(S['fw'], 'Not connected')}</td><td>{f"last {fmt_ts(S['fw']['last'])} · {S['fw']['blocks24']:,} blocks / 24 h" if S['fw']['last'] else 'blocked/denied counts unavailable — <a href="/netmon/settings/integrations">set up remote syslog</a>'}</td></tr>
<tr><td>Suricata IDS</td><td>{src_badge(S['ids'], 'Not connected')}</td><td>{f"last alert {fmt_ts(S['ids']['last'])} · {S['ids']['alerts24']} / 24 h" if S['ids']['last'] else 'not enabled on OPNsense — <a href="/netmon/settings/integrations">set up</a>'}</td></tr>
<tr><td>Notifications</td><td>{sev_ok(True, f"{S['channels']} channel(s)") if S['channels'] else sev_ok(None, 'Not configured')}</td><td><a href="/netmon/settings/notifications">email, SMS, webhook, Slack, Teams, Discord, ntfy, Pushover</a></td></tr>
</table></div>
<div class="stack"><div class="card"><div class="card-h"><h2>WAN interface counters (SNMP, read-only)</h2></div><table class="tbl"><tr><th>Site</th><th>Interface</th><th>Status</th><th>Last poll</th><th>Speed</th><th></th></tr>{snmp_rows or '<tr><td colspan=6 class=muted>Not configured</td></tr>'}</table>
<p class="note">Port speed is not contracted capacity; utilization is shown only when a WAN capacity is set on <a href="/netmon/settings/sites">Firewalls &amp; sites</a>.</p></div>
<div class="card"><div class="card-h"><h2>Features</h2></div><table class="tbl">
<tr><td>Firewalls</td><td>{len(cfg["sites"])} site(s)</td><td><a href="/netmon/settings/sites">Firewalls &amp; sites</a></td></tr>
<tr><td>Inventory</td><td>{len(cfg.get('assets', {}))} named servers</td><td><a href="/netmon/settings/inventory">edit names</a></td></tr>
<tr><td>Blocking</td><td>{f"{enforcement()[0]} of {enforcement()[1]} firewalls connected" if enforcement()[0] else 'not set up'}</td><td><a href="/netmon/blocks">block requests</a> · <a href="/netmon/settings/response">auto-response</a></td></tr>
<tr><td>AI analysis</td><td>{'configured · ' + e(ai.ac.get('model')) if ai.enabled else 'not configured'}</td><td><a href="/netmon/investigations">setup</a></td></tr>
<tr><td>GeoIP</td><td>{e(geo_sources())}</td><td><a href="/netmon/coverage">what is visible</a></td></tr>
</table></div></div></section>"""
    return page(req, "Settings · Health", body, "/netmon/settings", scoped=False)


def geo_sources():
    """The GeoIP databases actually loaded (country lookups, city placement on the map), not a fixed product list."""
    def one(prov, role, missing):
        if prov.get("database"):
            return f"{prov['database']} ({role}, built {prov.get('built', '?')})"
        return missing + (f": {prov['error']}" if prov.get("error") else "")
    return " · ".join([one(blocks().geo.provenance(), "country", "no country database"),
                       one(geocity.GEO.provenance(), "city placement", "no city database (map places countries only)")])


def src_badge(src, na):
    return {"ok": "<span class='sev s-good'>● Connected</span>", "stale": "<span class='sev s-warning'>◐ Stale</span>"}.get(
        src["state"], f"<span class='sev s-muted'>○ {e(na)}</span>")


def sev_ok(ok, label=None):
    if ok is None:
        return f"<span class='sev s-muted'>○ {e(label or 'info')}</span>"
    return f"<span class='sev s-good'>● {e(label or 'OK')}</span>" if ok else f"<span class='sev s-critical'>✕ {e(label or 'Problem')}</span>"


@app.post("/netmon/settings/ai")
def save_ai(req: Request, key: str = Form(""), model: str = Form(...), daily: str = Form("25"), tokens: str = Form("1500"),
            csrf: str = Form("")):
    import re as _re
    from .ai import check_key
    from .core import put_setting
    u = need(req, "admin")
    check_csrf(req, csrf)
    if not _re.match(r"^[A-Za-z0-9._:-]{1,64}$", model.strip()):
        raise HTTPException(400, "invalid model name")
    try:
        d, t = int(daily), int(tokens)
    except ValueError:
        raise HTTPException(400, "invalid number")
    if not (1 <= d <= 1000 and 200 <= t <= 8000):
        raise HTTPException(400, "limit out of range")
    key = key.strip()
    if key:
        err = check_key(key)
        if err:
            return RedirectResponse("/netmon/investigations?msg=" + quote(f"Key not saved: {err}"), 303)
        os.makedirs(os.path.dirname(ai.KEY_FILE), mode=0o700, exist_ok=True)
        fd = os.open(ai.KEY_FILE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key + "\n")
        os.replace(ai.KEY_FILE + ".tmp", ai.KEY_FILE)
    put_setting(conn, "ai", {"model": model.strip(), "daily_request_limit": d, "max_output_tokens": t}, u)
    audit(conn, u, "ai_settings_saved", {"model": model.strip(), "daily_request_limit": d, "max_output_tokens": t, "key_changed": bool(key)})
    return RedirectResponse("/netmon/investigations?msg=" + quote("AI settings saved." + (" Key checked with OpenAI and active." if key else "")), 303)


@app.post("/netmon/settings/ai/remove-key")
def remove_ai_key(req: Request, csrf: str = Form("")):
    u = need(req, "admin")
    check_csrf(req, csrf)
    try:
        os.remove(ai.KEY_FILE)
    except OSError:
        pass
    audit(conn, u, "ai_key_removed", {})
    msg = "Key removed." + (" A key file mounted from /opt/netmon/secrets still exists and stays in use." if ai.enabled else "")
    return RedirectResponse("/netmon/investigations?msg=" + quote(msg), 303)
