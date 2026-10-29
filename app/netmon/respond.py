"""Auto-response: time-limited blocks of external attackers, inside guardrails.

Triggers (each can be switched off): brute force against login services, high-priority IDS signatures initiated
from outside (scan signatures excluded), and single-source floods into a few service ports. Scans are never a
trigger. Every candidate passes the same guardrails as a manual block plus: allowlist, operator-labelled
addresses, recent human un-block, established clients (people who use several of our services), addresses our
servers use as a service, an hourly cap and a cap on active blocks.

Mode "dry_run" logs what would happen and changes nothing. Blocks go into netmon's own alias (netmon_auto) and
expire after a TTL. The only firewall objects touched are the ones netmon created (block.OPNsense.setup)."""
import copy
import ipaddress
import json
import time

from . import block as blk
from .core import audit, get_setting, put_setting

DEFAULTS = {
    "mode": "dry_run",            # off | dry_run | on
    "ttl_hours": 24,
    "max_per_hour": 30,
    "max_active": 500,
    "kill_states": True,
    "auto_setup": True,           # create/re-create netmon's own firewall objects when missing (never re-enables a disabled rule)
    "allowlist": [],
    "established_days": 7,        # look-back for the established-client guardrail
    "established_services": 2,    # services with a substantial (>= 50 KB) connection => a real client, never auto-blocked
    "triggers": {
        "bruteforce": {"enabled": True, "window_minutes": 10, "min_attempts": 30, "max_avg_bytes": 10000,
                       "ports": [21, 22, 2222, 3389, 5900, 8006, 10000, 465, 587]},
        "ids": {"enabled": True, "max_priority": 1, "exclude_scan": True, "window_minutes": 10},
        "flood": {"enabled": True, "window_minutes": 2, "min_flows": 1500, "max_ports": 5},
    },
}
TRIGGER_LABEL = {"bruteforce": "Brute force", "ids": "IDS signature", "flood": "Flood"}
IP = "replaceOne(IPv6NumToString({c}), '::ffff:', '')"


def settings(conn):
    s = copy.deepcopy(DEFAULTS)
    saved = get_setting(conn, "response", {}) or {}
    for k, v in saved.items():
        if k == "triggers":
            for t, tv in (v or {}).items():
                if t in s["triggers"]:
                    s["triggers"][t].update(tv)
        elif k in s:
            s[k] = v
    return s


def fw_state(conn, sid):
    return get_setting(conn, f"response:fw:{sid}", {}) or {}


def ready(conn, site):
    """(ok, why) — can auto-blocks be enforced on this firewall?"""
    fw = blk.enforcer(site)
    if not fw.enabled:
        return False, "no API key for this firewall"
    if isinstance(fw, blk.OPNsense):
        st = fw_state(conn, site["id"])
        if not st.get("rules", {}).get("auto_in"):
            return False, "netmon rules not created on the firewall yet (Settings → Auto-response → Set up)"
    return True, ""


def ensure_objects(conn, site, user="auto-response"):
    """Create whichever netmon category/aliases/rules are missing on an OPNsense site. Returns the list of what was
    created ([] if nothing was needed). Raises BlockError on failure, after recording what was created."""
    fw = blk.enforcer(site)
    if not isinstance(fw, blk.OPNsense) or not fw.enabled:
        return []
    st = fw_state(conn, site["id"])
    try:
        new, done = fw.setup(st)
    except blk.BlockError as ex:
        if getattr(ex, "state", None):
            put_setting(conn, f"response:fw:{site['id']}", {**st, **ex.state}, user)
        audit(conn, user, "response_setup_failed", {"site": site["id"], "error": str(ex)[:300], "done": getattr(ex, "done", [])})
        raise
    if done or not st.get("setup_at"):
        new.update(setup_at=time.time(), setup_by=user)
        put_setting(conn, f"response:fw:{site['id']}", new, user)
        audit(conn, user, "response_setup", {"site": site["id"], "done": done, "objects": new})
    return done


def in_allowlist(addr, allow):
    a = ipaddress.ip_address(addr)
    for x in allow:
        try:
            if a in ipaddress.ip_network(x, strict=False):
                return x
        except ValueError:
            continue
    return None


class Responder:
    def __init__(self, cfg, conn, det, notifier=None):
        self.cfg, self.conn, self.det, self.notifier = cfg, conn, det, notifier

    # ---- triggers: each returns candidates {address, trigger, title, evidence, window, query} ----
    def _q(self, site, sql, params):
        self.det.site = site
        return self.det.q(sql, params)

    def t_bruteforce(self, site, t, now):
        we = int(now - 30)
        ws = we - t["window_minutes"] * 60
        sql = f"""
        SELECT {IP.format(c='SrcAddr')} AS s, count() AS attempts, round(avg(Bytes)) AS avg_bytes,
               groupUniqArray(5)(DstPort) AS ports, groupUniqArray(5)({IP.format(c='DstAddr')}) AS targets,
               toUInt32(min(TimeReceived)) AS first, toUInt32(max(TimeReceived)) AS last
        FROM flows WHERE INB AND TOLAN AND Proto = 6 AND TimeReceived >= toDateTime({{ws:UInt32}}) AND TimeReceived < toDateTime({{we:UInt32}})
          AND has({{ports:Array(UInt16)}}, DstPort)
        GROUP BY s HAVING attempts >= {{m:UInt32}} AND avg_bytes <= {{b:UInt32}} ORDER BY attempts DESC LIMIT 50"""
        p = {"ws": ws, "we": we, "ports": [int(x) for x in t["ports"]], "m": int(t["min_attempts"]), "b": int(t["max_avg_bytes"])}
        return [{"address": r["s"], "trigger": "bruteforce", "window": (ws, we), "query": (sql, p), "evidence": r,
                 "title": f"{r['attempts']} short connections in {t['window_minutes']} min to login port(s) "
                          f"{', '.join(map(str, sorted(r['ports'])))} on {', '.join(self.cfg.asset_label(x) for x in r['targets'][:2])}"}
                for r in self._q(site, sql, p)]

    def t_flood(self, site, t, now):
        we = int(now - 30)
        ws = we - t["window_minutes"] * 60
        sql = f"""
        SELECT {IP.format(c='SrcAddr')} AS s, count() AS flows, uniq(DstPort) AS ports, groupUniqArray(5)(DstPort) AS sample_ports,
               uniq(DstAddr) AS targets, sum(Bytes) AS bytes, sum(Packets) AS packets
        FROM flows WHERE INB AND TOLAN AND TimeReceived >= toDateTime({{ws:UInt32}}) AND TimeReceived < toDateTime({{we:UInt32}})
        GROUP BY s HAVING flows >= {{m:UInt32}} AND ports <= {{mp:UInt32}} ORDER BY flows DESC LIMIT 20"""
        p = {"ws": ws, "we": we, "m": int(t["min_flows"]), "mp": int(t["max_ports"])}
        return [{"address": r["s"], "trigger": "flood", "window": (ws, we), "query": (sql, p), "evidence": r,
                 "title": f"{r['flows']} new connections in {t['window_minutes']} min to port(s) {', '.join(map(str, sorted(r['sample_ports'])))}"}
                for r in self._q(site, sql, p)]

    def t_ids(self, site, t, now):
        we = int(now - 30)
        ws = we - t["window_minutes"] * 60
        scan = "AND NOT (signature ILIKE '%SCAN%' OR category ILIKE '%scan%')" if t.get("exclude_scan", True) else ""
        sql = f"""
        SELECT JSONExtractString(raw, 'flow', 'src_ip') AS initiator, sig_id, any(signature) AS sig, any(category) AS cat,
               min(severity) AS priority, count() AS hits, groupUniqArray(3)({IP.format(c='dst')}) AS dsts,
               groupUniqArray(3)({IP.format(c='src')}) AS srcs, groupUniqArray(3)(action) AS actions, toUInt32(max(ts)) AS last
        FROM netmon.ids_events WHERE site = {{site:String}} AND ts >= toDateTime({{ws:UInt32}}) AND ts < toDateTime({{we:UInt32}})
          AND severity <= {{mp:UInt8}} {scan}
        GROUP BY initiator, sig_id ORDER BY hits DESC LIMIT 50"""
        p = {"ws": ws, "we": we, "mp": int(t["max_priority"]), "site": site["id"]}
        out = []
        for r in self.det.ch.query(sql, p):
            ini = r["initiator"]
            try:
                if not ini or self.cfg.is_ours(ini):
                    continue  # only connections opened from outside; a server's own outbound traffic is never a trigger
            except ValueError:
                continue
            out.append({"address": ini, "trigger": "ids", "window": (ws, we), "query": (sql, p), "evidence": r,
                        "title": f"IDS priority {r['priority']}: {r['sig']} ({r['hits']}×, initiated by {ini})"})
        return out

    # ---- guardrails ----
    def established(self, site, addr, s):
        """A real client: had substantial connections (>= 50 KB in one flow) to several of our services, is a
        WireGuard peer, or downloaded a lot from us, recently. Login attempts are small, so an attacker that tries
        many login ports does not qualify."""
        sql = """
        SELECT countIf(mx >= 50000) AS services, groupArrayIf(port, mx >= 50000) AS ports, sum(wg) AS wg, sum(sent) AS sent_to FROM (
          SELECT if(INB, DstPort, SrcPort) AS port, max(Bytes) AS mx,
                 countIf(INB AND Proto = 17 AND DstPort = 51820 AND Bytes > 200) AS wg, sumIf(Bytes, OUTB) AS sent
          FROM flows WHERE TimeReceived > now() - INTERVAL {d:UInt32} DAY AND (INB OR OUTB)
            AND (SrcAddr = toIPv6({a:String}) OR DstAddr = toIPv6({a:String}))
          GROUP BY port)"""
        r = (self._q(site, sql, {"d": int(s["established_days"]), "a": addr}) or [{}])[0]
        if int(r.get("services") or 0) >= int(s["established_services"]):
            return (f"established client: substantial connections to {r['services']} services "
                    f"(ports {', '.join(map(str, sorted(r['ports'])[:6]))}) in {s['established_days']} days")
        if int(r.get("wg") or 0) >= 3:
            return "established client: WireGuard peer"
        if int(r.get("sent_to") or 0) >= 50_000_000:
            return f"established client: received {int(r['sent_to']) // 1_000_000} MB from us"
        return None

    def dependency(self, site, addr):
        """Our servers use this address as a service (DNS, NTP, updates, APIs…)."""
        sql = """
        SELECT count() AS n, groupUniqArray(3)(DstPort) AS ports FROM flows
        WHERE OUTB AND TimeReceived > now() - INTERVAL 7 DAY AND DstAddr = toIPv6({a:String})
          AND (DstPort < 1024 OR has({svc:Array(UInt16)}, DstPort))"""
        r = (self._q(site, sql, {"a": addr, "svc": [int(x) for x in self.cfg.get("service_ports", [])]}) or [{}])[0]
        return f"our servers use it as a service (port {', '.join(map(str, r['ports']))})" if int(r.get("n") or 0) >= 3 else None

    def guard(self, site, c, s, now):
        addr = c["address"]
        try:
            blk.validate_target(self.cfg, addr)
        except blk.BlockError as ex:
            return str(ex)
        hit = in_allowlist(addr, s["allowlist"])
        if hit:
            return f"allowlisted ({hit})"
        if self.cfg.label(addr):
            return f"named address “{self.cfg.label(addr)}” (Inventory)"
        r = self.conn.execute("SELECT id FROM blocks WHERE address=? AND auto=1 AND status='removed' AND removed_by NOT LIKE 'auto%' "
                              "AND removed_at > ?", (addr, now - 7 * 86400)).fetchone()
        if r:
            return f"a person removed auto-block #{r['id']} for this address within 7 days"
        why = self.established(site, addr, s) or self.dependency(site, addr)
        if why:
            return why
        n = self.conn.execute("SELECT count(*) FROM blocks WHERE auto=1 AND applied_at > ?", (now - 3600,)).fetchone()[0]
        if n >= int(s["max_per_hour"]):
            return f"hourly cap reached ({n} auto-blocks in the last hour)"
        n = self.conn.execute("SELECT count(*) FROM blocks WHERE auto=1 AND status='applied'").fetchone()[0]
        if n >= int(s["max_active"]):
            return f"active cap reached ({n} auto-blocks)"
        return None

    # ---- decisions ----
    def log(self, site, c, decision, reason, block_id=None, alert_id=None, now=None):
        self.conn.execute("INSERT INTO response_log(ts,site,address,trigger,decision,reason,evidence,block_id,alert_id) VALUES (?,?,?,?,?,?,?,?,?)",
                          (now or time.time(), site["id"], c["address"], c["trigger"], decision, reason[:300],
                           json.dumps({"title": c["title"], "evidence": c["evidence"]}, default=str)[:4000], block_id, alert_id))
        self.conn.commit()

    def decide(self, site, c, s, now, dry=False):
        addr = c["address"]
        if self.conn.execute("SELECT 1 FROM blocks WHERE address=? AND site=? AND auto=1 AND status='applied'", (addr, site["id"])).fetchone():
            return "active"
        # one log line per address+trigger per hour, so a sustained attack does not flood the log
        if self.conn.execute("SELECT 1 FROM response_log WHERE address=? AND trigger=? AND site=? AND ts > ? AND decision != 'error'",
                             (addr, c["trigger"], site["id"], now - 3600)).fetchone():
            return "seen"
        why = self.guard(site, c, s, now)
        if why:
            self.log(site, c, "skipped", why, now=now)
            return "skipped"
        if s["mode"] != "on" or dry:
            self.log(site, c, "would_block", f"dry run: would block for {s['ttl_hours']} h", now=now)
            return "would_block"
        ok, why = ready(self.conn, site)
        if not ok and s.get("auto_setup"):
            try:
                ensure_objects(self.conn, site)
                ok, why = ready(self.conn, site)
            except Exception as ex:
                why = f"could not create netmon firewall objects: {str(ex)[:150]}"
        if not ok:
            self.log(site, c, "skipped", f"not enforced: {why}", now=now)
            return "skipped"
        return self.block(site, c, s, now)

    def block(self, site, c, s, now):
        fw = blk.enforcer(site)
        addr, alias = c["address"], fw.auto_alias
        try:
            ok, res = fw.add(addr, alias)
        except Exception as ex:
            ok, res = False, {"error": str(ex)}
        if not ok:
            self.log(site, c, "error", f"firewall did not confirm: {str(res)[:200]}", now=now)
            return "error"
        killed = 0
        if s["kill_states"] and isinstance(fw, blk.OPNsense):
            try:
                killed = fw.kill_states(addr)
            except Exception as ex:
                res = {**res, "kill_states_error": str(ex)[:200]}
        exp = now + float(s["ttl_hours"]) * 3600
        cur = self.conn.execute(
            "INSERT INTO blocks(address,alias,reason,requested_by,requested_at,status,approved_by,applied_at,result,impact,site,auto,trigger,expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?)",
            (addr, alias, f"{TRIGGER_LABEL[c['trigger']]}: {c['title']}"[:500], "auto-response", now, "applied", "auto-response", now,
             json.dumps({**res, "states_killed": killed}, default=str)[:4000], "[]", site["id"], c["trigger"], exp))
        bid = cur.lastrowid
        self.conn.commit()
        audit(self.conn, "auto-response", "block_applied", {"id": bid, "address": addr, "site": site["id"], "trigger": c["trigger"],
                                                            "expires_at": exp, "states_killed": killed})
        aid = self.alert(site, c, s, bid, killed, now)
        self.log(site, c, "blocked", f"blocked for {s['ttl_hours']} h · {killed} state(s) dropped", block_id=bid, alert_id=aid, now=now)
        return "blocked"

    def alert(self, site, c, s, bid, killed, now):
        f = dict(rule="auto_block", severity="medium", confidence="high", asset="", subject=c["address"], site=site["id"],
                 title=f"Auto-blocked {c['address']} for {s['ttl_hours']} h — {TRIGGER_LABEL[c['trigger']]}: {c['title']}"[:300],
                 window=c["window"], evidence=[{**c["evidence"], "peer": c["address"], "block_id": bid, "states_killed": killed}],
                 query=c["query"], baseline=f"Auto-response trigger “{TRIGGER_LABEL[c['trigger']]}” on {site['name']}; block #{bid} "
                                            f"in alias {blk.enforcer(site).auto_alias}, expires automatically.",
                 alternatives=["A legitimate client with a misconfigured or looping login (check with the owner)",
                               "Shared address (carrier NAT, VPN exit) where one user's behaviour affects others"],
                 next_steps=[f"If this is legitimate, remove block #{bid} (Security → Block requests) and add the address to the allowlist",
                             "Review the evidence and other traffic from the address in Connections"],
                 akvorado_filter=f"SrcAddr = {c['address']} OR DstAddr = {c['address']}")
        self.det.record(f, now)
        r = self.conn.execute("SELECT id FROM alerts WHERE rule='auto_block' AND subject=? ORDER BY id DESC LIMIT 1", (c["address"],)).fetchone()
        return r["id"] if r else None

    def expire(self, now):
        n = 0
        for b in self.conn.execute("SELECT * FROM blocks WHERE auto=1 AND status='applied' AND expires_at < ?", (now,)).fetchall():
            try:
                site = blk.site_of_block(self.cfg, b)
                res = blk.enforcer(site).delete(b["address"], b["alias"])
            except Exception as ex:
                audit(self.conn, "auto-response", "block_expiry_failed", {"id": b["id"], "error": str(ex)[:200]})
                continue
            self.conn.execute("UPDATE blocks SET status='expired', removed_by='auto-response (expired)', removed_at=?, result=? WHERE id=?",
                              (now, json.dumps(res, default=str)[:4000], b["id"]))
            self.conn.commit()
            audit(self.conn, "auto-response", "block_expired", {"id": b["id"], "address": b["address"]})
            n += 1
        return n

    def run_once(self, now=None, force_dry=False):
        """One evaluation. force_dry: run the triggers whatever the mode, never block, never expire."""
        now = now or time.time()
        s = settings(self.conn)
        summary = {"ts": now, "mode": s["mode"], "expired": 0 if force_dry else self.expire(now), "candidates": 0, "decisions": {}, "errors": []}
        if s["mode"] == "off" and not force_dry:
            return summary
        if s["mode"] == "on" and s.get("auto_setup") and not force_dry and now - getattr(self, "_checked", 0) > 600:
            self._checked = now  # every 10 min: re-create netmon objects someone deleted (disabled rules stay disabled)
            for site in self.cfg.sites:
                try:
                    made = ensure_objects(self.conn, site)
                    if made:
                        summary.setdefault("repaired", []).extend(f"{site['id']}: {x}" for x in made)
                except Exception as ex:
                    summary["errors"].append(f"{site['id']}/setup: {str(ex)[:200]}")
        for site in self.cfg.sites:
            for key, fn in (("bruteforce", self.t_bruteforce), ("ids", self.t_ids), ("flood", self.t_flood)):
                t = s["triggers"][key]
                if not t.get("enabled"):
                    continue
                try:
                    cands = fn(site, t, now)
                except Exception as ex:
                    summary["errors"].append(f"{site['id']}/{key}: {str(ex)[:200]}")
                    continue
                summary["candidates"] += len(cands)
                for c in cands:
                    try:
                        d = self.decide(site, c, s, now, dry=force_dry)
                    except Exception as ex:
                        summary["errors"].append(f"{c['address']}: {str(ex)[:200]}")
                        d = "error"
                    summary["decisions"][d] = summary["decisions"].get(d, 0) + 1
        return summary


def save_settings(conn, form: dict, user):
    """Validate and store UI-edited settings. Raises ValueError with a message for the operator."""
    s = settings(conn)
    mode = form.get("mode", s["mode"])
    if mode not in ("off", "dry_run", "on"):
        raise ValueError("unknown mode")

    def num(k, lo, hi, cast=int, cur=None):
        v = form.get(k, "")
        if v in ("", None):
            return cur
        try:
            x = cast(v)
        except ValueError:
            raise ValueError(f"{k.replace('_', ' ')} must be a number")
        if not lo <= x <= hi:
            raise ValueError(f"{k.replace('_', ' ')} must be between {lo} and {hi}")
        return x
    allow = []
    for line in str(form.get("allowlist", "")).replace(",", "\n").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            try:
                allow.append(str(ipaddress.ip_network(line, strict=False)))
            except ValueError:
                raise ValueError(f"allowlist: “{line[:40]}” is not an IP address or CIDR")
    ports = []
    for x in str(form.get("bf_ports", "")).replace(",", " ").split():
        if not x.isdigit() or not 1 <= int(x) <= 65535:
            raise ValueError(f"brute force ports: “{x[:10]}” is not a port")
        ports.append(int(x))
    new = {
        "mode": mode, "ttl_hours": num("ttl_hours", 1, 720, float, s["ttl_hours"]),
        "max_per_hour": num("max_per_hour", 1, 500, int, s["max_per_hour"]), "max_active": num("max_active", 1, 5000, int, s["max_active"]),
        "kill_states": form.get("kill_states") == "1", "auto_setup": form.get("auto_setup") == "1", "allowlist": allow,
        "established_services": num("established_services", 1, 50, int, s["established_services"]),
        "triggers": {
            "bruteforce": {"enabled": form.get("bf_enabled") == "1", "window_minutes": num("bf_window", 1, 60, int, s["triggers"]["bruteforce"]["window_minutes"]),
                           "min_attempts": num("bf_min", 5, 100000, int, s["triggers"]["bruteforce"]["min_attempts"]),
                           "max_avg_bytes": num("bf_bytes", 100, 1000000, int, s["triggers"]["bruteforce"]["max_avg_bytes"]),
                           "ports": ports or s["triggers"]["bruteforce"]["ports"]},
            "ids": {"enabled": form.get("ids_enabled") == "1", "max_priority": num("ids_priority", 1, 3, int, s["triggers"]["ids"]["max_priority"]),
                    "exclude_scan": form.get("ids_noscan") == "1", "window_minutes": s["triggers"]["ids"]["window_minutes"]},
            "flood": {"enabled": form.get("fl_enabled") == "1", "window_minutes": num("fl_window", 1, 30, int, s["triggers"]["flood"]["window_minutes"]),
                      "min_flows": num("fl_min", 100, 10_000_000, int, s["triggers"]["flood"]["min_flows"]),
                      "max_ports": num("fl_ports", 1, 100, int, s["triggers"]["flood"]["max_ports"])},
        },
    }
    put_setting(conn, "response", new, user)
    audit(conn, user, "response_settings", new)
    return new
