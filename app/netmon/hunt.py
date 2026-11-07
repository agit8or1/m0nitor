"""Historical threat hunting: search retained history for IP / CIDR / domain indicators.

A match is evidence to investigate, not proof. Every result says:
  - where the indicator came from (list, source, confidence), when it became known to netmon and, when the list says
    so, when it was published, and whether it is still valid;
  - whether the contact happened *before* the indicator was published or known (it may not have been malicious then);
  - whether the address belongs to a CDN or shared hosting (many unrelated sites share it);
  - which history was searched (per source and firewall) and where it has gaps.

Sources (read-only, parameterized, bounded): flow records (both directions; inbound and reply records are de-NATed, so
they name the internal device; outbound-only records through the shared NAT address cannot), the DNS query log
(names, and answers containing an indicator address) and the firewall log. Indicators from several lists are
deduplicated; matches are merged per indicator, source, firewall and device. A hunt runs in the background, one at a
time, in daily chunks with progress and cancellation, within MAX_DAYS and the indicator limits below.
"""
import csv
import io
import ipaddress
import json
import re
import threading
import time

from .core import audit

MAX_DAYS = 31
MAX_IPS, MAX_CIDRS, MAX_DOMAINS = 5000, 200, 2000
MAX_LIST = 50000
MAX_FEED_BYTES = 5 * 2 ** 20
MAX_RUNTIME = 600
STALE_DAYS = 180
CONFIDENCES = ("low", "medium", "high")
# address space of large CDNs / clouds: one address serves many unrelated sites (hint, not a verdict)
CDN_ASNS = {13335: "Cloudflare", 16625: "Akamai", 20940: "Akamai", 54113: "Fastly", 16509: "Amazon", 14618: "Amazon",
            15169: "Google", 396982: "Google Cloud", 8075: "Microsoft", 8068: "Microsoft", 32934: "Meta", 13414: "X",
            209242: "Cloudflare", 60068: "CDN77", 22822: "Edgio", 15133: "Edgio", 46489: "Twitch", 2906: "Netflix"}
SHARED_NAMES = 10
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9_-]{1,63}\.)+[a-z][a-z0-9-]{1,62}$")
_lock = threading.Lock()


# ---- indicators ------------------------------------------------------------------------------------------------
def classify(raw):
    """One indicator string -> (type, value) or None. Accepts IPs, CIDRs (at most /16 or /32 wide), domains, URLs
    (host taken) and defanged forms (example[.]com, hxxp://). Private, loopback and documentation-free checks:
    private and reserved addresses are rejected (they cannot be internet indicators)."""
    v = (raw or "").strip().strip('"\'').lower()
    if not v or v.startswith(("#", ";", "//")):
        return None
    v = v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("hxxp", "http")
    if "://" in v:
        v = v.split("://", 1)[1].split("/", 1)[0].split("@")[-1]
        if v.count(":") == 1:
            v = v.split(":")[0]
    v = v.rstrip(".").lstrip("*.")
    try:
        n = ipaddress.ip_network(v, strict=False)
    except ValueError:
        n = None
    if n is not None:
        a = n.network_address
        if a.is_private and not _documentation(a) or a.is_loopback or a.is_multicast or a.is_unspecified or a.is_link_local:
            return None
        if n.prefixlen == n.max_prefixlen:
            return ("ip", str(a))
        if n.prefixlen < (16 if n.version == 4 else 32):
            return None
        return ("cidr", str(n))
    if DOMAIN_RE.match(v):
        return ("domain", v)
    return None


def _documentation(a):
    return any(a in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def _date(v):
    v = (v or "").strip()
    if not v:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return time.mktime(time.strptime(v[:19] if "T" in v or " " in v else v, fmt.replace("Z", "")))
        except ValueError:
            continue
    return None


def parse_text(text, default_conf="medium"):
    """Plain list (one per line, # comments) or CSV with columns value[,confidence[,published[,valid_until]]].
    Returns (indicators, rejected_count). Indicators: dicts type, value, confidence, published, valid_until."""
    out, bad, seen = [], 0, set()
    for row in csv.reader(io.StringIO(text or "")):
        if not row or not row[0].strip() or row[0].strip().startswith("#"):
            continue
        if len(row) == 1 and (" " in row[0].strip() or "\t" in row[0]):
            row = row[0].split()
        c = classify(row[0])
        if not c:
            if row[0].strip().lower() not in ("value", "indicator", "ioc"):
                bad += 1
            continue
        if c in seen:
            continue
        seen.add(c)
        conf = row[1].strip().lower() if len(row) > 1 and row[1].strip().lower() in CONFIDENCES else default_conf
        out.append({"type": c[0], "value": c[1], "confidence": conf, "published": _date(row[2]) if len(row) > 2 else None,
                    "valid_until": _date(row[3]) if len(row) > 3 else None})
        if len(out) >= MAX_LIST:
            break
    return out, bad


def store(conn, list_id, items, now=None, replace=False):
    """Upsert a list's indicators. The first time netmon sees an indicator is kept as `known_since`. With replace
    (feeds), indicators no longer in the list become inactive (kept for history). Returns (added, total)."""
    now = now or time.time()
    before = conn.execute("SELECT count(*) FROM indicators WHERE list_id=?", (list_id,)).fetchone()[0]
    if replace:
        conn.execute("UPDATE indicators SET active=0 WHERE list_id=?", (list_id,))
    for x in items:
        conn.execute("INSERT INTO indicators(list_id, type, value, confidence, published, known_since, valid_until, active) VALUES (?,?,?,?,?,?,?,1) "
                     "ON CONFLICT(list_id, type, value) DO UPDATE SET confidence=excluded.confidence, published=coalesce(excluded.published, published), "
                     "valid_until=excluded.valid_until, active=1", (list_id, x["type"], x["value"], x["confidence"], x["published"], now, x["valid_until"]))
    conn.commit()
    after = conn.execute("SELECT count(*) FROM indicators WHERE list_id=?", (list_id,)).fetchone()[0]
    return after - before, after


def add_list(conn, name, kind, source, confidence, user, url=None, refresh_hours=24):
    if kind not in ("manual", "feed"):
        raise ValueError("unknown list kind")
    if confidence not in CONFIDENCES:
        raise ValueError("confidence must be low, medium or high")
    if kind == "feed" and not str(url or "").startswith("https://"):
        raise ValueError("a feed URL must use https://")
    name = " ".join((name or "").split())[:80]
    if not name:
        raise ValueError("give the list a name")
    cur = conn.execute("INSERT INTO indicator_lists(name, kind, url, source, confidence, refresh_hours, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
                       (name, kind, url, (source or "")[:200] or name, confidence, max(1, min(int(refresh_hours or 24), 168)), user, time.time()))
    conn.commit()
    audit(conn, user, "indicator_list_added", {"id": cur.lastrowid, "name": name, "kind": kind, "url": url})
    return cur.lastrowid


def fetch_feed(conn, list_id, client=None):
    """Download an HTTPS feed (size-limited, no redirects to other schemes) and store it. Returns a status string."""
    import httpx
    lst = conn.execute("SELECT * FROM indicator_lists WHERE id=? AND kind='feed'", (list_id,)).fetchone()
    if not lst:
        raise ValueError("no such feed")
    try:
        c = client or httpx.Client(timeout=20, follow_redirects=True, max_redirects=3, headers={"User-Agent": "m0nitor-indicator-fetch"})
        with c.stream("GET", lst["url"]) as r:
            if str(r.url).split(":", 1)[0] != "https":
                raise ValueError("feed redirected away from https")
            r.raise_for_status()
            buf = b""
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > MAX_FEED_BYTES:
                    raise ValueError(f"feed larger than {MAX_FEED_BYTES // 2 ** 20} MB")
        items, bad = parse_text(buf.decode("utf-8", "replace"), lst["confidence"])
        added, total = store(conn, list_id, items, replace=True)
        status = f"ok: {len(items):,} indicators ({added:,} new){f', {bad:,} lines not understood' if bad else ''}"
    except Exception as ex:
        status = f"failed: {type(ex).__name__}: {str(ex)[:200]}"
    conn.execute("UPDATE indicator_lists SET last_fetch=?, last_status=? WHERE id=?", (time.time(), status, list_id))
    conn.commit()
    return status


def refresh_due(conn):
    for lst in conn.execute("SELECT id FROM indicator_lists WHERE kind='feed' AND enabled=1 AND "
                            "(last_fetch IS NULL OR last_fetch < ? - refresh_hours * 3600)", (time.time(),)).fetchall():
        fetch_feed(conn, lst["id"])


def feed_loop():
    from .core import db_connect
    conn = db_connect()
    while True:
        try:
            refresh_due(conn)
        except Exception:
            pass
        time.sleep(1800)


def load(conn, list_ids, adhoc=()):
    """Deduplicated indicators: {(type, value): {"lists": [...], "confidence", "published", "known_since", "valid_until"}}."""
    out = {}
    if list_ids:
        q = ",".join("?" * len(list_ids))
        for r in conn.execute(f"SELECT i.*, l.name AS list_name, l.source AS list_source FROM indicators i JOIN indicator_lists l ON l.id = i.list_id "
                              f"WHERE i.active=1 AND l.enabled=1 AND l.id IN ({q})", list(list_ids)).fetchall():
            d = out.setdefault((r["type"], r["value"]), {"lists": [], "confidence": "low", "published": None, "known_since": r["known_since"],
                                                         "valid_until": r["valid_until"]})
            d["lists"].append(f"{r['list_name']} ({r['list_source']})" if r["list_source"] != r["list_name"] else r["list_name"])
            if CONFIDENCES.index(r["confidence"] or "low") > CONFIDENCES.index(d["confidence"]):
                d["confidence"] = r["confidence"]
            if r["published"] and (not d["published"] or r["published"] < d["published"]):
                d["published"] = r["published"]
            d["known_since"] = min(d["known_since"], r["known_since"])
            if r["valid_until"] and (d["valid_until"] is None or r["valid_until"] > d["valid_until"]):
                d["valid_until"] = r["valid_until"]
    for x in adhoc:
        d = out.setdefault((x["type"], x["value"]), {"lists": [], "confidence": x["confidence"], "published": x.get("published"),
                                                     "known_since": time.time(), "valid_until": x.get("valid_until")})
        d["lists"].append("pasted for this hunt")
    return out


# ---- running a hunt --------------------------------------------------------------------------------------------
def _v6(ip):
    a = ipaddress.ip_address(ip)
    return f"::ffff:{a}" if a.version == 4 else str(a)


def _range(cidr):
    n = ipaddress.ip_network(cidr)
    lo, hi = n.network_address, n.broadcast_address
    return (_v6(str(lo)), _v6(str(hi)))


def create_run(conn, user, spec):
    with _lock:
        busy = conn.execute("SELECT id FROM hunt_runs WHERE status IN ('queued','running','cancelling')").fetchone()
        if busy:
            raise ValueError(f"hunt #{busy[0]} is still running; wait for it or cancel it")
        cur = conn.execute("INSERT INTO hunt_runs(created_by, created_at, status, spec, progress) VALUES (?,?,?,?,?)",
                           (user, time.time(), "queued", json.dumps(spec), json.dumps({"pct": 0, "step": "queued"})))
        conn.commit()
    audit(conn, user, "hunt_started", {"run": cur.lastrowid, "lists": spec.get("lists"), "adhoc": len(spec.get("adhoc") or []),
                                       "t0": spec["t0"], "t1": spec["t1"], "sites": spec["sites"]})
    return cur.lastrowid


def cancel(conn, run_id, user):
    n = conn.execute("UPDATE hunt_runs SET status='cancelling' WHERE id=? AND status IN ('queued','running')", (run_id,)).rowcount
    conn.commit()
    if n:
        audit(conn, user, "hunt_cancelled", {"run": run_id})
    return bool(n)


class Cancelled(Exception):
    pass


class Hunt:
    def __init__(self, cfg, ch, conn, run_id):
        self.cfg, self.ch, self.conn, self.id = cfg, ch, conn, run_id

    def _progress(self, pct, step):
        st = self.conn.execute("SELECT status FROM hunt_runs WHERE id=?", (self.id,)).fetchone()[0]
        if st == "cancelling":
            raise Cancelled()
        if time.time() - self.started > MAX_RUNTIME:
            raise TimeoutError(f"stopped after {MAX_RUNTIME // 60} minutes; search a shorter period or fewer indicators")
        self.conn.execute("UPDATE hunt_runs SET status='running', progress=? WHERE id=?", (json.dumps({"pct": int(pct), "step": step}), self.id))
        self.conn.commit()

    def run(self):
        self.started = time.time()
        r = self.conn.execute("SELECT * FROM hunt_runs WHERE id=?", (self.id,)).fetchone()
        spec = json.loads(r["spec"])
        try:
            summary = self._run(spec)
            self.conn.execute("UPDATE hunt_runs SET status='done', summary=?, finished_at=?, progress=? WHERE id=?",
                              (json.dumps(summary, default=str), time.time(), json.dumps({"pct": 100, "step": "done"}), self.id))
        except Cancelled:
            self.conn.execute("UPDATE hunt_runs SET status='cancelled', finished_at=? WHERE id=?", (time.time(), self.id))
        except Exception as ex:
            self.conn.execute("UPDATE hunt_runs SET status='failed', error=?, finished_at=? WHERE id=?",
                              (f"{type(ex).__name__}: {str(ex)[:400]}", time.time(), self.id))
        self.conn.commit()

    def _run(self, spec):
        sites = [s for s in self.cfg.sites if s["id"] in spec["sites"]] or list(self.cfg.sites)
        inds = load(self.conn, spec.get("lists") or [], spec.get("adhoc") or [])
        ips = [v for (t, v) in inds if t == "ip"][:MAX_IPS]
        cidrs = [v for (t, v) in inds if t == "cidr"][:MAX_CIDRS]
        doms = [v for (t, v) in inds if t == "domain"][:MAX_DOMAINS]
        limited = (len([1 for (t, _) in inds if t == "ip"]) > MAX_IPS or len([1 for (t, _) in inds if t == "cidr"]) > MAX_CIDRS
                   or len([1 for (t, _) in inds if t == "domain"]) > MAX_DOMAINS)
        t0, t1 = int(spec["t0"]), int(spec["t1"])
        days = [(d, min(d + 86400, t1)) for d in range(t0, t1, 86400)]
        exps = [s["exporter"] for s in sites]
        site_of_exp = {s["exporter"]: s["id"] for s in sites}
        ip6 = [_v6(x) for x in ips]
        ranges = [_range(c) for c in cidrs]
        lo, hi = [a for a, _ in ranges], [b for _, b in ranges]
        acc = {}
        steps = max(1, len(days) * (1 + bool(doms or ips) + bool(ips or cidrs)))
        k = 0
        from .core import expand_flow_sql, flow_predicates
        macros, fp = flow_predicates(self.cfg, sites)
        for d0, d1 in days:
            if ip6 or lo:
                k += 1
                self._progress(100 * k / steps, f"traffic records {time.strftime('%Y-%m-%d', time.gmtime(d0))}")
                sql = expand_flow_sql("""SELECT ExporterName AS e, replaceOne(IPv6NumToString(l6), '::ffff:', '') AS l,
                    replaceOne(IPv6NumToString(r6), '::ffff:', '') AS r, inb, toUInt32(min(t)) AS first, toUInt32(max(t)) AS last,
                    count() AS n, sum(b) AS b, any(asn) AS asn FROM (SELECT ExporterName, TimeReceived AS t, INB AS inb,
                    if(INB, DstAddr, SrcAddr) AS l6, if(INB, SrcAddr, DstAddr) AS r6, Bytes * SamplingRate AS b, if(INB, SrcAS, DstAS) AS asn
                    FROM flows WHERE ExporterName IN {exps:Array(String)} AND TimeReceived >= toDateTime({d0:UInt32})
                    AND TimeReceived < toDateTime({d1:UInt32}) AND (INB OR OUTB) AND (
                      (INB AND (has({ip6:Array(IPv6)}, SrcAddr) OR arrayExists((a, z) -> SrcAddr >= a AND SrcAddr <= z, {lo:Array(IPv6)}, {hi:Array(IPv6)})))
                      OR (OUTB AND (has({ip6:Array(IPv6)}, DstAddr) OR arrayExists((a, z) -> DstAddr >= a AND DstAddr <= z, {lo:Array(IPv6)}, {hi:Array(IPv6)})))))
                    GROUP BY e, l6, r6, inb LIMIT 20000""", macros)
                for x in self.ch.query(sql, {**fp, "exps": exps, "d0": d0, "d1": d1, "ip6": ip6, "lo": lo, "hi": hi}):
                    ind = self._which(x["r"], ips, cidrs)
                    if ind:
                        self._add(acc, ind, "flows", site_of_exp.get(x["e"]), self.cfg.binat.get(x["l"], x["l"]), x, remote=x["r"],
                                  direction="traffic from it (incl. replies)" if x["inb"] else "traffic to it")
            if doms or ips:
                k += 1
                self._progress(100 * k / steps, f"DNS query log {time.strftime('%Y-%m-%d', time.gmtime(d0))}")
                for x in self.ch.query("""SELECT site, replaceOne(IPv6NumToString(client), '::ffff:', '') AS l, lower(trimRight(query, '.')) AS q,
                        toUInt32(min(ts)) AS first, toUInt32(max(ts)) AS last, count() AS n, arraySlice(groupUniqArrayArray(answers), 1, 10) AS ans
                        FROM netmon.dns_events WHERE site IN {sites:Array(String)} AND ts >= toDateTime64({d0:UInt32}, 3) AND ts < toDateTime64({d1:UInt32}, 3)
                        AND (has({doms:Array(String)}, lower(trimRight(query, '.')))
                             OR arrayExists(d -> endsWith(lower(trimRight(query, '.')), concat('.', d)), {doms:Array(String)})
                             OR hasAny(answers, {ips:Array(String)}))
                        GROUP BY site, l, q LIMIT 20000""", {"sites": [s["id"] for s in sites], "d0": d0, "d1": d1, "doms": doms, "ips": ips}):
                    dom = next((dd for dd in doms if x["q"] == dd or x["q"].endswith("." + dd)), None)
                    if dom:
                        self._add(acc, ("domain", dom), "dns", x["site"], x["l"], x, remote=x["q"], direction="looked up", answers=x["ans"])
                    for a in x["ans"]:
                        if a in ips:
                            self._add(acc, ("ip", a), "dns_answer", x["site"], x["l"], x, remote=x["q"], direction="looked up a name resolving to it")
            if ip6 or lo:
                k += 1
                self._progress(100 * k / steps, f"firewall log {time.strftime('%Y-%m-%d', time.gmtime(d0))}")
                for x in self.ch.query("""SELECT site, action, replaceOne(IPv6NumToString(src), '::ffff:', '') AS s, replaceOne(IPv6NumToString(dst), '::ffff:', '') AS d,
                        toUInt32(min(ts)) AS first, toUInt32(max(ts)) AS last, count() AS n FROM netmon.fw_events
                        WHERE site IN {sites:Array(String)} AND ts >= toDateTime64({d0:UInt32}, 3) AND ts < toDateTime64({d1:UInt32}, 3)
                        AND (has({ip6:Array(IPv6)}, src) OR has({ip6:Array(IPv6)}, dst)
                             OR arrayExists((a, z) -> (src >= a AND src <= z) OR (dst >= a AND dst <= z), {lo:Array(IPv6)}, {hi:Array(IPv6)}))
                        GROUP BY site, action, s, d LIMIT 20000""", {"sites": [s["id"] for s in sites], "d0": d0, "d1": d1, "ip6": ip6, "lo": lo, "hi": hi}):
                    ind = self._which(x["s"], ips, cidrs)
                    remote, local, dirn = (x["s"], x["d"], "from the indicator") if ind else (x["d"], x["s"], "to the indicator")
                    ind = ind or self._which(x["d"], ips, cidrs)
                    if ind:
                        self._add(acc, ind, "firewall", x["site"], self.cfg.binat.get(local, local), x, remote=remote,
                                  direction=f"{dirn} ({x['action'] or 'logged'})")
        self._progress(97, "checking shared hosting and coverage")
        nat_ips = set(self.cfg.get("outbound_nat_ips") or [])
        # outbound records through the shared NAT address name no device; when reply records already name the internal
        # device(s) for the same remote addresses, the NAT row adds nothing and is folded into those
        named = {}
        for m in acc.values():
            if m["src"] == "flows" and m["local"] not in nat_ips:
                named.setdefault((m["ind"], m["site"]), set()).update(m["remotes"])
        folded = 0
        for key in [k for k, m in acc.items() if m["src"] == "flows" and m["local"] in nat_ips
                    and m["remotes"] <= named.get((m["ind"], m["site"]), set())]:
            acc.pop(key)
            folded += 1
        asn_of = {}
        for m in acc.values():
            if m.get("asn"):
                for r_ in m["remotes"]:
                    asn_of.setdefault(r_, m["asn"])
        shared = self._shared_names([r_ for m in acc.values() if m["src"] in ("flows", "firewall") for r_ in m["remotes"]], t0, t1)
        now = time.time()
        rows = []
        for key, m in acc.items():
            info = inds.get(m["ind"], {})
            pub = info.get("published")
            known = pub or info.get("known_since")
            stale = bool(info.get("valid_until") and info["valid_until"] < now) or bool(known and now - known > STALE_DAYS * 86400)
            asn = m.get("asn") or asn_of.get(m["remote"]) or 0
            remotes = sorted(m["remotes"])
            detail = {"lists": info.get("lists", []), "confidence": info.get("confidence"), "published": pub,
                      "known_since": info.get("known_since"), "valid_until": info.get("valid_until"), "stale": stale,
                      "before_published": bool(pub and m["first"] < pub), "remotes": remotes[:10], "remote_count": len(remotes), "asn": asn,
                      "cdn": CDN_ASNS.get(int(asn or 0)), "shared_names": max([shared.get(r_, 0) for r_ in remotes] or [0]),
                      "answers": m.get("answers", [])[:10], "nat": m["local"] in nat_ips}
            rows.append((m["ind"][0], m["ind"][1], remotes[0] if remotes else m["remote"], m["src"], m["site"], m["local"], m["first"], m["last"],
                         m["n"], m["b"], m["direction"], json.dumps(detail, default=str)))
        ids = self._identities(rows)
        for r_ in rows:
            self.conn.execute("INSERT INTO hunt_matches(run_id, ind_type, ind_value, matched, source, site, device, first, last, events, bytes, direction, "
                              "detail, identity_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (self.id, *r_, ids.get((r_[4], r_[5], r_[6]))))
        self.conn.commit()
        return {"indicators": {"ip": len(ips), "cidr": len(cidrs), "domain": len(doms)}, "limited": limited,
                "matched_indicators": len({(r_[0], r_[1]) for r_ in rows}), "matches": len(rows),
                "devices": len({(r_[4], r_[5]) for r_ in rows}), "folded_nat": folded, "coverage": self._coverage(sites, t0, t1, bool(ip6 or lo), bool(doms or ips)),
                "t0": t0, "t1": t1, "sites": [s["id"] for s in sites], "seconds": round(time.time() - self.started, 1)}

    @staticmethod
    def _which(ip, ips, cidrs):
        if ip in ips:
            return ("ip", ip)
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for c in cidrs:
            if a in ipaddress.ip_network(c):
                return ("cidr", c)
        return None

    @staticmethod
    def _add(acc, ind, src, site, local, x, remote, direction, answers=None):
        key = (ind, src, site, local)
        m = acc.setdefault(key, {"ind": ind, "src": src, "site": site, "local": local, "first": x["first"], "last": x["last"], "n": 0, "b": 0,
                                 "remote": remote, "remotes": set(), "direction": direction, "asn": x.get("asn")})
        m["remotes"].add(remote)
        if x.get("asn") and not m.get("asn"):
            m["asn"] = x["asn"]
        m["first"], m["last"] = min(m["first"], x["first"]), max(m["last"], x["last"])
        m["n"] += int(x.get("n") or 0)
        m["b"] += int(x.get("b") or 0)
        if direction not in m["direction"]:
            m["direction"] = "both directions" if src == "flows" else f"{m['direction']}; {direction}"
        if answers:
            m["answers"] = list(dict.fromkeys((m.get("answers") or []) + list(answers)))[:10]

    def _shared_names(self, addrs, t0, t1):
        addrs = sorted({a for a in addrs if a})[:500]
        if not addrs:
            return {}
        try:
            rows = self.ch.query("""SELECT replaceOne(IPv6NumToString(addr), '::ffff:', '') AS a, uniqExact(query) AS n FROM netmon.dns_resolved
                WHERE ts >= toDateTime64({t0:UInt32}, 3) AND ts < toDateTime64({t1:UInt32}, 3) AND has({a6:Array(IPv6)}, addr) GROUP BY a""",
                                 {"t0": t0, "t1": t1, "a6": [_v6(a) for a in addrs]})
            return {r["a"]: r["n"] for r in rows}
        except Exception:
            return {}

    def _identities(self, rows):
        from .identity import owner_at
        out = {}
        for r in rows:
            site, dev, first = r[4], r[5], r[6]
            try:
                if dev and site and self.cfg.is_internal(dev):
                    out[(site, dev, first)] = owner_at(self.conn, site, self.cfg.binat.get(dev, dev), first)["identity"]
            except Exception:
                pass
        return out

    def _coverage(self, sites, t0, t1, flows, dns):
        """Which history was actually searched, per source and firewall, and how much of the period had data."""
        out = []
        want = max(1, (t1 - t0) // 3600)
        if flows:
            try:
                rows = self.ch.query("""SELECT ExporterName AS e, toUInt32(min(TimeReceived)) AS a, toUInt32(max(TimeReceived)) AS b,
                    uniqExact(toStartOfHour(TimeReceived)) AS h FROM flows_1h0m0s WHERE ExporterName IN {exps:Array(String)}
                    AND TimeReceived >= toDateTime({t0:UInt32}) AND TimeReceived < toDateTime({t1:UInt32}) GROUP BY e""",
                                     {"exps": [s["exporter"] for s in sites], "t0": t0, "t1": t1})
                raw = self.ch.query("SELECT toUInt32(min(TimeReceived)) AS a FROM flows WHERE ExporterName IN {exps:Array(String)}",
                                    {"exps": [s["exporter"] for s in sites]})
                by = {r["e"]: r for r in rows}
                raw0 = raw[0]["a"] if raw else 0
                for s in sites:
                    r = by.get(s["exporter"])
                    out.append({"source": "traffic records", "site": s["id"], "from": max(r["a"], raw0) if r else None, "to": r["b"] if r else None,
                                "hours": r["h"] if r else 0, "want": want, "retained_from": raw0})
            except Exception as ex:
                out.append({"source": "traffic records", "error": type(ex).__name__})
        if dns:
            try:
                rows = self.ch.query("""SELECT site, toUInt32(min(ts)) AS a, toUInt32(max(ts)) AS b, uniqExact(toStartOfHour(ts)) AS h FROM netmon.dns_events
                    WHERE site IN {sites:Array(String)} AND ts >= toDateTime64({t0:UInt32}, 3) AND ts < toDateTime64({t1:UInt32}, 3) GROUP BY site""",
                                     {"sites": [s["id"] for s in sites], "t0": t0, "t1": t1})
                by = {r["site"]: r for r in rows}
                for s in sites:
                    r = by.get(s["id"])
                    out.append({"source": "DNS query log", "site": s["id"], "from": r["a"] if r else None, "to": r["b"] if r else None,
                                "hours": r["h"] if r else 0, "want": want})
            except Exception as ex:
                out.append({"source": "DNS query log", "error": type(ex).__name__})
        return out


def start(cfg, ch, run_id):
    from .core import db_connect

    def go():
        Hunt(cfg, ch, db_connect(), run_id).run()
    threading.Thread(target=go, daemon=True, name=f"hunt-{run_id}").start()
