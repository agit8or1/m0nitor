"""WAN / VPN quality: small active probes run from the netmon server (the vantage point), and an honest reading of
the results.

Probes are opt-in (none by default) and small: a few pings, one DNS query or one HTTPS request per round, at the
interval an admin sets (30 s .. 1 h). There are no bandwidth tests. Each round records latency, loss and jitter
(ping/TCP), or the response time (DNS/HTTPS).

Reading the results keeps facts and suspicions apart:
- facts: which probes were degraded and when, by how much compared with their usual values, how busy the WAN link was
  (from the traffic records), and which events the firewall logged at the same time;
- a suspected cause only where the probes support it. The provider is never blamed without evidence: that needs a
  probe to the provider's first hop that was affected while the firewall itself answered normally and the link was
  not busy.
"""
import ipaddress
import json
import os
import socket
import statistics
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

KINDS = {"icmp": "ping", "tcp": "TCP connect", "dns": "DNS query", "https": "HTTPS request"}
ROLES = {"gateway": "the firewall itself", "upstream": "the provider's first hop", "internet": "an internet host",
         "vpn": "a site or host across a VPN", "service": "a DNS or web service"}
MAX_PROBES = 20
INTERVAL = (30, 3600)
COUNT = (1, 10)
TIMEOUT = (0.5, 5.0)
RETENTION = 30 * 86400
HTTPS_MAX_BYTES = 64 * 1024
LOSS_BAD = 0.2            # a lost ping in five (needs two rounds in a row: one bad round is not an episode)
SLOW_MS = {"icmp": 30, "tcp": 30, "dns": 100, "https": 300}   # and at least twice the usual value
MIN_ROUNDS = 2
LEARN_ROUNDS = 60
WORKERS = 4


# ---- configuration ---------------------------------------------------------------------------------------------
def _host(v):
    v = (v or "").strip()
    if not v or len(v) > 253 or any(c in v for c in " /\\@?#"):
        raise ValueError("give an IP address or host name")
    return v


def validate(kind, target, query="", interval_s=60, count=5, timeout_s=2.0, role="internet"):
    if kind not in KINDS:
        raise ValueError("unknown probe type")
    if role not in ROLES:
        raise ValueError("unknown role")
    target = (target or "").strip()
    if kind == "https":
        from urllib.parse import urlsplit
        u = urlsplit(target)
        if u.scheme != "https" or not u.hostname:
            raise ValueError("HTTPS probes need an https:// address")
    elif kind == "tcp":
        host, _, port = target.rpartition(":")
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError("TCP probes need host:port")
        _host(host.strip("[]"))
    elif kind == "dns":
        try:
            ipaddress.ip_address(target)
        except ValueError:
            raise ValueError("DNS probes need the resolver's IP address")
        q = (query or "").strip().rstrip(".")
        if not q or len(q) > 253 or not all(0 < len(p) < 64 for p in q.split(".")):
            raise ValueError("give a name to look up")
    else:
        _host(target)
    try:
        interval_s, count, timeout_s = int(interval_s), int(count), float(timeout_s)
    except (TypeError, ValueError):
        raise ValueError("interval, count and timeout must be numbers")
    if not INTERVAL[0] <= interval_s <= INTERVAL[1]:
        raise ValueError(f"interval must be {INTERVAL[0]} s to {INTERVAL[1]} s")
    if not COUNT[0] <= count <= COUNT[1]:
        raise ValueError(f"count must be {COUNT[0]} to {COUNT[1]}")
    if not TIMEOUT[0] <= timeout_s <= TIMEOUT[1]:
        raise ValueError(f"timeout must be {TIMEOUT[0]} s to {TIMEOUT[1]} s")
    if kind == "https":
        count = 1
    if count * timeout_s > interval_s / 2:
        raise ValueError("count × timeout must stay below half the interval")
    return target, (query or "").strip().rstrip(".") if kind == "dns" else "", interval_s, count, timeout_s


def add(conn, site, kind, target, name, role, user, query="", interval_s=60, count=5, timeout_s=2.0):
    from .core import audit
    if conn.execute("SELECT count(*) FROM probes").fetchone()[0] >= MAX_PROBES:
        raise ValueError(f"at most {MAX_PROBES} probes")
    target, query, interval_s, count, timeout_s = validate(kind, target, query, interval_s, count, timeout_s, role)
    name = " ".join((name or "").split())[:60] or f"{KINDS[kind]} {target}"
    pid = conn.execute("INSERT INTO probes(site, kind, target, name, role, interval_s, count, timeout_s, query, created_by, created_at) "
                       "VALUES (?,?,?,?,?,?,?,?,?,?,?)", (site, kind, target, name, role, interval_s, count, timeout_s, query, user, time.time())).lastrowid
    conn.commit()
    audit(conn, user, "probe_added", {"id": pid, "site": site, "kind": kind, "target": target, "interval_s": interval_s})
    return pid


def set_enabled(conn, pid, enabled, user):
    from .core import audit
    conn.execute("UPDATE probes SET enabled=? WHERE id=?", (1 if enabled else 0, pid))
    conn.commit()
    audit(conn, user, "probe_enabled" if enabled else "probe_paused", {"id": pid})


def delete(conn, pid, user):
    from .core import audit
    conn.execute("DELETE FROM probe_results WHERE probe_id=?", (pid,))
    conn.execute("DELETE FROM probes WHERE id=?", (pid,))
    conn.commit()
    audit(conn, user, "probe_deleted", {"id": pid})


def probes(conn, site=None):
    q = "SELECT * FROM probes WHERE site_ok(site)" + (" AND site=?" if site else "") + " ORDER BY site, CASE role WHEN 'gateway' THEN 0 WHEN 'upstream' THEN 1 ELSE 2 END, id"
    return [dict(r) for r in conn.execute(q, (site,) if site else ())]


def recommended(site):
    """Suggested probes, shown to the admin before anything is added: the firewall, two anycast resolvers, the
    firewall's DNS resolver and one HTTPS check. The provider's first hop must come from the admin (traceroute)."""
    fw = site.get("exporter_ip") or ""
    out = []
    if fw:
        out.append(dict(kind="icmp", target=fw, name="The firewall", role="gateway"))
    out += [dict(kind="icmp", target="1.1.1.1", name="Cloudflare resolver (anycast)", role="internet"),
            dict(kind="icmp", target="9.9.9.9", name="Quad9 resolver (anycast)", role="internet")]
    if fw:
        out.append(dict(kind="dns", target=fw, query="example.com", name="DNS through the firewall", role="service", count=1))
    out.append(dict(kind="https", target="https://example.com/", name="HTTPS check (example.com)", role="service", count=1))
    return out


# ---- measuring -------------------------------------------------------------------------------------------------
def _resolve(host):
    infos = socket.getaddrinfo(host.strip("[]"), None, type=socket.SOCK_DGRAM)
    fam, *_, addr = infos[0]
    return fam, addr[0]


def _icmp(target, count, timeout):
    """Unprivileged ping sockets (the kernel fills the identifier and checksum). Returns RTTs in ms (None = lost)."""
    fam, addr = _resolve(target)
    v6 = fam == socket.AF_INET6
    s = socket.socket(fam, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP)
    out = []
    try:
        for seq in range(1, count + 1):
            payload = os.urandom(16)
            s.settimeout(timeout)
            t = time.perf_counter()
            s.sendto(struct.pack(">BBHHH", 128 if v6 else 8, 0, 0, 0, seq) + payload, (addr, 0))
            rtt = None
            while True:
                left = timeout - (time.perf_counter() - t)
                if left <= 0:
                    break
                s.settimeout(left)
                try:
                    data = s.recv(2048)
                except (socket.timeout, TimeoutError):
                    break
                if len(data) >= 8 and data[0] == (129 if v6 else 0) and struct.unpack(">H", data[6:8])[0] == seq and data[8:24] == payload:
                    rtt = (time.perf_counter() - t) * 1000
                    break
            out.append(rtt)
            if seq < count:
                time.sleep(0.2)
    finally:
        s.close()
    return out, {"address": addr}


def _tcp(target, count, timeout):
    host, _, port = target.rpartition(":")
    fam, addr = _resolve(host)
    out, err = [], ""
    for i in range(count):
        t = time.perf_counter()
        try:
            with socket.create_connection((addr, int(port)), timeout=timeout):
                out.append((time.perf_counter() - t) * 1000)
        except OSError as ex:
            out.append(None)
            err = type(ex).__name__
        if i < count - 1:
            time.sleep(0.2)
    return out, {"address": addr, **({"error": err} if err else {})}


def dns_query(name, qid):
    labels = b"".join(bytes([len(p)]) + p.encode("ascii", "ignore") for p in name.rstrip(".").split("."))
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack(">HH", 1, 1)


RCODE = {0: "answered", 1: "format error", 2: "server failure", 3: "name does not exist", 5: "refused"}


def _dns(resolver, name, count, timeout):
    fam = socket.AF_INET6 if ":" in resolver else socket.AF_INET
    out, rc = [], None
    for i in range(count):
        qid = int.from_bytes(os.urandom(2), "big")
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        t = time.perf_counter()
        try:
            s.sendto(dns_query(name, qid), (resolver, 53))
            while True:
                data = s.recv(4096)
                if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                    rc = data[3] & 0x0F
                    out.append((time.perf_counter() - t) * 1000 if rc in (0, 3) else None)
                    break
        except OSError:
            out.append(None)
        finally:
            s.close()
        if i < count - 1:
            time.sleep(0.2)
    return out, {"rcode": rc, "result": RCODE.get(rc, "no answer" if rc is None else f"code {rc}")}


def _https(url, timeout):
    import httpx
    t = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=True, headers={"User-Agent": "netmon-quality-probe"}) as c:
            with c.stream("GET", url) as r:
                first = (time.perf_counter() - t) * 1000
                got = 0
                for chunk in r.iter_bytes():
                    got += len(chunk)
                    if got >= HTTPS_MAX_BYTES:
                        break
                ok = r.status_code < 500
                return [first if ok else None], {"status": r.status_code}
    except httpx.ConnectError as ex:
        why = "certificate problem" if "CERTIFICATE" in str(ex).upper() else "could not connect"
        return [None], {"error": why}
    except httpx.TimeoutException:
        return [None], {"error": "timed out"}
    except Exception as ex:
        return [None], {"error": type(ex).__name__}


def measure(p):
    """One round of one probe -> result dict (never raises)."""
    try:
        if p["kind"] == "icmp":
            rtts, detail = _icmp(p["target"], p["count"], p["timeout_s"])
        elif p["kind"] == "tcp":
            rtts, detail = _tcp(p["target"], p["count"], p["timeout_s"])
        elif p["kind"] == "dns":
            rtts, detail = _dns(p["target"], p["query"], p["count"], p["timeout_s"])
        else:
            rtts, detail = _https(p["target"], p["timeout_s"])
    except (OSError, ValueError) as ex:
        return {"probe_id": p["id"], "ts": time.time(), "ok": 0, "rtt_ms": None, "loss": 1.0, "jitter_ms": None,
                "detail": {"error": "name not found" if isinstance(ex, socket.gaierror) else type(ex).__name__}}
    return summarize(p["id"], rtts, detail)


def summarize(pid, rtts, detail, ts=None):
    got = [x for x in rtts if x is not None]
    loss = 1 - len(got) / max(1, len(rtts))
    jitter = statistics.mean(abs(a - b) for a, b in zip(got, got[1:])) if len(got) > 1 else None
    return {"probe_id": pid, "ts": ts or time.time(), "ok": 1 if got else 0, "rtt_ms": statistics.mean(got) if got else None,
            "loss": round(loss, 3), "jitter_ms": jitter, "detail": detail}


def store(conn, r):
    conn.execute("INSERT INTO probe_results(probe_id, ts, ok, rtt_ms, loss, jitter_ms, detail) VALUES (?,?,?,?,?,?,?)",
                 (r["probe_id"], r["ts"], r["ok"], r["rtt_ms"], r["loss"], r["jitter_ms"], json.dumps(r["detail"])))


class Runner(threading.Thread):
    """Runs due probes on a small pool; only this thread writes results. Honours the per-firewall 'probes' choice."""

    def __init__(self, cfg, connect):
        super().__init__(daemon=True, name="quality-probes")
        self.cfg, self.connect = cfg, connect
        self.stop = threading.Event()

    def run(self):
        from .ux import monitored
        conn = self.connect()
        pool = ThreadPoolExecutor(WORKERS, thread_name_prefix="probe")
        due, running, plist, loaded, pruned = {}, {}, [], 0, 0
        while not self.stop.is_set():
            now = time.time()
            try:
                if now - loaded > 30:
                    plist = [p for p in probes(conn) if p["enabled"] and monitored(self.cfg.site(p["site"]), "probes")]
                    loaded = now
                for p in plist:
                    if p["id"] not in running and due.get(p["id"], 0) <= now:
                        running[p["id"]] = pool.submit(measure, p)
                        due[p["id"]] = now + p["interval_s"]
                for pid, f in list(running.items()):
                    if f.done():
                        running.pop(pid)
                        r = f.result()
                        if conn.execute("SELECT 1 FROM probes WHERE id=?", (pid,)).fetchone():
                            store(conn, r)
                conn.commit()
                if now - pruned > 3600:
                    conn.execute("DELETE FROM probe_results WHERE ts < ?", (now - RETENTION,))
                    conn.commit()
                    pruned = now
            except Exception:
                import logging
                logging.getLogger(__name__).exception("probe loop")
            self.stop.wait(1)


# ---- reading the results ---------------------------------------------------------------------------------------
def results(conn, pid, t0, t1):
    return [dict(r) | {"detail": json.loads(r["detail"] or "{}")} for r in
            conn.execute("SELECT * FROM probe_results WHERE probe_id=? AND ts>=? AND ts<? ORDER BY ts", (pid, t0, t1))]


def baseline(conn, pid, now):
    """The probe's usual values: medians over the previous 7 days (excluding the last hour). None while learning."""
    rows = conn.execute("SELECT rtt_ms, jitter_ms FROM probe_results WHERE probe_id=? AND ok=1 AND ts>=? AND ts<? AND rtt_ms IS NOT NULL",
                        (pid, now - 7 * 86400, now - 3600)).fetchall()
    if len(rows) < LEARN_ROUNDS:
        return {"learning": True, "rounds": len(rows)}
    return {"learning": False, "rounds": len(rows), "rtt_ms": statistics.median(r["rtt_ms"] for r in rows),
            "jitter_ms": statistics.median([r["jitter_ms"] for r in rows if r["jitter_ms"] is not None] or [0])}


def problem(r, p, base):
    """Why one round is bad, or None."""
    if not r["ok"]:
        d = r["detail"] or {}
        return "no answer" + (f" ({d.get('error') or d.get('result')})" if d.get("error") or d.get("result") not in (None, "answered") else "")
    if r["loss"] >= LOSS_BAD:
        return f"{r['loss'] * 100:.0f}% loss"
    if base and not base["learning"] and r["rtt_ms"] is not None and r["rtt_ms"] > max(2 * base["rtt_ms"], base["rtt_ms"] + SLOW_MS[p["kind"]]):
        return f"slow ({r['rtt_ms']:.0f} ms, usually {base['rtt_ms']:.0f} ms)"
    if (p["kind"] == "icmp" and base and not base["learning"] and r["jitter_ms"] is not None
            and r["jitter_ms"] > max(30, 3 * base["jitter_ms"])):
        return f"unstable (jitter {r['jitter_ms']:.0f} ms)"
    return None


def episodes(conn, p, t0, t1, now=None):
    """Degraded periods: at least MIN_ROUNDS bad rounds in a row (a single bad round is noise, kept calm)."""
    now = now or time.time()
    base = baseline(conn, p["id"], t1)
    out, cur, prev_ts = [], None, None
    gap = 2.5 * p["interval_s"]
    for r in results(conn, p["id"], t0, t1):
        why = problem(r, p, base)
        if why and cur and r["ts"] - prev_ts <= gap:
            cur["end"], cur["rounds"] = r["ts"], cur["rounds"] + 1
            cur["why"].append(why)
            cur["failed"] += 0 if r["ok"] else 1
            cur["worst_loss"] = max(cur["worst_loss"], r["loss"])
            if r["rtt_ms"]:
                cur["worst_rtt"] = max(cur["worst_rtt"] or 0, r["rtt_ms"])
        elif why:
            if cur and cur["rounds"] >= MIN_ROUNDS:
                out.append(cur)
            cur = {"probe": p["id"], "start": r["ts"], "end": r["ts"], "rounds": 1, "why": [why], "failed": 0 if r["ok"] else 1,
                   "worst_loss": r["loss"], "worst_rtt": r["rtt_ms"]}
        else:
            if cur and cur["rounds"] >= MIN_ROUNDS:
                out.append(cur)
            cur = None
        prev_ts = r["ts"]
    if cur and cur["rounds"] >= MIN_ROUNDS:
        cur["ongoing"] = now - cur["end"] < gap
        out.append(cur)
    for x in out:
        x.setdefault("ongoing", False)
        x["summary"] = max(set(x["why"]), key=x["why"].count)
        x["down"] = x["failed"] == x["rounds"]
    return out


def status(conn, p, now=None):
    """Current state of one probe: normal | degraded | down | learning | no data | paused."""
    now = now or time.time()
    if not p["enabled"]:
        return {"state": "paused", "text": "paused"}
    last = conn.execute("SELECT * FROM probe_results WHERE probe_id=? ORDER BY ts DESC LIMIT 3", (p["id"],)).fetchall()
    if not last or now - last[0]["ts"] > 3 * p["interval_s"] + p["count"] * p["timeout_s"] + 30:
        return {"state": "no data", "text": "no recent results" + (f" (last {int((now - last[0]['ts']) / 60)} min ago)" if last else ""),
                "last": last[0]["ts"] if last else None}
    base = baseline(conn, p["id"], now)
    rs = [dict(r) | {"detail": json.loads(r["detail"] or "{}")} for r in last]
    bad = [problem(r, p, base) for r in rs[:MIN_ROUNDS]]
    cur = rs[0]
    vals = _values(cur, p)
    if len(rs) >= MIN_ROUNDS and all(bad):
        down = not any(r["ok"] for r in rs[:MIN_ROUNDS])
        return {"state": "down" if down else "degraded", "text": bad[0], "values": vals, "base": base, "last": cur["ts"]}
    if base["learning"]:
        return {"state": "learning", "text": f"learning usual values ({base['rounds']} of {LEARN_ROUNDS} rounds; the last hour is not counted)", "values": vals, "base": base,
                "last": cur["ts"]}
    return {"state": "normal", "text": "normal", "values": vals, "base": base, "last": cur["ts"]}


def _values(r, p):
    if not r["ok"]:
        return "no answer"
    parts = [f"{r['rtt_ms']:.1f} ms" if r["rtt_ms"] is not None else ""]
    if p["kind"] in ("icmp", "tcp", "dns") and p["count"] > 1:
        parts.append(f"{r['loss'] * 100:.0f}% loss")
    if r["jitter_ms"] is not None and p["kind"] == "icmp":
        parts.append(f"jitter {r['jitter_ms']:.1f} ms")
    d = r.get("detail") or {}
    if d.get("status"):
        parts.append(f"HTTP {d['status']}")
    return ", ".join(x for x in parts if x)


def overview(conn, cfg, now=None):
    """For the Overview strip and Status: probes that are degraded or down right now."""
    now = now or time.time()
    ps = probes(conn)
    bad = []
    for p in ps:
        st = status(conn, p, now)
        if st["state"] in ("degraded", "down"):
            s = cfg.site(p["site"])
            bad.append({"id": p["id"], "name": p["name"], "site": p["site"], "site_name": (s or {}).get("name", p["site"]), "state": st["state"],
                        "text": st["text"]})
    return {"configured": len(ps), "bad": bad}


def utilization(ch, site, t0, t1):
    """WAN traffic in the window from the per-minute traffic records: peak Mb/s each way and share of the contracted capacity."""
    rows = ch.query("""SELECT toUInt32(toStartOfMinute(TimeReceived)) AS m, sumIf(Bytes * SamplingRate, InIfName = {wan:String}) AS down,
        sumIf(Bytes * SamplingRate, OutIfName = {wan:String}) AS up FROM flows_1m0s
        WHERE ExporterName = {exp:String} AND TimeReceived >= toDateTime({t0:UInt32}) AND TimeReceived < toDateTime({t1:UInt32})
        GROUP BY m ORDER BY m LIMIT 1500""", {"wan": site["wan_if"], "exp": site["exporter"], "t0": int(t0), "t1": int(t1)})
    if not rows:
        return None
    down = max(r["down"] for r in rows) * 8 / 60 / 1e6
    up = max(r["up"] for r in rows) * 8 / 60 / 1e6
    out = {"down_mbps": down, "up_mbps": up, "minutes": len(rows)}
    if site.get("wan_down_mbps"):
        out["down_pct"] = 100 * down / site["wan_down_mbps"]
    if site.get("wan_up_mbps"):
        out["up_pct"] = 100 * up / site["wan_up_mbps"]
    pcts = [v for k, v in out.items() if k.endswith("_pct")]
    out["peak_pct"] = max(pcts) if pcts else None
    return out


EVENT_KINDS = ("gateway", "vpn", "interface", "routing", "ha")


def events(ch, site, t0, t1, limit=10):
    return ch.query("""SELECT toUInt32(ts) AS t, app, kind, substring(message, 1, 240) AS m FROM netmon.sys_events
        WHERE site = {s:String} AND ts >= toDateTime({t0:UInt32}) AND ts < toDateTime({t1:UInt32})
          AND (kind IN {k:Array(String)} OR app = 'audit') ORDER BY ts LIMIT {lim:UInt32}""",
                    {"s": site["id"], "t0": int(t0), "t1": int(t1), "k": list(EVENT_KINDS), "lim": limit})


def explain(ep, p, others, util, evs, site=None):
    """Facts and (only when supported) a suspected cause for one episode.
    `others`: [(probe, degraded_in_window: bool)] for the other probes of the same firewall that had results then."""
    from .ux import fmt_local
    facts = [f"{p['name']} ({KINDS[p['kind']]} to {p['target']}): {ep['summary']}, {ep['rounds']} rounds in a row"
             + (f", no answer in {ep['failed']}" if ep["failed"] and not ep["down"] else "") + "."]
    bad = [o for o, b in others if b]
    fine = [o for o, b in others if not b]
    if bad:
        facts.append("Also affected: " + ", ".join(o["name"] for o in bad) + ".")
    if fine:
        facts.append("Not affected: " + ", ".join(o["name"] for o in fine) + ".")
    if util:
        txt = f"WAN traffic peaked at {util['down_mbps']:.0f} Mb/s down and {util['up_mbps']:.0f} Mb/s up"
        if util.get("peak_pct") is not None:
            txt += f" ({util['peak_pct']:.0f}% of the contracted capacity at the busiest minute)"
        else:
            txt += " (set the contracted capacity under Firewalls & sites to see how busy that is)"
        facts.append(txt + ".")
    else:
        facts.append("No traffic records for that time, so how busy the WAN link was is unknown.")
    for ev in evs[:5]:
        facts.append(f"At {fmt_local(ev['t'], site, with_tz=False)} the firewall logged ({ev['app'] or ev['kind']}): {ev['m'][:160]} "
                     "(same time; not necessarily the cause).")
    gw = [o for o, _ in others if o["role"] == "gateway"]
    gw_bad = any(o["role"] == "gateway" for o in bad) or p["role"] == "gateway"
    gw_ok = bool(gw) and not gw_bad
    inet_all = [x for x in [p] + [o for o, _ in others] if x["role"] in ("internet", "upstream")]
    inet_bad = [x for x in [p] + bad if x["role"] in ("internet", "upstream")]
    upstream = [x for x in inet_all if x["role"] == "upstream"]
    upstream_bad = [x for x in inet_bad if x["role"] == "upstream"]
    pct = util.get("peak_pct") if util else None
    busy = pct is not None and pct >= 85
    suspect, why = None, ""
    if gw_bad:
        suspect = "between the netmon server and the firewall: the local network or the firewall itself"
        why = "the probe to the firewall was affected too"
    elif p["role"] == "vpn":
        if inet_all and not inet_bad:
            suspect, why = "the VPN tunnel or the remote site", "internet probes were not affected"
        elif inet_bad:
            suspect, why = "the WAN connection, which also carries the VPN", "internet probes were affected at the same time"
    elif p["kind"] == "dns" and fine and all(o["kind"] != "dns" for o in bad) and not inet_bad:
        suspect, why = "the DNS resolver", "pings to internet hosts were not affected"
    elif len(inet_all) >= 2 and len(inet_bad) == len(inet_all):
        if busy:
            suspect = "the WAN link was busy"
            why = f"traffic reached {pct:.0f}% of the contracted capacity while every internet probe was affected"
        elif upstream and len(upstream_bad) == len(upstream) and gw_ok and pct is not None and pct < 50:
            suspect = "beyond the firewall, at or after the provider's first hop: possibly a provider problem"
            why = ("the provider's first hop and every internet probe were affected, the firewall answered normally and the link was not busy "
                   f"({pct:.0f}% at most)")
        else:
            suspect = "beyond the firewall" if gw_ok else "the WAN connection, or the firewall"
            why = ("every internet probe was affected" + (", the firewall answered normally" if gw_ok else "")
                   + ("; whether it is the provider cannot be told without a probe to the provider's first hop" if not upstream else "")
                   + ("; how busy the link was is unknown (set the contracted capacity)" if pct is None else ""))
    elif fine and len(bad) == 0 and any(o["role"] in ("internet", "upstream", "service") for o in fine):
        suspect, why = "that destination or the path to it", "the other probes were fine, so the connection itself looks fine"
    if not suspect:
        why = "not enough probes to narrow it down: probes to the firewall and to two internet hosts tell the local side, the link and a destination apart"
    return {"facts": facts, "suspect": suspect, "why": why}


def episode_report(conn, cfg, ch, site, t0, t1, now=None, limit=20):
    """All degraded periods of a firewall's probes in [t0, t1), newest first, each with facts and a suspected cause."""
    now = now or time.time()
    ps = probes(conn, site["id"])
    eps = {p["id"]: episodes(conn, p, t0, t1, now) for p in ps}
    out = []
    for p in ps:
        for ep in eps[p["id"]]:
            w0, w1 = ep["start"] - 90, ep["end"] + 90
            others = []
            for o in ps:
                if o["id"] == p["id"]:
                    continue
                had = conn.execute("SELECT 1 FROM probe_results WHERE probe_id=? AND ts>=? AND ts<? LIMIT 1", (o["id"], w0, w1)).fetchone()
                if had:
                    others.append((o, any(x["start"] <= w1 and x["end"] >= w0 for x in eps[o["id"]])))
            try:
                util = utilization(ch, site, w0 - 60, w1 + 60)
            except Exception:
                util = None
            try:
                evs = events(ch, site, w0 - 600, w1 + 300)
            except Exception:
                evs = []
            out.append(ep | {"probe_name": p["name"], "role": p["role"], "kind": p["kind"]} | explain(ep, p, others, util, evs, site))
    out.sort(key=lambda x: -x["start"])
    return out[:limit]


def series(conn, pid, t0, t1, buckets=96):
    """Bucketed values for a small chart: [(t, avg rtt, max loss, failed rounds)]."""
    step = max(1, (t1 - t0) / buckets)
    rows = conn.execute("SELECT CAST((ts - ?) / ? AS INTEGER) AS b, avg(rtt_ms) AS rtt, max(loss) AS loss, sum(1 - ok) AS failed, count(*) AS n "
                        "FROM probe_results WHERE probe_id=? AND ts>=? AND ts<? GROUP BY b ORDER BY b", (t0, step, pid, t0, t1)).fetchall()
    return [{"t": t0 + r["b"] * step, "rtt": r["rtt"], "loss": r["loss"], "failed": r["failed"], "n": r["n"]} for r in rows], step


def sparkline(name, pts, t0, t1, width=320, height=48):
    """Latency line with loss/failure marks. Labelled for screen readers; the numbers are also in the text."""
    from html import escape
    vals = [p["rtt"] for p in pts if p["rtt"] is not None]
    if not pts:
        return ""
    hi = max(vals) if vals else 1
    lo = min(vals) if vals else 0
    span = max(1e-9, t1 - t0)

    def x(t):
        return 2 + (width - 4) * (t - t0) / span

    def y(v):
        return height - 4 - (height - 10) * ((v - lo) / (hi - lo) if hi > lo else 0.5)
    line = " ".join(f"{x(p['t']):.1f},{y(p['rtt']):.1f}" for p in pts if p["rtt"] is not None)
    marks = "".join(f"<rect x='{x(p['t']) - 1.5:.1f}' y='0' width='3' height='{height}' class='{'q-fail' if p['failed'] else 'q-loss'}'/>"
                    for p in pts if p["failed"] or (p["loss"] or 0) >= LOSS_BAD)
    label = (f"{name}: latency {lo:.1f} to {hi:.1f} ms" if vals else f"{name}: no answers") + \
        (f"; {sum(1 for p in pts if p['failed'] or (p['loss'] or 0) >= LOSS_BAD)} periods with loss or no answer" if marks else "; no loss")
    return (f"<svg viewBox='0 0 {width} {height}' class='qspark' role='img' aria-label='{escape(label)}'>{marks}"
            f"<polyline points='{line}' class='q-line'/></svg>")


def health_checks(conn, cfg, now=None):
    """Settings → Health rows: one per firewall with probes."""
    from .health import check
    now = now or time.time()
    out = []
    by_site = {}
    for p in probes(conn):
        by_site.setdefault(p["site"], []).append(p)
    for sid, ps in by_site.items():
        s = cfg.site(sid) or {"name": sid}
        sts = [(p, status(conn, p, now)) for p in ps if p["enabled"]]
        if not sts:
            continue
        bad = [(p, st) for p, st in sts if st["state"] in ("degraded", "down")]
        nodata = [(p, st) for p, st in sts if st["state"] == "no data"]
        if bad:
            state, val = "warn", "; ".join(f"{p['name']}: {st['text']}" for p, st in bad)
        elif nodata and len(nodata) == len(sts):
            state, val = "warn", "no probe results recently (is the probe runner working?)"
        else:
            state, val = "ok", f"{len(sts)} probe{'s' if len(sts) != 1 else ''} normal or learning" + (f", {len(nodata)} without recent results" if nodata else "")
        out.append(check(f"probes:{sid}", "Infrastructure", f"WAN / VPN quality ({s['name']})", state, val, now,
                         limits="Measured from the netmon server; a problem between netmon and the firewall also shows here.",
                         action="Settings → WAN / VPN quality"))
    return out
