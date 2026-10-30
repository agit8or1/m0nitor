"""Explainable detection rules over Akvorado's ClickHouse flows table.

Every rule returns Finding dicts carrying the evidence, the exact query, the
baseline comparison, alternative explanations and next steps. Rules never
claim payload-level conclusions: they only describe observed flow metadata.
"""
import ipaddress
import json
import statistics
import time

import os

from . import threatradar
from .core import (get_setting, DATA_DIR, PROTO, apply_overrides, audit, expand_flow_sql, expected_devices, expected_match,
                   flow_predicates, set_state)

IP = "replaceOne(IPv6NumToString({col}), '::ffff:', '')"

# Inbound across WAN. Routed exporters: DstAddr is the real internal host (validated, see config.yaml).
# Capture exporters (pfSense softflowd on WAN): DstAddr is the address as seen on the WAN.
INBOUND = f"""
SELECT TimeReceived AS t, {IP.format(col='DstAddr')} AS local, {IP.format(col='SrcAddr')} AS peer,
       DstPort AS local_port, SrcPort AS peer_port, Proto AS proto, Bytes AS bytes,
       Packets AS packets, SrcCountry AS cc, SrcAS AS asn,
       ((has({{svc:Array(UInt16)}}, peer_port) OR peer_port < 1024) AND local_port >= 1024) AS local_initiated
FROM flows
WHERE ExporterName = {{exporter:String}} AND INB AND TOLAN
"""

# Outbound across WAN: SrcAddr is post-NAT. FWORIG = firewall-originated (routed exporters only).
OUTBOUND = f"""
SELECT TimeReceived AS t, {IP.format(col='SrcAddr')} AS src, SrcPort AS sport,
       {IP.format(col='DstAddr')} AS dst, DstPort AS dport, Proto AS proto, Bytes AS bytes,
       Packets AS packets, DstCountry AS cc, DstAS AS asn, FWORIG AS fw_origin
FROM flows
WHERE ExporterName = {{exporter:String}} AND OUTB
"""

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def fmt_ts(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(ts))


def human_bytes(n: float) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1000:
            return f"{n:.1f} {u}"
        n /= 1000
    return f"{n:.1f} PB"


def beacon_stats(ts: list[int]):
    """Return (mean_interval, coefficient_of_variation) for sorted event times."""
    ts = sorted(ts)
    diffs = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    if len(diffs) < 2:
        return None, None
    mean = statistics.fmean(diffs)
    if mean <= 0:
        return None, None
    return mean, statistics.pstdev(diffs) / mean


def robust_upper(values: list[float], k: float = 3.0) -> float:
    """median + k * scaled MAD; robust to a few backup/patch spikes in the baseline."""
    if not values:
        return 0.0
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values]) * 1.4826
    return med + k * mad


def exception_matches(exc: dict, rule: str, asset: str, subject: str, now: float) -> bool:
    if not exc["enabled"] or (exc["expires_at"] and exc["expires_at"] < now):
        return False
    if exc["rule"] not in ("*", rule) or exc["asset"] not in ("*", asset or ""):
        return False
    s = exc["subject"]
    if s in ("*", subject):
        return True
    if s.endswith("*") and (subject or "").startswith(s[:-1]):   # e.g. "2000328|*": one IDS signature, any remote
        return True
    try:  # CIDR exception covering an IP subject
        return ipaddress.ip_address(subject) in ipaddress.ip_network(s, strict=False)
    except ValueError:
        return False


class Detector:
    def __init__(self, cfg, ch, conn, notifier=None):
        self.cfg, self.ch, self.conn, self.notifier = cfg, ch, conn, notifier
        self.site = cfg.sites[0]  # rules run once per site; run_once sets this

    # ---- helpers -------------------------------------------------------
    def base_params(self) -> dict:
        s = self.site
        return {"exporter": s["exporter"], "wan": s["wan_if"], "lan": s["lan_if"], "site": s["id"],
                "svc": self.cfg["service_ports"]}

    def q(self, sql, params):
        macros, fp = flow_predicates(self.cfg, [self.site])
        return self.ch.query(expand_flow_sql(sql, macros), {**self.base_params(), **fp, **params})

    def windows(self, now):
        d = self.cfg["detector"]
        we = int(now - d["ingest_delay_seconds"])
        ws = we - d["window_minutes"] * 60
        bs = int(now - d["baseline_days"] * 86400)
        return ws, we, bs

    def learning(self):
        """Days of flow data available for this exporter (cold-start indicator)."""
        r = self.q("SELECT toUInt32(min(TimeReceived)) AS first FROM flows "
                   "WHERE ExporterName = {exporter:String}", {})
        first = r[0]["first"] if r else 0
        days = (time.time() - first) / 86400 if first else 0.0
        return days

    def confidence(self, days, base="medium"):
        return "low" if days < self.cfg["detector"]["baseline_days"] else base

    def exposed_public_ports(self) -> str:
        """Port-forwarded (public_ip, port) pairs as a ClickHouse Array(Tuple) literal."""
        pairs = sorted({(e.public_ip, p) for e in self.cfg.exposures for p in range(e.lo, e.hi + 1)})
        return "[" + ",".join(f"('{ip}',{p})" for ip, p in pairs) + "]"

    def akv(self, expr: str) -> str:
        return f"ExporterName = {self.site['exporter']} AND {expr}"

    # ---- rules ---------------------------------------------------------
    def rule_new_dest(self, now, days, kind):
        """New destination country/ASN for an internal host (host-initiated, inferred)."""
        rc = self.cfg["rules"][f"new_dest_{kind}"]
        if not rc["enabled"] or days < self.cfg["detector"]["min_learning_days"]:
            return []
        col = "cc" if kind == "country" else "asn"
        notempty = "cc != ''" if kind == "country" else "asn != 0"
        ws, we, bs = self.windows(now)
        sql = f"""
        WITH conv AS ({INBOUND})
        SELECT local, {col} AS v, count() AS flows, sum(bytes) AS bytes,
               groupUniqArray(5)(peer) AS peers, groupUniqArray(5)(peer_port) AS ports,
               any(dictGetOrDefault('asns', 'name', asn, '')) AS asname
        FROM conv
        WHERE t >= toDateTime({{ws:UInt32}}) AND t < toDateTime({{we:UInt32}})
          AND local_initiated AND {notempty}
          AND (local, {col}) NOT IN (
              SELECT local, {col} FROM conv
              WHERE t >= toDateTime({{bs:UInt32}}) AND t < toDateTime({{ws:UInt32}}) AND {notempty})
        GROUP BY local, v HAVING flows >= {{min:UInt32}}
        ORDER BY bytes DESC LIMIT 200"""
        params = {"ws": ws, "we": we, "bs": bs, "min": rc["min_flows"]}
        out = []
        for r in self.q(sql, params):
            if not self.cfg.is_internal(r["local"]):
                continue
            a = self.cfg.asset(r["local"])
            label = r["v"] if kind == "country" else f"AS{r['v']} {r['asname']}".strip()
            sev = ("high" if a.get("sensitive") else "medium") if kind == "country" else \
                  ("medium" if a.get("sensitive") else "low")
            peer_expr = " OR ".join(f"SrcAddr = {p}" for p in r["peers"])
            out.append(dict(
                rule=f"new_dest_{kind}", severity=sev, confidence=self.confidence(days),
                asset=r["local"], subject=str(r["v"]),
                title=f"{self.cfg.asset_label(r['local'])} contacted new {kind} {label}",
                window=(ws, we), evidence=[r], query=(sql, params),
                baseline=(f"No traffic between this host and {kind} {label} in the "
                          f"{min(days, self.cfg['detector']['baseline_days']):.1f} days of baseline "
                          f"before {fmt_ts(ws)}. Baseline = observed history, not approval."),
                alternatives=[
                    "CDN/cloud endpoint churn (provider moved a service to another region/ASN)",
                    "Software update or new SaaS integration",
                    f"GeoIP/ASN databases attribute address blocks, not operators; {kind} is a hint only",
                    "Initiator is inferred from ports (peer used a service port); may be inbound",
                ],
                next_steps=[
                    "Review peers and ports in evidence; check reverse DNS/WHOIS as untrusted hints",
                    "Ask the asset owner whether a new integration or update was deployed",
                    "Check the host's process/connection table (ss -tnp) for the peer addresses",
                    "If unexplained, request a block of the specific peer (not the country)",
                ],
                akvorado_filter=self.akv(f"DstAddr = {r['local']} AND ({peer_expr})"),
            ))
        return self.group_new_dest(out, kind, rc.get("group_min", 4))

    def group_new_dest(self, out, kind, group_min):
        """Several new countries/ASNs for one host in one window are one finding (a scanning host would otherwise
        raise one per country). Subject "many" keeps it a single alert that later runs update."""
        by = {}
        for f in out:
            by.setdefault(f["asset"], []).append(f)
        res = []
        for host, fs in by.items():
            if len(fs) < group_min:
                res += fs
                continue
            fs.sort(key=lambda f: -f["evidence"][0]["bytes"])
            labels = [f["subject"] if kind == "country" else f"AS{f['subject']}" for f in fs]
            g = dict(fs[0])
            g.update(subject="many", severity=max((f["severity"] for f in fs), key=lambda x: SEV_ORDER[x]),
                     title=f"{self.cfg.asset_label(host)} contacted {len(fs)} new {'countries' if kind == 'country' else 'networks'}: "
                           + ", ".join(labels[:8]) + (" …" if len(fs) > 8 else ""),
                     evidence=[f["evidence"][0] for f in fs[:25]],
                     baseline=fs[0]["baseline"].replace(f"{kind} {fs[0]['subject']}", f"any of the listed {kind} values"),
                     alternatives=["Scanning or crawling from this host (many destinations in many countries at once)"]
                                  + fs[0]["alternatives"],
                     akvorado_filter=self.akv(f"DstAddr = {host}"))
            res.append(g)
        return res

    def rule_unexpected_inbound(self, now, days):
        """Passed inbound traffic to an internal port that no port forward explains."""
        rc = self.cfg["rules"]["unexpected_inbound"]
        if not rc["enabled"]:
            return []
        ws, we, _ = self.windows(now)
        sql = f"""
        WITH conv AS ({INBOUND})
        SELECT local, proto, local_port, count() AS flows, sum(bytes) AS bytes,
               uniqExact(peer) AS peers, groupUniqArray(5)(peer) AS sample_peers,
               groupUniqArray(5)(cc) AS countries
        FROM conv
        WHERE t >= toDateTime({{ws:UInt32}}) AND t < toDateTime({{we:UInt32}})
          AND proto IN (6, 17) AND local_port < {{floor:UInt16}} AND peer_port >= 1024
          AND NOT has({{svc:Array(UInt16)}}, peer_port)
        GROUP BY local, proto, local_port ORDER BY flows DESC LIMIT 500"""
        params = {"ws": ws, "we": we, "floor": rc["ephemeral_floor"]}
        out = []
        for r in self.q(sql, params):
            proto = PROTO.get(r["proto"], str(r["proto"]))
            if not self.cfg.is_internal(r["local"]) or self.cfg.exposed(r["local"], proto, r["local_port"]):
                continue
            a = self.cfg.asset(r["local"])
            out.append(dict(
                rule="unexpected_inbound", severity="high" if a.get("sensitive") else "medium",
                confidence="medium", asset=r["local"], subject=f"{proto}/{r['local_port']}",
                title=f"Inbound {proto}/{r['local_port']} reached {self.cfg.asset_label(r['local'])} "
                      f"from {r['peers']} external peer(s) — not in port-forward list",
                window=(ws, we), evidence=[r], query=(sql, params),
                baseline="Expected exposure = OPNsense port forwards recorded in config.yaml (exposures).",
                alternatives=[
                    "Port forward/1:1 NAT added on OPNsense but not yet listed in config.yaml",
                    "Return traffic of a connection the internal host opened from a low source port",
                    "UDP peer-to-peer/STUN behaviour (VoIP, remote-access software)",
                ],
                next_steps=[
                    "Compare with Firewall → NAT → Port Forward / One-to-One on OPNsense",
                    f"Check what listens on {proto}/{r['local_port']} on the host (ss -lntup)",
                    "If unintended, remove the NAT/pass rule (firewall change, needs approval)",
                ],
                akvorado_filter=self.akv(f"InIfName = {self.site['wan_if']} AND DstAddr = {r['local']} "
                                         f"AND DstPort = {r['local_port']}"),
            ))
        return out

    def rule_outbound_volume(self, now, days):
        """Outbound bytes per post-NAT source vs the same hour-of-day baseline."""
        rc = self.cfg["rules"]["outbound_volume"]
        if not rc["enabled"]:
            return []
        ws, we, bs = self.windows(now)
        sql = f"""
        WITH o AS ({OUTBOUND})
        SELECT src, toUInt32(toStartOfHour(t)) AS h, sum(bytes) AS bytes
        FROM o WHERE t >= toDateTime({{bs:UInt32}}) AND t < toDateTime({{ws:UInt32}}) AND NOT fw_origin
        GROUP BY src, h"""
        cur_sql = f"""
        WITH o AS ({OUTBOUND})
        SELECT src, sum(bytes) AS bytes, uniqExact(dst) AS dsts,
               topK(5)(dst) AS top_dsts, topK(5)(sport) AS top_sports, topK(3)(proto) AS protos
        FROM o WHERE t >= toDateTime({{ws:UInt32}}) AND t < toDateTime({{we:UInt32}}) AND NOT fw_origin
        GROUP BY src HAVING bytes >= {{min:UInt64}}"""
        cur = self.q(cur_sql, {"ws": ws, "we": we, "min": rc["min_bytes"]})
        if not cur:
            return []
        hist = self.q(sql, {"ws": ws, "bs": bs})
        hour = time.gmtime(ws).tm_hour
        out = []
        win_h = self.cfg["detector"]["window_minutes"] / 60
        ndays = max(1, int(min(days, self.cfg["detector"]["baseline_days"])))
        for r in cur:
            by_day = {}
            for h in hist:
                if h["src"] == r["src"] and time.gmtime(h["h"]).tm_hour == hour:
                    by_day[h["h"] // 86400] = h["bytes"]
            vals = [by_day.get(d, 0) * win_h for d in range(int(ws // 86400) - ndays, int(ws // 86400))]
            upper = max(robust_upper(vals), max(vals or [0]))
            if r["bytes"] < rc["factor"] * max(upper, 1):
                continue
            attrib = [self.cfg.attribute_public(r["src"], p, PROTO.get(r["protos"][0], "tcp"))
                      for p in r["top_sports"]]
            hosts = sorted({a[0] for a in attrib if a[0]})
            asset = hosts[0] if len(hosts) == 1 else r["src"]
            out.append(dict(
                rule="outbound_volume", severity="high" if r["bytes"] > 10 * max(upper, 1) else "medium",
                confidence=self.confidence(days, "medium" if hosts else "low"),
                asset=asset, subject=r["src"],
                title=f"Outbound {human_bytes(r['bytes'])} from {r['src']} in "
                      f"{self.cfg['detector']['window_minutes']} min "
                      f"(baseline upper {human_bytes(upper)})",
                window=(ws, we), evidence=[r, {"attribution": [a[2] for a in attrib]}],
                query=(cur_sql, {"ws": ws, "we": we}),
                baseline=f"Same UTC hour ({hour:02d}:00) over {ndays} day(s): values {[human_bytes(v) for v in vals]}; "
                         f"robust upper bound {human_bytes(upper)}; alert at x{rc['factor']}.",
                alternatives=["Backups/replication (PBS, Nextcloud sync, mail queues)",
                              "Patch mirrors, container image pulls, large legitimate uploads",
                              "Shared NAT address aggregates many hosts; one host may not be the cause",
                              "Flow metadata cannot show what data was transferred"],
                next_steps=["Open the Akvorado link and group by DstAddr/DstAS/DstPort",
                            "Identify the internal host (LAN-side capture or host netstat) if NATed",
                            "Check scheduled jobs and backups for this hour"],
                akvorado_filter=self.akv(f"OutIfName = {self.site['wan_if']} AND SrcAddr = {r['src']}"),
            ))
        return out

    def rule_fanout(self, now, days):
        rc = self.cfg["rules"]["fanout"]
        if not rc["enabled"]:
            return []
        we = int(now - self.cfg["detector"]["ingest_delay_seconds"])
        ws = we - rc["window_minutes"] * 60
        sql = f"""
        WITH o AS ({OUTBOUND})
        SELECT src, uniqExact(dst) AS dsts, max(ports_per_dst) AS max_ports, count() AS flows,
               argMax(dst, ports_per_dst) AS top_dst, uniqExact(dport) AS distinct_ports, groupUniqArray(10)(dport) AS sample_ports
        -- UDP 33434-33534 are traceroute/mtr probe ports: one path trace uses dozens of them, so they never count as a port scan
        FROM (SELECT src, dst, dport, uniqExactIf(dport, NOT (proto = 17 AND dport BETWEEN 33434 AND 33534))
                     OVER (PARTITION BY src, dst) AS ports_per_dst
              FROM o WHERE t >= toDateTime({{ws:UInt32}}) AND t < toDateTime({{we:UInt32}}) AND NOT fw_origin
                -- keep host-initiated traffic only: drop replies from port forwards and server ports
                AND sport >= 1024 AND NOT has({{svc:Array(UInt16)}}, sport)
                AND NOT has({{exp:Array(Tuple(String, UInt16))}}, (src, sport))
                AND NOT (sport >= 32768 AND dport >= 32768))
        GROUP BY src HAVING dsts >= {{p:UInt32}} OR max_ports >= {{pp:UInt32}}"""
        params = {"ws": ws, "we": we, "p": rc["min_peers"], "pp": rc["min_ports_per_peer"],
                  "exp": self.exposed_public_ports()}
        out = []
        for r in self.q(sql, params):
            vertical = r["max_ports"] >= rc["min_ports_per_peer"]
            # every port actually seen on the top destination, so the evidence is complete rather than a sample
            tp = self.q(f"""WITH o AS ({OUTBOUND}) SELECT dport, proto, count() AS n FROM o
                WHERE t >= toDateTime({{ws:UInt32}}) AND t < toDateTime({{we:UInt32}}) AND NOT fw_origin
                  AND src = {{s:String}} AND dst = {{d:String}} GROUP BY dport, proto ORDER BY dport""",
                        {"ws": ws, "we": we, "s": r["src"], "d": r["top_dst"]})
            trace = sorted(x["dport"] for x in tp if x["proto"] == 17 and 33434 <= x["dport"] <= 33534)
            r["top_dst_ports"] = sorted({x["dport"] for x in tp} - set(trace))
            if trace:
                r["top_dst_traceroute"] = f"{len(trace)} UDP traceroute/mtr probe ports ({trace[0]}-{trace[-1]}), not counted as scanned ports"
            if r["src"] in self.cfg.get("outbound_nat_ips", []):
                r.update(self.nat_hosts(r["src"], ws, we))
                if r["dsts_expected"]:
                    # destinations whose replies went to expected devices (Settings: expected devices) do not count
                    if vertical and self.reply_hosts([r["top_dst"]], ws, we) <= set(r["expected_hosts"]) | {""}:
                        continue
                    if not vertical and r["dsts"] - r["dsts_expected"] < rc["min_peers"]:
                        continue
            out.append(dict(
                rule="fanout", severity="medium", confidence="low" if r["src"] in self.cfg.get("outbound_nat_ips", []) else "medium",
                asset=r["src"], subject="vertical" if vertical else "horizontal",
                title=(f"{r['src']} contacted {r['max_ports']} ports on {r['top_dst']}" if vertical else
                       f"{r['src']} contacted {r['dsts']} distinct destinations in {rc['window_minutes']} min"),
                window=(ws, we), evidence=[r], query=(sql, params),
                baseline=f"Thresholds: {rc['min_peers']} destinations or {rc['min_ports_per_peer']} ports/destination.",
                alternatives=["Authorized vulnerability scanner or monitoring", "P2P / torrent / VoIP",
                              "traceroute/mtr (UDP 33434-33534) or path monitoring",
                              "Scans to high ports from high source ports are excluded (cannot tell them from replies)",
                              "Mail server delivering to many MX hosts", "Shared NAT aggregates many hosts"],
                next_steps=["Group by DstPort in Akvorado to see scan pattern",
                            "Identify the internal host behind the NAT address", "Confirm authorized scanning"],
                akvorado_filter=self.akv(f"OutIfName = {self.site['wan_if']} AND SrcAddr = {r['src']}"),
            ))
        return out

    def reply_hosts(self, peers, ws, we):
        """LAN hosts that received traffic from any of `peers` in the window (return path); {""} if none did."""
        if not peers:
            return {""}
        rows = self.q(f"""SELECT DISTINCT {IP.format(col='DstAddr')} AS h FROM flows WHERE ExporterName = {{exporter:String}} AND INB AND TOLAN
                          AND TimeReceived >= toDateTime({{ws:UInt32}}) AND TimeReceived < toDateTime({{we:UInt32}}) + 120
                          AND has({{p:Array(String)}}, {IP.format(col='SrcAddr')}) LIMIT 50""",
                      {"ws": int(ws), "we": int(we), "p": [str(x) for x in peers][:200]})
        return {r["h"] for r in rows} or {""}

    def expected_only(self, f):
        """True if a shared-NAT finding's named peers replied only to expected devices (so it is their traffic)."""
        exp = expected_devices(self.conn)
        if not exp or f["asset"] not in self.cfg.get("outbound_nat_ips", []):
            return False
        peers = []
        for ev in f["evidence"] if isinstance(f["evidence"], list) else [f["evidence"]]:
            for k in ("peers", "sample_peers", "top_dsts", "peer", "top_dst", "dst"):
                v = ev.get(k) if isinstance(ev, dict) else None
                peers += [str(x) for x in (v if isinstance(v, list) else [v] if v else [])]
        if not peers:
            return False
        hosts = self.reply_hosts(peers, *f["window"])
        return hosts != {""} and all(expected_match(exp, h) for h in hosts)

    def nat_hosts(self, src, ws, we):
        """Which LAN host(s) stand behind a shared NAT address's destinations, from the return path.

        A destination that answered sends its reply across the LAN interface to the real host, and that record is
        exported with the host's own address. Per destination: exactly one receiving host -> attributed to it; several
        -> ambiguous (never split); none -> no reply (unanswered probes, or firewall-originated) and not attributable
        from flow records. Only destinations that answered can be attributed. Same flow filters as rule_fanout.
        Hosts with their own 1:1 NAT to another public address are never candidates: binat wins over outbound NAT, so
        their traffic cannot leave through src even when they talk to the same peers."""
        own = sorted({x["internal"].removesuffix("/32") for x in self.cfg.raw.get("binat", []) if x["external"].removesuffix("/32") != src})
        rows = self.q(f"""
            WITH e AS (SELECT DISTINCT dst FROM ({OUTBOUND}) WHERE t >= toDateTime({{ws:UInt32}}) AND t < toDateTime({{we:UInt32}})
                         AND src = {{s:String}} AND NOT fw_origin AND sport >= 1024 AND NOT has({{svc:Array(UInt16)}}, sport)
                         AND NOT has({{exp:Array(Tuple(String, UInt16))}}, (src, sport)) AND NOT (sport >= 32768 AND dport >= 32768)),
                 r AS (SELECT {IP.format(col='SrcAddr')} AS dst, groupUniqArrayIf(21)({IP.format(col='DstAddr')}, NOT has({{own:Array(String)}}, {IP.format(col='DstAddr')})) AS hosts FROM flows
                       WHERE ExporterName = {{exporter:String}} AND INB AND TOLAN
                         AND TimeReceived >= toDateTime({{ws:UInt32}}) AND TimeReceived < toDateTime({{we:UInt32}}) + 120
                         AND {IP.format(col='SrcAddr')} IN (SELECT dst FROM e) GROUP BY dst)
            SELECT multiIf(length(r.hosts) = 1, 'one', length(r.hosts) > 1, 'many', 'none') AS k, if(k = 'one', r.hosts[1], '') AS host,
                   if(k = 'many', arraySort(r.hosts), []) AS several, count() AS dsts
            FROM e LEFT JOIN r ON e.dst = r.dst GROUP BY k, host, several ORDER BY dsts DESC""",
                      {"ws": ws, "we": we, "s": src, "exp": self.exposed_public_ports(), "own": own})
        total = sum(int(x["dsts"]) for x in rows) or 1
        exp = expected_devices(self.conn)
        hosts = [{"host": x["host"], "destinations": int(x["dsts"]), "share_pct": round(100 * int(x["dsts"]) / total, 1),
                  **({"expected": True} if expected_match(exp, x["host"]) else {})} for x in rows if x["k"] == "one"]
        excluded = [h for h in hosts if h.get("expected")]
        # several hosts got replies: still the expected devices' traffic when every one of them is expected
        # (at most 20 hosts are listed per destination; 21 means "more", which is never treated as all-expected)
        many_exp = [x for x in rows if x["k"] == "many" and len(x["several"]) <= 20 and all(expected_match(exp, h) for h in x["several"])]
        return {"lan_hosts": hosts[:10],
                "dsts_expected": sum(h["destinations"] for h in excluded) + sum(int(x["dsts"]) for x in many_exp),
                "expected_hosts": sorted({h["host"] for h in excluded} | {h for x in many_exp for h in x["several"]}),
                "dsts_ambiguous": sum(int(x["dsts"]) for x in rows if x["k"] == "many") - sum(int(x["dsts"]) for x in many_exp),
                "dsts_no_reply": sum(int(x["dsts"]) for x in rows if x["k"] == "none"),
                "lan_hosts_basis": "return path: the LAN host that received each destination's replies; destinations that never "
                                   "answered cannot be attributed from flow records"}

    def rule_beaconing(self, now, days):
        rc = self.cfg["rules"]["beaconing"]
        if not rc["enabled"]:
            return []
        we = int(now - self.cfg["detector"]["ingest_delay_seconds"])
        ws = we - rc["hours"] * 3600
        sql = f"""
        WITH conv AS ({INBOUND})
        SELECT local, peer, peer_port, proto, count() AS n, sum(bytes) AS bytes,
               arraySort(groupArray(toUInt32(t))) AS ts, any(cc) AS cc
        FROM conv WHERE t >= toDateTime({{ws:UInt32}}) AND t < toDateTime({{we:UInt32}})
          AND local_initiated AND NOT has({{ign:Array(UInt16)}}, peer_port)
        GROUP BY local, peer, peer_port, proto HAVING n BETWEEN {{mn:UInt32}} AND 2000"""
        params = {"ws": ws, "we": we, "mn": rc["min_events"], "ign": rc["ignore_ports"]}
        out = []
        at = self.site["active_timeout"]
        for r in self.q(sql, params):
            mean, cv = beacon_stats(r["ts"])
            if mean is None or cv > rc["max_cv"] or not rc["min_interval_s"] <= mean <= rc["max_interval_s"]:
                continue
            if abs(mean - at) <= at * 0.05:  # periodic active-timeout exports of one long flow
                continue
            r = {k: v for k, v in r.items() if k != "ts"} | {"mean_interval_s": round(mean, 1), "cv": round(cv, 3)}
            out.append(dict(
                rule="beaconing", severity="medium" if self.cfg.asset(r["local"]).get("sensitive") else "low",
                confidence="low", asset=r["local"], subject=f"{r['peer']}:{r['peer_port']}",
                title=f"{self.cfg.asset_label(r['local'])} → {r['peer']}:{r['peer_port']} every "
                      f"~{mean:.0f}s ({r['n']} times, CV {cv:.2f})",
                window=(ws, we), evidence=[r], query=(sql, params),
                baseline=f"Regularity test: CV of inter-flow intervals ≤ {rc['max_cv']} with ≥ {rc['min_events']} events.",
                alternatives=["Monitoring checks, health probes, update/telemetry agents, API polling",
                              "NTP/DNS-like keepalives on non-standard ports",
                              "Flow export timing adds jitter; true periodicity may differ"],
                next_steps=["Identify the process on the host talking to the peer",
                            "Check peer ownership (WHOIS/ASN) as an untrusted hint",
                            "Add an exception with owner/reason if it is a known agent"],
                akvorado_filter=self.akv(f"DstAddr = {r['local']} AND SrcAddr = {r['peer']}"),
            ))
        return out

    def _ours(self, ip):
        try:
            return self.cfg.is_ours(ip)
        except ValueError:
            return False

    def rule_ids(self, now):
        """Suricata alerts from OPNsense (signature matches — evidence of a pattern, not of compromise)."""
        rc = self.cfg["rules"]["ids_alert"]
        if not rc["enabled"]:
            return []
        we = int(now - 30)
        ws = we - rc["window_minutes"] * 60
        sql = """
        SELECT sig_id, any(signature) AS signature, any(category) AS category, min(severity) AS severity,
               groupUniqArray(3)(action) AS actions, count() AS hits,
               replaceOne(IPv6NumToString(src), '::ffff:', '') AS s, replaceOne(IPv6NumToString(dst), '::ffff:', '') AS d,
               groupUniqArray(5)(dport) AS dports, any(proto) AS proto, toUInt32(max(ts)) AS last,
               any(JSONExtractString(raw, 'flow', 'src_ip')) AS initiator,
               any(JSONExtractString(raw, 'flow', 'dest_ip')) AS responder,
               any(JSONExtractString(raw, 'direction')) AS pkt_dir,
               arraySlice(arrayDistinct(arrayFlatten(groupArray(extractAll(raw, '(?i)cve[-_][0-9]{4}[-_][0-9]{4,7}')))), 1, 10) AS cves
        FROM netmon.ids_events WHERE ts >= toDateTime({ws:UInt32}) AND ts < toDateTime({we:UInt32}) AND site = {site:String}
        GROUP BY sig_id, src, dst ORDER BY severity, hits DESC LIMIT 200"""
        params = {"ws": ws, "we": we, "site": self.site["id"]}
        out = []
        for r in self.ch.query(sql, params):
            asset = r["d"] if self._ours(r["d"]) else r["s"] if self._ours(r["s"]) else r["d"]
            remote = r["s"] if asset == r["d"] else r["d"]
            asset = self.cfg.binat.get(asset, asset)   # a 1:1 NAT address is exactly one server
            sev = {1: "high", 2: "medium"}.get(int(r["severity"]), "low")
            client, server = (r["initiator"], r["responder"]) if r["initiator"] else (r["s"], r["d"])
            radar = threatradar.lookup(self.conn, r.get("cves") or [])
            intel, steps = "", []
            if radar:
                top = radar[0]
                intel = (" Threat intel (ExploitHound Threat Radar): " + "; ".join(
                    f"{h['cve']}: {threatradar.SECTIONS[h['section']]}" + (f", EPSS {100 * h['epss']:.1f}%" if h["epss"] is not None else "")
                    for h in radar[:3]) + ". This says the vulnerability is exploited or likely to be, not that this server is vulnerable.")
                steps = [f"Check whether the target runs software affected by {top['cve']} ({', '.join(top['products'][:2]) or 'see NVD'}) and is patched"]
                if top["section"] == "confirmed" and threatradar.settings(self.conn)["raise_known_exploited"]:
                    sev = {"low": "medium", "medium": "high", "high": "critical"}.get(sev, sev)
            out.append(dict(
                rule="ids_alert", severity=sev, confidence="medium", asset=asset, subject=f"{r['sig_id']}|{remote}",
                title=f"IDS: {r['signature']} — {client} → {server} ({r['hits']}×)",
                window=(ws, we), evidence=[{**r, "peer": remote, **({"threat_radar": radar[:5]} if radar else {})}], query=(sql.strip(), params),
                baseline=f"Suricata signature {r['sig_id']} ({r['category']}), priority {r['severity']}; action {', '.join(r['actions'])}.{intel}",
                alternatives=["Signature false positive (check rule documentation and the matched traffic)",
                              "Internet background scanning that the service is not vulnerable to",
                              "Authorized vulnerability scan"],
                next_steps=steps + ["Check whether the target service is exposed and patched",
                            "Look up the signature ID and its known false-positive conditions",
                            "Review other traffic from the remote address in Connections"],
                akvorado_filter=self.akv(f"SrcAddr = {remote} OR DstAddr = {remote}"),
            ))
        return out

    def rule_fw_blocks(self, now):
        """Firewall-logged blocks: outbound attempts from internal hosts (security) and inbound scanning (informational)."""
        out = []
        lan, wan = self.site["lan_if"], self.site["wan_if"]
        rc = self.cfg["rules"]["fw_blocked_outbound"]
        if rc["enabled"]:
            we = int(now - 30)
            ws = we - rc["window_minutes"] * 60
            sql = """
            SELECT replaceOne(IPv6NumToString(src), '::ffff:', '') AS s, count() AS events, uniq(dst) AS dsts,
                   groupUniqArray(8)(dport) AS dports, groupUniqArray(5)(replaceOne(IPv6NumToString(dst), '::ffff:', '')) AS sample_dsts,
                   groupUniqArray(3)(rulenr) AS rules
            FROM netmon.fw_events WHERE ts >= toDateTime({ws:UInt32}) AND ts < toDateTime({we:UInt32})
              AND action = 'block' AND dir = 'in' AND iface = {lan:String} AND site = {site:String}
            GROUP BY src HAVING events >= {m:UInt32} ORDER BY events DESC LIMIT 50"""
            params = {"ws": ws, "we": we, "lan": lan, "m": rc["min_events"], "site": self.site["id"]}
            for r in self.ch.query(sql, params):
                out.append(dict(
                    rule="fw_blocked_outbound", severity="medium", confidence="high", asset=r["s"], subject="outbound-blocked",
                    title=f"{self.cfg.asset_label(r['s'])} was blocked {r['events']}× trying to reach {r['dsts']} destination(s)",
                    window=(ws, we), evidence=[{**r, "top_dsts": r["sample_dsts"]}], query=(sql.strip(), params),
                    baseline=f"Firewall log evidence: ≥ {rc['min_events']} LAN-side blocks in {rc['window_minutes']} min.",
                    alternatives=["Misconfigured application or stale DNS/NTP/update target",
                                  "Policy working as intended for a known restricted host"],
                    next_steps=["Identify the process on the host making the blocked connections",
                                "Check which rule blocked it (rule number in evidence)"],
                    akvorado_filter=""))
        rc = self.cfg["rules"]["fw_blocked_scan"]
        if rc["enabled"]:
            we = int(now - 30)
            ws = we - rc["window_minutes"] * 60
            sql = """
            SELECT replaceOne(IPv6NumToString(src), '::ffff:', '') AS s, count() AS events, uniq(dport) AS ports, uniq(dst) AS targets,
                   groupUniqArray(10)(dport) AS sample_ports
            FROM netmon.fw_events WHERE ts >= toDateTime({ws:UInt32}) AND ts < toDateTime({we:UInt32})
              AND action = 'block' AND dir = 'in' AND iface = {wan:String} AND site = {site:String}
            GROUP BY src HAVING events >= {m:UInt32} OR ports >= {p:UInt32} ORDER BY events DESC LIMIT 30"""
            params = {"ws": ws, "we": we, "wan": wan, "m": rc["min_events"], "p": rc["min_ports"], "site": self.site["id"]}
            for r in self.ch.query(sql, params):
                out.append(dict(
                    rule="fw_blocked_scan", severity="info", confidence="high", asset="", subject=r["s"],
                    title=f"Blocked scanning from {r['s']}: {r['events']} attempts on {r['ports']} ports",
                    window=(ws, we), evidence=[{**r, "peer": r["s"]}], query=(sql.strip(), params),
                    baseline="Firewall blocked it. Internet-wide scanning is constant background noise.",
                    alternatives=["Commercial/academic Internet scanners", "Misconfigured client"],
                    next_steps=["No action needed unless the same source also reached an exposed service",
                                "Check Connections for passed traffic from this address"],
                    akvorado_filter=self.akv(f"SrcAddr = {r['s']}")))
        return out

    def rule_dns(self, now):
        """Hosts that use external resolvers directly (from resolver replies on the return path, so it works
        through shared NAT), plus explainable anomalies from DNS logs when a DNS source is connected."""
        from . import dnsctx
        rc = {"enabled": True, "window_minutes": 60, "nxdomain_min": 50, "nxdomain_ratio": 0.5, "label_len": 25,
              "label_entropy": 3.8, "odd_names_min": 20, **(self.cfg.get("rules", {}).get("dns") or {})}
        if not rc["enabled"]:
            return []
        we = int(now - self.cfg["detector"]["ingest_delay_seconds"])
        ws = we - rc["window_minutes"] * 60
        out = []
        sql = f"""SELECT {IP.format(col='DstAddr')} AS host, groupUniqArray(10)({IP.format(col='SrcAddr')}) AS resolvers,
                         groupUniqArray(4)(SrcPort) AS ports, count() AS flows
                  FROM flows WHERE ExporterName = {{exporter:String}} AND INB AND TOLAN AND SrcPort IN (53, 853)
                    AND TimeReceived >= toDateTime({{ws:UInt32}}) AND TimeReceived < toDateTime({{we:UInt32}})
                  GROUP BY host"""
        params = {"ws": ws, "we": we}
        for r in self.q(sql, params):
            out.append(dict(rule="dns_bypass", severity="low", confidence="high", asset=r["host"], subject="external_resolvers",
                            title=f"{r['host']} resolves names through external DNS servers ({', '.join(sorted(r['resolvers'])[:3])})",
                            window=(ws, we), evidence=[{"host": r["host"], "resolvers": r["resolvers"], "ports": r["ports"], "flows": r["flows"]}],
                            query=(sql, params), baseline="Replies from external resolvers delivered to this host (port 53/853).",
                            alternatives=["Host or container configured with public resolvers (8.8.8.8, 1.1.1.1)",
                                          "Mail servers and recursive resolvers query authoritative servers directly",
                                          "Software with hard-coded resolvers"],
                            next_steps=["Expected for mail servers and resolvers; otherwise point the host at the local resolver",
                                        "Names of these queries are not visible without the host's or a sensor's DNS logs"],
                            akvorado_filter=self.akv(f"DstAddr = {r['host']} AND SrcPort = 53")))
        try:
            for x in dnsctx.anomalies(self.ch, self.site["id"], ws, we, rc):
                out.append(dict(rule="dns_anomaly", severity="medium", confidence="low", asset=x["client"], subject=x["subject"],
                                title=x["title"], window=(ws, we), evidence=[x["evidence"]], query=("dns_events", {}),
                                baseline=x["baseline"], alternatives=x["alternatives"],
                                next_steps=["Review the names on the server page (DNS tab)", "Check the host's processes"],
                                akvorado_filter=""))
        except Exception:
            pass   # no DNS source connected yet
        return out

    def rule_health(self, now):
        out = []
        if (get_setting(self.conn, "health", {}) or {}).get("enabled", True) and os.environ.get("NETMON_DETECTOR", "1") == "1":
            return out   # netmon.health owns exporter/syslog silence and disk checks (with recovery and hold-down)
        rc = self.cfg["rules"]["exporter_silence"]
        if rc["enabled"]:
            s = self.site
            r = self.q("SELECT toUInt32(max(TimeReceived)) AS last FROM flows WHERE ExporterName = {exporter:String} "
                       "AND TimeReceived > now() - INTERVAL 1 DAY", {})
            last = r[0]["last"] if r else 0
            if not last or now - last > rc["minutes"] * 60:
                out.append(self._health("exporter_silence", s["exporter"],
                                        f"No flows from {s['exporter']} ({s['name']}) since "
                                        f"{fmt_ts(last) if last else '>24h'}",
                                        [f"NetFlow export stopped or reconfigured on the {s['vendor']} firewall",
                                         "Collector/Kafka/ClickHouse problem on the monitor VM",
                                         "Network path, VPN tunnel or host firewall ACL change"]))
        rc = self.cfg["rules"].get("syslog_silence", {"enabled": False})
        if rc["enabled"] and self.site.get("syslog_source"):
            r = self.ch.query("SELECT toUInt32(max(m)) AS last FROM (SELECT max(received) AS m FROM netmon.fw_events WHERE site = {site:String} "
                              "UNION ALL SELECT max(received) FROM netmon.sys_events WHERE site = {site:String} "
                              "UNION ALL SELECT max(received) FROM netmon.ids_events WHERE site = {site:String})", {"site": self.site["id"]})
            last = r[0]["last"] if r else 0
            if last and now - last > rc["minutes"] * 60:  # never-connected sites are shown in Settings, not alerted
                out.append(self._health("syslog_silence", "monitor", f"No firewall/IDS log lines from {self.site['name']} since {fmt_ts(last)}",
                                        ["Remote syslog disabled or changed on the firewall", "rsyslog stopped on the monitor VM",
                                         "Host firewall (ufw) change"]))
        rc = self.cfg["rules"]["disk_usage"]
        if rc["enabled"] and self.site is self.cfg.sites[0]:
            st = os.statvfs(DATA_DIR)
            pct = 100 * (1 - st.f_bavail / st.f_blocks)
            if pct >= rc["percent"]:
                out.append(self._health("disk_usage", "monitor", f"Disk {pct:.0f}% used on monitor VM",
                                        ["Retention too long for ingest rate", "Logs or images accumulating"]))
        return out

    def _health(self, rule, asset, title, alternatives):
        now = time.time()
        return dict(rule=rule, severity="high", confidence="high", asset=asset, subject=rule, title=title,
                    window=(now - 300, now), evidence=[], query=("", {}), baseline="Health check",
                    alternatives=alternatives,
                    next_steps=["cd /opt/netmon/akvorado && sudo docker compose ps", "See /opt/netmon/README.md"],
                    akvorado_filter="")

    # ---- direction -----------------------------------------------------
    def _dir(self, initiator, responder) -> str:
        a, b = self._ours(initiator), self._ours(responder)
        return "internal" if a and b else "outbound" if a else "inbound" if b else "transit"

    def _fw_states(self, ws, we, where, params):
        """Firewall pass-log lines matching `where`. pf logs only the packet that creates a
        state, so each line is one connection and its src is the side that opened it."""
        sql = f"""SELECT iface, count() AS n, uniqExact(dst) AS dsts FROM netmon.fw_events
                  WHERE ts >= toDateTime({{ws:UInt32}}) AND ts < toDateTime({{we:UInt32}})
                    AND action = 'pass' AND dir = 'out' AND site = {{site:String}} AND ({where}) GROUP BY iface"""
        return {r["iface"]: r for r in self.ch.query(sql, {"ws": int(ws), "we": int(we), "site": self.site["id"], **params})}

    def _fw_log_start(self):
        cache = self.__dict__.setdefault("_fw_since", {})
        if self.site["id"] not in cache:
            r = self.ch.query("SELECT toUInt32(min(ts)) AS t FROM netmon.fw_events WHERE site = {site:String}", {"site": self.site["id"]})
            cache[self.site["id"]] = (r[0]["t"] if r else 0) or None
        return cache[self.site["id"]]

    def _by_states(self, f, ws, we, out_where, in_where, params, guess, what):
        """Decide direction from who opened the connections: WAN-out states were opened from
        inside, LAN-out states from the peer (the firewall forwarded a new inbound connection)."""
        wan, lan = self.site["wan_if"], self.site["lan_if"]
        o = self._fw_states(ws, we, f"iface = {{wan:String}} AND {out_where}", {**params, "wan": wan}).get(wan)
        i = self._fw_states(ws, we, f"iface = {{lan:String}} AND {in_where}", {**params, "lan": lan}).get(lan)
        no, ni = (o or {}).get("n", 0), (i or {}).get("n", 0)
        if no and not ni:
            return "outbound", True, f"Firewall state log: {no} connection(s) {what} were opened from inside (WAN egress, {wan})."
        if ni and not no:
            return "inbound", True, f"Firewall state log: {ni} connection(s) {what} were opened from outside and forwarded in ({lan})."
        if no and ni:
            return "both", True, f"Firewall state log: {no} opened from inside, {ni} opened from outside ({what})."
        since = self._fw_log_start()
        why = (f"firewall log only starts {fmt_ts(since)}" if since and since > ws else
               "firewall logged no new connection for it (long-lived connection, or the matching rule does not log)")
        return guess, False, f"Not verified — {why}. Direction inferred from ports, which can be wrong."

    def verify_direction(self, f) -> dict:
        """Who opened the connection(s) behind a finding, with the evidence used."""
        rule, ev = f["rule"], (f["evidence"] or [{}])[0]
        ws, we = f["window"]
        ws -= 3600  # a connection may have been opened before the flows that were analysed
        we += 120
        nat = self.site.get("outbound_nat_ips") or self.cfg.get("outbound_nat_ips", [])
        res = None
        if rule == "ids_alert":
            s, d = ev.get("s"), ev.get("d")
            ini, resp = ev.get("initiator"), ev.get("responder")
            if not ini and s and d:  # alert stored before the initiator was recorded
                r = self.ch.query("SELECT any(JSONExtractString(raw,'flow','src_ip')) AS i, any(JSONExtractString(raw,'flow','dest_ip')) AS r "
                                  "FROM netmon.ids_events WHERE sig_id = {sid:UInt32} AND src = toIPv6({s:String}) AND dst = toIPv6({d:String}) "
                                  "AND site = {site:String}",
                                  {"sid": int(f["subject"].split("|")[0]), "s": s, "d": d, "site": self.site["id"]})
                ini, resp = (r[0]["i"], r[0]["r"]) if r else ("", "")
            if ini and resp:
                note = "" if ini == s else f" The matched packet was the reply ({s} → {d})."
                res = (self._dir(ini, resp), True, f"Suricata flow record: {ini} opened the connection to {resp}.{note}")
            elif ev.get("pkt_dir") in ("to_server", "to_client"):
                ini, resp = (s, d) if ev["pkt_dir"] == "to_server" else (d, s)
                res = (self._dir(ini, resp), True, f"Suricata packet direction ({ev['pkt_dir']}): {ini} is the client.")
        elif rule == "fw_blocked_scan":
            res = ("inbound", True, f"Firewall log: blocked arriving on the WAN interface ({self.site['wan_if']}).")
        elif rule == "fw_blocked_outbound":
            dsts = ev.get("sample_dsts") or []
            internal = dsts and all(self._ours(x) for x in dsts)
            res = ("internal" if internal else "outbound", True,
                   f"Firewall log: blocked as it entered from the LAN ({self.site['lan_if']}), sent by {ev.get('s')}.")
        elif rule == "outbound_volume":
            res = ("outbound", True, f"Flow records on WAN egress ({self.site['wan_if']}): these bytes left the network. "
                                     "Who opened the connections is not determined.")
        elif rule == "fanout":
            src = ev.get("src") or f["asset"]
            o = self._fw_states(ws, we, "iface = {wan:String} AND src = toIPv6({src:String})",
                                {"wan": self.site["wan_if"], "src": src}).get(self.site["wan_if"])
            if o and o["dsts"] >= max(1, min(ev.get("dsts") or 1, self.cfg["rules"]["fanout"]["min_peers"]) // 2):
                res = ("outbound", True, f"Firewall state log: {src} opened {o['n']} connection(s) to {o['dsts']} destination(s).")
            else:
                since = self._fw_log_start()
                why = (f"firewall log only starts {fmt_ts(since)}" if since and since > ws else
                       f"firewall logged few new outbound connections from {src} ({(o or {}).get('dsts', 0)} destinations) — "
                       "these flows may be replies to inbound connections")
                res = ("outbound", False, f"Not verified — {why}.")
        elif rule in ("beaconing", "new_dest_country", "new_dest_asn", "unexpected_inbound"):
            local = f["asset"]
            if rule == "beaconing":
                peers, ports = [ev.get("peer")], [ev.get("peer_port")]
            elif rule == "unexpected_inbound":
                peers, ports = ev.get("sample_peers") or [], []
            else:
                peers, ports = ev.get("peers") or [], ev.get("ports") or []
            peers = [p for p in peers if p]
            if peers:
                srcs = [local] + nat + [x.public_ip for x in self.cfg.exposures if x.ip == local] + self.cfg.binat_ext(local)
                p = {"peers": peers, "srcs": srcs, "local": local, "ports": [int(x) for x in ports if x is not None]}
                pe = "has(arrayMap(x -> toIPv6(x), {peers:Array(String)}), COL)"
                if rule == "unexpected_inbound":
                    lp = int(f["subject"].split("/")[1])
                    p["lp"] = lp
                    res = self._by_states(f, ws, we,
                                          pe.replace("COL", "dst") + " AND has(arrayMap(x -> toIPv6(x), {srcs:Array(String)}), src) AND sport = {lp:UInt16}",
                                          pe.replace("COL", "src") + " AND dst = toIPv6({local:String}) AND dport = {lp:UInt16}",
                                          p, "inbound", f"between {local}:{lp} and the peers")
                else:
                    portf = " AND has({ports:Array(UInt16)}, dport)" if p["ports"] else ""
                    res = self._by_states(f, ws, we,
                                          pe.replace("COL", "dst") + " AND has(arrayMap(x -> toIPv6(x), {srcs:Array(String)}), src)" + portf,
                                          pe.replace("COL", "src") + " AND dst = toIPv6({local:String})",
                                          p, "outbound", f"between {local} and {', '.join(peers[:3])}")
        if not res:
            return {"direction": None, "direction_verified": 0, "direction_basis": None}
        return {"direction": res[0], "direction_verified": int(res[1]), "direction_basis": res[2]}

    # ---- runner --------------------------------------------------------
    def run_once(self, now=None):
        now = now or time.time()
        apply_overrides(self.cfg, self.conn)
        findings, errors, per_site = [], [], {}
        for site in self.cfg.sites:
            self.site = site
            f, err, days = self.run_site(now)
            findings += f
            errors += [f"{site['id']}: {x}" for x in err]
            per_site[site["id"]] = round(days, 2)
        self.site = self.cfg.sites[0]
        if errors:
            findings.append(self._health("detector_error", "monitor", "Detector errors: " + "; ".join(errors)[:300],
                                         ["ClickHouse unavailable or schema changed after upgrade"]))
        new = sum(self.record(f, now) for f in findings)
        set_state(self.conn, "detector", {"last_run": now, "learning_days": per_site.get(self.cfg.sites[0]["id"], 0),
                                          "sites": per_site, "findings": len(findings), "new": new, "errors": errors})
        return findings

    def run_site(self, now):
        """All rules for self.site. Returns (findings, errors, learning_days)."""
        findings, errors = [], []
        try:
            days = self.learning()
        except Exception as e:  # ClickHouse down: report and stop this cycle
            days, errors = 0, [f"learning: {e}"]
        if not errors:
            for name, fn in [("new_dest_country", lambda: self.rule_new_dest(now, days, "country")),
                             ("new_dest_asn", lambda: self.rule_new_dest(now, days, "asn")),
                             ("unexpected_inbound", lambda: self.rule_unexpected_inbound(now, days)),
                             ("outbound_volume", lambda: self.rule_outbound_volume(now, days)),
                             ("fanout", lambda: self.rule_fanout(now, days)),
                             ("beaconing", lambda: self.rule_beaconing(now, days)),
                             ("ids", lambda: self.rule_ids(now)),
                             ("firewall", lambda: self.rule_fw_blocks(now)),
                             ("dns", lambda: self.rule_dns(now)),
                             ("health", lambda: self.rule_health(now))]:
                try:
                    findings += fn()
                except Exception as e:
                    errors.append(f"{name}: {e}")
        self.__dict__.pop("_fw_since", None)
        kept = []
        for f in findings:
            try:
                f.update(self.verify_direction(f))
            except Exception as e:
                f.update(direction=None, direction_verified=0, direction_basis=f"direction check failed: {e}")
            # firewall shows the peer did not open it: reply traffic of an outbound connection, not exposure
            if f["rule"] == "unexpected_inbound" and f.get("direction") == "outbound" and f.get("direction_verified"):
                continue
            if f["rule"] != "fanout" and self.expected_only(f):
                continue
            kept.append(dict(f, site=self.site["id"]))
        return kept, errors, days

    def record(self, f, now) -> int:
        """Insert or merge a finding. Returns 1 if a new alert was created."""
        excs = [dict(r) for r in self.conn.execute("SELECT * FROM exceptions WHERE enabled=1")]
        for e in excs:
            if exception_matches(e, f["rule"], f["asset"], f["subject"], now):
                return 0
        exp = expected_devices(self.conn, now)
        if exp and f["rule"] not in ("source_health", "detector_error") and \
                (expected_match(exp, f["asset"]) or expected_match(exp, str(f["subject"]).split("|")[-1].split(":")[0])):
            return 0   # an expected device (or its known peer): legitimate by operator decision
        site = f.get("site") or self.cfg.sites[0]["id"]
        key = f"{site}|{f['rule']}|{f['asset']}|{f['subject']}"
        cooldown = self.cfg["detector"]["cooldown_minutes"] * 60
        row = self.conn.execute("SELECT id, last_seen, status FROM alerts WHERE key=? AND status IN ('open','acked') "
                                "ORDER BY id DESC LIMIT 1", (key,)).fetchone()
        if row and now - row["last_seen"] < cooldown:
            self.conn.execute("UPDATE alerts SET last_seen=?, window_end=?, count=count+1, evidence=?, title=?, "
                              "direction=?, direction_verified=?, direction_basis=? WHERE id=?",
                              (now, f["window"][1], json.dumps(f["evidence"], default=str), f["title"],
                               f.get("direction"), f.get("direction_verified", 0), f.get("direction_basis"), row["id"]))
            self.conn.commit()
            return 0
        sql, params = f["query"]
        cur = self.conn.execute(
            "INSERT INTO alerts(key,rule,severity,confidence,asset,subject,title,first_seen,last_seen,window_start,"
            "window_end,evidence,query,baseline,alternatives,next_steps,akvorado_filter,direction,direction_verified,direction_basis,site) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (key, f["rule"], f["severity"], f["confidence"], f["asset"], f["subject"], f["title"], now, now,
             f["window"][0], f["window"][1], json.dumps(f["evidence"], default=str),
             json.dumps({"sql": sql.strip(), "params": params}, default=str), f["baseline"],
             json.dumps(f["alternatives"]), json.dumps(f["next_steps"]), f["akvorado_filter"],
             f.get("direction"), f.get("direction_verified", 0), f.get("direction_basis"), site))
        self.conn.commit()
        audit(self.conn, "detector", "alert_created", {"id": cur.lastrowid, "key": key, "severity": f["severity"]})
        if self.notifier:
            self.notifier.alert(cur.lastrowid)
        return 1
