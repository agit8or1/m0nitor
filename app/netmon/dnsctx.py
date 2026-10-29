"""DNS context: who asked for what, which connections a name probably explains, and explainable DNS anomalies.

Sources (any combination; each is labelled in the UI):
  * Resolver logs (Unbound log-queries/log-replies via syslog): client, name, type, rcode. No answers.
  * Zeek dns.log: client, name, type, rcode, answers and TTLs - only for queries the sensor sees.
  * Flow metadata (always): DNS *transport* per host - which resolvers a host talks to on 53/853, and
    connections to well-known DoH endpoints on 443. No names: encrypted DNS (DoH/DoT) content is not visible
    and DoH to an arbitrary HTTPS server cannot be distinguished from ordinary HTTPS.

Correlation (DNS answer -> later connection) needs answers (Zeek). Confidence:
  high    same client asked, the answer contains the address, the connection started within the TTL, and the
          address answered only this name for this client in the window
  medium  as high, but the address answered several names (CDN / shared hosting) - all names are listed
  low     only another client's answer matches (shared resolver cache: the client may have used a cached answer)
A caching resolver means a client's query can precede its connections by up to the TTL, or not appear at all.
"""
import ipaddress
import math
from collections import Counter

DOH = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
       "94.140.14.14", "94.140.15.15", "2606:4700:4700::1111", "2001:4860:4860::8888"}
IPS = "replaceOne(IPv6NumToString({c}), '::ffff:', '')"


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def label_score(name):
    """(longest label, its entropy) - long random-looking labels are what DGA and tunnelling produce."""
    labels = [x for x in name.split(".")[:-2] if x]   # ignore the registrable part's last two labels
    if not labels:
        return 0, 0.0
    lab = max(labels, key=len)
    return len(lab), entropy(lab)


def transport(dash, sc, host=None):
    """Per-host DNS transport from the return path (resolver replies delivered to the LAN host)."""
    resolvers = [str(x) for x in dash.cfg.get("dns_resolvers", [])] or [s.get("lan_gateway", "") for s in sc.sites]
    w = f"{dash.where(sc)} AND INB AND TOLAN"
    if host:
        w += f" AND {IPS.format(c='DstAddr')} = {{h:String}}"
    rows = dash.q(sc, f"""
        SELECT {IPS.format(c='DstAddr')} AS host, {IPS.format(c='SrcAddr')} AS resolver, SrcPort AS port, Proto AS proto,
               count() AS flows, sum(Bytes * SamplingRate) AS bytes, toUInt32(max(TimeReceived)) AS last
        FROM flows WHERE {w} AND ((SrcPort IN (53, 853)) OR (SrcPort = 443 AND has({{doh:Array(String)}}, {IPS.format(c='SrcAddr')})))
        GROUP BY host, resolver, port, proto ORDER BY flows DESC LIMIT 500""", {"doh": sorted(DOH), "h": host or ""})
    for r in rows:
        r["kind"] = ("DoT (encrypted)" if r["port"] == 853 else "possible DoH (HTTPS to a public resolver; not confirmable)" if r["port"] == 443
                     else "plain DNS")
        r["bypass"] = r["port"] in (53, 853) and r["resolver"] not in resolvers
    return {"rows": rows, "resolvers": resolvers,
            "note": "From resolver replies delivered to each host (works through shared NAT). Names are not in flow records."}


def domains(ch, site_ids, t0, t1, client, limit=50):
    rows = ch.query("""
        SELECT query, qtype, count() AS n, countIf(rcode = 'NXDOMAIN') AS nx, toUInt32(max(ts)) AS last,
               groupUniqArrayArray(5)(answers) AS answers, any(source) AS source
        FROM netmon.dns_events WHERE has({sites:Array(String)}, site) AND client = toIPv6({c:String})
          AND ts >= toDateTime64({t0:UInt32}, 3) AND ts < toDateTime64({t1:UInt32}, 3)
        GROUP BY query, qtype ORDER BY n DESC LIMIT {l:UInt32}""",
                    {"sites": site_ids, "c": _v6(client), "t0": int(t0), "t1": int(t1), "l": limit})
    return rows


def _v6(ip):
    a = ipaddress.ip_address(ip)
    return str(a if a.version == 6 else ipaddress.IPv6Address("::ffff:" + str(a)))


def correlate(ch, site_ids, client, remote, t, max_ttl=86400):
    """Which DNS names probably led `client` to connect to `remote` at time t (see module doc for confidence)."""
    p = {"sites": site_ids, "ip": remote, "t0": int(t - max_ttl), "t1": int(t + 5), "c": _v6(client)}
    rows = ch.query("""
        SELECT replaceOne(IPv6NumToString(client), '::ffff:', '') AS client, query, toUInt32(ts) AS t,
               arrayElement(ttls, indexOf(answers, {ip:String})) AS ttl
        FROM netmon.dns_events WHERE has({sites:Array(String)}, site) AND has(answers, {ip:String})
          AND ts >= toDateTime64({t0:UInt32}, 3) AND ts <= toDateTime64({t1:UInt32}, 3)
        ORDER BY ts DESC LIMIT 200""", p)
    mine = [r for r in rows if r["client"] == client and r["t"] <= t <= r["t"] + max(r["ttl"], 1) + 5]
    if mine:
        names = sorted({r["query"] for r in mine})
        return {"confidence": "high" if len(names) == 1 else "medium", "names": names, "query_ts": mine[0]["t"],
                "basis": "this host's own query answered with this address, connection within the TTL" +
                         ("" if len(names) == 1 else "; the address answered several names (shared hosting/CDN)")}
    if rows:
        return {"confidence": "low", "names": sorted({r["query"] for r in rows})[:10], "query_ts": rows[0]["t"],
                "basis": "only another client's answer matches (shared resolver cache)"}
    return {"confidence": "none", "names": [], "basis": "no DNS answer with this address was observed"}


def anomalies(ch, site, t0, t1, rc):
    """Explainable DNS findings for one site and window (needs resolver logs or Zeek dns.log)."""
    out = []
    p = {"site": site, "t0": int(t0), "t1": int(t1)}
    for r in ch.query("""
        SELECT replaceOne(IPv6NumToString(client), '::ffff:', '') AS client, count() AS n, countIf(rcode = 'NXDOMAIN') AS nx,
               groupUniqArrayIf(10)(query, rcode = 'NXDOMAIN') AS sample
        FROM netmon.dns_events WHERE site = {site:String} AND ts >= toDateTime64({t0:UInt32}, 3) AND ts < toDateTime64({t1:UInt32}, 3)
          AND rcode != ''
        GROUP BY client HAVING nx >= {m:UInt32} AND nx / n >= {f:Float64}""", {**p, "m": rc["nxdomain_min"], "f": rc["nxdomain_ratio"]}):
        out.append({"kind": "nxdomain", "client": r["client"], "subject": "nxdomain",
                    "title": f"{r['client']}: {r['nx']} of {r['n']} DNS answers were NXDOMAIN",
                    "evidence": {"client": r["client"], "queries": r["n"], "nxdomain": r["nx"], "sample_names": r["sample"]},
                    "baseline": f"Thresholds: >= {rc['nxdomain_min']} NXDOMAIN and >= {int(rc['nxdomain_ratio'] * 100)}% of answers.",
                    "alternatives": ["Misconfigured search domain or stale service names", "Software probing for optional services",
                                     "Domain-generation malware (random-looking names)"]})
    for r in ch.query("""
        SELECT replaceOne(IPv6NumToString(client), '::ffff:', '') AS client, groupUniqArray(200)(query) AS names, count() AS n,
               countIf(qtype = 'TXT') AS txt
        FROM netmon.dns_events WHERE site = {site:String} AND ts >= toDateTime64({t0:UInt32}, 3) AND ts < toDateTime64({t1:UInt32}, 3)
        GROUP BY client""", p):
        odd = [q for q in r["names"] if (lambda L, H: L >= rc["label_len"] and H >= rc["label_entropy"])(*label_score(q))]
        if len(odd) >= rc["odd_names_min"]:
            out.append({"kind": "random_labels", "client": r["client"], "subject": "random_labels",
                        "title": f"{r['client']}: {len(odd)} DNS names with long random-looking labels",
                        "evidence": {"client": r["client"], "names": odd[:10], "queries": r["n"], "txt_queries": r["txt"]},
                        "baseline": f"Label >= {rc['label_len']} characters with entropy >= {rc['label_entropy']} bits/char, "
                                    f"at least {rc['odd_names_min']} names.",
                        "alternatives": ["CDN/telemetry hostnames with hashes", "Anti-virus/reputation lookups (encoded queries)",
                                         "DNS tunnelling or domain-generation malware"]})
    return out
