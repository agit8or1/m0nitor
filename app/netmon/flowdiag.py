"""Flow export diagnostics: decode NetFlow v5/v9, IPFIX and sFlow v5 packet headers and track exporter health.

Akvorado is the collector; this module never stores flows. It answers onboarding questions about one exporter:
which protocol/version it sends, observation domains, templates (and data that arrives before its template),
sampling rate (and changes), sequence gaps (= export packets or records lost on the way), exporter clock drift
and sFlow agent drops. Used by tests with synthetic packets and by the troubleshooting CLI:

  docker exec app-netmon-app-1 python -m netmon.flowdiag --listen 0.0.0.0:2056 --seconds 60
  (point the exporter at port 2056 temporarily; publish the port only for the test)
"""
import argparse
import ipaddress
import socket
import struct
import time

TEMPLATE_TIMEOUT = 1800   # templates not refreshed for 30 min are treated as expired


class DecodeError(ValueError):
    pass


def _u(fmt, b, off):
    try:
        return struct.unpack_from(fmt, b, off)
    except struct.error:
        raise DecodeError("truncated packet")


def decode(pkt):
    """Header-level decode. Returns a dict; raises DecodeError for anything malformed (never guesses)."""
    if len(pkt) < 4:
        raise DecodeError("too short")
    (ver,) = _u("!H", pkt, 0)
    if ver == 5:
        cnt, up, secs, nsecs, seq, etype, eid, samp = _u("!HIIIIBBH", pkt, 2)
        if not 1 <= cnt <= 30 or len(pkt) < 24 + 48 * cnt:
            raise DecodeError("NetFlow v5: bad record count/length")
        interval = samp & 0x3FFF   # top 2 bits: sampling mode
        return {"protocol": "netflow_v5", "export_time": secs + nsecs / 1e9, "sequence": seq, "records": cnt,
                "domain": (etype << 8) | eid, "sampling": interval or None,
                "sampling_known": bool(samp), "templates": [], "data_sets": []}
    if ver == 9:
        cnt, up, secs, seq, src = _u("!HIIII", pkt, 2)
        sets = _sets(pkt, 20, template_id=0, options_id=1, ipfix=False)
        return {"protocol": "netflow_v9", "export_time": float(secs), "sequence": seq, "records": cnt, "domain": src, **sets}
    if ver == 10:
        length, secs, seq, dom = _u("!HIII", pkt, 2)
        if length != len(pkt):
            raise DecodeError("IPFIX: length field does not match datagram")
        sets = _sets(pkt, 16, template_id=2, options_id=3, ipfix=True)
        return {"protocol": "ipfix", "export_time": float(secs), "sequence": seq, "domain": dom, **sets}
    if len(pkt) >= 28:
        (sver, atype) = _u("!II", pkt, 0)
        if sver == 5 and atype in (1, 2):
            return _sflow(pkt, atype)
    raise DecodeError(f"unknown flow protocol (first word {ver})")


def _sets(pkt, off, template_id, options_id, ipfix):
    templates, data_sets = [], []
    while off + 4 <= len(pkt):
        sid, slen = _u("!HH", pkt, off)
        if slen < 4 or off + slen > len(pkt):
            raise DecodeError("bad set length")
        body, end = off + 4, off + slen
        if sid == template_id:
            p = body
            while p + 4 <= end:
                tid, n = _u("!HH", pkt, p)
                p += 4
                fields, reclen = [], 0
                for _ in range(n):
                    ftype, flen = _u("!HH", pkt, p)
                    p += 4
                    if ipfix and ftype & 0x8000:   # enterprise-specific element
                        p += 4
                    fields.append(ftype & 0x7FFF)
                    reclen += flen if flen != 0xFFFF else 0
                templates.append({"id": tid, "fields": fields, "record_len": reclen})
                if n == 0:
                    break
        elif sid == options_id:
            templates.append({"id": _u("!H", pkt, body)[0], "fields": [], "record_len": 0, "options": True})
        elif sid >= 256:
            data_sets.append({"template": sid, "bytes": slen - 4})
        off = end
    return {"templates": templates, "data_sets": data_sets}


def _sflow(pkt, atype):
    alen = 4 if atype == 1 else 16
    agent = str(ipaddress.ip_address(pkt[8:8 + alen]))
    sub, seq, up, n = _u("!IIII", pkt, 8 + alen)
    off = 8 + alen + 16
    samples, rates, drops = 0, set(), 0
    for _ in range(n):
        fmt, slen = _u("!II", pkt, off)
        body = off + 8
        if off + 8 + slen > len(pkt):
            raise DecodeError("sFlow: bad sample length")
        enterprise, form = fmt >> 12, fmt & 0xFFF
        if enterprise == 0 and form in (1, 3):   # flow_sample / expanded flow_sample
            if form == 1:
                _sq, _src, rate, _pool, dr = _u("!IIIII", pkt, body)
            else:
                _sq, _st, _si, rate, _pool, dr = _u("!IIIIII", pkt, body)
            rates.add(rate)
            drops += dr
            samples += 1
        off = body + slen
    return {"protocol": "sflow", "export_time": None, "uptime_ms": up, "sequence": seq, "domain": sub, "agent": agent,
            "samples": samples, "sampling": min(rates) if len(rates) == 1 else (sorted(rates) or None), "agent_drops": drops,
            "templates": [], "data_sets": []}


class Tracker:
    """Health of one or more exporters from successive packets: (exporter, protocol, domain) is one stream."""

    def __init__(self):
        self.s = {}

    def feed(self, exporter, pkt, now=None):
        now = time.time() if now is None else now
        try:
            d = decode(pkt)
        except DecodeError as ex:
            st = self.s.setdefault((exporter, "malformed", 0), {"packets": 0, "errors": {}})
            st["packets"] += 1
            st["errors"][str(ex)] = st["errors"].get(str(ex), 0) + 1
            return None
        key = (exporter, d["protocol"], d["domain"])
        st = self.s.setdefault(key, {"packets": 0, "lost": 0, "templates": {}, "missing_template": 0, "sampling": set(),
                                     "sampling_changes": 0, "drift": None, "last_seq": None, "next_seq": None,
                                     "agent_drops": 0, "first": now, "last": now, "agent": d.get("agent")})
        st["packets"] += 1
        st["last"] = now
        seq = d["sequence"]
        if st["next_seq"] is not None and seq != st["next_seq"]:
            gap = (seq - st["next_seq"]) & 0xFFFFFFFF
            if gap < 1_000_000:          # forward gap = lost; otherwise a restart/reset, not loss
                st["lost"] += gap
            else:
                st["resets"] = st.get("resets", 0) + 1
        p = d["protocol"]
        if p == "netflow_v5":
            st["next_seq"] = (seq + d["records"]) & 0xFFFFFFFF      # counts flows
        elif p in ("netflow_v9", "sflow"):
            st["next_seq"] = (seq + 1) & 0xFFFFFFFF                  # counts export packets / datagrams
        else:                                                        # IPFIX counts data records; unknown until decoded
            nrec = sum(ds["bytes"] // st["templates"][ds["template"]]["record_len"]
                       for ds in d["data_sets"] if st["templates"].get(ds["template"], {}).get("record_len"))
            st["next_seq"] = (seq + nrec) & 0xFFFFFFFF if all(st["templates"].get(ds["template"]) for ds in d["data_sets"]) else None
        for t in d["templates"]:
            st["templates"][t["id"]] = {**t, "seen": now}
        for ds in d["data_sets"]:
            t = st["templates"].get(ds["template"])
            if not t or now - t["seen"] > TEMPLATE_TIMEOUT:
                st["missing_template"] += 1
        if d.get("sampling") is not None:
            rate = tuple(d["sampling"]) if isinstance(d["sampling"], list) else d["sampling"]
            if st["sampling"] and rate not in st["sampling"]:
                st["sampling_changes"] += 1
            st["sampling"].add(rate)
        if d.get("export_time"):
            st["drift"] = round(d["export_time"] - now, 1)
        st["agent_drops"] += d.get("agent_drops", 0)
        return d

    def report(self, now=None):
        now = time.time() if now is None else now
        out = []
        for (exp, proto, dom), st in sorted(self.s.items(), key=lambda kv: (kv[0][0], kv[0][1], str(kv[0][2]))):
            if proto == "malformed":
                out.append({"exporter": exp, "protocol": "malformed", "packets": st["packets"], "issues": [f"{k} ×{v}" for k, v in st["errors"].items()]})
                continue
            issues = []
            if st["lost"]:
                issues.append(f"sequence gaps: about {st['lost']:,} {'flows' if proto == 'netflow_v5' else 'records' if proto == 'ipfix' else 'packets'} lost in transit")
            if st.get("resets"):
                issues.append(f"sequence restarted {st['resets']}× (exporter restart or counter reset)")
            if st["missing_template"]:
                issues.append(f"{st['missing_template']} data sets without a current template (cannot be decoded until the template arrives)")
            exp_t = [t for t in st["templates"].values() if now - t["seen"] > TEMPLATE_TIMEOUT]
            if exp_t:
                issues.append(f"{len(exp_t)} template(s) not refreshed for 30 min (expired)")
            if st["sampling_changes"]:
                issues.append(f"sampling rate changed {st['sampling_changes']}× ({sorted(map(str, st['sampling']))}): volumes before/after differ in scale")
            if st["drift"] is not None and abs(st["drift"]) > 60:
                issues.append(f"exporter clock is {st['drift']:+.0f} s off: fix NTP on the device (flow times would be wrong)")
            if st["agent_drops"]:
                issues.append(f"sFlow agent reports {st['agent_drops']:,} dropped samples")
            out.append({"exporter": exp, "protocol": proto, "domain": dom, "packets": st["packets"], "templates": sorted(st["templates"]),
                        "sampling": sorted(map(str, st["sampling"])) or ["unknown"], "clock_drift_s": st["drift"],
                        "agent": st.get("agent"), "issues": issues})
        return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Listen for flow export packets and report exporter health (no storage).")
    ap.add_argument("--listen", default="0.0.0.0:2056")
    ap.add_argument("--seconds", type=int, default=60)
    a = ap.parse_args(argv)
    host, _, port = a.listen.rpartition(":")
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, int(port)))
    s.settimeout(1)
    tr, end = Tracker(), time.time() + a.seconds
    while time.time() < end:
        try:
            pkt, (src, *_r) = s.recvfrom(65535)
        except socket.timeout:
            continue
        tr.feed(src, pkt)
    for r in tr.report():
        print(r)
    if not tr.s:
        print("no packets received: check the exporter destination, port and any firewall on the path")


if __name__ == "__main__":
    main()
