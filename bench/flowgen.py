#!/usr/bin/env python3
"""Synthetic flow and firewall-log generator for benchmarks. Standard library only.

Every address is from documentation (RFC 5737 / RFC 3849) or private ranges; nothing here is captured traffic.
Send ONLY to an isolated benchmark stack: these records are indistinguishable from real ones once ingested.

  flowgen.py netflow5|netflow9|ipfix  HOST:PORT  --rate FLOWS_PER_S --seconds N
  flowgen.py syslog                   HOST:PORT  --rate LINES_PER_S --seconds N
  flowgen.py selftest                 (encodes one packet of each kind and checks the headers)

sFlow is not generated: sFlow carries sampled packet headers rather than flow records, so a flow-rate benchmark
does not map onto it. Benchmarks for sFlow exporters have to be run with a real exporter.
"""
import argparse
import ipaddress
import json
import random
import socket
import struct
import sys
import time

INTERNAL = ipaddress.ip_network("10.99.0.0/16")
EXTERNAL = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
PORTS = (53, 80, 123, 443, 443, 443, 993, 3478, 8443)


def _addr(rng, net):
    return int(net.network_address) + rng.randrange(1, net.num_addresses - 1)


def record(rng, now):
    """One synthetic flow: (src, dst, sport, dport, proto, packets, bytes, first_ms, last_ms, in_if, out_if, flags)."""
    inside, outside = _addr(rng, INTERNAL), _addr(rng, rng.choice(EXTERNAL))
    dport, sport, proto = rng.choice(PORTS), rng.randrange(1024, 65535), rng.choice((6, 6, 6, 17))
    if rng.random() < 0.5:
        src, dst, i, o = inside, outside, 2, 1
    else:
        src, dst, i, o, sport, dport = outside, inside, 1, 2, dport, sport
    pk = max(1, int(rng.expovariate(1 / 20)))
    by = pk * rng.randrange(60, 1500)
    dur = rng.randrange(0, 60000)
    return src, dst, sport, dport, proto, pk, by, now - dur, now, i, o, 0x18 if proto == 6 else 0


# ------------------------------------------------------------------------------------------------ NetFlow v5
def netflow5(recs, seq, uptime_ms, unix):
    hdr = struct.pack("!HHIIIIBBH", 5, len(recs), uptime_ms, int(unix), int((unix % 1) * 1e9), seq, 0, 0, 0)
    body = b"".join(struct.pack("!IIIHHIIIIHHBBBBHHBBH", s, d, 0, i, o, pk, by, max(0, uptime_ms - (unix_ms - f)),
                                max(0, uptime_ms - (unix_ms - la)), sp, dp, 0, fl, pr, 0, 0, 0, 24, 24, 0)
                    for s, d, sp, dp, pr, pk, by, f, la, i, o, fl in recs for unix_ms in (int(unix * 1000),))
    return hdr + body


# ------------------------------------------------------------------------------------------------ v9 / IPFIX
# (field type, length): src4, dst4, sport, dport, proto, packets, bytes, in_if, out_if, tcpflags, first, last
V9_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4), (10, 2), (14, 2), (6, 1), (22, 4), (21, 4)]
IPFIX_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 8), (1, 8), (10, 4), (14, 4), (6, 1), (152, 8), (153, 8)]
TEMPLATE_ID = 256


def _v9_record(r, uptime_ms, unix_ms):
    s, d, sp, dp, pr, pk, by, f, la, i, o, fl = r
    return struct.pack("!IIHHBIIHHBII", s, d, sp, dp, pr, pk, by, i, o, fl, max(0, uptime_ms - (unix_ms - f)), max(0, uptime_ms - (unix_ms - la)))


def _ipfix_record(r):
    s, d, sp, dp, pr, pk, by, f, la, i, o, fl = r
    return struct.pack("!IIHHBQQIIBQQ", s, d, sp, dp, pr, pk, by, i, o, fl, f, la)


def _pad4(b):
    return b + b"\0" * (-len(b) % 4)


def netflow9(recs, seq, uptime_ms, unix, with_template):
    sets, count = [], 0
    if with_template:
        t = struct.pack("!HH", TEMPLATE_ID, len(V9_FIELDS)) + b"".join(struct.pack("!HH", *f) for f in V9_FIELDS)
        sets.append(struct.pack("!HH", 0, 4 + len(t)) + t)
        count += 1
    unix_ms = int(unix * 1000)
    data = _pad4(b"".join(_v9_record(r, uptime_ms, unix_ms) for r in recs))
    sets.append(struct.pack("!HH", TEMPLATE_ID, 4 + len(data)) + data)
    count += len(recs)
    return struct.pack("!HHIIII", 9, count, uptime_ms, int(unix), seq, 1) + b"".join(sets)


def ipfix(recs, seq, unix, with_template):
    sets = []
    if with_template:
        t = struct.pack("!HH", TEMPLATE_ID, len(IPFIX_FIELDS)) + b"".join(struct.pack("!HH", *f) for f in IPFIX_FIELDS)
        sets.append(struct.pack("!HH", 2, 4 + len(t)) + t)
    data = _pad4(b"".join(_ipfix_record(r) for r in recs))
    sets.append(struct.pack("!HH", TEMPLATE_ID, 4 + len(data)) + data)
    body = b"".join(sets)
    return struct.pack("!HHIII", 10, 16 + len(body), int(unix), seq, 1) + body


# ------------------------------------------------------------------------------------------------ syslog
def filterlog_line(rng, unix):
    """OPNsense filterlog, RFC 5424, as the firewall sends it (block rules mostly, some pass)."""
    s, d, sp, dp, pr, *_ = record(rng, int(unix * 1000))
    action = "block" if rng.random() < 0.8 else "pass"
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(unix)) + "Z"
    src, dst = str(ipaddress.IPv4Address(s)), str(ipaddress.IPv4Address(d))
    if pr == 6:
        tail = f"6,tcp,60,{src},{dst},{sp},{dp},0,S,{rng.randrange(1 << 31)},,64240,,mss"
    else:
        tail = f"17,udp,76,{src},{dst},{sp},{dp},56"
    return (f"<134>1 {ts} fw.example filterlog {rng.randrange(1000, 99999)} - [meta sequenceId=\"{rng.randrange(1 << 20)}\"] "
            f"5,,,0123456789abcdef0123456789abcdef,igb0,match,{action},in,4,0x0,,64,{rng.randrange(65535)},0,DF,{tail}")


# ------------------------------------------------------------------------------------------------ sender
def send(kind, target, rate, seconds, per_packet=None, seed=1):
    """Paced sender. Returns counts actually handed to the kernel (sent), never 'delivered'."""
    host, port = target.rsplit(":", 1)
    fam = socket.AF_INET6 if ":" in host.strip("[]") else socket.AF_INET
    sk = socket.socket(fam, socket.SOCK_DGRAM)
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    addr = (host.strip("[]"), int(port))
    rng = random.Random(seed)
    per = per_packet or {"netflow5": 30, "netflow9": 28, "ipfix": 20, "syslog": 1}[kind]
    start = time.time()
    boot = start - 86400
    sent_records = sent_packets = errors = seq = 0
    next_tmpl = 0.0
    interval = per / rate
    t_next = start
    while True:
        now = time.time()
        if now - start >= seconds:
            break
        if now < t_next:
            time.sleep(min(t_next - now, 0.01))
            continue
        t_next += interval
        if t_next < now - 1:          # cannot keep up: do not burst to catch up, record the shortfall
            t_next = now
        up = int((now - boot) * 1000)
        now_ms = int(now * 1000)
        if kind == "syslog":
            pkt = filterlog_line(rng, now).encode()
        else:
            recs = [record(rng, now_ms) for _ in range(per)]
            tmpl = now >= next_tmpl
            if tmpl:
                next_tmpl = now + 10
            if kind == "netflow5":
                pkt = netflow5(recs, seq, up, now)
            elif kind == "netflow9":
                pkt = netflow9(recs, seq, up, now, tmpl)
            else:
                pkt = ipfix(recs, seq, now, tmpl)
        try:
            sk.sendto(pkt, addr)
            sent_packets += 1
            sent_records += per
            seq += 1 if kind == "netflow9" else per
        except OSError:
            errors += 1
    took = time.time() - start
    return {"kind": kind, "target_rate": rate, "seconds": round(took, 2), "packets": sent_packets, "records": sent_records,
            "achieved_rate": round(sent_records / took, 1) if took else 0, "send_errors": errors, "records_per_packet": per}


def selftest():
    rng = random.Random(7)
    now = time.time()
    recs = [record(rng, int(now * 1000)) for _ in range(3)]
    v5 = netflow5(recs, 0, 1000, now)
    assert struct.unpack("!HH", v5[:4]) == (5, 3) and len(v5) == 24 + 48 * 3
    v9 = netflow9(recs, 0, 1000, now, True)
    assert struct.unpack("!HH", v9[:4]) == (9, 4)
    ip = ipfix(recs, 0, now, True)
    assert struct.unpack("!HH", ip[:4]) == (10, len(ip))
    for r in recs:
        for a in r[:2]:
            ip4 = ipaddress.IPv4Address(a)
            assert ip4 in INTERNAL or any(ip4 in n for n in EXTERNAL)
    line = filterlog_line(rng, now)
    assert " filterlog " in line and ",match," in line
    return {"netflow5": v5.hex(), "netflow9": v9.hex(), "ipfix": ip.hex(), "syslog": line}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kind", choices=("netflow5", "netflow9", "ipfix", "syslog", "selftest"))
    ap.add_argument("target", nargs="?")
    ap.add_argument("--rate", type=float, default=1000)
    ap.add_argument("--seconds", type=float, default=30)
    ap.add_argument("--per-packet", type=int)
    a = ap.parse_args()
    if a.kind == "selftest":
        print(json.dumps(selftest()))
        return
    if not a.target:
        sys.exit("target HOST:PORT required")
    print(json.dumps(send(a.kind, a.target, a.rate, a.seconds, a.per_packet)))


if __name__ == "__main__":
    main()
