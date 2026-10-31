"""NetFlow v5, NetFlow v9, IPFIX and sFlow v5 decoding and exporter health, each path with its own synthetic packets."""
import ipaddress
import struct

import pytest

from netmon.flowdiag import DecodeError, Tracker, decode

NOW = 1793448000


def v5(seq, n=2, sampling=0, secs=NOW):
    hdr = struct.pack("!HHIIIIBBH", 5, n, 1000, secs, 0, seq, 0, 1, sampling)
    rec = struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", ipaddress.ip_address("198.51.100.7").packed,
                      ipaddress.ip_address("10.40.0.5").packed, b"\0" * 4, 1, 2, 3, 180, 0, 0, 51515, 22, 0, 2, 6, 0,
                      0, 0, 0, 0, 0)
    return hdr + rec * n


def v9(seq, src=7, template=True, data=True, secs=NOW):
    sets = b""
    if template:
        fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4)]
        body = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", *f) for f in fields)
        sets += struct.pack("!HH", 0, 4 + len(body)) + body
    if data:
        rec = ipaddress.ip_address("198.51.100.7").packed + ipaddress.ip_address("10.40.0.5").packed + struct.pack("!HHBI", 51515, 22, 6, 100)
        sets += struct.pack("!HH", 256, 4 + len(rec) * 2) + rec * 2
    return struct.pack("!HHIIII", 9, 3, 1000, secs, seq, src) + sets


def ipfix(seq, dom=42, template=True, nrec=2, secs=NOW):
    sets = b""
    if template:
        fields = [(8, 4), (12, 4), (7, 2), (11, 2)]
        body = struct.pack("!HH", 300, len(fields)) + b"".join(struct.pack("!HH", *f) for f in fields)
        sets += struct.pack("!HH", 2, 4 + len(body)) + body
    rec = ipaddress.ip_address("198.51.100.7").packed + ipaddress.ip_address("10.40.0.5").packed + struct.pack("!HH", 51515, 22)
    sets += struct.pack("!HH", 300, 4 + len(rec) * nrec) + rec * nrec
    return struct.pack("!HHIII", 10, 16 + len(sets), secs, seq, dom) + sets


def sflow(seq, rate=1024, drops=0):
    sample = struct.pack("!IIIIIIII", 1, 1, rate, 1000, drops, 1, 2, 0)   # flow_sample with 0 records
    return (struct.pack("!II4sIIII", 5, 1, ipaddress.ip_address("192.0.2.30").packed, 0, seq, 5000, 1)
            + struct.pack("!II", 1, len(sample)) + sample)


def test_netflow_v5():
    d = decode(v5(100, sampling=(1 << 14) | 100))
    assert d["protocol"] == "netflow_v5" and d["records"] == 2 and d["sampling"] == 100
    assert decode(v5(1))["sampling"] is None      # not reported: unknown, not 1:1
    t = Tracker()
    t.feed("192.0.2.1", v5(100), NOW)
    t.feed("192.0.2.1", v5(102), NOW)             # contiguous (2 flows)
    t.feed("192.0.2.1", v5(110), NOW)             # 6 flows missing
    r = t.report(NOW)[0]
    assert r["protocol"] == "netflow_v5" and any("about 6 flows lost" in i for i in r["issues"])


def test_netflow_v9_templates_and_missing_template():
    t = Tracker()
    t.feed("192.0.2.1", v9(1, template=False), NOW)       # data before any template
    t.feed("192.0.2.1", v9(2), NOW)
    t.feed("192.0.2.1", v9(3, template=False), NOW)
    r = t.report(NOW)[0]
    assert r["protocol"] == "netflow_v9" and r["domain"] == 7 and r["templates"] == [256]
    assert any("without a current template" in i for i in r["issues"]) and not any("lost" in i for i in r["issues"])
    assert any("expired" in i for i in t.report(NOW + 4000)[0]["issues"])


def test_ipfix_record_sequence_and_clock_drift():
    t = Tracker()
    t.feed("192.0.2.2", ipfix(10), NOW)                   # 2 records -> next 12
    t.feed("192.0.2.2", ipfix(12, template=False), NOW)
    t.feed("192.0.2.2", ipfix(20, template=False, secs=NOW + 600), NOW)   # 6 records lost, clock 10 min ahead
    r = t.report(NOW)[0]
    assert r["protocol"] == "ipfix" and r["domain"] == 42
    assert any("about 6 records lost" in i for i in r["issues"]) and any("clock is +600 s off" in i for i in r["issues"])


def test_sflow_sampling_change_and_drops():
    t = Tracker()
    t.feed("192.0.2.30", sflow(1), NOW)
    t.feed("192.0.2.30", sflow(2, rate=2048, drops=5), NOW)
    r = t.report(NOW)[0]
    assert r["protocol"] == "sflow" and r["agent"] == "192.0.2.30"
    assert any("sampling rate changed" in i for i in r["issues"]) and any("5 dropped samples" in i for i in r["issues"])


def test_mixed_exporters_are_tracked_separately():
    t = Tracker()
    t.feed("192.0.2.1", v9(1), NOW)
    t.feed("192.0.2.2", v9(50, src=7), NOW)                # same source id, other exporter: no false gap
    t.feed("192.0.2.1", v9(2), NOW)
    assert all(not r["issues"] for r in t.report(NOW))


@pytest.mark.parametrize("pkt", [b"", b"\x00\x05", v5(1)[:30], v9(1)[:22] + b"\x01\x00\x00\x02", ipfix(1)[:-3],
                                 b"\x00\x07" + b"\x00" * 40, sflow(1)[:30]])
def test_malformed_packets(pkt):
    with pytest.raises(DecodeError):
        decode(pkt)
    t = Tracker()
    t.feed("192.0.2.9", pkt, NOW)
    assert t.report(NOW)[0]["protocol"] == "malformed"
