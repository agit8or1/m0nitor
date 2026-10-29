"""Parser tests with synthetic lines in the formats OPNsense 26.7.7 emits (no production data)."""
from netmon.logingest import parse_line

site = lambda ip: "site-a" if ip == "10.40.0.1" else ip  # noqa: E731


def test_filterlog_rfc5424_udp_pass():
    line = ('1793290000 10.40.0.1 <134>1 2026-10-29T12:21:53-04:00 fw.example filterlog 21562 - [meta sequenceId="1"] '
            '70,,,62718b3b909245529bfa6c5cc4fa06ad,ix0,match,pass,out,4,0x0,,64,0,0,DF,17,udp,80,203.0.113.9,198.51.100.33,54931,53,60')
    t, r = parse_line(line, site)
    assert t == "fw_events" and r["site"] == "site-a" and r["action"] == "pass" and r["dir"] == "out"
    assert r["src"] == "::ffff:203.0.113.9" and r["dport"] == 53 and r["proto"] == "udp" and r["length"] == 80
    assert abs(r["ts"] - 1793290913) < 86400  # 12:21:53-04:00 converted to UTC epoch


def test_filterlog_tcp_block_rfc3164():
    line = ('1793290000 10.40.0.1 <134>Oct 29 12:21:53 fw filterlog[123]: 5,,,02f4bab031b57d1e30553ce08e0ec131,ix0,match,block,in,4,'
            '0x0,,242,54321,0,none,6,tcp,40,198.51.100.7,203.0.113.10,51515,3389,0,S,123,,1024,,')
    t, r = parse_line(line, site)
    assert t == "fw_events" and r["action"] == "block" and r["dport"] == 3389 and r["tcpflags"] == "S"
    assert r["ts"] == 1793290000  # RFC3164 has no year/zone -> receipt time


def test_filterlog_ipv6():
    line = ('1793290000 10.40.0.1 <134>1 2026-10-29T16:00:00Z fw filterlog 1 - - 5,,,abc,ix0,match,block,in,6,0x00,0x00000,64,'
            'tcp,6,20,2001:db8::1,2001:db8::2,443,51000,0,S,1,,64800,,')
    t, r = parse_line(line, site)
    assert t == "fw_events" and r["src"] == "2001:db8::1" and r["sport"] == 443


def test_suricata_eve_and_classic():
    eve = ('1793290000 10.40.0.1 <33>1 2026-10-29T16:00:00Z fw suricata 9 - - {"timestamp":"2026-10-29T16:00:00.123456+0000",'
           '"flow_id":123,"in_iface":"ix0","event_type":"alert","src_ip":"198.51.100.7","src_port":4444,"dest_ip":"203.0.113.10",'
           '"dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2010935,"rev":3,'
           '"signature":"ET SCAN <script>alert(1)</script>","category":"Attempted Information Leak","severity":2}}')
    t, r = parse_line(eve, site)
    assert t == "ids_events" and r["sig_id"] == 2010935 and r["severity"] == 2 and r["dst"] == "::ffff:203.0.113.10"
    classic = ('1793290000 10.40.0.1 <33>Oct 29 12:00:00 fw suricata[9]: [1:2010935:3] ET SCAN Suspicious inbound '
               '[Classification: Attempted Information Leak] [Priority: 2] {TCP} 198.51.100.7:4444 -> 203.0.113.10:80')
    t, r = parse_line(classic, site)
    assert t == "ids_events" and r["sig_id"] == 2010935 and r["sport"] == 4444


def test_other_and_garbage():
    t, r = parse_line("1793290000 10.40.0.1 <30>1 2026-10-29T16:00:00Z fw dpinger 1 - - WAN_GW 1.2.3.4: Alarm latency 300ms", site)
    assert t == "sys_events" and r["kind"] == "gateway"
    assert parse_line("garbage", site)[0] is None
    assert parse_line("1793290000 10.40.0.1 not syslog", site) == (None, "unparsed header")


def test_suricata_classic_dropped_when_eve_present():
    from netmon.logingest import Ingest
    ing = Ingest.__new__(Ingest)
    ing.eve_seen = {}
    eve = ('1793290000 10.40.0.1 <33>1 2026-10-29T16:00:00Z fw suricata 9 - - {"timestamp":"2026-10-29T16:00:00Z","flow_id":7,'
           '"event_type":"alert","src_ip":"198.51.100.7","src_port":80,"dest_ip":"203.0.113.10","dest_port":5000,"proto":"TCP",'
           '"alert":{"action":"allowed","gid":1,"signature_id":2100498,"rev":7,"signature":"GPL","category":"x","severity":2}}')
    classic = ('1793290000 10.40.0.1 <33>Oct 29 12:00:00 fw suricata[9]: [1:2100498:7] GPL [Classification: x] [Priority: 2] '
               '{TCP} 198.51.100.7:80 -> 203.0.113.10:5000')
    other = classic.replace(" fw suricata", " fw2 suricata")
    rows = [parse_line(x, site)[1] for x in (classic, eve, other)]
    stats = {"unparsed": {}}
    kept = ing.dedupe_ids(rows, stats)
    assert [r["sensor"] for r in kept] == ["fw", "fw2"] and kept[0]["flow_id"] == 7
    assert stats["unparsed"]["suricata classic (EVE preferred)"] == 1
