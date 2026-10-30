from netmon import threatradar as tr
from netmon.core import get_state, set_state
from netmon.detect import Detector

# same structure as the ExploitHound Threat Radar page; ids from the reserved-looking 2099 range (synthetic)
PAGE = """<section id="confirmed"><table>
<tr class="radar-row" id="cve-2099-0001" data-band="critical" data-epss="0.91" data-text="x" data-product="examplesoft web server|examplesoft proxy" data-cvss="9.8">
<td data-label="CVE"><a>CVE-2099-0001</a></td><td data-label="What it is"><span class="radar-desc">Example &amp; RCE</span></td>
<td data-label="CVSS">9.8</td><td data-label="EPSS">91%</td><td data-label="Added to KEV">29 Oct 2026</td></tr></table></section>
<section id="predicted"><table>
<tr class="radar-row" id="cve-2099-0002" data-band="high" data-epss="0.40" data-text="x" data-product="nextcloud server" data-cvss="7.5">
<td data-label="CVE">CVE-2099-0002</td><td data-label="What it is">Nextcloud thing</td><td data-label="Published">28 Oct 2026</td></tr></table></section>
<section id="disclosed"><table>
<tr class="radar-row" id="new-cve-2099-0001" data-band="critical" data-epss="-1" data-text="x" data-product="examplesoft web server" data-cvss="9.8">
<td data-label="CVE">CVE-2099-0001</td><td data-label="What it is">dup</td><td data-label="Published">27 Oct 2026</td></tr>
<tr class="radar-row" id="new-cve-2099-0003" data-band="none" data-epss="-1" data-text="x" data-product="nextcloudish" data-cvss="-1">
<td data-label="CVE">CVE-2099-0003</td><td data-label="What it is">new</td><td data-label="Published">29 Oct 2026</td></tr></table></section>
<section id="scoring"><tr class="radar-row" id="cve-2099-0009" data-band="x"></tr></section>"""


def load(conn, monkeypatch):
    monkeypatch.setattr(tr, "fetch", lambda url: PAGE)
    return tr.refresh(conn, force=True)


def test_parse_keeps_strongest_section_and_fields():
    r = tr.parse(PAGE)
    assert set(r) == {"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"}   # the scoring panel is not a list
    a = r["CVE-2099-0001"]
    assert a["section"] == "confirmed" and a["cvss"] == 9.8 and a["epss"] == 0.91 and a["desc"] == "Example & RCE"
    assert a["date"] == "29 Oct 2026" and a["products"] == ["examplesoft web server", "examplesoft proxy"]
    assert r["CVE-2099-0003"]["epss"] is None and r["CVE-2099-0003"]["cvss"] is None


def test_lookup_and_software_matching(conn, monkeypatch):
    st = load(conn, monkeypatch)
    assert st["counts"] == {"confirmed": 1, "predicted": 1, "disclosed": 1} and not st["error"]
    assert [h["cve"] for h in tr.lookup(conn, ["cve_2099_0002", "CVE-2099-0001", "CVE-2099-7777"])] == ["CVE-2099-0001", "CVE-2099-0002"]
    assert [h["cve"] for h in tr.software_matches(conn, ["Nextcloud"])] == ["CVE-2099-0002"]   # whole words: not "nextcloudish"
    assert [h["cve"] for h in tr.software_matches(conn, ["examplesoft proxy"])] == ["CVE-2099-0001"]
    assert tr.software_matches(conn, ["ab"]) == []


def test_failed_fetch_keeps_last_good_copy(conn, monkeypatch):
    load(conn, monkeypatch)
    def boom(url):
        raise OSError("network down")
    monkeypatch.setattr(tr, "fetch", boom)
    st = tr.refresh(conn, force=True)
    assert "network down" in st["error"] and len(st["rows"]) == 3
    monkeypatch.setattr(tr, "fetch", lambda url: "<html>layout changed</html>")
    assert "no CVE rows" in tr.refresh(conn, force=True)["error"] and len(tr.data(conn)["rows"]) == 3


def test_refresh_respects_interval_and_switch(conn, monkeypatch):
    load(conn, monkeypatch)
    calls = []
    monkeypatch.setattr(tr, "fetch", lambda url: calls.append(url) or PAGE)
    tr.refresh(conn)
    assert calls == []                                   # fetched moments ago
    st, _ = get_state(conn, tr.STATE, None)
    set_state(conn, tr.STATE, dict(st, attempt=st["attempt"] - 7 * 3600))
    tr.refresh(conn)
    assert len(calls) == 1
    tr.save_settings(conn, {"enabled": False}, "t")
    tr.refresh(conn, force=True)
    assert len(calls) == 1


def test_settings_require_https(conn):
    import pytest
    with pytest.raises(ValueError):
        tr.save_settings(conn, {"url": "http://example.com/"}, "t")


class IdsCH:
    def __init__(self, rows):
        self.rows = rows

    def query(self, sql, params):
        return self.rows


def ids_row(**kw):
    return {"sig_id": 2099001, "signature": "ET EXPLOIT Example", "category": "Attempted Admin", "severity": 2, "actions": ["allowed"],
            "hits": 3, "s": "198.51.100.9", "d": "10.40.0.50", "dports": [443], "proto": "TCP", "last": 1, "initiator": "198.51.100.9",
            "responder": "10.40.0.50", "pkt_dir": "to_server", **kw}


def test_ids_findings_marked_and_optionally_raised(cfg, conn, monkeypatch):
    load(conn, monkeypatch)
    d = Detector(cfg, IdsCH([ids_row(cves=["CVE_2099_0001"]), ids_row(sig_id=2099002, cves=[])]), conn)
    hit, plain = d.rule_ids(1_000_000)
    assert hit["evidence"][0]["threat_radar"][0]["cve"] == "CVE-2099-0001" and "CISA KEV" in hit["baseline"]
    assert hit["severity"] == "medium" and "CVE-2099-0001" in hit["next_steps"][0]
    assert "threat_radar" not in plain["evidence"][0] and "Threat intel" not in plain["baseline"]
    tr.save_settings(conn, {"raise_known_exploited": True}, "t")
    assert d.rule_ids(1_000_000)[0]["severity"] == "high"
