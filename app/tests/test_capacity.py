"""Capacity planning: measurement rules, models, storage forecast, suggestions, firewall discovery (synthetic data only)."""
import json
import math
import random

import pytest

from netmon import capacity as C
from netmon import fwres

T0 = 1_700_000_000 // 60 * 60


# ---------------------------------------------------------------- measurement rules
def test_summary_excludes_gaps_and_time_before_collection():
    vals = {T0 + 60 * i: 10.0 for i in range(120, 240)}          # collection starts 2 h into the window
    vals.update({T0 + 60 * i: 10.0 for i in range(300, 360)})    # 60-minute outage (240..299) = telemetry gap
    vals[T0 + 60 * 361] = 40.0                                   # one quiet minute (360) then a busy minute
    s = C.summarize(vals, T0, T0 + 60 * 400)
    assert s["label"] == "MEASURED"
    assert s["before_collection_s"] == 120 * 60
    assert len(s["missing"]) == 2                                 # the outage and the trailing 38 empty minutes
    assert s["missing"][0] == (T0 + 60 * 240, T0 + 60 * 300)
    assert s["samples"] == 120 + 60 + 2                           # the short quiet minute counts as zero load
    assert s["avg"] == pytest.approx((180 * 10 + 0 + 40) / 182)
    assert s["peak"] == 40.0 and s["peak_interval"] == "1-minute" and s["peak_at"] == T0 + 60 * 361
    assert s["confidence"] == "low"                               # ~3 h of data


def test_summary_unknown_without_data_never_zero():
    s = C.summarize({}, T0, T0 + 3600)
    assert s["label"] == "UNKNOWN" and "avg" not in s


def test_confidence_rule():
    assert C.confidence(2, 1.0)[0] == "low"
    assert C.confidence(30, 1.0)[0] == "medium"
    assert C.confidence(24 * 30, 1.0)[0] == "high"
    lvl, why = C.confidence(24 * 30, 0.5)
    assert lvl == "medium" and "missing" in why


def test_p95_and_peak_are_distinct_from_instantaneous_values():
    vals = {T0 + 60 * i: float(i % 100) for i in range(1000)}
    s = C.summarize(vals, T0, T0 + 60 * 1000)
    assert s["p95"] == 94.0 and s["peak"] == 99.0


# ---------------------------------------------------------------- models
def _rows(n, a=0.05, b=0.0002, c=0.0005, noise=0.005, seed=1):
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        f, e = rng.uniform(100, 2000), rng.uniform(10, 300)
        out.append((f, e, a + b * f + c * e + rng.gauss(0, noise)))
    for i in range(0, n, 25):                                   # spikes from unrelated activity
        out[i] = (out[i][0], out[i][1], out[i][2] + 0.5)
    return out


def test_robust_fit_recovers_costs_despite_outliers():
    m = C.fit_cpu(_rows(400))
    assert m["valid"], m
    assert m["per_flow"] == pytest.approx(0.0002, rel=0.1)
    assert m["per_event"] == pytest.approx(0.0005, rel=0.2)


def test_model_invalid_when_cost_not_measurable():
    rows = [(250 + random.Random(i).uniform(-5, 5), 50.0, 0.1 + random.Random(i + 9).gauss(0, 0.05)) for i in range(300)]
    m = C.fit_cpu(rows)
    assert not m["valid"] and m["reason"]
    assert not C.fit_cpu(rows[:20])["valid"]                     # too few samples


def _obs(**kw):
    s = lambda avg, p95, peak: {"label": "MEASURED", "avg": avg, "p95": p95, "peak": peak, "observed_hours": 200, "confidence": "high"}  # noqa: E731
    o = {"flows": s(500, 800, 1500), "events": s(50, 90, 200), "cpu": s(0.2, 0.3, 0.6), "mem": s(0.4, 0.5, 0.6), "io_util": s(0.02, 0.1, 0.4)}
    o.update(kw)
    return o


def test_capacity_unknown_without_defensible_model():
    cap = C.server_capacity(_obs(), {"valid": False, "reason": "no variation"}, {}, 0.3)
    assert cap["flows_capacity"]["label"] == "UNKNOWN" and cap["flows_capacity"]["value"] is None
    assert "benchmark" in cap["flows_capacity"]["note"]


def test_capacity_estimate_has_range_and_flags_extrapolation():
    m = C.fit_cpu(_rows(400))
    cap = C.server_capacity(_obs(), m, {}, 0.3)
    fc = cap["flows_capacity"]
    assert fc["label"] == "ESTIMATED" and fc["range"][0] < fc["value"] < fc["range"][1]
    assert fc["value"] == pytest.approx((0.7 - m["intercept"] - m["per_event"] * 90) / m["per_flow"])
    assert "extrapolated" not in fc["note"] or fc["extrapolation"] > 3
    assert cap["bottleneck"]["resource"] in ("cpu", "disk_io")


def test_benchmark_wins_over_model():
    cap = C.server_capacity(_obs(), {"valid": False, "reason": "x"}, {}, 0.3, benchmark={"sustained_flows_per_s": 12345, "id": "b1"})
    assert cap["flows_capacity"]["label"] == "BENCHMARKED" and cap["flows_capacity"]["value"] == 12345


# ---------------------------------------------------------------- storage
def _tab(group, bytes_, per_day, ttl, age, table="t"):
    return {"db": "default", "table": table, "group": group, "rows": 1, "bytes": bytes_, "bytes_per_row": 10.0, "largest_part": 0,
            "ttl_days": ttl, "age_days": age, "bytes_per_day": per_day}


def test_disk_forecast_grows_until_ttl_then_flat():
    tabs = [_tab("Raw flows", 10e9, 1e9, 30, 10)]                 # 20 more days of growth, then flat at 30 GB
    fc = C.disk_forecast(tabs, fs_total=100e9, fs_used=20e9, reserve=0.15)
    assert fc["days_until_limit"] is None
    assert fc["steady_state_bytes"] == pytest.approx(10e9 + 30e9)   # other files 10 GB + 30 GB at TTL
    small = C.disk_forecast(tabs, fs_total=40e9, fs_used=20e9, reserve=0.15)   # limit 34 GB: reached after 14 days
    assert small["days_until_limit"] == pytest.approx(14, abs=0.6)


def test_retention_override_and_scale_change_projection():
    tabs = [_tab("Raw flows", 5e9, 1e9, 30, 5)]
    _, _, ss30 = C.project_storage(tabs)
    _, _, ss90 = C.project_storage(tabs, {"Raw flows": 90})
    assert ss90 == pytest.approx(3 * ss30)
    _, _, ss2 = C.project_storage(tabs, scale=2.0)
    assert ss2 == pytest.approx(2 * ss30)


def test_disk_multiplier():
    tabs = [_tab("Raw flows", 0, 1e9, 10, 10)]
    fc = C.disk_forecast(tabs, 100e9, 10e9, reserve=0.0)
    assert C.disk_multiplier(fc) == pytest.approx((100e9 - 10e9) / 10e9)


# ---------------------------------------------------------------- new installations
def test_suggestions_need_no_rates_and_are_ranges():
    s = C.suggest({"devices": 2, "link_mbps": 1000, "activity": "typical", "detail": "balanced", "network": "small_office",
                   "features": ["flows", "syslog", "dns"]})
    for k in ("flows", "flows_peak", "events", "dns"):
        assert s[k]["label"] == "SUGGESTED" and s[k]["low"] < s[k]["high"]
    assert s["flows"]["high"] / s["flows"]["low"] >= 10            # speed alone never gives an exact rate
    assert any("not measurements" in a for a in s["assumptions"])
    off = C.suggest({"devices": 2, "link_mbps": 1000, "features": ["syslog"]})
    assert off["flows"]["high"] == 0


def test_local_calibration_narrows_and_is_reported():
    a = {"devices": 1, "link_mbps": 1000, "activity": "typical", "features": ["flows"]}
    g, cal = C.suggest(a), C.suggest(a, {"flows_per_mbps": 30.0})
    assert cal["calibrated"] and not g["calibrated"]
    assert cal["flows"]["high"] / cal["flows"]["low"] < g["flows"]["high"] / g["flows"]["low"]


def test_detailed_logging_adds_pass_rule_events():
    a = {"devices": 1, "link_mbps": 1000, "activity": "typical", "features": ["flows", "syslog"]}
    assert C.suggest({**a, "detail": "detailed"})["events"]["high"] > C.suggest({**a, "detail": "balanced"})["events"]["high"]


def test_storage_plan():
    s = C.suggest({"devices": 1, "link_mbps": 100, "activity": "light", "features": ["flows", "syslog"]})
    p = C.storage_plan(s, 30)
    assert 0 < p["low"]["total"] < p["high"]["total"]
    assert p["low"]["raw_flows"] == pytest.approx(s["flows"]["low"] * 86400 * C.ASSUME["bytes_per_row"]["flows"][0] * 30)


# ---------------------------------------------------------------- firewall discovery
def fake_snmp(tables, scalars, fail=None):
    def get(host, cred, oids):
        if fail:
            raise fwres.SnmpError(fwres.classify(fail))
        out = []
        for o in oids.values():
            if o not in scalars:
                raise fwres.SnmpError(fwres.classify("No Such Object available on this agent at this OID"))
            out.append(scalars[o])
        return out

    def walk(host, cred, oid, max_rows=256):
        if fail:
            raise fwres.SnmpError(fwres.classify(fail))
        return dict(list(tables.get(oid, {}).items())[:max_rows])
    return {"get": get, "walk": walk}


DEV = {"id": "fw-a", "name": "fw-a", "snmp": {"host": "192.0.2.1", "version": "v2c", "community_file": "/x"}}
OPN = fake_snmp({fwres.HR_PROC_LOAD: {str(196608 + i): "4" for i in range(8)},
                 fwres.HR_DEV_DESCR: {str(196608 + i): "Example CPU @ 2.0GHz" for i in range(8)},
                 fwres.HR_STORAGE["type"]: {"1": "1.3.6.1.2.1.25.2.1.2", "31": "1.3.6.1.2.1.25.2.1.4"},
                 fwres.HR_STORAGE["descr"]: {"1": "Physical memory", "31": "/"}, fwres.HR_STORAGE["units"]: {"1": "4096", "31": "4096"},
                 fwres.HR_STORAGE["size"]: {"1": "2000000", "31": "5000000"}, fwres.HR_STORAGE["used"]: {"1": "500000", "31": "1000000"},
                 fwres.IF_NAME: {"1": "igb0", "2": "igb1", "3": "lo0"}, fwres.IF_SPEED: {"1": "1000", "2": "10000", "3": "0"},
                 fwres.IF_OPER: {"1": "1", "2": "1", "3": "1"}},
                {fwres.SYS["descr"]: "FreeBSD fw.example 14.1 OPNsense", fwres.SYS["object_id"]: ".1.3.6.1.4.1.8072.3.2.8",
                 fwres.SYS["uptime"]: "1:2:3:4.00", fwres.HR_MEM: "8192000", fwres.UCD["cpu_idle"]: "93",
                 fwres.UCD["mem_total_kb"]: "8192000", fwres.UCD["mem_avail_kb"]: "6144000"})


def test_discovery_standard_mibs_with_missing_entity_mib(monkeypatch):
    monkeypatch.setattr(fwres, "cred_of", lambda sn: "community")
    f, steps = fwres.discover(DEV, OPN)
    assert f["cpu_cores"]["value"] == 8 and f["cpu_model"]["value"] == "Example CPU @ 2.0GHz"
    assert f["ram_bytes"]["value"] == 8192000 * 1024
    assert f["cpu_pct"]["value"] == 7.0 and "UCD" in f["cpu_pct"]["source"]
    assert f["interfaces"]["value"] == 3 and f["if_speed_mbps"]["value"] == 10000
    assert f["storage_bytes"]["value"] == 5000000 * 4096
    assert "model" not in f                                        # ENTITY-MIB not answered: unknown, not invented
    st = {w: (ok, d) for w, ok, d in steps}
    assert st["Model (ENTITY-MIB)"][0] is False
    assert st["SNMP security"][0] and "clear text" in st["SNMP security"][1]
    assert fwres.manufacturer_from(f) == "OPNsense"


def test_discovery_vendor_mib_fortigate(monkeypatch):
    monkeypatch.setattr(fwres, "cred_of", lambda sn: {"version": "v3"})
    oids = fwres.VENDOR["12356"][1]
    snmp = fake_snmp({}, {fwres.SYS["descr"]: "FortiGate-60F v7.4", fwres.SYS["object_id"]: ".1.3.6.1.4.1.12356.101.1.1",
                          fwres.SYS["uptime"]: "1", oids["cpu_pct"]: "12", oids["mem_pct"]: "40", oids["mem_capacity_kb"]: "2000000",
                          oids["sessions"]: "1234"})
    f, steps = fwres.discover({**DEV, "snmp": {**DEV["snmp"], "version": "v3"}}, snmp)
    assert f["cpu_pct"]["value"] == 12 and "not verified" in f["cpu_pct"]["source"]
    assert f["sessions"]["value"] == 1234 and f["ram_bytes"]["value"] == 2000000 * 1024
    assert not any(w == "SNMP security" for w, _, _ in steps)       # v3: no clear-text warning


@pytest.mark.parametrize("err,kind", [("Timeout: No Response from 192.0.2.1", "timeout"), ("Authentication failure (incorrect password, community or key)", "authentication"),
                                      ("authorizationError (access denied to that object)", "permission")])
def test_discovery_failures_are_explained(monkeypatch, err, kind):
    monkeypatch.setattr(fwres, "cred_of", lambda sn: "community")
    f, steps = fwres.discover(DEV, fake_snmp({}, {}, fail=err))
    assert f == {}
    assert steps[-1][1] is False and steps[-1][2].startswith(kind)


def test_no_snmp_configured():
    f, steps = fwres.discover({"id": "x", "name": "x"})
    assert f == {} and "manually" in steps[0][2]


def test_manual_values_survive_discovery(conn, monkeypatch):
    C.init(conn)
    monkeypatch.setattr(fwres, "cred_of", lambda sn: "community")
    fwres.save_manual(conn, "fw-a", {"cpu_cores": 4, "model": "Lab box"})
    f, steps = fwres.discover(DEV, OPN)
    fwres.save_discovered(conn, "fw-a", f, steps)
    hw, meta = fwres.hardware(conn, "fw-a")
    assert hw["cpu_cores"]["label"] == "MANUAL" and hw["cpu_cores"]["value"] == 4 and hw["cpu_cores"]["auto"]["value"] == 8
    assert hw["ram_bytes"]["label"] == "MEASURED"
    assert meta["_discovery"]["steps"]
    fwres.save_manual(conn, "fw-a", {"cpu_cores": None})             # clearing the manual value falls back to discovery
    assert fwres.hardware(conn, "fw-a")[0]["cpu_cores"]["label"] == "MEASURED"


class FakeCH:
    def query(self, sql, params=None):
        return []


def test_device_capacity_with_partial_data(conn):
    C.init(conn)
    d = {"id": "fw-b", "name": "fw-b", "exporter": "fw-b", "flows": ["netflow_v9"]}
    st = fwres.device_capacity(conn, FakeCH(), d)
    assert st["cpu"]["label"] == "UNKNOWN" and st["flows"]["label"] == "UNKNOWN"
    assert st["cpu_model"]["valid"] is False
    assert all(p["label"] == "UNKNOWN" for p in st["profiles"])
    for i in range(100):
        fwres.record_sample(conn, "fw-b", 20 + (i % 10), 40, ts=1e9 + 60 * i)
    conn.commit()
    st = fwres.device_capacity(conn, FakeCH(), d, window_s=1e10)
    assert st["cpu"]["label"] == "MEASURED" and st["cpu"]["p95"] == 29
    assert st["cpu_trend"]["label"] == "UNKNOWN"                    # under 2 days of samples


def test_export_bandwidth_measured_vs_estimated():
    m = fwres.export_bandwidth(100, 50.0)
    assert m["label"] == "MEASURED" and m["low"] == m["high"] == 100 * 50 * 8
    e = fwres.export_bandwidth(100, None, "netflow_v5")
    assert e["label"] == "ESTIMATED" and e["low"] == pytest.approx(100 * 48.8 * 8)
    assert fwres.export_bandwidth(100, None, "sflow")["label"] == "UNKNOWN"


def test_impacts_never_claim_cpu_without_evidence():
    rows = fwres.feature_impacts({"flows": {"avg": 200}, "events": {"avg": 20}, "export_flow_bw": {"label": "ESTIMATED"}}, None)
    assert all(r["cpu_pct"] is None for r in rows)
    assert all(r["cpu_label"] in ("UNKNOWN", "ESTIMATED") for r in rows)


def test_theil_sen_and_trend():
    pts = [(i * 86400, 100 + 10 * i) for i in range(10)]
    assert C.theil_sen(pts) * 86400 == pytest.approx(10)
    series = {T0 + 60 * i: 100.0 + (i // 1440) * 10 for i in range(1440 * 5)}
    tr = C.daily_trend(series)
    assert tr["pct"] > 0 and tr["days"] >= 4


def test_wire_size_from_counter_deltas(monkeypatch):
    import httpx

    class R:
        def __init__(self, t):
            self.text = t
    seq = iter([
        R('akvorado_inlet_flow_input_udp_bytes_total{exporter="192.0.2.1",listener=":2055",worker="1"} 1000000\n'
          'akvorado_inlet_flow_input_udp_packets_total{exporter="192.0.2.1",listener=":2055",worker="1"} 1000\n'),
        R('akvorado_outlet_core_received_flows_total{exporter="192.0.2.1"} 20000\n'),
        R('akvorado_inlet_flow_input_udp_bytes_total{exporter="192.0.2.1",listener=":2055",worker="1"} 2400000\n'
          'akvorado_inlet_flow_input_udp_packets_total{exporter="192.0.2.1",listener=":2055",worker="1"} 2000\n'),
        R('akvorado_outlet_core_received_flows_total{exporter="192.0.2.1"} 48000\n')])
    monkeypatch.setattr(httpx, "get", lambda url, timeout=5: next(seq))
    cur, wire = C.scrape_export({}, None)
    assert wire == {}
    _, wire = C.scrape_export({}, cur)
    assert wire["192.0.2.1"]["bytes_per_record"] == pytest.approx(1400000 / 28000)
    assert wire["192.0.2.1"]["records_per_packet"] == pytest.approx(28)


def test_inventory_reads_proc_and_labels_virtual_disks(monkeypatch):
    inv = C.server_inventory(None, {"disk_type": "NVMe SSD (Ceph)"})
    assert inv["logical_cpus"]["label"] == "MEASURED" and inv["logical_cpus"]["value"] >= 1
    assert inv["ram_total"]["value"] > 0
    assert inv["disk_type"]["label"] == "MANUAL" and "detected" in inv["disk_type"]
    d = C.disk_type({"disks": [{"name": "sda", "model": "QEMU HARDDISK", "rota": True, "size": 10}]})
    assert d["value"].startswith("virtual disk") and "not visible" in d["note"]
    assert C.disk_type({"disks": [{"name": "nvme0n1", "model": "Example NVMe", "rota": False, "size": 10}]})["value"].startswith("SSD")


def test_json_safe_and_no_nan():
    from netmon.capacity_views import json_safe
    assert json.dumps(json_safe({"a": float("nan"), "b": [math.inf, 1.0]})) == '{"a": null, "b": [null, 1.0]}'


# ---------------------------------------------------------------- web (ClickHouse unreachable in tests: everything degrades to UNKNOWN)
def test_capacity_pages_and_apis():
    from tests.test_web import ADMINPW, VIEWPW, client, sid
    from netmon import web
    a = client("admin", ADMINPW)
    for p in ("/netmon/settings/capacity", "/netmon/settings/resources", "/netmon/settings/capacity/report",
              "/netmon/settings/devices/site-a/hardware"):
        r = a.get(p)
        assert r.status_code == 200, (p, r.text[:300])
    ov = a.get("/netmon/api/capacity/overview?window=24h").json()
    assert ov["capacity"]["flows_capacity"]["label"] in ("UNKNOWN", "BENCHMARKED")
    assert a.get("/netmon/api/capacity/overview?window=bogus").status_code == 400
    assert a.get("/netmon/api/capacity/series?range=1h").status_code == 200
    assert a.get("/netmon/api/capacity/device/site-a").json()["hardware"] is not None
    assert a.get("/netmon/api/capacity/device/nope").status_code == 404
    tok = web.csrf_token(sid(a))
    r = a.post("/netmon/api/capacity/calc", json={"mode": "new", "answers": {"devices": 1, "link_mbps": 500, "features": ["flows"]}},
               headers={"x-csrf": tok})
    assert r.status_code == 200, r.text[:300]
    assert a.post("/netmon/api/capacity/calc", json={"mode": "new"}, headers={"x-csrf": "bad"}).status_code == 403
    r = a.post("/netmon/settings/devices/site-a/hardware/manual", data={"csrf": tok, "cpu_cores": "6"}, follow_redirects=False)
    assert r.status_code == 303
    hw = a.get("/netmon/api/capacity/device/site-a").json()["hardware"]
    assert hw["cpu_cores"]["label"] == "MANUAL" and hw["cpu_cores"]["value"] == 6
    r = a.post("/netmon/settings/devices/site-a/hardware/manual", data={"csrf": tok, "cpu_cores": "lots"}, follow_redirects=False)
    assert "not%20a%20number" in r.headers["location"]
    v = client("viewer1", VIEWPW)
    vt = web.csrf_token(sid(v))
    assert v.post("/netmon/settings/devices/site-a/hardware/manual", data={"csrf": vt, "cpu_cores": "1"}).status_code == 403
    assert v.post("/netmon/settings/capacity/server", data={"csrf": vt}).status_code == 403
    assert v.post("/netmon/api/capacity/plan", json={}, headers={"x-csrf": vt}).status_code == 403


def test_storage_plan_with_measured_bytes_per_row():
    s = C.suggest({"devices": 1, "link_mbps": 100, "activity": "light", "features": ["flows", "syslog", "dns"]})
    p = C.storage_plan(s, 30, {"flows": (20.0, 20.0), "events": (15.0, 15.0)})
    assert p["low"]["raw_flows"] == pytest.approx(s["flows"]["low"] * 86400 * 20.0 * 30)
    assert p["low"]["dns"] == pytest.approx(s["dns"]["low"] * 86400 * C.ASSUME["bytes_per_row"]["dns"][0] * 30)


# ---------------------------------------------------------------- hardware grade
def test_headroom_score_scale():
    assert [C.headroom_score(k) for k in (0.5, 1, 2, 4, 10)] == [0.0, 0.0, 50.0, 75.0, 90.0]
    assert C.headroom_score(None) is None


def test_grade_is_weakest_resource_with_caps():
    obs = _obs()                                                    # cpu P95 0.3, mem P95 0.5
    cap = {"bottleneck": {"limits": {"disk_io": {"multiplier": 8.0}, "disk_space": {"multiplier": 15.0}}}}
    g = C.hardware_grade(obs, cap)
    assert g["label"] == "ESTIMATED" and g["limited_by"] == "memory"          # 0.85/0.5 = 1.7x -> 41
    assert g["value"] == round(100 * (1 - 0.5 / 0.85)) and g["band"] == "tight: plan an upgrade"
    assert g["components"]["cpu"]["multiplier"] == pytest.approx(0.7 / 0.3)  # no model: utilization headroom
    hdd = C.hardware_grade(_obs(mem={"p95": 0.1}), cap, {"disk_type": {"value": "HDD (rotational)"}})
    assert hdd["value"] <= 60 and hdd["caps"]
    full = C.hardware_grade(_obs(mem={"p95": 0.1}), cap, None, {"days_until_limit": 12})
    assert full["value"] <= 30


def test_grade_unknown_without_measurements():
    g = C.hardware_grade({"cpu": {"label": "UNKNOWN"}, "mem": {"label": "UNKNOWN"}}, {})
    assert g["label"] == "UNKNOWN" and g["value"] is None


def test_grade_band_matches_displayed_value():
    cap = {"bottleneck": {"limits": {"disk_io": {"multiplier": 8.0}}}}
    g = C.hardware_grade(_obs(cpu={"p95": 0.1}, mem={"p95": 0.85 / 1.99}), cap)   # memory scores 49.7 -> shown 50
    assert g["value"] == 50 and g["band"] == "comfortable"


# ---------------------------------------------------------------- hardware change
def test_find_change_detects_vm_resize():
    gb = 2**30
    rows = [(T0 + 300 * i, 16, 15.6 * gb) for i in range(500)] + [(T0 + 300 * i, 48, 31.3 * gb) for i in range(502, 520)]
    hw = C.find_change(rows)
    assert hw["before"] == {"vcpus": 16, "ram_bytes": 15.6 * gb} and hw["after"]["vcpus"] == 48
    assert hw["at"] == T0 + 300 * 503          # end of the first bucket on the new hardware: it may hold mixed samples


def test_find_change_ignores_small_ram_jitter_and_no_change():
    gb = 2**30
    assert C.find_change([(T0 + 300 * i, 16, (15.6 + 0.1 * (i % 2)) * gb) for i in range(100)]) is None
    assert C.find_change([(T0, 16, 15.6 * gb)]) is None


def test_grade_reports_hardware_change():
    hw = {"at": T0, "before": {"vcpus": 16, "ram_bytes": 1}, "after": {"vcpus": 48, "ram_bytes": 2}, "note": "hardware changed"}
    g = C.hardware_grade({**_obs(cpu={"p95": 0.1}, mem={"p95": 0.2}), "hardware_change": hw}, {})
    assert "hardware changed" in g["caps"]


def test_projection_scales_previous_load_to_new_hardware():
    before = {"label": "MEASURED", "avg": 0.27, "p95": 0.36, "peak": 0.9, "observed_hours": 50, "confidence": "medium"}
    p = C.projected(before, 16 / 48, "vCPU")
    assert p["label"] == "ESTIMATED" and p["projected"] and p["confidence"] == "low"
    assert abs(p["p95"] - 0.12) < 1e-9 and abs(p["peak"] - 0.3) < 1e-9
    g = C.hardware_grade(_obs(cpu=p, mem=C.projected({"p95": 0.5, "confidence": "high"}, 0.5, "RAM")), {})
    assert g["components"]["cpu"]["score"] > 80          # 0.7 / 0.12 = 5.8x -> 83
    assert C.projected({"p95": 0.9}, 2.0, "RAM")["p95"] == 1.0   # shrinking hardware is capped at 100 % in use
