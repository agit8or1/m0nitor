"""'What changed?': DST-aware periods, coverage-normalized volumes, honest wording, prioritization (synthetic data only)."""
from datetime import datetime
from zoneinfo import ZoneInfo

from netmon import changes as chg
from netmon.changes_views import summarize

NY = {"id": "site-a", "tz": "America/New_York"}


def _local(ts, tz="America/New_York"):
    return datetime.fromtimestamp(ts, ZoneInfo(tz))


def test_day_period_uses_site_midnight_and_same_wall_clock_across_dst():
    # Sunday 2026-11-01 is the US fall-back day (25 hours). Monday 10:00 local vs Sunday 00:00-10:00 local.
    now = datetime(2026, 11, 2, 10, 0, tzinfo=ZoneInfo("America/New_York")).timestamp()
    p = chg.periods("day", now, NY)
    a0, a1 = p["a"]
    (b0, b1), = p["b"]
    assert _local(a0).hour == 0 and _local(a0).day == 2 and a1 == int(now)
    assert _local(b0).day == 1 and _local(b0).hour == 0 and _local(b1).hour == 10
    assert b1 - b0 == 11 * 3600          # the DST day really had 11 hours from midnight to 10:00
    assert a1 - a0 == 10 * 3600


def test_weekday_period_keeps_local_time_on_previous_weeks():
    # spring-forward 2026-03-08: a Monday 09:00-10:00 compared with previous Mondays at the same local hours
    now = datetime(2026, 3, 16, 10, 0, tzinfo=ZoneInfo("America/New_York")).timestamp()
    p = chg.periods("weekday", now, NY, span="1h", weeks=3)
    assert len(p["b"]) == 3
    for b0, b1 in p["b"]:
        assert _local(b0).hour == 9 and _local(b1).hour == 10 and _local(b0).weekday() == 0
        assert b1 - b0 == 3600


def test_week_and_custom_periods():
    now = datetime(2026, 11, 5, 15, 30, tzinfo=ZoneInfo("UTC")).timestamp()   # Thursday
    p = chg.periods("week", now, {"tz": "UTC"})
    assert _local(p["a"][0], "UTC").weekday() == 0 and p["a"][0] - p["b"][0][0] == 7 * 86400
    assert p["b"][0][1] - p["b"][0][0] == p["a"][1] - p["a"][0]
    c = chg.periods("custom", now, None, a=(100, 200), b=(10, 50))
    assert c["a"] == (100, 200) and c["b"] == [(10, 50)]
    for bad in (((200, 100), (10, 50)), ((0, 40 * 86400), (10, 50))):
        try:
            chg.periods("custom", now, None, a=bad[0], b=bad[1])
            raise AssertionError("invalid custom period accepted")
        except ValueError:
            pass


class Fake(chg.Changes):
    """Engine with canned query results: lets us test the compose logic without ClickHouse."""
    def __init__(self, cfg, conn, cov_a=1.0, cov_b=1.0, vol_a=(), vol_b=(), asn=(), hist=30):
        super().__init__(cfg, None, conn)
        self.r = dict(cov_a=cov_a, cov_b=cov_b, vol_a=list(vol_a), vol_b=list(vol_b), asn=list(asn), hist=hist)
        self.calls = []

    def coverage(self, sites, t0, t1):
        return {s["id"]: self.r["cov_a" if t0 >= self.a0 else "cov_b"] for s in sites}

    def history_days(self, sites, before):
        return self.r["hist"]

    def volume(self, sites, t0, t1):
        return self.r["vol_a"] if t0 >= self.a0 else self.r["vol_b"]

    def novel(self, sites, a0, a1, l0, what):
        self.calls.append((what, a0 - l0))
        return self.r["asn"] if what == "asn" else []

    def answered(self, *a):
        return []

    def new_locals(self, *a):
        return []

    def config_changes(self, *a):
        return []

    def source_slots(self, *a):
        return {}


def run(cfg, conn, **kw):
    per = {"a": (1_000_000 + 86400, 1_000_000 + 2 * 86400), "b": [(1_000_000, 1_000_000 + 86400)], "label_a": "A", "label_b": "B"}
    f = Fake(cfg, conn, **kw)
    f.a0 = per["a"][0]
    return f._compute(cfg.sites, per, per["a"][1] + 10, 14), f


def test_missing_telemetry_is_not_zero_traffic(cfg, conn):
    # Same bytes per covered hour: half the coverage in A must not look like "half as much traffic".
    gb = 10 ** 9
    res, _ = run(cfg, conn, cov_a=0.5, cov_b=1.0, vol_a=[{"l": "10.40.0.8", "in_b": 2 * gb, "out_b": 0, "n": 1}],
                 vol_b=[{"l": "10.40.0.8", "in_b": 4 * gb, "out_b": 0, "n": 1}])
    kinds = [x["kind"] for x in res["items"]]
    assert "decrease" not in kinds and "download" not in kinds
    assert not res["complete"] and any("not counted as zero" in n for n in res["notes"])
    assert "telemetry" in kinds and res["items"][0]["kind"] == "telemetry"     # data gaps lead the list


def test_volume_increase_has_values_and_comparison(cfg, conn):
    res, _ = run(cfg, conn, vol_a=[{"l": "10.40.0.8", "in_b": 0, "out_b": 900 * 10 ** 6, "n": 5}],
                 vol_b=[{"l": "10.40.0.8", "in_b": 0, "out_b": 100 * 10 ** 6, "n": 5}])
    up = [x for x in res["items"] if x["kind"] == "upload"]
    assert len(up) == 1 and "9×" in up[0]["title"] and "900.0 MB" in up[0]["detail"] and "100.0 MB" in up[0]["detail"]
    assert up[0]["confidence"] == "high" and up[0]["link"].startswith("/netmon/connections?")


def test_no_traffic_at_all_is_worded_plainly(cfg, conn):
    res, _ = run(cfg, conn, vol_a=[], vol_b=[{"l": "10.40.0.8", "in_b": 0, "out_b": 2 * 10 ** 9, "n": 5}])
    d = [x for x in res["items"] if x["kind"] == "decrease"]
    assert d and "had no upload traffic" in d[0]["title"] and "−100%" not in d[0]["title"]


def test_newly_observed_wording_history_and_shared_nat(cfg, conn):
    rows = [{"l": "10.40.0.8", "v": 64500 + i, "cc": "NL", "n": 3, "b": 1000, "first": 1_000_000 + 90000} for i in range(2)]
    rows += [{"l": "203.0.113.179", "v": 64600 + i, "cc": "US", "n": 3, "b": 1000, "first": 1_000_000 + 90000} for i in range(5)]
    res, f = run(cfg, conn, asn=rows, hist=3)
    net = [x for x in res["items"] if x["kind"] == "new_network"]
    dev = next(x for x in net if x["device"]["ip"] == "10.40.0.8")
    nat = next(x for x in net if x["device"].get("shared"))
    assert "not seen in the 3 days before" in dev["detail"] and "has not used before" in dev["title"]
    assert "Devices behind the shared NAT address" in nat["title"] and nat["confidence"] == "low"
    assert nat["priority"] < dev["priority"]
    assert any("Only 3.0 days of history" in n for n in res["notes"])
    assert all(look == 3 * 86400 for _, look in f.calls)     # lookback is bounded by the history that exists
    assert all(x["confidence"] != "high" for x in net)       # less history than asked for: never high


def test_expected_device_is_demoted_and_labelled(cfg, conn):
    from netmon.core import EXPECTED_KEY, put_setting
    put_setting(conn, EXPECTED_KEY, {"10.40.0.8": {"reason": "nightly backup", "by": "t"}}, "t")
    res, _ = run(cfg, conn, vol_a=[{"l": "10.40.0.8", "in_b": 0, "out_b": 900 * 10 ** 6, "n": 5},
                                   {"l": "10.40.0.9", "in_b": 0, "out_b": 900 * 10 ** 6, "n": 5}],
                 vol_b=[{"l": "10.40.0.8", "in_b": 0, "out_b": 100 * 10 ** 6, "n": 5},
                        {"l": "10.40.0.9", "in_b": 0, "out_b": 100 * 10 ** 6, "n": 5}])
    up = [x for x in res["items"] if x["kind"] == "upload"]
    assert [x["device"]["ip"] for x in up] == ["10.40.0.9", "10.40.0.8"]
    assert "Expected device: nightly backup" in up[1]["detail"]


def test_summary_caps_each_kind():
    items = [{"kind": "new_network", "priority": 40}] * 10 + [{"kind": "config", "priority": 70}] * 2
    items.sort(key=lambda x: -x["priority"])
    top = summarize(items)
    assert sum(1 for x in top if x["kind"] == "new_network") == 3 and sum(1 for x in top if x["kind"] == "config") == 2
