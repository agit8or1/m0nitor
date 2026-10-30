"""City-level GeoIP for map placement (synthetic locations; no real database)."""
import os

from netmon import geocity


class FakeGeo:
    def __init__(self, m):
        self.m = m

    def loc(self, ip):
        return self.m.get(ip)


FL = {"lat": 30.0, "lon": -81.0, "city": "Jacksonville", "region": "Florida", "cc": "US"}
FL2 = {"lat": 26.0, "lon": -80.0, "city": "Miami", "region": "Florida", "cc": "US"}
GA = {"lat": 33.7, "lon": -84.4, "city": "Atlanta", "region": "Georgia", "cc": "US"}
DE = {"lat": 50.1, "lon": 8.7, "city": "Frankfurt", "region": "Hesse", "cc": "DE"}


def row(ip, b, cc="US"):
    return {"ip": ip, "cc": cc, "in_b": b, "out_b": 0, "flows": 1}


def test_regions_weight_by_bytes_and_trust_the_flow_country():
    geo = FakeGeo({"45.83.64.1": FL, "45.83.64.2": FL2, "45.83.64.3": GA, "45.83.64.4": DE})
    regs = geocity.regions([row("45.83.64.1", 300), row("45.83.64.2", 100), row("45.83.64.3", 50),
                            row("45.83.64.4", 999),          # flow says US, city db says DE: not placed
                            row("45.83.64.5", 999)], geo)    # no location: not placed
    assert [r["region"] for r in regs] == ["Florida", "Georgia"]
    fl = regs[0]
    assert fl["in_b"] == 400 and fl["peers"] == 2 and fl["cities"] == ["Jacksonville", "Miami"]
    assert fl["ll"] == [29.0, -80.75]   # byte-weighted: (30*300 + 26*100) / 400


def test_locate_drops_locations_in_another_country():
    rows = geocity.locate([row("45.83.64.1", 1), row("45.83.64.4", 1)], FakeGeo({"45.83.64.1": FL, "45.83.64.4": DE}))
    assert rows[0]["loc"] == FL and rows[1]["loc"] is None


def test_refresh_keeps_trying_politely_and_skips_a_fresh_file(conn, tmp_path):
    path, calls = str(tmp_path / "geo" / "city.mmdb"), []

    def boom(url, dest):
        calls.append(url)
        raise OSError("offline")
    st = geocity.refresh(conn, now=1_790_000_000, fetch=boom, path=path)
    assert not st["ok"] and "offline" in st["error"] and len(calls) == 2   # this month, then last month
    assert not os.path.exists(path) and not os.path.exists(path + ".part")
    geocity.refresh(conn, now=1_790_000_000 + 60, fetch=boom, path=path)
    assert len(calls) == 2   # no retry storm within RETRY_SECONDS
    open(path, "wb").close()
    geocity.refresh(conn, now=os.path.getmtime(path) + 86400, fetch=boom, path=path)
    assert len(calls) == 2   # fresh file: nothing to do
