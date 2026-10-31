"""Query caching for long ranges: window rounding, cache lifetime and background warm-up (fake ClickHouse)."""
import netmon.web  # noqa: F401  (netmon.views needs netmon.web loaded first)
from netmon import views, web
from netmon.dash import PRESETS, QUANTUM


class CountingCH:
    def __init__(self):
        self.n = 0

    def query(self, sql, params=None):
        self.n += 1
        return []


def test_window_end_is_rounded_per_range():
    assert set(QUANTUM) == set(PRESETS)
    for rk, step in QUANTUM.items():
        sc = web.dash.scope(site="all", range_key=rk)
        assert sc.end % step == 0 and sc.end - sc.start == PRESETS[rk]
    assert web.dash.scope(range_key="custom", start=1793448000, end=1793448123).end == 1793448123   # custom: exact


def test_window_bound_queries_live_as_long_as_the_window(monkeypatch):
    ch = CountingCH()
    monkeypatch.setattr(web.dash, "ch", ch)
    web.dash._cache.clear()
    sc = web.dash.scope(site="all", range_key="7d")
    t = [1000.0]
    monkeypatch.setattr("netmon.dash.time.time", lambda: t[0])
    sql = "SELECT count() FROM flows WHERE TimeReceived >= toDateTime({t0:UInt32}) AND TimeReceived < toDateTime({t1:UInt32})"
    web.dash.q(sc, sql)
    t[0] += 250                       # default ttl is 10 s, but the 7-day window is valid for 300 s
    web.dash.q(sc, sql)
    assert ch.n == 1
    t[0] += 60
    web.dash.q(sc, sql)
    assert ch.n == 2
    live = "SELECT countIf(TimeReceived > now() - 300) FROM flows"   # not bound to the window: short ttl kept
    web.dash.q(sc, live, ttl=5)
    t[0] += 6
    web.dash.q(sc, live, ttl=5)
    assert ch.n == 4


def test_warm_up_runs_once_per_window_step(monkeypatch):
    calls = []
    for name in ("overview", "servers", "countries", "connections"):
        monkeypatch.setattr(views, f"{name}_traffic", lambda *a, _n=name: calls.append(_n) or {})
    views._ROLL.clear()
    last = {}
    assert views.warm_once("7d", last) is True
    assert set(calls) == {"overview", "servers", "countries", "connections"}
    n = len(calls)
    assert views.warm_once("7d", last) is False and len(calls) == n      # same window: nothing recomputed


def test_rolling_window_serves_previous_step_with_its_own_scope(monkeypatch):
    import time
    from types import SimpleNamespace
    views._ROLL.clear()
    computed = []

    def fn(sc):
        computed.append(sc.end)
        time.sleep(0.2)
        return {"end": sc.end}
    sites = web.cfg.sites
    mk = lambda end, rk="24h": SimpleNamespace(sites=sites, range_key=rk, cc="", host="", asn=0, port=0, rip="",  # noqa: E731
                                               start=end - 86400, end=end, ip_level=False)
    monkeypatch.setattr(views, "scope_json", lambda sc: {"end": sc.end})
    v, scope = views.rolling(mk(1000 * 120), "t", fn)
    assert v == {"end": 120000} and scope == {"end": 120000}
    t = time.time()
    v, scope = views.rolling(mk(1001 * 120), "t", fn)            # next step: previous result, immediately
    assert time.time() - t < 0.1 and v == {"end": 120000} and scope == {"end": 120000}   # labels match the numbers
    end = time.time() + 3
    while time.time() < end and views._ROLL_BUSY:
        time.sleep(0.02)
    assert views.rolling(mk(1001 * 120), "t", fn)[0] == {"end": 120120}   # refreshed once in the background
    assert computed.count(120120) == 1
    assert views.rolling(mk(1005 * 120), "t", fn)[0] == {"end": 120600}   # more than two steps old: computed, not served
    c = mk(5000, rk="custom")
    assert views.rolling(c, "t", fn)[0] == {"end": 5000} and views.rolling(c, "t", fn)[0] == {"end": 5000}
    assert computed.count(5000) == 2                                         # custom windows: never cached here


def test_cached_results_are_not_modified_by_requests(monkeypatch):
    views._ROLL.clear()
    shared = {"rows": [{"remote": "198.51.100.7", "rdns": None}], "total": 1}
    monkeypatch.setattr(web.dash.rdns, "wait", lambda ips, timeout=0: {"198.51.100.7": "host.example.net"})
    out = views.fresh_rdns(shared)
    assert out["rows"][0]["rdns"] == "host.example.net" and shared["rows"][0]["rdns"] is None


def test_slow_reverse_dns_does_not_hold_list_pages(monkeypatch):
    import time
    from netmon import rdns

    def slow(name, qtype, server, timeout=4.0):
        time.sleep(1.5)
        return [("host.example.net.", 3600)]
    monkeypatch.setattr(rdns, "query", slow)
    r = rdns.RDNS(web.cfg)
    monkeypatch.setattr(r, "server", lambda: "192.0.2.53")
    ips = [f"198.51.100.{i}" for i in range(1, 41)]
    t0 = time.time()
    got = r.wait(ips, timeout=rdns.LIST_WAIT)
    assert time.time() - t0 < rdns.LIST_WAIT + 0.3            # the page is not held for the lookups
    assert all(v is None for v in got.values())                  # unknown yet (UI shows nothing), not "no rDNS"
    t0 = time.time()
    while time.time() - t0 < 10 and r.pending:
        time.sleep(0.05)
    assert time.time() - t0 < 6 and r.get(ips[0]) == "host.example.net"   # 40 slow lookups drain on parallel workers


def test_block_stats_rolling_window_never_waits_and_history_is_exact():
    import time
    from netmon.geoblocks import Blocks

    class CH:
        def __init__(self):
            self.n = 0

        def query(self, sql, params=None):
            self.n += 1
            return [{"n": 0}] if "count() AS n" in sql else []
    ch = CH()
    b = Blocks(web.cfg, ch, lambda s: {}, lambda s: object())
    sites = web.cfg.sites
    t1 = int(time.time()) // 120 * 120
    t0 = t1 - 86400
    assert b.stats(sites, t0, t1)["window"] == [t0, t1]              # first: computed
    n = ch.n
    v = b.stats(sites, t0 + 120, t1 + 120)                            # window rolled: previous result, no wait
    assert v["window"] == [t0, t1]
    end = time.time() + 5
    while time.time() < end and b._inflight:
        time.sleep(0.02)
    assert ch.n > n and b.stats(sites, t0 + 120, t1 + 120)["window"] == [t0 + 120, t1 + 120]   # refreshed in background
    old = (t0 - 3 * 86400, t1 - 3 * 86400)
    assert b.stats(sites, *old)["window"] == list(old)                 # historical window: exact, never a stale stand-in


def test_block_stats_custom_windows_do_not_grow_memory():
    import time
    from netmon.geoblocks import Blocks

    class CH:
        def query(self, sql, params=None):
            return [{"n": 0}] if "count() AS n" in sql else []
    b = Blocks(web.cfg, CH(), lambda s: {}, lambda s: object())
    old = int(time.time()) - 30 * 86400
    for i in range(200):                       # many different historical/custom windows
        b.stats(web.cfg.sites, old - 3600 - i * 60, old)
    assert len(b._latest) == 0 and len(b._cache) <= 51
    now = int(time.time()) // 60 * 60
    for i in range(40):                        # many rolling windows of different lengths
        b.stats(web.cfg.sites, now - 3600 - i * 60, now)
    assert len(b._latest) <= 21
