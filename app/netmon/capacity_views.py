"""Settings -> System -> Capacity planner and Resources & capacity; Devices -> Hardware & capacity.

Pages are thin: static/capacity.js renders from the JSON APIs below. Reads need the viewer role; saving a plan needs
analyst; hardware corrections, discovery and manual device values need admin (all audited)."""
import glob
import json
import os
import threading
import time

from fastapi import HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from urllib.parse import quote

from . import capacity as C
from . import fwres
from .core import DATA_DIR, audit, get_setting, get_state, put_setting
from .web import app, cfg, check_csrf, conn, csrf_field, dash, e, need, page, user_of

C.init(conn)
BENCH_DIR = os.path.join(DATA_DIR, "benchmarks")
_busy = threading.Lock()


def tabs_html(active):
    from .admin import SETTINGS_TABS, tabs
    return tabs(SETTINGS_TABS, active)


def benchmarks():
    """Results written by the benchmark harness (bench/bench.py). Only measured runs; nothing is synthesized here."""
    out = []
    for p in sorted(glob.glob(os.path.join(BENCH_DIR, "*.json"))):
        try:
            with open(p) as f:
                b = json.load(f)
            b["id"] = os.path.basename(p)[:-5]
            out.append(b)
        except (OSError, ValueError):
            continue
    return out


def matching_benchmark(inv):
    """A benchmark counts as BENCHMARKED for this server only if it ran on the same CPU model and vCPU count."""
    model, n = (inv.get("cpu_model") or {}).get("value"), (inv.get("logical_cpus") or {}).get("value")
    best = None
    for b in benchmarks():
        r = b.get("result") or {}
        if b.get("hardware", {}).get("cpu_model") == model and b.get("hardware", {}).get("cpus") == n and r.get("sustained_flows_per_s"):
            if not best or b.get("ts", 0) > best.get("ts", 0):
                best = {**r, "id": b["id"], "cpu": model, "cpus": b["hardware"].get("bench_cpus") or n, "ts": b.get("ts")}
    return best


def overview(window="7d", t0=None, t1=None, refresh=False):
    key = f"ov:{window}:{t0}:{t1}"
    if refresh:
        C._cache.pop(key, None)

    def build():
        manual = get_setting(conn, "capacity:server_manual", {}) or {}
        inv = C.server_inventory(dash.ch, manual)
        obs = C.observe(dash.ch, cfg, conn, window, t0, t1)
        model = C.cpu_model(dash.ch, cfg, obs["window"].get("resources_t0") or obs["window"]["t0"], obs["window"]["t1"])
        try:
            tabs = C.storage(dash.ch)
        except Exception:
            tabs = []
        tot = (inv.get("clickhouse_disk_total") or {}).get("value") or (inv.get("disk_total") or {}).get("value")
        free = (inv.get("clickhouse_disk_free") or {}).get("value") or (inv.get("disk_free") or {}).get("value")
        hi = C.hostinfo() or {}
        kafka = (hi.get("kafka") or {}).get("bytes") or 0
        fc = C.disk_forecast(tabs, tot, tot - free, kafka_bytes=kafka) if tot and free is not None else None
        bench = matching_benchmark(inv)
        cap = C.server_capacity(obs, model, inv, 0.3, fc, bench)
        ratios, cal_ts = C.local_calibration(conn)
        if not ratios:
            ratios = C.calibration_ratios(obs)
        env = environment(obs, inv, cap)
        fw_fc = [x for d in env["devices"] for x in d.get("forecasts", [])]
        fcs = C.forecasts(obs, fc or {}, cap, fw_fc) + storage_findings(tabs)
        grade = C.hardware_grade(obs, cap, inv, fc)
        return {"generated": time.time(), "grade": grade, "inventory": inv, "observe": obs, "model": model, "storage": tabs,
                "disk": {k: x for k, x in (fc or {}).items() if k != "tables"} if fc else None, "capacity": cap, "forecasts": fcs,
                "calibration": {"ratios": ratios, "ts": cal_ts, "history": C.calibration_history(conn)},
                "environment": env, "benchmarks": [{k: b.get(k) for k in ("id", "ts", "hardware", "workload", "result", "versions")} for b in benchmarks()],
                "plan": get_setting(conn, "capacity:plan", {}) or {}, "assumptions": C.ASSUME,
                "wire": get_state(conn, "capacity:wire", {})[0], "line_bytes": get_state(conn, "capacity:line_bytes", None)[0]}
    return C.cached(key, 300, build)


def storage_findings(tabs):
    tot = sum(t["bytes_per_day"] or 0 for t in tabs)
    sysl = sum(t["bytes_per_day"] or 0 for t in tabs if t["group"] == "ClickHouse system logs")
    out = []
    if tot and sysl / tot > 0.3:
        big = sorted((t for t in tabs if t["group"] == "ClickHouse system logs" and t["bytes_per_day"]), key=lambda t: -t["bytes_per_day"])[:3]
        out.append({"level": "info", "label": "MEASURED",
                    "text": f"ClickHouse's own diagnostic logs are {100 * sysl / tot:.0f}% of the daily data volume "
                            f"({sysl / 1e9:.2f} of {tot / 1e9:.2f} GB/day), mostly {', '.join(t['table'] for t in big)}. "
                            "Shortening their TTL in ClickHouse's config frees disk without touching monitoring data.",
                    "basis": "system.parts sizes and rows per day, per table"})
    young = [t for t in tabs if t["ttl_days"] and t["age_days"] is not None and t["age_days"] < t["ttl_days"] and t["group"] != "ClickHouse system logs"]
    if young:
        out.append({"level": "info", "label": "ESTIMATED",
                    "text": "Not yet at full retention: " + ", ".join(f"{t['table']} ({t['age_days']:.1f} of {t['ttl_days']:.0f} days)" for t in young[:4])
                            + ". Disk use keeps growing until each reaches its TTL.", "basis": "oldest row vs table TTL"})
    return out


def environment(obs, inv, cap):
    """Every monitored device plus the central server: resources, sources, current load, headroom."""
    from . import devices as dv
    wire = get_state(conn, "capacity:wire", {})[0] or {}
    lb = get_state(conn, "capacity:line_bytes", None)[0]
    devs = []
    for d in dv.all_devices(cfg):
        try:
            st = fwres.device_capacity(conn, dash.ch, d, 7 * 86400, {k: x["bytes_per_record"] for k, x in wire.items()}, lb)
        except Exception as ex:
            devs.append({"id": d["id"], "name": d["name"], "error": str(ex)[:160]})
            continue
        hw = st["hardware"]
        srcs = sorted({(x.get("label"), (x.get("source") or "").split(" ")[0]) for x in hw.values()})
        fc = []
        if st["cpu"].get("p95") is not None and st["cpu"]["p95"] > 70:
            fc.append({"level": "warn", "label": "MEASURED",
                       "text": f"{d['name']} has limited CPU headroom at busy times (P95 {st['cpu']['p95']:.0f}%). Review export overhead before "
                               "enabling detailed logging.", "basis": "SNMP CPU samples"})
        devs.append({"id": d["id"], "name": d["name"], "primary": d["primary"], "vendor": d.get("vendor"),
                     "manufacturer": (hw.get("manufacturer") or {}).get("value") or fwres.manufacturer_from({k: x.get("auto") or {} for k, x in hw.items()}),
                     "model": (hw.get("model") or {}).get("value") or d.get("model"), "cpu_cores": (hw.get("cpu_cores") or {}).get("value"),
                     "ram_bytes": (hw.get("ram_bytes") or {}).get("value"), "sources": [list(x) for x in srcs],
                     "cpu": st["cpu"], "mem": st.get("mem"), "flows": {k: st["flows"].get(k) for k in ("avg", "p95", "peak", "label", "confidence")},
                     "events": {k: st["events"].get(k) for k in ("avg", "p95", "peak", "label", "confidence")}, "forecasts": fc,
                     "samples": st["samples"]})
    return {"server": {"cpus": (inv.get("logical_cpus") or {}).get("value"), "ram": (inv.get("ram_total") or {}).get("value"),
                       "disk": (inv.get("clickhouse_disk_total") or inv.get("disk_total") or {}).get("value"),
                       "disk_type": (inv.get("disk_type") or {}).get("value"), "cpu_p95": obs["cpu"].get("p95"), "mem_p95": obs["mem"].get("p95"),
                       "bottleneck": cap.get("bottleneck")},
            "totals": {"devices": len(devs), "flows_avg": obs["flows"].get("avg"), "flows_p95": obs["flows"].get("p95"),
                       "events_avg": obs["events"].get("avg"), "events_p95": obs["events"].get("p95")},
            "devices": devs,
            "note": "Device count is not a capacity measure: one busy firewall can export more than dozens of quiet ones. "
                    "Capacity follows records per second and retention."}


# ------------------------------------------------------------------------------------------------ calculation
def calc(body, ov):
    """Recalculate from the calculator's inputs. Never mutates measurements; returns outputs with labels."""
    mode = body.get("mode", "existing")
    inp = body.get("inputs") or {}
    ret = {k: float(x) for k, x in (body.get("retention") or {}).items() if x}
    headroom = min(0.9, max(0.0, float(body.get("headroom", 30)) / 100))
    reserve = min(0.5, max(0.0, float(body.get("reserve", 15)) / 100))
    obs, tabs, inv = ov["observe"], ov["storage"], ov["inventory"]
    tot = (inv.get("clickhouse_disk_total") or inv.get("disk_total") or {}).get("value")
    free = (inv.get("clickhouse_disk_free") or inv.get("disk_free") or {}).get("value")
    out = {"mode": mode}
    num = lambda k, d=None: float(inp[k]) if inp.get(k) not in (None, "") else d  # noqa: E731
    if mode == "new":
        sug = C.suggest(body.get("answers") or {}, ov["calibration"]["ratios"] if body.get("calibrate", True) else None)
        out["suggested"] = sug
        bpr = measured_bpr(tabs) if tabs else None
        days = float((body.get("answers") or {}).get("retention_days") or 30)
        out["storage_plan"] = C.storage_plan(sug, days, bpr)
        out["storage_basis"] = "bytes per row measured on this installation" if bpr else "assumed bytes per row (no local data)"
        out["requirements"] = requirements(sug, ov, days)
        return out
    flows_m, ev_m = obs["flows"].get("avg"), obs["events"].get("avg")
    dns_m = (obs["event_tables"].get("dns_events") or {}).get("avg")
    flows = num("flows_avg", flows_m)
    events = num("events_avg", ev_m)
    dns = num("dns_avg", dns_m)
    sc = lambda new, old: (new / old) if (new is not None and old) else 1.0  # noqa: E731
    scale = {"Raw flows": sc(flows, flows_m), "Aggregated flows": sc(flows, flows_m), "DNS events": sc(dns, dns_m),
             "Firewall, IDS and system events": sc((events or 0) - (dns or 0), (ev_m or 0) - (dns_m or 0)) if ev_m else 1.0}
    if mode == "advanced":
        bpr_f = num("bytes_per_flow")
        if bpr_f:
            for t in tabs:
                if t["group"] == "Raw flows":
                    scale["Raw flows"] *= bpr_f / t["bytes_per_row"]
        ovh = num("storage_overhead_pct", 0) / 100
        for g in scale:
            scale[g] *= 1 + ovh
    if tot and free is not None:
        fc = disk_forecast_scaled(tabs, tot, tot - free, ret, scale, reserve, ((C.hostinfo() or {}).get("kafka") or {}).get("bytes") or 0)
        out["disk"] = {k: x for k, x in fc.items() if k != "tables"}
        out["tables"] = [{k: t.get(k) for k in ("db", "table", "group", "bytes", "bytes_per_row", "bytes_per_day", "ttl_days", "retention_days",
                                                "steady_state_bytes", "age_days", "per_day_confidence", "compression")} for t in fc["tables"]]
    model = ov["model"]
    target = 1 - headroom
    if model.get("valid"):
        a, b, c = model["intercept"], model["per_flow"], model["per_event"]
        fp = num("flows_p95", obs["flows"].get("p95")) or 0
        ep = num("events_p95", obs["events"].get("p95")) or 0
        cpu = a + b * fp + c * ep
        out["cpu_at_inputs"] = {"value": cpu, "label": "ESTIMATED", "fits": cpu <= target,
                                "note": f"host CPU at the P95 rates entered, from the regression (target {100 * target:.0f}%)"}
    else:
        out["cpu_at_inputs"] = {"value": None, "label": "UNKNOWN", "note": model.get("reason")}
    out["capacity"] = C.server_capacity({**obs}, model, inv, headroom, fc if tot else None, matching_benchmark(inv))
    out["scale"] = scale
    return out


def disk_forecast_scaled(tabs, total, used, retention, scale, reserve, kafka):
    """disk_forecast with a per-group workload scale."""
    scaled = []
    for t in tabs:
        s = scale.get(t["group"], 1.0)
        scaled.append({**t, "bytes_per_day": (t["bytes_per_day"] * s) if t["bytes_per_day"] is not None else None})
    return C.disk_forecast(scaled, total, used, retention, 1.0, reserve, kafka)


def measured_bpr(tabs):
    m = {}
    for t in tabs:
        if t["group"] == "Raw flows":
            m["flows"] = (t["bytes_per_row"], t["bytes_per_row"])
        elif t["table"] == "fw_events":
            m["events"] = (t["bytes_per_row"], t["bytes_per_row"])
        elif t["table"] == "dns_events":
            m["dns"] = (t["bytes_per_row"], t["bytes_per_row"])
    return m or None


def requirements(sug, ov, days):
    """CPU and RAM for a planned installation: only from a benchmark or a measured local model; otherwise unknown."""
    model, obs = ov["model"], ov["observe"]
    out = {}
    bench = [b for b in ov.get("benchmarks") or [] if (b.get("result") or {}).get("sustained_flows_per_s")]
    if bench:
        best = max(bench, key=lambda b: b["result"]["sustained_flows_per_s"])
        r, hw = best["result"], best.get("hardware") or {}
        per_cpu = r["sustained_flows_per_s"] / max(1, hw.get("bench_cpus") or hw.get("cpus") or 1)
        out["cpu"] = {"label": "ESTIMATED", "value": [sug["flows_peak"]["low"] / per_cpu, sug["flows_peak"]["high"] / per_cpu],
                      "note": f"vCPUs for the suggested peak flow rate, scaling benchmark {best['id']} ({r['sustained_flows_per_s']:,.0f} records/s on "
                              f"{hw.get('bench_cpus') or hw.get('cpus')} vCPU of {hw.get('cpu_model')}) linearly; real scaling is not perfectly linear"}
    elif model.get("valid"):
        out["cpu"] = {"label": "ESTIMATED", "note": "see the CPU estimate under Existing installation (local model)"}
    else:
        out["cpu"] = {"label": "UNKNOWN", "value": None,
                      "note": "no pipeline benchmark result yet and no measurable local CPU model; run bench/bench.py pipeline to measure this hardware"}
    rss = obs.get("ch_rss", {}).get("p95")
    out["ram"] = {"label": "MEASURED" if rss else "UNKNOWN", "value": rss,
                  "note": (f"reference: ClickHouse used {rss / 1e9:.1f} GB (P95) here at {obs['flows'].get('avg') or 0:,.0f} flow records/s on average; "
                           "the whole stack needs more (Kafka, Akvorado, the app). Memory follows queries and merges more than ingest rate.")
                  if rss else "no ClickHouse memory measurements"}
    return out


# ------------------------------------------------------------------------------------------------ pages
def shell(req, active, title, inner, scripts=("d3.min.js", "capacity.js")):
    return page(req, title, f"{tabs_html(active)}{inner}", "/netmon/settings", scripts=scripts, scoped=False)


@app.get("/netmon/settings/capacity", response_class=HTMLResponse)
def capacity_page(req: Request, msg: str = ""):
    u, r = user_of(req)
    inner = f"""{f"<div class='banner'>{e(msg)}</div>" if msg else ''}
<div id="cap" data-view="planner" data-role="{e(r)}" data-csrf-form='{e(csrf_field(req))}'>
<section class="card capstart"><div class="card-h"><h2>Capacity planner</h2><span class="muted small">What this server and your firewalls can handle, from your own measurements</span></div>
<div class="capbtns">
<button class="primary big" data-mode="existing">Use my current setup<small>loads this server's hardware and the measured load: averages, peaks, storage growth</small></button>
<button class="big" data-mode="new">Plan a new installation<small>a few plain questions; no flow or event rates needed</small></button></div>
<p class="center"><button class="link" data-mode="advanced">Advanced / manual settings</button> · <a href="/netmon/settings/capacity/report" target="_blank" rel="noopener">Printable report</a>
 · <a href="/netmon/settings/resources">Live resources &amp; capacity</a></p>
<p class="muted small legend-labels"><span class="lab MEASURED">MEASURED</span> from this installation · <span class="lab ESTIMATED">ESTIMATED</span> calculated with a documented model ·
<span class="lab SUGGESTED">SUGGESTED</span> planning assumption · <span class="lab BENCHMARKED">BENCHMARKED</span> measured by the benchmark harness ·
<span class="lab MANUAL">MANUAL</span> entered by you · <span class="lab UNKNOWN">UNKNOWN</span> not available (never shown as zero)</p></section>
<div id="capbody"><p class="muted">Loading measurements…</p></div></div>"""
    return shell(req, "/netmon/settings/capacity", "Settings · Capacity planner", inner)


@app.get("/netmon/settings/resources", response_class=HTMLResponse)
def resources_page(req: Request):
    need(req, "viewer")
    inner = """<div id="cap" data-view="resources">
<section class="card"><div class="card-h"><h2>Resources &amp; capacity</h2><div class="seg" id="resrange"><button data-r="1h">1 h</button><button data-r="24h" class="on">24 h</button>
<button data-r="7d">7 d</button><button data-r="30d">30 d</button></div></div><p class="muted small" id="resnote">Current load (measured) is shown separately from
estimated and benchmarked capacity. Gaps are missing samples, not zero.</p><div id="reskpis" class="cards"></div></section>
<div id="rescharts"></div></div>"""
    return shell(req, "/netmon/settings/resources", "Settings · Resources & capacity", inner)


@app.get("/netmon/settings/capacity/report", response_class=HTMLResponse)
def report_page(req: Request, window: str = "7d"):
    need(req, "viewer")
    ov = overview(window if window in C.WINDOWS else "7d")
    return HTMLResponse(render_report(ov), headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'",
                                                     "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})


# ------------------------------------------------------------------------------------------------ APIs
@app.get("/netmon/api/capacity/overview")
def api_overview(req: Request, window: str = "7d", start: float = 0, end: float = 0, refresh: int = 0):
    need(req, "viewer")
    if window not in C.WINDOWS and not (start and end):
        raise HTTPException(400, "window")
    if start and end and not (0 < end - start <= 31 * 86400):
        raise HTTPException(400, "custom range must be 1 s to 31 days")
    with _busy:
        return JSONResponse(json_safe(overview(window, start or None, end or None, bool(refresh))))


@app.post("/netmon/api/capacity/calc")
async def api_calc(req: Request):
    need(req, "viewer")
    body = await req.json()
    check_csrf(req, req.headers.get("x-csrf", ""))
    ov = overview(body.get("window", "7d") if body.get("window") in C.WINDOWS else "7d")
    return JSONResponse(json_safe(calc(body, ov)))


@app.post("/netmon/api/capacity/plan")
async def api_plan(req: Request):
    u = need(req, "analyst")
    check_csrf(req, req.headers.get("x-csrf", ""))
    body = await req.json()
    plan = {k: body.get(k) for k in ("mode", "answers", "inputs", "labels", "retention", "headroom", "reserve", "suggested")}
    put_setting(conn, "capacity:plan", plan, u)
    audit(conn, u, "capacity_plan_saved", {"mode": plan.get("mode")})
    return {"ok": True}


@app.post("/netmon/settings/capacity/server")
async def server_manual(req: Request):
    u = need(req, "admin")
    form = dict(await req.form())
    check_csrf(req, form.get("csrf", ""))
    keep = {}
    for k in ("disk_type", "nics", "cpu_model", "hypervisor", "sockets", "cores_per_socket"):
        val = str(form.get(k, "")).strip()[:120]
        if val:
            keep[k] = val
    put_setting(conn, "capacity:server_manual", keep, u)
    audit(conn, u, "capacity_server_corrected", {"fields": sorted(keep)})
    C._cache.clear()
    return RedirectResponse("/netmon/settings/capacity?msg=" + quote("Hardware corrections saved; detected values are kept beside them."), 303)


@app.get("/netmon/api/capacity/series")
def api_series(req: Request, window: str = Query("24h", alias="range")):
    need(req, "viewer")
    if window not in C.WINDOWS:
        raise HTTPException(400, "range")
    step = {"1h": 60, "24h": 300, "7d": 1800, "30d": 3600}[window]

    def build():
        t1 = time.time()
        t0 = t1 - C.WINDOWS[window]
        wl, _, res, dev, _ = C.series_or_empty(dash.ch, cfg, t0, t1, step)
        lat = {}
        try:
            for r in dash.ch.query("SELECT toUInt32(toStartOfInterval(event_time, toIntervalSecond({s:UInt32}))) AS b, "
                                   "quantile(0.95)(query_duration_ms) AS p95 FROM system.query_log WHERE event_time >= {t0:DateTime} "
                                   "AND type = 'QueryFinish' AND query_kind = 'Select' GROUP BY b", {"s": step, "t0": C._dt(t0)}):
                lat[int(r["b"])] = r["p95"]
        except Exception:
            pass
        b0 = int(t0 // step * step)
        pts = []
        for b in range(b0, int(t1), step):
            x, w = res.get(b, {}), wl.get(b, {})
            pts.append({"t": b, "cpu": x.get("cpu"), "mem": x.get("mem"), "io_util": x.get("io_util"), "write_Bps": x.get("write_Bps"),
                        "read_Bps": x.get("read_Bps"), "io_latency_ms": x.get("io_latency_ms"), "fs_frac": x.get("fs_frac"),
                        "flows": w.get("flows"), "events": w.get("events"), "q_p95_ms": lat.get(b)})
        devs = {}
        from . import devices as dv
        for d in dv.all_devices(cfg):
            hist = C.fw_resource_history(conn, d["id"], t0, t1)
            if hist:
                buck = {}
                for h in hist:
                    buck.setdefault(int(h["ts"] // step * step), []).append(h)
                devs[d["id"]] = {"name": d["name"], "points": [{"t": b, "cpu": avg([h["cpu"] for h in hs]), "mem": avg([h["mem"] for h in hs])}
                                                               for b, hs in sorted(buck.items())]}
        return {"step": step, "device": dev, "points": pts, "devices": devs, "kafka_lag": C.kafka_lag(cfg), "ingest": C.ingest_lag(conn)}
    return JSONResponse(json_safe(C.cached(f"series:{window}", 60 if window in ("1h", "24h") else 600, build)))


def avg(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


# ------------------------------------------------------------------------------------------------ device hardware
@app.get("/netmon/settings/devices/{did}/hardware", response_class=HTMLResponse)
def device_hw_page(req: Request, did: str, msg: str = ""):
    from . import devices as dv
    u, r = user_of(req)
    d = dv.device(cfg, did)
    if not d:
        raise HTTPException(404, "no such device")
    inner = f"""{f"<div class='banner'>{e(msg)}</div>" if msg else ''}<div id="cap" data-view="device" data-device="{e(did)}" data-role="{e(r)}">
<section class="card"><div class="card-h"><h2>{e(d['name'])} · Hardware &amp; capacity</h2><a class="small" href="/netmon/settings/devices/{e(did)}">← device</a></div>
{f'''<form method=post action="/netmon/settings/devices/{e(did)}/hardware/discover" class="row">{csrf_field(req)}<button class="primary">Auto-populate firewall resources</button>
<span class="muted small">Uses the SNMP settings already stored for this device (read-only GETs and small table walks). Manual values are never overwritten.</span></form>''' if r == 'admin' else ''}
<div id="hwbody"><p class="muted">Loading…</p></div></section></div>"""
    return shell(req, "/netmon/settings/devices", f"Settings · Devices · {d['name']} · Hardware", inner)


@app.get("/netmon/api/capacity/device/{did}")
def api_device(req: Request, did: str, days: int = 7):
    need(req, "viewer")
    from . import devices as dv
    d = dv.device(cfg, did)
    if not d:
        raise HTTPException(404, "no such device")
    wire = get_state(conn, "capacity:wire", {})[0] or {}
    st = fwres.device_capacity(conn, dash.ch, d, max(1, min(30, days)) * 86400, {k: x["bytes_per_record"] for k, x in wire.items()},
                               get_state(conn, "capacity:line_bytes", None)[0])
    st["manual_fields"] = fwres.MANUAL_FIELDS
    st["snmp"] = {"configured": bool(d.get("snmp")), "version": (d.get("snmp") or {}).get("version", "v2c") if d.get("snmp") else None}
    st["manufacturer_guess"] = fwres.manufacturer_from({k: x.get("auto") or {} for k, x in st["hardware"].items()})
    return JSONResponse(json_safe(st))


@app.post("/netmon/settings/devices/{did}/hardware/discover")
async def device_discover(req: Request, did: str):
    from . import devices as dv
    u = need(req, "admin")
    form = dict(await req.form())
    check_csrf(req, form.get("csrf", ""))
    d = dv.device(cfg, did)
    if not d:
        raise HTTPException(404, "no such device")
    fields, steps = fwres.Refresher(cfg, None).refresh(conn, d)
    ok = sum(1 for s in steps if s[1])
    audit(conn, u, "device_resources_discovered", {"device": did, "fields": sorted(fields), "steps_ok": ok})
    C._cache.clear()
    return RedirectResponse(f"/netmon/settings/devices/{did}/hardware?msg=" + quote(f"Discovery finished: {len(fields)} fields read, "
                                                                                    f"{ok} of {len(steps)} steps answered."), 303)


@app.post("/netmon/settings/devices/{did}/hardware/manual")
async def device_manual(req: Request, did: str):
    from . import devices as dv
    u = need(req, "admin")
    form = dict(await req.form())
    check_csrf(req, form.get("csrf", ""))
    if not dv.device(cfg, did):
        raise HTTPException(404, "no such device")
    vals = {}
    for k, _, kind in fwres.MANUAL_FIELDS:
        raw = str(form.get(k, "")).strip()[:120]
        if not raw:
            vals[k] = None
        elif kind in ("number", "gb"):
            try:
                x = float(raw)
            except ValueError:
                return RedirectResponse(f"/netmon/settings/devices/{did}/hardware?msg=" + quote(f"{k}: not a number"), 303)
            if x < 0 or x > 1e7:
                return RedirectResponse(f"/netmon/settings/devices/{did}/hardware?msg=" + quote(f"{k}: out of range"), 303)
            vals[k] = int(x * 1024 ** 3) if kind == "gb" else x
        elif kind.startswith("select:"):
            vals[k] = raw if raw in kind[7:].split(",") and raw != "unknown" else None
        else:
            vals[k] = raw
    fwres.save_manual(conn, did, vals)
    audit(conn, u, "device_resources_manual", {"device": did, "fields": sorted(k for k, x in vals.items() if x is not None)})
    C._cache.clear()
    return RedirectResponse(f"/netmon/settings/devices/{did}/hardware?msg=" + quote("Manual values saved. Discovered values are kept beside them."), 303)


# ------------------------------------------------------------------------------------------------ helpers
def json_safe(x):
    if isinstance(x, float):
        return None if x != x or x in (float("inf"), float("-inf")) else x
    if isinstance(x, dict):
        return {str(k): json_safe(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [json_safe(v) for v in x]
    return x


def _b(n):
    if n is None:
        return "unknown"
    for u in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1000:
            return f"{n:.1f} {u}" if u != "B" else f"{n:.0f} B"
        n /= 1000
    return f"{n:.1f} EB"


def _n(x, d=0):
    return "unknown" if x is None else f"{x:,.{d}f}"


def _p(x):
    return "unknown" if x is None else f"{100 * x:.0f}%"


def lab(x):
    return f"<span class='lab {e(x)}'>{e(x)}</span>"


def render_report(ov):
    """Printable capacity report (self-contained HTML, no scripts)."""
    inv, obs, cap, disk = ov["inventory"], ov["observe"], ov["capacity"], ov["disk"] or {}
    w = obs["window"]
    rows = lambda items: "".join(f"<tr><td>{e(a)}</td><td>{b}</td><td>{lab(c)}</td><td class=s>{e(d)}</td></tr>" for a, b, c, d in items)  # noqa: E731
    inv_rows = rows([(k.replace("_", " "), e(fmt_inv(k, x.get("value"))), x["label"], x.get("source", "") + (" — " + x["note"] if x.get("note") else ""))
                     for k, x in inv.items() if k not in ("container_limits",)])
    st = lambda s, f=_n: f"avg {f(s.get('avg'))} · P95 {f(s.get('p95'))} · peak 1-min {f(s.get('peak'))}" if s.get("label") == "MEASURED" else "unknown"  # noqa: E731
    load = rows([("Flow records/s", st(obs["flows"], lambda x: _n(x, 0)), obs["flows"]["label"], obs["flows"].get("confidence_reason", "")),
                 ("Stored log events/s", st(obs["events"], lambda x: _n(x, 0)), obs["events"]["label"], obs["events"].get("confidence_reason", "")),
                 ("WAN throughput (SNMP)", st(obs["throughput_snmp"], lambda x: f"{x / 1e6:,.1f} Mb/s" if x is not None else "unknown"),
                  obs["throughput_snmp"]["label"], obs["throughput_snmp"].get("source", "")),
                 ("Host CPU", st(obs["cpu"], _p), obs["cpu"]["label"], "share of all vCPUs; ClickHouse system metrics"),
                 ("Host memory", st(obs["mem"], _p), obs["mem"]["label"], ""),
                 ("Disk busy time", st(obs["io_util"], _p), obs["io_util"]["label"], obs.get("block_device") or "")])
    g = ov.get("grade") or {}
    capr = rows([("Hardware grade (0-100)", f"{g['value']} — {e(g['band'])}, limited by {e(g['limited_by'].replace('_', ' '))}" if g.get("value") is not None else "unknown",
                  g.get("label", "UNKNOWN"), "; ".join([g.get("note", "")] + (g.get("caps") or []))),
                 ("Flow ingestion capacity", _n((cap.get("flows_capacity") or {}).get("value")), (cap.get("flows_capacity") or {}).get("label", "UNKNOWN"),
                  (cap.get("flows_capacity") or {}).get("note", "")),
                 ("CPU headroom", _p((cap.get("cpu_headroom") or {}).get("value")), (cap.get("cpu_headroom") or {}).get("label", "UNKNOWN"),
                  (cap.get("cpu_headroom") or {}).get("note", "")),
                 ("RAM headroom", _p((cap.get("ram_headroom") or {}).get("value")), (cap.get("ram_headroom") or {}).get("label", "UNKNOWN"), ""),
                 ("Disk I/O headroom", _p((cap.get("io_headroom") or {}).get("value")), (cap.get("io_headroom") or {}).get("label", "UNKNOWN"),
                  (cap.get("io_headroom") or {}).get("note", "")),
                 ("Days until disk limit", _n(disk.get("days_until_limit")) if disk.get("days_until_limit") is not None else "not reached at current rates",
                  "ESTIMATED", f"limit = {100 * (1 - (disk.get('reserve') or 0.15)):.0f}% of the disk"),
                 ("Steady-state data size", _b(disk.get("steady_state_bytes")), "ESTIMATED", "when every table has reached its retention")])
    b = cap.get("bottleneck") or {}
    stor = "".join(f"<tr><td>{e(t['db'])}.{e(t['table'])}</td><td>{e(t['group'])}</td><td>{_b(t['bytes'])}</td><td>{t['bytes_per_row']:.1f}</td>"
                   f"<td>{_b(t['bytes_per_day'])}</td><td>{_n(t['ttl_days'])}</td></tr>" for t in ov["storage"][:20])
    envr = "".join(f"<tr><td>{e(d['name'])}</td><td>{e(d.get('manufacturer') or '')} {e(d.get('model') or '')}</td>"
                   f"<td>{_n((d.get('cpu') or {}).get('p95'), 0)}%</td><td>{_n((d.get('flows') or {}).get('avg'))}</td><td>{_n((d.get('events') or {}).get('avg'))}</td>"
                   f"<td class=s>{e(', '.join(f'{a}: {s}' for a, s in d.get('sources') or []))}</td></tr>" for d in ov["environment"]["devices"])
    fc = "".join(f"<li>{lab(f['label'])} {e(f['text'])} <span class=s>({e(f['basis'])})</span></li>" for f in ov["forecasts"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Capacity report</title><style>
body{{font:13px/1.45 system-ui,sans-serif;margin:24px;color:#111}} h1{{font-size:20px}} h2{{font-size:15px;margin-top:22px;border-bottom:1px solid #ccc}}
table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid #e5e5e5;padding:4px 6px;text-align:left;vertical-align:top}} .s{{color:#555;font-size:11px}}
.lab{{font-size:10px;font-weight:700;border:1px solid #999;border-radius:4px;padding:0 4px}} @media print{{body{{margin:0}}}}</style></head><body>
<h1>m0nitor capacity report</h1><p class=s>Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(ov['generated']))}. Measurement window
{time.strftime('%Y-%m-%d %H:%M', time.gmtime(w['t0']))} – {time.strftime('%Y-%m-%d %H:%M', time.gmtime(w['t1']))} UTC. {e(w.get('note') or '')}</p>
<h2>Server hardware</h2><table>{inv_rows}</table><h2>Measured load</h2><table>{load}</table>
<h2>What this server can handle</h2><table>{capr}</table><p>First likely limit: <b>{e(C.BOTTLENECK_NAME.get(b.get('resource'), b.get('resource') or 'not estimable'))}</b>
{f"at about {b['multiplier']:.1f}x today's workload" if b.get('multiplier') else ''}.</p>
<h2>Findings</h2><ul>{fc}</ul><h2>Monitored devices</h2><table><tr><th>Device</th><th>Hardware</th><th>CPU P95</th><th>Flows/s</th><th>Events/s</th><th>Sources</th></tr>{envr}</table>
<h2>Storage by table</h2><table><tr><th>Table</th><th>Group</th><th>Size</th><th>Bytes/row</th><th>Per day</th><th>TTL (days)</th></tr>{stor}</table>
<p class=s>Labels: MEASURED from this installation; ESTIMATED from a documented model (docs/capacity-planning.md); BENCHMARKED by the benchmark harness;
MANUAL entered by a user; UNKNOWN not available. Throughput, CPU clock or core count alone do not determine flow-processing capacity.</p></body></html>"""


def fmt_inv(k, x):
    if x is None:
        return "unknown"
    if k in ("ram_total", "ram_available", "swap_total", "swap_used", "disk_total", "disk_free", "clickhouse_disk_total", "clickhouse_disk_free"):
        return _b(x)
    if k == "uptime_s":
        return f"{x / 86400:.1f} days"
    if k == "nics" and isinstance(x, list):
        return ", ".join(f"{n.get('name')} {n.get('speed_mbps') or '?'} Mb/s" for n in x)
    if k == "host_helper":
        return f"updated {x:.0f} s ago"
    return str(x)
