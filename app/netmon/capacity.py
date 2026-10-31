"""Capacity planning: what this server has, what it is doing, what it can take, how long the data fits.

Every value carries a label:
  MEASURED     read from this installation (ClickHouse system metrics, flow/log tables, SNMP, /proc, the host helper)
  ESTIMATED    calculated from measured values with a documented model (docs/capacity-planning.md); shown as a range
  SUGGESTED    from the documented assumption model for new installations (not measured, not vendor data)
  BENCHMARKED  from a benchmark run on recorded hardware (bench/, docs/performance-benchmarks.md)
  MANUAL       entered by a user
  UNKNOWN      not available; never shown as zero

Measurement rules (docs/capacity-planning.md#measurement-rules):
- rates are per 1-minute bucket by time received; the peak is the highest 1-minute rate, not an instantaneous value;
- time before the first record is "before collection", not zero load;
- a run of >= GAP_MIN empty minutes is a telemetry gap and is excluded; shorter empty runs count as zero (quiet);
- only complete minutes are used.
"""
import glob
import json
import math
import os
import platform
import re
import threading
import time

from .core import DATA_DIR, expand_flow_sql, flow_predicates, get_setting, get_state, set_state

GAP_MIN = 10
WINDOWS = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
HOSTINFO = os.path.join(DATA_DIR, "hostinfo.json")
LABELS = ("MEASURED", "ESTIMATED", "SUGGESTED", "BENCHMARKED", "MANUAL", "UNKNOWN")


def v(value, label, source="", note=""):
    """A labelled value."""
    assert label in LABELS
    return {"value": value, "label": label if value is not None or label == "MANUAL" else "UNKNOWN", "source": source, "note": note}


# ------------------------------------------------------------------------------------------------ statistics
def pctl(xs, p):
    """Nearest-rank percentile (p in 0..100) of a non-empty list."""
    s = sorted(xs)
    return s[max(0, min(len(s) - 1, math.ceil(p / 100 * len(s)) - 1))]


def summarize(vals: dict, t0: float, t1: float, step: int = 60, gap_steps: int = GAP_MIN):
    """vals: bucket start (epoch s, aligned to step) -> rate. Applies the measurement rules above."""
    b0 = int(t0 // step * step) + (step if t0 % step else 0)
    b1 = int(t1 // step * step) - step          # last complete bucket
    have = [b for b in vals if b0 <= b <= b1]
    if not have:
        return {"label": "UNKNOWN", "samples": 0, "note": "no measurements in this window"}
    first, last = min(have), max(have)
    obs, missing, run = [], [], []
    peak_t, peak = None, None
    for b in range(first, b1 + step, step):
        if b in vals:
            if run:
                if len(run) >= gap_steps:
                    missing.append((run[0], run[-1] + step))
                else:
                    obs += [0.0] * len(run)
                run = []
            x = float(vals[b])
            obs.append(x)
            if peak is None or x > peak:
                peak, peak_t = x, b
        else:
            run.append(b)
    if run:
        if len(run) >= gap_steps:
            missing.append((run[0], run[-1] + step))
        else:
            obs += [0.0] * len(run)
    hours = len(obs) * step / 3600
    span = (b1 + step - first) / 3600
    coverage = hours / span if span else 0
    conf, why = confidence(hours, coverage)
    return {"label": "MEASURED", "avg": sum(obs) / len(obs), "p95": pctl(obs, 95), "peak": peak, "peak_at": peak_t,
            "peak_interval": f"{step // 60}-minute" if step >= 60 else f"{step}-second", "samples": len(obs), "step": step,
            "first": first, "last": last, "freshness_s": max(0, t1 - (last + step)), "observed_hours": round(hours, 2),
            "coverage": round(coverage, 4), "missing": missing, "before_collection_s": max(0, first - b0),
            "confidence": conf, "confidence_reason": why}


def confidence(hours, coverage):
    """Documented rule, not a score: <6 h low, <72 h medium, otherwise high; <90 % coverage lowers it one step."""
    lvl = 0 if hours < 6 else 1 if hours < 72 else 2
    why = f"{hours:.1f} h of measurements" if hours < 48 else f"{hours / 24:.1f} days of measurements"
    if coverage < 0.9 and lvl:
        lvl -= 1
        why += f", {100 * (1 - coverage):.0f}% of the period missing"
    return ("low", "medium", "high")[lvl], why


def robust_fit(X, y, iters=8):
    """y ~ b0 + X·b with Huber IRLS. Returns coefficients, standard errors, R², n. X: list of rows (no intercept)."""
    n, k = len(y), (len(X[0]) if X else 0) + 1
    if n < k + 5:
        return None
    A = [[1.0, *row] for row in X]
    w = [1.0] * n
    beta = None
    for _ in range(iters):
        beta = _wls(A, y, w)
        if beta is None:
            return None
        r = [yi - sum(a * b for a, b in zip(ai, beta)) for ai, yi in zip(A, y)]
        s = 1.4826 * pctl([abs(x) for x in r], 50) or 1e-12
        c = 1.345 * s
        w = [1.0 if abs(ri) <= c else c / abs(ri) for ri in r]
    r = [yi - sum(a * b for a, b in zip(ai, beta)) for ai, yi in zip(A, y)]
    sw = sum(w)
    sigma2 = sum(wi * ri * ri for wi, ri in zip(w, r)) / max(1, sw - k)
    inv = _inv([[sum(w[i] * A[i][p] * A[i][q] for i in range(n)) for q in range(k)] for p in range(k)])
    if inv is None:
        return None
    se = [math.sqrt(max(0.0, sigma2 * inv[j][j])) for j in range(k)]
    ym = sum(y) / n
    ss_tot = sum((yi - ym) ** 2 for yi in y) or 1e-12
    r2 = 1 - sum(ri * ri for ri in r) / ss_tot
    return {"coef": beta, "se": se, "r2": r2, "n": n}


def _wls(A, y, w):
    k = len(A[0])
    M = [[sum(w[i] * A[i][p] * A[i][q] for i in range(len(y))) for q in range(k)] for p in range(k)]
    b = [sum(w[i] * A[i][p] * y[i] for i in range(len(y))) for p in range(k)]
    inv = _inv(M)
    return None if inv is None else [sum(inv[p][q] * b[q] for q in range(k)) for p in range(k)]


def _inv(M):
    n = len(M)
    a = [row[:] + [1.0 if i == j else 0.0 for j in range(n)] for i, row in enumerate(M)]
    for c in range(n):
        p = max(range(c, n), key=lambda r: abs(a[r][c]))
        if abs(a[p][c]) < 1e-15:
            return None
        a[c], a[p] = a[p], a[c]
        f = a[c][c]
        a[c] = [x / f for x in a[c]]
        for r in range(n):
            if r != c and a[r][c]:
                g = a[r][c]
                a[r] = [x - g * y for x, y in zip(a[r], a[c])]
    return [row[n:] for row in a]


def theil_sen(points):
    """Robust slope of (t, y) points (median of pairwise slopes, subsampled). Per second of t."""
    pts = [p for p in points if p[1] is not None]
    if len(pts) < 4:
        return None
    if len(pts) > 200:
        pts = pts[:: math.ceil(len(pts) / 200)]
    sl = [(y2 - y1) / (t2 - t1) for i, (t1, y1) in enumerate(pts) for (t2, y2) in pts[i + 1:] if t2 != t1]
    return pctl(sl, 50) if sl else None


# ------------------------------------------------------------------------------------------------ server inventory
def _read(path, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def hostinfo():
    """Facts written by the read-only host helper (host/netmon-hostinfo, systemd timer). None if not installed."""
    try:
        with open(HOSTINFO) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    d["age_s"] = time.time() - d.get("ts", 0)
    return d


def _cpuinfo():
    txt = _read("/proc/cpuinfo", "") or ""
    blocks = [dict(re.findall(r"^([^:\n]+?)\s*:\s*(.*)$", b, re.M)) for b in txt.split("\n\n") if b.strip()]
    return blocks


def server_inventory(ch=None, manual=None):
    """CPU, memory, disk, network, virtualization and limits of the machine running m0nitor. Each field labelled."""
    manual = manual or {}
    hi = hostinfo()
    cpus = _cpuinfo()
    c0 = cpus[0] if cpus else {}
    flags = set((c0.get("flags") or "").split())
    out = {}
    model = c0.get("model name") or c0.get("Model") or c0.get("cpu model")
    out["cpu_model"] = v(model, "MEASURED", "/proc/cpuinfo") if model else v(None, "UNKNOWN", "/proc/cpuinfo", "CPU model not exposed")
    out["cpu_vendor"] = v(c0.get("vendor_id"), "MEASURED", "/proc/cpuinfo")
    out["arch"] = v(platform.machine(), "MEASURED", "kernel")
    out["logical_cpus"] = v(os.cpu_count(), "MEASURED", "kernel", "vCPUs visible to the OS (allocated vCPUs in a VM)")
    phys = {(b.get("physical id"), b.get("core id")) for b in cpus if b.get("core id") is not None}
    lscpu = (hi or {}).get("lscpu") or {}
    if lscpu.get("sockets"):
        out["sockets"] = v(int(lscpu["sockets"]), "MEASURED", "lscpu (host helper)")
        out["cores_per_socket"] = v(int(lscpu.get("cores_per_socket") or 0) or None, "MEASURED", "lscpu (host helper)")
        out["threads_per_core"] = v(int(lscpu.get("threads_per_core") or 0) or None, "MEASURED", "lscpu (host helper)")
    elif phys:
        out["physical_cores"] = v(len(phys), "MEASURED", "/proc/cpuinfo (physical id, core id)",
                                  "as presented to this OS; in a VM these are virtual cores")
    nominal = re.search(r"@\s*([\d.]+)\s*GHz", model or "")
    out["cpu_nominal_ghz"] = v(float(nominal.group(1)) if nominal else None, "MEASURED", "CPU model string")
    mhz = [float(b["cpu MHz"]) for b in cpus if b.get("cpu MHz")]
    out["cpu_current_mhz"] = v(round(sum(mhz) / len(mhz)) if mhz else None, "MEASURED", "/proc/cpuinfo",
                               "reported by the (virtual) CPU; a clock speed is not an ingestion rate")
    isa = [f for f in ("sse4_2", "avx", "avx2", "avx512f", "aes", "sha_ni") if f in flags]
    out["cpu_isa"] = v(", ".join(isa) or None, "MEASURED", "/proc/cpuinfo flags",
                       "" if "avx2" in flags else "No AVX2: ClickHouse >= 26.6 needs x86-64-v3; pin 26.3 (docs/install.md)")
    # virtualization
    virt = (hi or {}).get("virt")
    dmi = " ".join(x for x in (_read("/sys/class/dmi/id/sys_vendor"), _read("/sys/class/dmi/id/product_name")) if x)
    if virt and virt != "none":
        out["hypervisor"] = v(f"{virt}" + (f" ({dmi})" if dmi else ""), "MEASURED", "systemd-detect-virt (host helper)")
    elif "hypervisor" in flags:
        out["hypervisor"] = v(f"virtual machine{f' ({dmi})' if dmi else ''}", "MEASURED", "CPU hypervisor flag, DMI")
    elif virt == "none":
        out["hypervisor"] = v("none (bare metal)", "MEASURED", "systemd-detect-virt (host helper)")
    else:
        out["hypervisor"] = v(None, "UNKNOWN", "", "no hypervisor flag; bare metal or not exposed")
    # memory
    mi = dict(re.findall(r"^(\w+):\s+(\d+)", _read("/proc/meminfo", "") or "", re.M))
    kb = lambda k: int(mi[k]) * 1024 if k in mi else None  # noqa: E731
    out["ram_total"] = v(kb("MemTotal"), "MEASURED", "/proc/meminfo", "bytes visible to the OS")
    out["ram_available"] = v(kb("MemAvailable"), "MEASURED", "/proc/meminfo")
    out["swap_total"] = v(kb("SwapTotal"), "MEASURED", "/proc/meminfo")
    out["swap_used"] = v((kb("SwapTotal") or 0) - (kb("SwapFree") or 0) if "SwapTotal" in mi else None, "MEASURED", "/proc/meminfo")
    # container limits
    lim = {}
    cm = _read("/sys/fs/cgroup/cpu.max")
    if cm:
        q, p = (cm.split() + ["100000"])[:2]
        lim["app_cpu"] = None if q == "max" else round(int(q) / int(p), 2)
    mm = _read("/sys/fs/cgroup/memory.max")
    if mm:
        lim["app_memory"] = None if mm == "max" else int(mm)
    out["container_limits"] = v({"app": lim, "containers": (hi or {}).get("containers")}, "MEASURED",
                                "cgroup v2 (app) + docker inspect (host helper)",
                                "None = no limit (the container can use the whole machine)")
    # disk
    try:
        st = os.statvfs(DATA_DIR)
        out["disk_total"] = v(st.f_blocks * st.f_frsize, "MEASURED", f"statvfs({DATA_DIR})")
        out["disk_free"] = v(st.f_bavail * st.f_frsize, "MEASURED", f"statvfs({DATA_DIR})")
    except OSError:
        out["disk_total"] = out["disk_free"] = v(None, "UNKNOWN", "statvfs")
    out["disk_type"] = disk_type(hi)
    # network
    nics = (hi or {}).get("nics")
    if nics:
        out["nics"] = v(nics, "MEASURED", "/sys/class/net (host helper)",
                        "speed -1/None = the driver reports no link speed (common for virtio NICs)")
    else:
        out["nics"] = v(None, "UNKNOWN", "", "host network interfaces are not visible inside the container: install the host helper "
                                              "(host/netmon-hostinfo)")
    out["uptime_s"] = v(float((_read("/proc/uptime", "0") or "0").split()[0]), "MEASURED", "/proc/uptime")
    out["host_helper"] = v(round(hi["age_s"]) if hi else None, "MEASURED" if hi else "UNKNOWN", HOSTINFO,
                           "" if hi else "not installed: NIC speeds, sockets/cores, container limits and Kafka disk use stay unknown")
    if hi and hi["age_s"] > 1800:
        out["host_helper"]["note"] = f"stale: last written {round(hi['age_s'] / 60)} min ago"
    if ch is not None:
        try:
            r = ch.query("SELECT metric, value FROM system.asynchronous_metrics WHERE metric IN "
                         "('FilesystemMainPathTotalBytes','FilesystemMainPathAvailableBytes','OSMemoryTotal','CGroupMemoryTotal')", {})
            m = {x["metric"]: float(x["value"]) for x in r}
            out["clickhouse_disk_total"] = v(m.get("FilesystemMainPathTotalBytes"), "MEASURED", "ClickHouse system.asynchronous_metrics")
            out["clickhouse_disk_free"] = v(m.get("FilesystemMainPathAvailableBytes"), "MEASURED", "ClickHouse system.asynchronous_metrics")
        except Exception as ex:
            out["clickhouse_disk_total"] = v(None, "UNKNOWN", "ClickHouse", str(ex)[:120])
    for k, val in manual.items():          # manual corrections win, the detected value is kept for comparison
        if k in out and val not in (None, ""):
            out[k] = {**v(val, "MANUAL", "entered by a user"), "detected": out[k].get("value")}
        elif val not in (None, ""):
            out[k] = v(val, "MANUAL", "entered by a user")
    return out


def disk_type(hi=None):
    """SSD/HDD from the kernel, but virtual disks report what the hypervisor emulates, not the backing storage."""
    disks = (hi or {}).get("disks") or []
    if not disks:
        for dev in sorted(glob.glob("/sys/block/*")):
            name = os.path.basename(dev)
            if re.match(r"(loop|sr|ram|zram|dm-)", name):
                continue
            disks.append({"name": name, "model": (_read(f"{dev}/device/model") or "").strip(), "rota": _read(f"{dev}/queue/rotational"),
                          "size": int(_read(f"{dev}/size", "0") or 0) * 512})
    if not disks:
        return v(None, "UNKNOWN", "/sys/block")
    d = max(disks, key=lambda x: int(x.get("size") or 0))
    model = (d.get("model") or "").strip()
    if re.search(r"QEMU|VMware|Virtual|VBOX|Msft", model, re.I) or d.get("name", "").startswith(("vd", "xvd")):
        return v(f"virtual disk ({model or d['name']})", "MEASURED", "/sys/block",
                 "the backing storage (SSD/HDD/network) is not visible from inside the VM; enter it manually if known")
    if str(d.get("rota")) in ("0", "False", "false"):
        return v(f"SSD/flash ({model or d['name']})", "MEASURED", "/sys/block rotational=0")
    if str(d.get("rota")) in ("1", "True", "true"):
        return v(f"rotational disk ({model or d['name']})", "MEASURED", "/sys/block rotational=1")
    return v(None, "UNKNOWN", "/sys/block")


# ------------------------------------------------------------------------------------------------ measurements
_cache, _lock = {}, threading.Lock()


def cached(key, ttl, fn):
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
    val = fn()
    with _lock:
        _cache[key] = (time.time(), val)
    return val


def _dt(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))


def block_device(ch):
    """The block device ClickHouse reports the most writes for (its data disk in practice)."""
    r = ch.query("SELECT replaceOne(metric, 'BlockWriteBytes_', '') AS d, sum(value) AS w FROM system.asynchronous_metric_log "
                 "WHERE event_time > now() - INTERVAL 1 HOUR AND metric LIKE 'BlockWriteBytes\\_%' AND metric NOT LIKE '%\\_sr%' "
                 "AND metric NOT LIKE '%\\_loop%' GROUP BY d ORDER BY w DESC LIMIT 1", {})
    return r[0]["d"] if r else None


RES_METRICS = ("OSIdleTimeNormalized", "OSIOWaitTimeNormalized", "OSStealTimeNormalized", "OSMemoryAvailable", "OSMemoryTotal",
               "MemoryResident", "LoadAverage1", "FilesystemMainPathUsedBytes", "FilesystemMainPathTotalBytes")


def resource_series(ch, t0, t1, step=60):
    """Host-wide CPU, memory, disk I/O and filesystem per bucket, from ClickHouse's system.asynchronous_metric_log
    (its 1-second samples of /proc: host-wide, since /proc is not namespaced). bucket -> dict."""
    dev = block_device(ch)
    names = list(RES_METRICS)
    if dev:
        names += [f"Block{x}_{dev}" for x in ("ActiveTime", "ReadBytes", "WriteBytes", "ReadOps", "WriteOps", "ReadTime", "WriteTime")]
    rows = ch.query("SELECT toUInt32(toStartOfInterval(event_time, toIntervalSecond({step:UInt32}))) AS b, metric, avg(value) AS v "
                    "FROM system.asynchronous_metric_log WHERE event_time >= {t0:DateTime} AND event_time < {t1:DateTime} "
                    "AND metric IN {m:Array(String)} GROUP BY b, metric",
                    {"step": step, "t0": _dt(t0), "t1": _dt(t1), "m": names})
    by = {}
    for r in rows:
        by.setdefault(int(r["b"]), {})[r["metric"]] = float(r["v"])
    out = {}
    for b, m in by.items():
        x = {}
        if "OSIdleTimeNormalized" in m:
            x["cpu"] = max(0.0, 1 - m["OSIdleTimeNormalized"] - m.get("OSIOWaitTimeNormalized", 0) - m.get("OSStealTimeNormalized", 0))
            x["iowait"] = m.get("OSIOWaitTimeNormalized")
            x["steal"] = m.get("OSStealTimeNormalized")
        if m.get("OSMemoryTotal"):
            x["mem"] = 1 - m.get("OSMemoryAvailable", 0) / m["OSMemoryTotal"]
            x["mem_avail"] = m.get("OSMemoryAvailable")
        x["ch_rss"] = m.get("MemoryResident")
        x["load1"] = m.get("LoadAverage1")
        if m.get("FilesystemMainPathTotalBytes"):
            x["fs_used"] = m.get("FilesystemMainPathUsedBytes")
            x["fs_frac"] = m["FilesystemMainPathUsedBytes"] / m["FilesystemMainPathTotalBytes"]
        if dev and f"BlockActiveTime_{dev}" in m:
            x["io_util"] = min(1.0, m[f"BlockActiveTime_{dev}"])
            x["read_Bps"], x["write_Bps"] = m.get(f"BlockReadBytes_{dev}"), m.get(f"BlockWriteBytes_{dev}")
            ops = (m.get(f"BlockReadOps_{dev}") or 0) + (m.get(f"BlockWriteOps_{dev}") or 0)
            tm = (m.get(f"BlockReadTime_{dev}") or 0) + (m.get(f"BlockWriteTime_{dev}") or 0)
            x["io_latency_ms"] = 1000 * tm / ops if ops else None
        out[b] = x
    return out, dev


def log_tables(ch):
    """netmon tables with a `received` column: everything ingested from logs and sensors."""
    r = ch.query("SELECT table FROM system.columns WHERE database = 'netmon' AND name = 'received'", {})
    return sorted(x["table"] for x in r)


def workload_series(ch, cfg, t0, t1, step=60):
    """Per bucket (time received): flow records/s, WAN throughput (flow-estimated bits/s), stored log events/s."""
    p = {"step": step, "t0": _dt(t0), "t1": _dt(t1)}
    out = {}
    for r in ch.query("SELECT toUInt32(toStartOfInterval(TimeReceived, toIntervalSecond({step:UInt32}))) AS b, count() AS n "
                      "FROM flows WHERE TimeReceived >= {t0:DateTime} AND TimeReceived < {t1:DateTime} GROUP BY b", p):
        out.setdefault(int(r["b"]), {})["flows"] = r["n"] / step
    m, fp = flow_predicates(cfg, cfg.sites)
    sql = expand_flow_sql("SELECT toUInt32(toStartOfInterval(TimeReceived, toIntervalSecond({step:UInt32}))) AS b, "
                          "sumIf(Bytes * SamplingRate, INB) AS i, sumIf(Bytes * SamplingRate, OUTB) AS o FROM flows "
                          "WHERE TimeReceived >= {t0:DateTime} AND TimeReceived < {t1:DateTime} GROUP BY b", m)
    for r in ch.query(sql, {**p, **fp}):
        x = out.setdefault(int(r["b"]), {})
        x["in_bps"], x["out_bps"] = 8 * r["i"] / step, 8 * r["o"] / step
    cats = {}
    for t in log_tables(ch):
        for r in ch.query(f"SELECT toUInt32(toStartOfInterval(received, toIntervalSecond({{step:UInt32}}))) AS b, count() AS n "
                          f"FROM netmon.{t} WHERE received >= {{t0:DateTime}} AND received < {{t1:DateTime}} GROUP BY b", p):
            x = out.setdefault(int(r["b"]), {})
            x["events"] = x.get("events", 0) + r["n"] / step
            x[f"ev_{t}"] = r["n"] / step
            cats[t] = cats.get(t, 0) + r["n"]
    return out, cats


def snmp_throughput(conn, t0, t1, step=60):
    """WAN throughput from SNMP interface counters (8 days kept), summed over sites: bucket -> bits/s. MEASURED."""
    from .counters import rates
    rows = conn.execute("SELECT site, iface, ts, in_oct, out_oct FROM counters WHERE ts >= ? AND ts < ? ORDER BY site, iface, ts",
                        (t0 - 600, t1)).fetchall()
    series = {}
    for r in rows:
        series.setdefault((r["site"], r["iface"]), []).append((r["ts"], r["in_oct"], r["out_oct"]))
    out = {}
    for _, s in series.items():
        iv = max(1.0, pctl([b[0] - a[0] for a, b in zip(s, s[1:])] or [60], 50))
        for t, i, o, _dt_ in rates(s, iv):
            if i is None or t < t0:
                continue
            b = int(t // step * step)
            x = out.setdefault(b, {"in": [], "out": []})
            x["in"].append(i)
            x["out"].append(o)
    return {b: sum(x["in"]) / len(x["in"]) + sum(x["out"]) / len(x["out"]) for b, x in out.items()}


def fw_resource_history(conn, device, t0, t1):
    return [dict(r) for r in conn.execute("SELECT ts, cpu, mem, load1 FROM fw_resources WHERE device=? AND ts >= ? AND ts < ? ORDER BY ts",
                                          (device, t0, t1)).fetchall()]


def available_since(ch):
    """First flow/log record still stored: limits how far back measurements can go."""
    try:
        r = ch.query("SELECT toUInt32(min(TimeReceived)) AS f FROM flows", {})
        return r[0]["f"] or None
    except Exception:
        return None


def series_or_empty(ch, cfg, t0, t1, step=60):
    """(workload, categories, resources, block device, error). ClickHouse unreachable -> empty series and the error, so every
    figure built on them reads UNKNOWN instead of failing the page."""
    try:
        wl, cats = workload_series(ch, cfg, t0, t1, step)
        res, dev = resource_series(ch, t0, t1, step)
        return wl, cats, res, dev, None
    except Exception as ex:
        return {}, [], {}, None, f"ClickHouse query failed: {type(ex).__name__}"


def pick_window(ch, want="7d", t0=None, t1=None, now=None):
    """Requested window, shortened to the data that exists. Returns (t0, t1, note)."""
    now = now or time.time()
    if t0 and t1:
        return float(t0), float(t1), "custom range"
    t1 = now
    t0 = t1 - WINDOWS.get(want, WINDOWS["7d"])
    first = available_since(ch)
    if first and first > t0:
        return first, t1, (f"only {(t1 - first) / 86400:.1f} days of data exist (requested {want}); using all of it"
                           if t1 - first > 86400 else f"only {(t1 - first) / 3600:.1f} hours of data exist (requested {want}); using all of it")
    return t0, t1, ""


HW_WARMUP_S = 600     # skip the first 10 minutes after a hardware change: boot and ClickHouse catch-up are not normal load


def hardware_change(ch, t0, t1, step=300):
    """Newest time in [t0, t1) where the vCPU count or total RAM changed (VM resized or moved), from ClickHouse's own
    per-CPU idle and OSMemoryTotal samples. Resource figures measured before it describe other hardware. None if no change."""
    try:
        rows = ch.query("SELECT toUInt32(toStartOfInterval(event_time, toIntervalSecond({step:UInt32}))) AS b, "
                        "uniqExactIf(metric, startsWith(metric, 'OSIdleTimeCPU')) AS cpus, maxIf(value, metric = 'OSMemoryTotal') AS mem "
                        "FROM system.asynchronous_metric_log WHERE event_time >= {t0:DateTime} AND event_time < {t1:DateTime} "
                        "AND (startsWith(metric, 'OSIdleTimeCPU') OR metric = 'OSMemoryTotal') GROUP BY b ORDER BY b",
                        {"step": step, "t0": _dt(t0), "t1": _dt(t1)})
    except Exception:
        return None
    return find_change([(int(r["b"]), int(r["cpus"]), float(r["mem"])) for r in rows], step)


def find_change(rows, step=300):
    """rows: (bucket, vCPUs, RAM bytes) ascending. Newest bucket whose hardware differs from the newest bucket's (RAM
    within 2 % counts as equal). The bucket right after it can hold samples of both, so the change counts from the end
    of that bucket."""
    rows = [r for r in rows if r[1] and r[2]]
    if len(rows) < 2:
        return None
    _, cpus, mem = rows[-1]
    for i in range(len(rows) - 2, -1, -1):
        b, c, m = rows[i]
        if c != cpus or abs(m - mem) > 0.02 * mem:
            return {"at": rows[i + 1][0] + step, "before": {"vcpus": c, "ram_bytes": m}, "after": {"vcpus": cpus, "ram_bytes": mem}}
    return None


def observe(ch, cfg, conn, window="7d", t0=None, t1=None):
    """'Use My Current Setup': measured workload, resources and inventory counts for the window."""
    t0, t1, note = pick_window(ch, window, t0, t1)
    wl, cats, res, dev, err = series_or_empty(ch, cfg, t0, t1)
    snmp = snmp_throughput(conn, t0, t1)
    pick = lambda d, k: {b: x[k] for b, x in d.items() if x.get(k) is not None}  # noqa: E731
    out = {"window": {"t0": t0, "t1": t1, "requested": window, "note": note, "duration_s": t1 - t0}, "block_device": dev, "error": err}
    out["flows"] = summarize(pick(wl, "flows"), t0, t1)
    out["events"] = summarize(pick(wl, "events"), t0, t1)
    out["event_tables"] = {t: summarize(pick(wl, f"ev_{t}"), t0, t1) for t in cats}
    tp = {b: (x.get("in_bps") or 0) + (x.get("out_bps") or 0) for b, x in wl.items() if "in_bps" in x}
    out["throughput_flow"] = summarize(tp, t0, t1)
    out["throughput_flow"]["source"] = "flow-estimated (WAN boundary, sampled bytes x sampling rate, by time received)"
    out["throughput_snmp"] = summarize(snmp, t0, t1, gap_steps=3)
    out["throughput_snmp"]["source"] = "SNMP IF-MIB 64-bit counters on the WAN interface(s), summed in+out"
    r0, hw = t0, (hardware_change(ch, t0, t1) if not err else None)
    if hw:
        settle = hw["at"] + HW_WARMUP_S
        r0 = max(t0, settle if t1 - settle >= 1800 else hw["at"])
        gb = lambda b: f"{b / 2**30:.0f} GB"  # noqa: E731
        hw["note"] = (f"hardware changed at {_dt(hw['at'])} UTC ({hw['before']['vcpus']} vCPU / {gb(hw['before']['ram_bytes'])} -> "
                      f"{hw['after']['vcpus']} vCPU / {gb(hw['after']['ram_bytes'])}): CPU, memory and disk figures are measured "
                      f"since {_dt(r0)} UTC only" + (", skipping the first 10 minutes after the change" if r0 > hw["at"] else ""))
    out["window"]["resources_t0"] = r0
    out["hardware_change"] = hw
    for k in ("cpu", "mem", "io_util", "write_Bps", "read_Bps", "io_latency_ms", "iowait", "steal", "ch_rss"):
        out[k] = summarize(pick(res, k), r0, t1, gap_steps=5)
    out["fs_growth"] = fs_growth(res)
    out["flows_trend"] = daily_trend(pick(wl, "flows"))
    out["events_trend"] = daily_trend(pick(wl, "events"))
    out["counts"] = inventory_counts(ch, cfg, conn)
    out["kafka_lag"] = kafka_lag(cfg)
    out["ingest"] = ingest_lag(conn)
    return out


def fs_growth(res):
    """Filesystem growth from ClickHouse's own filesystem samples: robust slope, bytes per day. MEASURED."""
    pts = sorted((b, x["fs_used"]) for b, x in res.items() if x.get("fs_used") is not None)
    if len(pts) < 60:
        return {"label": "UNKNOWN", "note": "less than an hour of filesystem samples"}
    hourly = {}
    for b, y in pts:
        hourly.setdefault(b // 3600, []).append(y)
    hp = [(h * 3600, pctl(ys, 50)) for h, ys in sorted(hourly.items())]
    s = theil_sen(hp)
    days = (pts[-1][0] - pts[0][0]) / 86400
    return {"label": "MEASURED", "bytes_per_day": s * 86400 if s is not None else None, "first": pts[0][1], "last": pts[-1][1],
            "days": round(days, 2), "confidence": confidence(days * 24, 1.0)[0],
            "note": "includes every file on the ClickHouse data filesystem, and data still below its retention (TTL) limit grows until it reaches it"}


def inventory_counts(ch, cfg, conn):
    from . import devices as dv
    devs = dv.all_devices(cfg)
    kinds, vend = {"site firewalls": 0, "additional devices": 0}, {}
    for d in devs:
        kinds["site firewalls" if d["primary"] else "additional devices"] += 1
        name = dv.vendors.PROFILES.get(d.get("vendor") or "generic", {}).get("name") or d.get("vendor") or "generic"
        vend[name] = vend.get(name, 0) + 1
    try:
        exporters = ch.query("SELECT uniqExact(ExporterName) AS e FROM flows WHERE TimeReceived > now() - INTERVAL 1 HOUR", {})[0]["e"]
        ri = ch.query("SELECT count() AS n FROM (SELECT ExporterName, InIfName AS i FROM flows WHERE TimeReceived > now() - INTERVAL 1 HOUR "
                      "AND InIfName != '' GROUP BY ExporterName, i UNION DISTINCT SELECT ExporterName, OutIfName AS i FROM flows "
                      "WHERE TimeReceived > now() - INTERVAL 1 HOUR AND OutIfName != '' GROUP BY ExporterName, i)", {})
        ifaces = ri[0]["n"] if ri else None
    except Exception:
        exporters, ifaces = None, None
    snmp_targets = sum(1 for d in devs if d.get("snmp"))
    snmp_ifs = sum(len((d.get("snmp") or {}).get("interfaces") or {}) for d in devs)
    # counters.Poller: 3 OIDs per interface per poll, plus once a minute 4 system OIDs and 4 error OIDs per interface
    oids = sum(len((d.get("snmp") or {}).get("interfaces") or {}) * 3 * 60 / max(1, (d.get("snmp") or {}).get("interval_seconds") or 10)
               + 4 + 4 * len((d.get("snmp") or {}).get("interfaces") or {}) for d in devs if d.get("snmp"))
    feats = active_features(ch, cfg, conn)
    return {"devices": len(devs), "by_kind": kinds, "by_vendor": vend, "firewalls": sum(1 for d in devs if d["primary"]),
            "active_exporters": exporters, "active_interfaces": ifaces, "snmp_targets": snmp_targets, "snmp_interfaces": snmp_ifs,
            "snmp_oids_per_minute": round(oids), "features": feats}


def active_features(ch, cfg, conn):
    from .ai import AI
    f = {}
    try:
        r = {x["t"]: x["n"] for x in ch.query(
            "SELECT 'flows' AS t, count() AS n FROM flows WHERE TimeReceived > now() - INTERVAL 1 HOUR UNION ALL "
            "SELECT 'fw' AS t, count() AS n FROM netmon.fw_events WHERE received > now() - INTERVAL 1 HOUR UNION ALL "
            "SELECT 'ids' AS t, count() AS n FROM netmon.ids_events WHERE received > now() - INTERVAL 1 DAY UNION ALL "
            "SELECT 'dns' AS t, count() AS n FROM netmon.dns_events WHERE received > now() - INTERVAL 1 HOUR UNION ALL "
            "SELECT 'zeek' AS t, count() AS n FROM netmon.zeek_conn WHERE received > now() - INTERVAL 1 HOUR", {})}
    except Exception:
        r = {}
    f["flows"], f["syslog"], f["ids"], f["dns"], f["zeek"] = (bool(r.get("flows")), bool(r.get("fw")), bool(r.get("ids")),
                                                             bool(r.get("dns")), bool(r.get("zeek")))
    f["snmp"] = any(s.get("snmp") for s in cfg.sites) or any(d.get("snmp") for d in (cfg.raw.get("devices") or []))
    f["behavioral"] = os.environ.get("NETMON_DETECTOR", "1") != "0"
    ti, _ = get_state(conn, "threatradar", None)
    f["threat_intel"] = bool(ti)
    try:
        f["ai"] = AI(cfg, conn).enabled
    except Exception:
        f["ai"] = False
    return f


def kafka_lag(cfg):
    from .health import msum, prom
    import httpx
    url = (cfg.get("akvorado_metrics") or {}).get("outlet") if cfg.get("akvorado_metrics") is not None else \
        "http://akvorado-outlet:8080/api/v0/outlet/metrics"
    if not url:
        return v(None, "UNKNOWN", "", "no Akvorado metrics configured")
    try:
        return v(msum(prom(httpx.get(url, timeout=5).text), "akvorado_outlet_kafkainput_consumergroup_lag_messages"), "MEASURED",
                 "Akvorado outlet consumer-group lag (messages)")
    except Exception as ex:
        return v(None, "UNKNOWN", "Akvorado outlet metrics", str(ex)[:120])


def ingest_lag(conn):
    st, ts = get_state(conn, "ingest", {})
    if not st:
        return v(None, "UNKNOWN", "log ingest state")
    last = (st or {}).get("last_line")
    return v(round(time.time() - last, 1) if last else None, "MEASURED", "seconds since the last parsed syslog line",
             "a growing value while devices keep sending means the parser is behind")


# ------------------------------------------------------------------------------------------------ storage
GROUPS = [("Raw flows", lambda d, t: d == "default" and t == "flows"),
          ("Aggregated flows", lambda d, t: d == "default" and re.match(r"flows_\d", t) is not None and "raw" not in t),
          ("DNS events", lambda d, t: d == "netmon" and t.startswith("dns_")),
          ("Firewall, IDS and system events", lambda d, t: d == "netmon"),
          ("ClickHouse system logs", lambda d, t: d == "system"),
          ("Other", lambda d, t: True)]
TIME_COLS = ("TimeReceived", "received", "event_time", "hour", "ts")


def storage(ch, now=None):
    """Per table: size, rows, bytes/row, TTL, rows/day, projected size at its TTL. All MEASURED except projections."""
    now = now or time.time()
    parts = ch.query("SELECT database AS d, table AS t, sum(rows) AS rows, sum(bytes_on_disk) AS bytes, sum(data_compressed_bytes) AS comp, "
                     "sum(data_uncompressed_bytes) AS raw, max(bytes_on_disk) AS largest_part FROM system.parts WHERE active "
                     "AND database IN ('default', 'netmon', 'system') GROUP BY d, t", {})
    meta = {(r["database"], r["name"]): r for r in ch.query(
        "SELECT database, name, engine_full FROM system.tables WHERE database IN ('default', 'netmon', 'system')", {})}
    cols = {}
    for r in ch.query("SELECT database AS d, table AS t, name FROM system.columns WHERE database IN ('default', 'netmon', 'system') "
                      "AND name IN {c:Array(String)}", {"c": list(TIME_COLS)}):
        cols.setdefault((r["d"], r["t"]), set()).add(r["name"])
    out = []
    for p in parts:
        key = (p["d"], p["t"])
        if not p["rows"]:
            continue
        eng = (meta.get(key) or {}).get("engine_full", "")
        ttl = None
        m = re.search(r"TTL\s+\S+\s*\+\s*toInterval(Second|Day|Hour|Month)\((\d+)\)", eng)
        if m:
            ttl = int(m.group(2)) * {"Second": 1, "Hour": 3600, "Day": 86400, "Month": 30 * 86400}[m.group(1)] / 86400
        tcol = next((c for c in TIME_COLS if c in cols.get(key, ())), None)
        age_days, per_day = None, None
        if tcol:
            try:
                r = ch.query(f"SELECT toUInt32(min({tcol})) AS f, countIf({tcol} > now() - INTERVAL 1 DAY) AS d1 FROM {p['d']}.`{p['t']}`", {})[0]
                if r["f"]:
                    age_days = (now - r["f"]) / 86400
                    per_day = r["d1"] / min(1.0, age_days) if age_days > 0 else None
            except Exception:
                pass
        bpr = p["bytes"] / p["rows"]
        grp = next(g for g, f in GROUPS if f(p["d"], p["t"]))
        out.append({"db": p["d"], "table": p["t"], "group": grp, "rows": p["rows"], "bytes": p["bytes"], "bytes_per_row": bpr,
                    "compression": (p["raw"] / p["comp"]) if p["comp"] else None, "largest_part": p["largest_part"],
                    "ttl_days": ttl, "age_days": age_days, "rows_per_day": per_day,
                    "bytes_per_day": per_day * bpr if per_day is not None else None, "time_col": tcol,
                    "per_day_confidence": "low" if age_days is not None and age_days < 1 else "medium" if age_days is not None and age_days < 7 else "high"})
    return sorted(out, key=lambda x: -x["bytes"])


def project_storage(tables, retention=None, scale=1.0):
    """Steady-state size per table once data reaches its retention. retention: {group: days} overrides (raw/aggregated
    flows and log groups); ClickHouse system logs keep their own TTL. scale: workload multiplier."""
    retention = retention or {}
    out, total_now, total_ss = [], 0, 0
    for t in tables:
        days = retention.get(t["group"], t["ttl_days"])
        ss = t["bytes_per_day"] * scale * days if (t["bytes_per_day"] is not None and days) else None
        if ss is None:
            ss = t["bytes"] * scale        # no TTL or unknown rate: assume it stays as it is
        out.append({**t, "retention_days": days, "steady_state_bytes": ss})
        total_now += t["bytes"]
        total_ss += ss
    return out, total_now, total_ss


def disk_forecast(tables, fs_total, fs_used, retention=None, scale=1.0, reserve=0.15, kafka_bytes=0, horizon=3650):
    """Days until the data filesystem reaches (1-reserve) of its size, if ever. Each table grows by its measured daily
    volume until its retention, then stays flat. Other files on the filesystem stay as they are."""
    retention = retention or {}
    proj, now_b, ss_b = project_storage(tables, retention, scale)
    limit = fs_total * (1 - reserve)
    other = fs_used - now_b
    merge_reserve = max((t["largest_part"] for t in tables), default=0)

    def size_at(d):
        s = 0
        for t in proj:
            days = t["retention_days"]
            if t["bytes_per_day"] is None or not days:
                s += t["bytes"] * scale
                continue
            age = min(t["age_days"] or 0, days)
            s += t["bytes"] * (scale if age >= days else 1) + (t["bytes_per_day"] * scale * min(d, max(0.0, days - age)) if age < days else 0)
        return other + s + kafka_bytes + merge_reserve

    full = None
    if size_at(0) >= limit:
        full = 0
    else:
        lo, hi = 0, horizon
        if size_at(hi) >= limit:
            while hi - lo > 0.5:
                mid = (lo + hi) / 2
                lo, hi = (lo, mid) if size_at(mid) >= limit else (mid, hi)
            full = hi
    return {"days_until_limit": full, "limit_bytes": limit, "steady_state_bytes": other + ss_b + kafka_bytes + merge_reserve,
            "steady_state_frac": (other + ss_b + kafka_bytes + merge_reserve) / fs_total if fs_total else None,
            "other_bytes": other, "merge_reserve_bytes": merge_reserve, "reserve": reserve, "tables": proj}


# ------------------------------------------------------------------------------------------------ server capacity model
def cpu_model(ch, cfg, t0, t1, step=300):
    """Host CPU (fraction of all vCPUs) ~ a + b*flows/s + c*events/s over 5-minute buckets, robust fit. ESTIMATED.
    Valid only if load varied enough and the slopes are positive beyond 2 standard errors."""
    wl, _, res, _, err = series_or_empty(ch, cfg, t0, t1, step)
    if err:
        return {"valid": False, "reason": err, "n": 0}
    rows = [(wl[b].get("flows", 0.0), wl[b].get("events", 0.0), res[b]["cpu"]) for b in sorted(wl)
            if b in res and res[b].get("cpu") is not None and "flows" in wl[b]]
    return fit_cpu(rows)


def fit_cpu(rows):
    if len(rows) < 72:
        return {"valid": False, "reason": f"{len(rows)} five-minute samples; at least 72 (6 hours) are needed", "n": len(rows)}
    f = [r[0] for r in rows]
    ev = [r[1] for r in rows]
    y = [r[2] for r in rows]
    fit = robust_fit([[a, b] for a, b in zip(f, ev)], y)
    if not fit:
        return {"valid": False, "reason": "regression failed (no variation in the inputs)", "n": len(rows)}
    a, b, c = fit["coef"]
    sa, sb, sc = fit["se"]
    mean = lambda xs: sum(xs) / len(xs)  # noqa: E731
    cv = lambda xs: (math.sqrt(sum((x - mean(xs)) ** 2 for x in xs) / len(xs)) / mean(xs)) if mean(xs) else 0  # noqa: E731
    res = {"n": fit["n"], "intercept": a, "per_flow": b, "per_event": c, "se": [sa, sb, sc], "r2": fit["r2"],
           "flow_range": [min(f), max(f)], "event_range": [min(ev), max(ev)], "flow_cv": cv(f), "event_cv": cv(ev)}
    probs = []
    if not (b > 0 and b - 2 * sb > 0):
        probs.append("flow-rate effect on CPU not distinguishable from noise")
    if not (c > 0 and c - 2 * sc > 0):
        res["per_event"], res["event_effect"] = max(0.0, c), "not distinguishable from noise"
    if cv(f) < 0.1:
        probs.append(f"flow rate varied too little ({100 * cv(f):.0f}%) to measure its cost")
    res["valid"] = not probs
    res["reason"] = "; ".join(probs)
    return res


def server_capacity(obs, model, inv, headroom=0.3, storage_fc=None, benchmark=None):
    """Reverse calculation: how much more of the current workload mix fits before the first limit."""
    target = 1 - headroom
    fp, ep = (obs["flows"].get("p95") or 0), (obs["events"].get("p95") or 0)
    cpu_now = obs["cpu"].get("p95")
    limits, notes = {}, []
    out = {"target_cpu": target}
    if benchmark and benchmark.get("sustained_flows_per_s"):
        out["flows_capacity"] = v(benchmark["sustained_flows_per_s"], "BENCHMARKED", benchmark.get("id", "benchmark"),
                                  f"measured on {benchmark.get('cpu', '?')} with {benchmark.get('cpus', '?')} vCPU")
    if model.get("valid"):
        a, b, c = model["intercept"], model["per_flow"], model["per_event"]
        sb = model["se"][1]
        mix = b * fp + c * ep
        k = (target - a) / mix if mix > 0 else None
        k_lo = (target - a) / ((b + 2 * sb) * fp + c * ep) if fp else None
        k_hi = (target - a) / (max(1e-12, b - 2 * sb) * fp + c * ep) if fp else None
        if k is not None:
            limits["cpu"] = {"multiplier": k, "range": [k_lo, k_hi], "label": "ESTIMATED"}
        fmax = (target - a - c * ep) / b
        fmax_lo, fmax_hi = (target - a - c * ep) / (b + 2 * sb), (target - a - c * ep) / max(1e-12, b - 2 * sb)
        ext = fmax / max(1e-9, model["flow_range"][1])
        out.setdefault("flows_capacity", v(fmax, "ESTIMATED", "CPU regression on measured load",
                                           f"range {fmax_lo:,.0f}–{fmax_hi:,.0f} flow records/s at {100 * target:.0f}% CPU, "
                                           f"with today's log rate; {ext:.1f}x the highest 5-minute rate observed"))
        out["flows_capacity"]["range"] = [fmax_lo, fmax_hi]
        out["flows_capacity"]["extrapolation"] = ext
        if ext > 3:
            out["flows_capacity"]["note"] += " — extrapolated far beyond observed load: low confidence, run the benchmark harness"
        if c > 0 and model.get("event_effect") is None:
            emax = (target - a - b * fp) / c
            out["events_capacity"] = v(emax, "ESTIMATED", "CPU regression on measured load", f"at {100 * target:.0f}% CPU with today's flow rate")
        else:
            out["events_capacity"] = v(None, "UNKNOWN", "", "log-event cost not measurable from current data; run the benchmark harness")
    else:
        out.setdefault("flows_capacity", v(None, "UNKNOWN", "", f"no defensible model: {model.get('reason')}. Run the benchmark harness (bench/)."))
        out["events_capacity"] = v(None, "UNKNOWN", "", "see flow capacity")
    if cpu_now is not None:
        out["cpu_headroom"] = v(max(0.0, target - cpu_now), "MEASURED", "P95 host CPU vs target", f"P95 CPU {100 * cpu_now:.0f}%")
    io = obs["io_util"].get("p95")
    if io is not None:
        out["io_headroom"] = v(max(0.0, 0.8 - io), "ESTIMATED", "P95 disk busy time vs 80%",
                               "disk busy time from the kernel; on virtual or flash storage it understates the real limit")
        if io > 0:
            limits["disk_io"] = {"multiplier": 0.8 / io, "label": "ESTIMATED"}
    mem = obs["mem"].get("p95")
    if mem is not None:
        out["ram_headroom"] = v(max(0.0, 1 - mem), "MEASURED", "P95 memory in use",
                                "ClickHouse memory follows queries and merges more than ingest rate: not scaled with workload")
    if storage_fc:
        k_disk = disk_multiplier(storage_fc)
        if k_disk is not None:
            limits["disk_space"] = {"multiplier": k_disk, "label": "ESTIMATED"}
    known = {k: x for k, x in limits.items() if x.get("multiplier") is not None}
    if known:
        first = min(known, key=lambda k: known[k]["multiplier"])
        out["bottleneck"] = {"resource": first, "multiplier": known[first]["multiplier"], "limits": limits}
    else:
        out["bottleneck"] = {"resource": None, "limits": limits, "note": "no limit can be estimated from the current data"}
    out["notes"] = notes
    return out


GRADE_BANDS = ((75, "ample headroom"), (50, "comfortable"), (25, "tight: plan an upgrade"), (0, "undersized"))   # 4x, 2x, 1.33x headroom


def headroom_score(k):
    """Workload multiplier k (how many times today's load fits before the target) -> 0..100: 100 * (1 - 1/k).
    1x -> 0, 2x -> 50, 4x -> 75, 10x -> 90. Documented, monotonic, not a benchmark."""
    if k is None:
        return None
    return 0.0 if k <= 1 else round(100 * (1 - 1 / k), 1)


def hardware_grade(obs, cap, inv=None, fc=None, cpu_target=0.7, mem_target=0.85):
    """Current-hardware grade 0..100 (100 best) = the weakest resource's headroom score, with documented caps.
    ESTIMATED; UNKNOWN when fewer than two resources can be scored."""
    limits = (cap.get("bottleneck") or {}).get("limits") or {}
    comp = {}
    if "cpu" in limits:
        comp["cpu"] = (limits["cpu"]["multiplier"], "CPU model fitted on measured load")
    elif (obs.get("cpu") or {}).get("p95"):
        comp["cpu"] = (cpu_target / obs["cpu"]["p95"], f"measured P95 CPU vs a {100 * cpu_target:.0f}% target; assumes all CPU use grows with the workload")
    if (obs.get("mem") or {}).get("p95"):
        comp["memory"] = (mem_target / obs["mem"]["p95"], f"measured P95 memory vs a {100 * mem_target:.0f}% target; memory grows less than linearly with load")
    for k, name in (("disk_io", "disk I/O"), ("disk_space", "disk space")):
        if k in limits and limits[k].get("multiplier") is not None:
            comp[k] = (limits[k]["multiplier"], f"{name} multiplier from the capacity calculation")
    parts = {k: {"score": headroom_score(m), "multiplier": m, "basis": b} for k, (m, b) in comp.items()}
    if len(parts) < 2:
        return {"label": "UNKNOWN", "value": None, "components": parts, "note": "fewer than two resources could be measured"}
    weakest = min(parts, key=lambda k: parts[k]["score"])
    score, caps = parts[weakest]["score"], []
    dt = str(((inv or {}).get("disk_type") or {}).get("value") or "")
    if dt.upper().startswith("HDD"):
        score = min(score, 60)
        caps.append("rotational disk: capped at 60")
    steal = (obs.get("steal") or {}).get("p95")
    if steal is not None and steal > 0.05:
        score = max(0, score - 10)
        caps.append(f"CPU steal {100 * steal:.0f}% at P95 (host oversubscribed): -10")
    days = (fc or {}).get("days_until_limit")
    if days is not None and days < 30:
        score = min(score, 30)
        caps.append(f"disk limit reached in {days:.0f} days: capped at 30")
    conf = (obs.get("cpu") or {}).get("confidence") or "low"
    if obs.get("hardware_change"):
        caps.append(obs["hardware_change"]["note"])
    score = round(score)
    band = next(t for lo, t in GRADE_BANDS if score >= lo)
    return {"label": "ESTIMATED", "value": score, "band": band, "limited_by": weakest, "components": parts, "caps": caps,
            "confidence": conf, "note": "weakest resource's headroom: score = 100 x (1 - 1/k), k = how many times today's workload fits "
                                        "before that resource reaches its target"}


def disk_multiplier(fc):
    """Workload multiplier at which the steady-state size reaches the usable disk."""
    tabs = fc["tables"]
    var = sum(t["steady_state_bytes"] for t in tabs if t["bytes_per_day"] is not None and t["retention_days"])
    fixed = fc["steady_state_bytes"] - var
    if var <= 0:
        return None
    return (fc["limit_bytes"] - fixed) / var


# ------------------------------------------------------------------------------------------------ new installations
# The assumption model for "Plan a new installation". Generic assumptions, NOT vendor data or benchmarks: ranges are
# wide on purpose. docs/capacity-planning.md documents and explains each one. (low, high); "mid" = geometric mean.
ASSUME = {
    "util": {"light": (0.02, 0.05), "typical": (0.05, 0.15), "heavy": (0.15, 0.35), "very_heavy": (0.35, 0.6), "unknown": (0.02, 0.35)},
    "flows_per_mbps": (2.0, 50.0),           # flow records/s per Mb/s of AVERAGE traffic, 1:1 export, 60-120 s active timeout
    "peak_factor": (2.0, 4.0),               # busiest 1-minute rate / average
    "logs_per_fw": {"lightweight": (0.5, 20.0), "balanced": (2.0, 50.0), "detailed": (2.0, 50.0)},   # events/s per firewall
    "pass_log_ratio": (0.3, 1.0),            # detailed: pass-rule logging adds this many events per flow record
    "ids_per_fw": (0.001, 0.05),
    "clients": {"home_lab": (5, 30), "small_office": (10, 100), "medium": (100, 1000), "msp": (10, 200), "datacenter": (50, 2000),
                "enterprise": (1000, 20000)},
    "dns_qps_per_client": (0.02, 0.3),
    "zeek_per_flow": (0.5, 2.0),             # Zeek conn records per flow record seen on the mirror
    "bytes_per_row": {"flows": (8.0, 40.0), "flows_agg_frac": (0.03, 0.1), "events": (10.0, 40.0), "dns": (6.0, 30.0)},
    "system_logs_per_day": (0.2e9, 1.5e9),  # ClickHouse's own logs, bytes/day (30-day TTL)
}


def gmean(a, b):
    return math.sqrt(a * b) if a > 0 and b > 0 else (a + b) / 2


def suggest(answers, calib=None):
    """Suggested workload ranges from plain answers (docs/capacity-planning.md#assumption-model).
    calib: locally measured ratios ({'flows_per_mbps': x, 'logs_per_fw': y}) narrow the ranges when present."""
    calib = calib or {}
    n = max(1, int(answers.get("devices") or 1))
    link = float(answers.get("link_mbps") or 1000)
    act = answers.get("activity") or "unknown"
    detail = answers.get("detail") or "balanced"
    feats = set(answers.get("features") or ["flows", "syslog", "snmp", "ids", "behavioral"])
    u_lo, u_hi = ASSUME["util"].get(act, ASSUME["util"]["unknown"])
    mb_lo, mb_hi = link * u_lo * n, link * u_hi * n
    used = []
    if calib.get("flows_per_mbps"):
        r = calib["flows_per_mbps"]
        fpm = (r * 0.5, r * 2)
        used.append(f"flow records per Mb/s calibrated from this installation ({r:.1f}), range x0.5–x2")
    else:
        fpm = ASSUME["flows_per_mbps"]
    flows = (mb_lo * fpm[0], mb_hi * fpm[1]) if "flows" in feats else (0, 0)
    lp = ASSUME["logs_per_fw"][detail]
    if calib.get("logs_per_fw"):
        lp = (calib["logs_per_fw"] * 0.5, calib["logs_per_fw"] * 2)
        used.append(f"log events per firewall calibrated from this installation ({calib['logs_per_fw']:.1f}/s)")
    ev = (n * lp[0], n * lp[1]) if "syslog" in feats else (0, 0)
    if detail == "detailed" and "syslog" in feats:
        ev = (ev[0] + flows[0] * ASSUME["pass_log_ratio"][0], ev[1] + flows[1] * ASSUME["pass_log_ratio"][1])
    ids = (n * ASSUME["ids_per_fw"][0], n * ASSUME["ids_per_fw"][1]) if "ids" in feats else (0, 0)
    cl = ASSUME["clients"].get(answers.get("network") or "small_office", (10, 100))
    per_net = n if answers.get("network") == "msp" else 1
    dns = (cl[0] * per_net * ASSUME["dns_qps_per_client"][0], cl[1] * per_net * ASSUME["dns_qps_per_client"][1]) if "dns" in feats else (0, 0)
    zeek = (flows[0] * ASSUME["zeek_per_flow"][0], flows[1] * ASSUME["zeek_per_flow"][1]) if "zeek" in feats else (0, 0)
    rng = lambda lo, hi: {"low": lo, "mid": gmean(lo, hi), "high": hi, "label": "SUGGESTED"}  # noqa: E731
    pf = ASSUME["peak_factor"]
    out = {"throughput_avg_mbps": rng(mb_lo, mb_hi), "flows": rng(*flows), "flows_peak": rng(flows[0] * pf[0], flows[1] * pf[1]),
           "events": rng(ev[0] + ids[0], ev[1] + ids[1]), "dns": rng(*dns), "zeek": rng(*zeek), "devices": n,
           "calibrated": used, "assumptions": assumption_text(answers, (u_lo, u_hi), fpm, lp)}
    return out


def assumption_text(a, util, fpm, lp):
    return [f"average traffic = {100 * util[0]:.0f}–{100 * util[1]:.0f}% of the connection speed ({a.get('activity') or 'unknown'} activity)",
            f"{fpm[0]:g}–{fpm[1]:g} flow records/s per Mb/s of average traffic (1:1 export, 60–120 s active timeout); "
            "connection mix matters more than speed: many small connections (DNS, scans, IoT) raise it, bulk transfers lower it",
            f"busiest minute = {ASSUME['peak_factor'][0]:g}–{ASSUME['peak_factor'][1]:g}x the average",
            f"{lp[0]:g}–{lp[1]:g} stored log events/s per firewall ({a.get('detail') or 'balanced'} logging)"
            + ("; detailed adds 0.3–1 event per flow record (pass-rule logging)" if a.get("detail") == "detailed" else ""),
            "these are generic planning assumptions, not measurements or vendor figures: replace them with measured values as soon as data exists"]


def storage_plan(rates, retention_days, bpr=None, agg_days=None):
    """Bytes for raw flows, aggregated flows, events and DNS at the given rates (records/s) and retention."""
    bpr = bpr or {}

    def b(k, i):
        x = bpr.get(k)
        if isinstance(x, (tuple, list)):
            x = x[i]
        elif isinstance(x, dict):
            x = x.get(i)
        return float(x) if x else ASSUME["bytes_per_row"][k][i]
    out = {}
    for lvl, i in (("low", 0), ("high", 1)):
        fl = rates["flows"][lvl] * 86400
        raw = fl * b("flows", i) * retention_days
        agg = raw * ASSUME["bytes_per_row"]["flows_agg_frac"][i] * ((agg_days or 365) / max(1, retention_days))
        ev = rates["events"][lvl] * 86400 * b("events", i) * min(retention_days, 90)
        dns = rates["dns"][lvl] * 86400 * b("dns", i) * min(retention_days, 30)
        sysl = ASSUME["system_logs_per_day"][i] * 30
        out[lvl] = {"raw_flows": raw, "aggregated_flows": agg, "events": ev, "dns": dns, "system_logs": sysl,
                    "total": raw + agg + ev + dns + sysl}
    return out


def calibration_ratios(obs):
    """Local ratios that calibrate the suggestion model: flow records per Mb/s, log events per firewall."""
    out = {}
    tp = obs.get("throughput_snmp") if obs.get("throughput_snmp", {}).get("avg") else obs.get("throughput_flow")
    if tp and tp.get("avg") and obs["flows"].get("avg") and obs["flows"].get("confidence") != "low":
        out["flows_per_mbps"] = obs["flows"]["avg"] / (tp["avg"] / 1e6)
    fw = obs["counts"].get("firewalls") or 0
    ev = obs["event_tables"].get("fw_events", {})
    if fw and ev.get("avg") and ev.get("confidence") != "low":
        out["logs_per_fw"] = ev["avg"] / fw
    return out


# ------------------------------------------------------------------------------------------------ calibration history
CAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS capacity_calib (ts REAL NOT NULL, metric TEXT NOT NULL, predicted REAL, actual REAL, window_s REAL,
  confidence TEXT, note TEXT);
CREATE INDEX IF NOT EXISTS capacity_calib_i ON capacity_calib(metric, ts);
CREATE TABLE IF NOT EXISTS fw_resources (device TEXT NOT NULL, ts REAL NOT NULL, cpu REAL, mem REAL, load1 REAL, extra TEXT);
CREATE INDEX IF NOT EXISTS fw_resources_i ON fw_resources(device, ts);
CREATE TABLE IF NOT EXISTS fw_hardware (device TEXT NOT NULL, field TEXT NOT NULL, value TEXT, source TEXT, ts REAL,
  PRIMARY KEY (device, field, source));
"""


def init(conn):
    conn.executescript(CAL_SCHEMA)


def record_calibration(conn, ch, cfg):
    """Once a day: yesterday's predictions vs what was measured since, kept locally (never sent anywhere)."""
    last, _ = get_state(conn, "capacity:calib", None)
    now = time.time()
    if last and now - last.get("ts", 0) < 86400:
        return None
    t0 = now - 86400
    try:
        obs1 = observe(ch, cfg, conn, "24h")
        if obs1.get("error"):
            raise RuntimeError(obs1["error"])
        tabs = storage(ch)
    except Exception as ex:
        set_state(conn, "capacity:calib", {"ts": now, "error": str(ex)[:200], "pred": (last or {}).get("pred")})
        return None
    rows = []
    pred = (last or {}).get("pred") or {}
    actual = {"flows": obs1["flows"].get("avg"), "events": obs1["events"].get("avg"),
              "storage_per_day": sum(t["bytes_per_day"] or 0 for t in tabs), "cpu_p95": obs1["cpu"].get("p95")}
    for k, a in actual.items():
        if a is not None:
            rows.append((now, k, pred.get(k), a, 86400, obs1["flows"].get("confidence"), ""))
    plan = get_setting(conn, "capacity:plan", {}) or {}
    sug = (plan.get("suggested") or {})
    for k in ("flows", "events"):
        if sug.get(k) and actual.get(k) is not None:
            rows.append((now, f"suggested_{k}", sug[k].get("mid"), actual[k], 86400, "", f"suggested range {sug[k]['low']:.0f}–{sug[k]['high']:.0f}"))
    conn.executemany("INSERT INTO capacity_calib VALUES (?,?,?,?,?,?,?)", rows)
    conn.execute("DELETE FROM capacity_calib WHERE ts < ?", (now - 400 * 86400,))
    conn.commit()
    set_state(conn, "capacity:calib", {"ts": now, "pred": actual, "ratios": calibration_ratios(obs1), "since": t0})
    return rows


def calibration_history(conn, metric=None, limit=60):
    q = "SELECT * FROM capacity_calib" + (" WHERE metric=?" if metric else "") + " ORDER BY ts DESC LIMIT ?"
    return [dict(r) for r in conn.execute(q, ((metric, limit) if metric else (limit,))).fetchall()]


def local_calibration(conn):
    st, ts = get_state(conn, "capacity:calib", None)
    return (st or {}).get("ratios") or {}, ts


# ------------------------------------------------------------------------------------------------ forecasting
def forecasts(obs, fc, model_cap, fw_items=()):
    """Specific, evidence-backed statements. Each carries the numbers it rests on."""
    out = []
    d = fc.get("days_until_limit")
    if d is not None and d < 3650:
        out.append({"level": "warn" if d < 60 else "info", "label": "ESTIMATED",
                    "text": f"At the measured daily volume and current retention, the data disk reaches {100 * (1 - fc['reserve']):.0f}% "
                            f"in about {d:.0f} days.", "basis": "per-table measured rows/day x bytes/row, growing until each table's TTL"})
    elif fc.get("steady_state_frac") is not None:
        out.append({"level": "ok", "label": "ESTIMATED",
                    "text": f"At current rates the data settles at about {100 * fc['steady_state_frac']:.0f}% of the disk once every table "
                            "has reached its retention.", "basis": "measured daily volume x retention"})
    for k, name in (("flows", "Flow ingestion"), ("events", "Log event ingestion")):
        tr = obs.get(f"{k}_trend")
        if tr and tr.get("pct") is not None and abs(tr["pct"]) >= 10 and tr.get("days", 0) >= 2:
            out.append({"level": "info", "label": "MEASURED",
                        "text": f"{name} changed {tr['pct']:+.0f}% over the {tr['days']:.0f}-day measurement period (daily medians, robust slope).",
                        "basis": "Theil-Sen slope of daily median rates"})
    cpu = obs.get("cpu", {})
    if cpu.get("p95") is not None and cpu["p95"] > 0.7:
        out.append({"level": "warn", "label": "MEASURED", "text": f"Host CPU P95 is {100 * cpu['p95']:.0f}%: little headroom at busy times.",
                    "basis": "ClickHouse asynchronous_metric_log, 1-minute averages"})
    lag = obs.get("kafka_lag", {}).get("value")
    if lag is not None and lag > 100000:
        out.append({"level": "warn", "label": "MEASURED", "text": f"The flow queue is {lag:,.0f} messages behind: ClickHouse inserts are not keeping up.",
                    "basis": "Akvorado outlet consumer-group lag"})
    b = (model_cap or {}).get("bottleneck") or {}
    if b.get("resource"):
        out.append({"level": "info", "label": "ESTIMATED",
                    "text": f"First likely limit: {BOTTLENECK_NAME.get(b['resource'], b['resource'])}, at about {b['multiplier']:.1f}x today's workload.",
                    "basis": "smallest multiplier across CPU model, disk space and disk I/O"})
    for it in fw_items:
        out.append(it)
    return out


BOTTLENECK_NAME = {"cpu": "CPU", "disk_space": "disk space", "disk_io": "disk I/O", "ram": "memory"}


def daily_trend(series):
    """{bucket: rate} -> % change per measured period from daily medians (robust). None if < 2 days."""
    days = {}
    for b, x in series.items():
        days.setdefault(b // 86400, []).append(x)
    pts = [(d * 86400, pctl(xs, 50)) for d, xs in sorted(days.items()) if len(xs) >= 60]
    if len(pts) < 3:
        return None
    s = theil_sen(pts)
    if s is None:
        return None
    span = (pts[-1][0] - pts[0][0]) / 86400
    base = pctl([p[1] for p in pts], 50)
    return {"pct": 100 * s * 86400 * span / base if base else None, "days": span + 1}


# ------------------------------------------------------------------------------------------------ background sampler
def scrape_export(cfg, prev):
    """Per exporter address: UDP bytes received (inlet) and flows decoded (outlet). Deltas between two scrapes give
    measured bytes on the wire per flow record; lifetime totals are not used (the two processes restart separately)."""
    import httpx
    from .health import prom
    urls = cfg.get("akvorado_metrics", {"inlet": "http://akvorado-inlet:8080/api/v0/inlet/metrics",
                                        "outlet": "http://akvorado-outlet:8080/api/v0/outlet/metrics"})
    if not urls:
        return None, {}
    i = prom(httpx.get(urls["inlet"], timeout=5).text)
    o = prom(httpx.get(urls["outlet"], timeout=5).text)
    cur = {"ts": time.time(), "bytes": {}, "packets": {}, "flows": {}}
    for (name, labels), val in i.items():
        ex = dict(labels).get("exporter")
        if ex and name == "akvorado_inlet_flow_input_udp_bytes_total":
            cur["bytes"][ex] = cur["bytes"].get(ex, 0) + val
        if ex and name == "akvorado_inlet_flow_input_udp_packets_total":
            cur["packets"][ex] = cur["packets"].get(ex, 0) + val
    for (name, labels), val in o.items():
        ex = dict(labels).get("exporter")
        if ex and name == "akvorado_outlet_core_received_flows_total":
            cur["flows"][ex] = cur["flows"].get(ex, 0) + val
    wire = {}
    if prev:
        for ex, b in cur["bytes"].items():
            db, df = b - prev["bytes"].get(ex, 0), cur["flows"].get(ex, 0) - prev["flows"].get(ex, 0)
            dp = cur["packets"].get(ex, 0) - prev["packets"].get(ex, 0)
            if db > 0 and df > 100 and dp > 0:      # both counters moved forward: no restart in between
                wire[ex] = {"bytes_per_record": db / df, "records_per_packet": df / dp, "interval_s": cur["ts"] - prev["ts"]}
    return cur, wire


def syslog_line_bytes(log_dir=None, sample=1 << 20):
    """Average line length from the start of the newest syslog file (a 1 MiB sample). MEASURED (sampled)."""
    log_dir = log_dir or os.environ.get("NETMON_SYSLOG_DIR", "/var/log/netmon")
    files = sorted(glob.glob(os.path.join(log_dir, "*.log")), key=os.path.getmtime)
    if not files:
        return None
    try:
        with open(files[-1], "rb") as f:
            data = f.read(sample)
    except OSError:
        return None
    lines = data.count(b"\n")
    return round(len(data[: data.rfind(b"\n") + 1]) / lines) if lines > 50 else None


class Sampler:
    """Every 5 minutes: export wire size per exporter, syslog line size, daily calibration record."""

    def __init__(self, cfg, conn_factory, ch):
        self.cfg, self.conn_factory, self.ch = cfg, conn_factory, ch

    def run(self):
        conn = self.conn_factory()
        init(conn)
        prev = None
        while True:
            try:
                cur, wire = scrape_export(self.cfg, prev)
                if wire:
                    old, _ = get_state(conn, "capacity:wire", {})
                    set_state(conn, "capacity:wire", {**(old or {}), **wire})
                prev = cur
            except Exception:
                prev = None
            try:
                lb = syslog_line_bytes()
                if lb:
                    set_state(conn, "capacity:line_bytes", lb)
            except Exception:
                pass
            try:
                record_calibration(conn, self.ch, self.cfg)
            except Exception:
                pass
            time.sleep(300)

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
