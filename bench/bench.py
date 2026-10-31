#!/usr/bin/env python3
"""m0nitor benchmark harness. Explicitly initiated only; never runs on its own. Standard library + the docker CLI.

  bench.py component [--cpus 4] [--memory 4g] [--rate 500] [--hours 24] [--out DIR]
      Isolated: a throwaway ClickHouse container (same image as the stack, --network none, CPU/RAM capped, own volume,
      removed afterwards) and the netmon image's syslog parser (--network none, 1 CPU). Synthetic data only.
      Measures: storage-layer insert rate, bytes per row, dashboard-style query latency, syslog lines parsed per second
      per core. It does NOT measure end-to-end flow capacity (no UDP decoding, Kafka or Akvorado outlet), so it never
      writes sustained_flows_per_s and the Capacity Planner keeps CPU capacity UNKNOWN on its account.

  bench.py pipeline --inlet HOST:PORT --clickhouse-container NAME --i-confirm-isolated-stack
                    [--kind netflow9] [--rates 500,1000,2000,4000] [--step-seconds 60] [--out DIR]
      End to end against a NON-PRODUCTION install (synthetic records would mix with real data otherwise): sends paced
      synthetic flows (flowgen.py) at each rate and counts the rows that reach that stack's ClickHouse. sustained_flows_per_s
      is the highest rate with < 1 % loss and no growing backlog. Only this mode feeds the planner's BENCHMARKED figures.

Results: one JSON file per run in --out (default /opt/netmon/data/benchmarks, read by Settings -> Capacity planner).
The file records hardware, versions, workload, duration, ingested vs dropped, throughput and query latency, and
whether other workloads shared the host (results from a shared host are a lower bound).
"""
import argparse
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import flowgen  # noqa: E402

CH_IMAGE = "clickhouse/clickhouse-server:26.3"
NAME = "m0nitor-bench-ch"
VOLUME = "m0nitor-bench-ch-data"
PROD_HINTS = ("akvorado-clickhouse-1",)


def sh(*args, input=None, check=True, timeout=600):
    r = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(args[:4])}...: {r.stderr.strip()[:400]}")
    return r.stdout


def chq(container, sql, fmt="TSV", input=None, tag=None):
    tagged = ("--log_comment", tag) if tag else ()
    return sh("docker", "exec", "-i", container, "clickhouse-client", "--format", fmt, *tagged, "-q", sql, input=input)


def server_ms(container, prefix):
    """Server-side durations (system.query_log) of the queries tagged prefix*: excludes docker exec and client start-up."""
    chq(container, "SYSTEM FLUSH LOGS")
    out = {}
    for line in chq(container, "SELECT log_comment, query_duration_ms FROM system.query_log WHERE type = 'QueryFinish' "
                               f"AND log_comment LIKE '{prefix}%' ORDER BY event_time_microseconds").splitlines():
        tag, ms = line.split("\t")
        out.setdefault(tag.split("#")[0], []).append(float(ms))
    return out


def hardware():
    model = None
    with open("/proc/cpuinfo") as f:
        for line in f:
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    mem = 0
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemTotal:"):
                mem = int(line.split()[1]) * 1024
    hv = None
    try:
        hv = sh("systemd-detect-virt", check=False).strip() or None
    except (OSError, subprocess.SubprocessError):
        pass
    disk = None
    try:
        with open("/opt/netmon/data/hostinfo.json") as f:
            hi = json.load(f)
        disk = [{k: d.get(k) for k in ("name", "model", "rota", "size")} for d in hi.get("disks", [])]
    except (OSError, ValueError):
        pass
    return {"cpu_model": model, "cpus": os.cpu_count(), "ram_bytes": mem, "virtualization": hv if hv != "none" else None,
            "disks": disk, "kernel": platform.release()}


def host_load():
    with open("/proc/loadavg") as f:
        la = [float(x) for x in f.read().split()[:3]]
    others = [n for n in sh("docker", "ps", "--format", "{{.Names}}").split() if not n.startswith("m0nitor-bench")]
    return {"loadavg": la, "other_containers": len(others)}


def app_image():
    for p in (os.path.join(HERE, "..", "app", "docker-compose.yml"), "/opt/netmon/app/docker-compose.yml"):
        try:
            m = re.search(r"image:\s*(netmon-app:[\w.]+)", open(p).read())
            if m:
                return m.group(1)
        except OSError:
            continue
    return None


def preflight(need_disk_gb, need_ram_gb, data_dir="/var/lib/docker"):
    free = shutil.disk_usage(data_dir if os.path.exists(data_dir) else "/").free
    with open("/proc/meminfo") as f:
        avail = next(int(line.split()[1]) * 1024 for line in f if line.startswith("MemAvailable:"))
    probs = []
    if free < need_disk_gb * 1e9:
        probs.append(f"only {free / 1e9:.0f} GB free for Docker, {need_disk_gb} GB needed")
    if avail < need_ram_gb * 1e9:
        probs.append(f"only {avail / 1e9:.1f} GB RAM available, {need_ram_gb} GB needed")
    return probs


def write(out_dir, res):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{res['scope']}-{time.strftime('%Y%m%d-%H%M%S', time.gmtime(res['ts']))}.json")
    with open(path, "w") as f:
        json.dump(res, f, indent=1)
    os.chmod(path, 0o644)
    return path


# ------------------------------------------------------------------------------------------------ component
INSERT = """INSERT INTO flows (TimeReceived, SamplingRate, ExporterAddress, ExporterName, SrcAddr, DstAddr, SrcNetMask, DstNetMask,
 SrcAS, DstAS, SrcCountry, DstCountry, InIfName, OutIfName, InIfSpeed, OutIfSpeed, InIfBoundary, OutIfBoundary, EType, Proto,
 SrcPort, DstPort, Bytes, Packets, ForwardingStatus, TCPFlags)
SELECT toDateTime({t0} + intDiv(number + {off}, {rate})) AS t, 1, toIPv6('::ffff:192.0.2.1'), 'bench-fw',
 if(o, toIPv6(IPv4NumToString(toUInt32(174260224 + rand(1) % 65536))), toIPv6(IPv4NumToString(toUInt32(3325256704 + rand(2) % 256)))),
 if(o, toIPv6(IPv4NumToString(toUInt32(3325256704 + rand(3) % 256))), toIPv6(IPv4NumToString(toUInt32(174260224 + rand(4) % 65536)))),
 24, 24, if(o, 0, 64496 + rand(5) % 10), if(o, 64496 + rand(6) % 10, 0), if(o, '', ['US', 'DE', 'NL', 'GB'][1 + rand(7) % 4]),
 if(o, ['US', 'DE', 'NL', 'GB'][1 + rand(8) % 4], ''), if(o, 'igb1', 'igb0'), if(o, 'igb0', 'igb1'), 1000, 1000,
 if(o, 'internal', 'external'), if(o, 'external', 'internal'), 2048, [6, 6, 6, 17][1 + rand(9) % 4],
 if(o, 1024 + rand(10) % 64000, [53, 80, 443, 443, 993][1 + rand(11) % 5]), if(o, [53, 80, 443, 443, 993][1 + rand(12) % 5], 1024 + rand(13) % 64000),
 64 + rand(14) % 200000, 1 + rand(15) % 200, 64, 24
FROM (SELECT number, rand(0) % 2 = 0 AS o FROM numbers({n}))"""

QUERIES = {
    "traffic_per_minute_1h": "SELECT toStartOfMinute(TimeReceived) m, sum(Bytes * SamplingRate) FROM flows WHERE TimeReceived > {t1} - 3600 GROUP BY m ORDER BY m",
    "top_destinations_1h": "SELECT DstAddr, sum(Bytes) b FROM flows WHERE TimeReceived > {t1} - 3600 GROUP BY DstAddr ORDER BY b DESC LIMIT 20",
    "top_ports_24h": "SELECT Proto, DstPort, count() c FROM flows WHERE TimeReceived > {t1} - 86400 GROUP BY Proto, DstPort ORDER BY c DESC LIMIT 20",
    "host_lookup_24h": "SELECT count(), sum(Bytes) FROM flows WHERE TimeReceived > {t1} - 86400 AND (SrcAddr = toIPv6('::ffff:10.99.0.7') OR DstAddr = toIPv6('::ffff:10.99.0.7'))",
    "countries_24h": "SELECT SrcCountry, DstCountry, sum(Bytes) b FROM flows WHERE TimeReceived > {t1} - 86400 GROUP BY SrcCountry, DstCountry ORDER BY b DESC LIMIT 20",
}

PARSER = r"""
import json, sys, time, random
sys.path.insert(0, '/bench')
import flowgen
from netmon.logingest import parse_line
rng = random.Random(3); now = time.time()
lines = [f"{int(now)} 10.40.0.1 " + flowgen.filterlog_line(rng, now) for _ in range(20000)]
ok = sum(1 for l in lines if parse_line(l, lambda ip: 'bench')[0] == 'fw_events')
n, t0 = 0, time.perf_counter()
while time.perf_counter() - t0 < float(sys.argv[1]):
    for l in lines:
        parse_line(l, lambda ip: 'bench')
    n += len(lines)
dt = time.perf_counter() - t0
print(json.dumps({"lines": n, "seconds": dt, "lines_per_s": n / dt, "parse_ok_frac": ok / len(lines)}))
"""


def component(a):
    probs = preflight(need_disk_gb=max(10, a.rate * a.hours * 3600 * 60 / 1e9 * 3), need_ram_gb=float(a.memory.rstrip("g")) + 1)
    if probs:
        sys.exit("refusing to start: " + "; ".join(probs))
    hw, before = hardware(), host_load()
    image = app_image()
    notes = ["synthetic records from documentation/private address ranges; real traffic compresses differently",
             "server-side INSERT ... SELECT batches: the storage ceiling, not end-to-end ingestion (no UDP decode, Kafka or outlet)"]
    sh("docker", "rm", "-f", NAME, check=False)
    sh("docker", "volume", "rm", "-f", VOLUME, check=False)
    started = time.time()
    try:
        sh("docker", "run", "-d", "--name", NAME, "--network", "none", "--hostname", "localhost", "--cpus", str(a.cpus), "--memory", a.memory,
           "-v", f"{VOLUME}:/var/lib/clickhouse", "-e", "CLICKHOUSE_SKIP_USER_SETUP=1", CH_IMAGE)
        for _ in range(60):
            if sh("docker", "exec", NAME, "clickhouse-client", "-q", "SELECT 1", check=False).strip() == "1":
                break
            time.sleep(1)
        else:
            raise RuntimeError("benchmark ClickHouse did not start")
        ch_version = chq(NAME, "SELECT version()").strip()
        ddl = open(os.path.join(HERE, "flows_schema.sql")).read().split("\n", 1)[1]
        chq(NAME, ddl.rstrip() + ", allow_suspicious_low_cardinality_types = 1")   # as Akvorado creates it
        total = int(a.rate * a.hours * 3600)
        t1 = int(time.time())
        t0 = t1 - int(a.hours * 3600)
        batch = a.batch
        lat, done = [], 0
        ins0 = time.perf_counter()
        while done < total:
            n = min(batch, total - done)
            s = time.perf_counter()
            chq(NAME, INSERT.format(t0=t0, off=done, rate=a.rate, n=n), tag="ins")
            lat.append(time.perf_counter() - s)
            done += n
        ins_s = time.perf_counter() - ins0
        parts_end = int(chq(NAME, "SELECT count() FROM system.parts WHERE table = 'flows' AND active").strip())
        time.sleep(10)
        rows = int(chq(NAME, "SELECT count() FROM flows").strip())
        size = chq(NAME, "SELECT sum(bytes_on_disk), sum(data_uncompressed_bytes) FROM system.parts WHERE table = 'flows' AND active").split()
        wall = {}
        for name, q in QUERIES.items():
            for i in range(a.repeats):
                s = time.perf_counter()
                chq(NAME, q.format(t1=t1), fmt="Null", tag=f"q:{name}#{i}")
                wall.setdefault(name, []).append((time.perf_counter() - s) * 1000)
        srv = server_ms(NAME, "q:")
        ins_srv = server_ms(NAME, "ins").get("ins", [])
        qres = {n: {"server_p50_ms": round(statistics.median(srv.get(f"q:{n}", [0])), 1), "server_max_ms": round(max(srv.get(f"q:{n}", [0])), 1),
                    "wall_p50_ms": round(statistics.median(w), 1), "runs": len(w)} for n, w in wall.items()}
        parser = None
        if image:
            out = sh("docker", "run", "--rm", "--network", "none", "--cpus", "1", "-v", f"{HERE}:/bench:ro", "--entrypoint", "python",
                     image, "-c", PARSER, str(a.parse_seconds))
            parser = json.loads(out.strip().splitlines()[-1])
        else:
            notes.append("netmon image not found: syslog parser not measured")
    finally:
        sh("docker", "rm", "-f", NAME, check=False)
        sh("docker", "volume", "rm", "-f", VOLUME, check=False)
    after = host_load()
    shared = before["other_containers"] > 0
    if shared:
        notes.append(f"{before['other_containers']} other containers were running on this host: treat the figures as a lower bound")
    res = {"scope": "component", "ts": time.time(), "duration_s": round(time.time() - started, 1),
           "hardware": {**hw, "bench_cpus": a.cpus, "bench_memory": a.memory},
           "versions": {"clickhouse": ch_version, "clickhouse_image": CH_IMAGE, "netmon_image": image, "bench": "1"},
           "workload": {"simulated_flows_per_s": a.rate, "simulated_hours": a.hours, "rows": total, "insert_batch_rows": batch,
                        "syslog": "OPNsense filterlog RFC 5424 (flowgen.filterlog_line)"},
           "environment": {"before": before, "after": after, "shared_host": shared},
           "result": {"ingested_rows": rows, "dropped_rows": total - rows,
                      "ch_insert_rows_per_s": round(total / ins_s),
                      "ch_insert_rows_per_s_server": round(total / (sum(ins_srv) / 1000)) if ins_srv else None,
                      "insert_batch_server_p50_ms": round(statistics.median(ins_srv), 1) if ins_srv else None,
                      "insert_batch_wall_p50_ms": round(statistics.median(lat) * 1000, 1), "active_parts_after_insert": parts_end,
                      "bytes_on_disk": int(size[0]), "bytes_per_row": round(int(size[0]) / max(1, rows), 2),
                      "compression_ratio": round(int(size[1]) / max(1, int(size[0])), 2), "queries": qres,
                      "syslog_parse_lines_per_s_per_core": round(parser["lines_per_s"]) if parser else None,
                      "syslog_parse_ok_frac": parser["parse_ok_frac"] if parser else None},
           "notes": notes + ["wall_* timings include docker exec and clickhouse-client start-up; server_* come from system.query_log",
                             "ch_insert_rows_per_s is wall-clock over the whole insert phase (sequential batches, background merges running)"]}
    print(json.dumps(res, indent=1))
    print("wrote", write(a.out, res), file=sys.stderr)


# ------------------------------------------------------------------------------------------------ pipeline
def pipeline(a):
    if not a.i_confirm_isolated_stack:
        sys.exit("pipeline mode writes synthetic flows into the target stack; pass --i-confirm-isolated-stack for a non-production install")
    if a.clickhouse_container in PROD_HINTS and not a.allow_default_names:
        sys.exit(f"{a.clickhouse_container} is the default production container name; run the benchmark stack under its own "
                 "compose project name (or pass --allow-default-names on a dedicated benchmark host)")
    hw, before = hardware(), host_load()
    ch = a.clickhouse_container
    ver = chq(ch, "SELECT version()").strip()
    steps, best = [], None
    started = time.time()
    for rate in [float(x) for x in a.rates.split(",")]:
        c0 = int(chq(ch, "SELECT count() FROM flows").strip())
        s = flowgen.send(a.kind, a.inlet, rate, a.step_seconds)
        time.sleep(a.settle)
        c1 = int(chq(ch, "SELECT count() FROM flows").strip())
        time.sleep(10)
        c2 = int(chq(ch, "SELECT count() FROM flows").strip())
        got = c2 - c0
        loss = max(0.0, 1 - got / s["records"]) if s["records"] else None
        step = {"target_rate": rate, "sent": s["records"], "achieved_send_rate": s["achieved_rate"], "ingested": got,
                "dropped": max(0, s["records"] - got), "loss_frac": round(loss, 4) if loss is not None else None,
                "still_arriving_after_settle": c2 - c1, "send_errors": s["send_errors"]}
        steps.append(step)
        print(json.dumps(step), file=sys.stderr)
        sender_ok = s["achieved_rate"] >= 0.97 * rate
        if loss is not None and loss < 0.01 and step["still_arriving_after_settle"] == 0 and sender_ok:
            best = rate
        elif not sender_ok:
            step["note"] = "the generator could not reach this rate on this host; run flowgen from a second machine"
            break
        else:
            break
    after = host_load()
    res = {"scope": "pipeline", "ts": time.time(), "duration_s": round(time.time() - started, 1),
           "hardware": {**hw, "bench_cpus": hw["cpus"]},
           "versions": {"clickhouse": ver, "netmon_image": app_image(), "bench": "1"},
           "workload": {"kind": a.kind, "step_seconds": a.step_seconds, "rates": a.rates},
           "environment": {"before": before, "after": after, "shared_host": before["other_containers"] > 0,
                           "generator_on_same_host": True},
           "result": {"steps": steps, **({"sustained_flows_per_s": best} if best else {})},
           "notes": ["synthetic flows; the generator shares CPU with the stack when run on the same host (a lower bound)"]}
    print(json.dumps(res, indent=1))
    print("wrote", write(a.out, res), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="mode", required=True)
    c = sp.add_parser("component")
    c.add_argument("--cpus", type=float, default=4)
    c.add_argument("--memory", default="4g")
    c.add_argument("--rate", type=int, default=500, help="simulated flow records/s (sets the dataset size)")
    c.add_argument("--hours", type=float, default=24, help="simulated hours of data")
    c.add_argument("--batch", type=int, default=100000, help="rows per INSERT")
    c.add_argument("--repeats", type=int, default=7)
    c.add_argument("--parse-seconds", type=float, default=10)
    c.add_argument("--out", default="/opt/netmon/data/benchmarks")
    p = sp.add_parser("pipeline")
    p.add_argument("--inlet", required=True)
    p.add_argument("--clickhouse-container", required=True)
    p.add_argument("--kind", default="netflow9", choices=("netflow5", "netflow9", "ipfix"))
    p.add_argument("--rates", default="500,1000,2000,4000,8000")
    p.add_argument("--step-seconds", type=float, default=60)
    p.add_argument("--settle", type=float, default=30)
    p.add_argument("--i-confirm-isolated-stack", action="store_true")
    p.add_argument("--allow-default-names", action="store_true")
    p.add_argument("--out", default="/opt/netmon/data/benchmarks")
    a = ap.parse_args()
    (component if a.mode == "component" else pipeline)(a)


if __name__ == "__main__":
    main()
