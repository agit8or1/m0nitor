"""Firewall / device hardware and resource discovery (read-only SNMP), manual values, and per-device capacity.

Discovery order (docs/firewall-resource-requirements.md):
  1. the device's existing SNMP configuration (SNMPv3 authPriv preferred, v2c with a warning) — GETs plus small table walks
     of HOST-RESOURCES-MIB and IF-MIB, and vendor MIB scalars where the sysObjectID identifies the vendor;
  2. metrics m0nitor already collects (UCD-SNMP CPU/memory samples, interface counters, flow and log rates);
  3. manual values. Manual values are never overwritten by discovery; both are kept and shown.
No vendor REST API adapter is implemented (OPNsense's diagnostics endpoints exist but need a read privilege the
blocking key does not have; their response format is not verified here).

Each field records its source and the time of the last successful read. Fields a device does not expose stay unknown.
"""
import json
import re
import subprocess
import threading
import time

from . import capacity as C
from .counters import auth_args, snmp_get

# standard MIBs
SYS = {"descr": ".1.3.6.1.2.1.1.1.0", "object_id": ".1.3.6.1.2.1.1.2.0", "uptime": ".1.3.6.1.2.1.1.3.0"}
HR_MEM = ".1.3.6.1.2.1.25.2.2.0"                 # hrMemorySize (KB)
HR_PROC_LOAD = ".1.3.6.1.2.1.25.3.3.1.2"         # hrProcessorLoad per processor (% over the last minute)
HR_DEV_DESCR = ".1.3.6.1.2.1.25.3.2.1.3"         # hrDeviceDescr (processor model for hrDeviceProcessor entries)
HR_STORAGE = {"type": ".1.3.6.1.2.1.25.2.3.1.2", "descr": ".1.3.6.1.2.1.25.2.3.1.3", "units": ".1.3.6.1.2.1.25.2.3.1.4",
              "size": ".1.3.6.1.2.1.25.2.3.1.5", "used": ".1.3.6.1.2.1.25.2.3.1.6"}
HR_RAM, HR_DISK = ".1.3.6.1.2.1.25.2.1.2", ".1.3.6.1.2.1.25.2.1.4"
IF_NAME, IF_SPEED, IF_OPER = ".1.3.6.1.2.1.31.1.1.1.1", ".1.3.6.1.2.1.31.1.1.1.15", ".1.3.6.1.2.1.2.2.1.8"
ENT_MODEL = ".1.3.6.1.2.1.47.1.1.1.1.13"         # entPhysicalModelName (ENTITY-MIB)
UCD = {"cpu_idle": ".1.3.6.1.4.1.2021.11.11.0", "mem_total_kb": ".1.3.6.1.4.1.2021.4.5.0", "mem_avail_kb": ".1.3.6.1.4.1.2021.4.6.0"}
# vendor scalars, from the vendors' published MIBs. Implemented, NOT verified on hardware unless listed in VERIFIED_MIBS.
VENDOR = {
    "12356": ("Fortinet (FORTINET-FORTIGATE-MIB)", {"cpu_pct": ".1.3.6.1.4.1.12356.101.4.1.3.0", "mem_pct": ".1.3.6.1.4.1.12356.101.4.1.4.0",
                                                     "mem_capacity_kb": ".1.3.6.1.4.1.12356.101.4.1.5.0", "sessions": ".1.3.6.1.4.1.12356.101.4.1.8.0"}),
    "25461": ("Palo Alto Networks (PAN-COMMON-MIB)", {"session_util_pct": ".1.3.6.1.4.1.25461.2.1.2.3.1.0", "sessions_max": ".1.3.6.1.4.1.25461.2.1.2.3.2.0",
                                                       "sessions": ".1.3.6.1.4.1.25461.2.1.2.3.3.0"}),
}
VERIFIED_MIBS = {"HOST-RESOURCES-MIB (OPNsense/net-snmp)", "IF-MIB", "UCD-SNMP-MIB (OPNsense/net-snmp)"}
ENTERPRISE = {"8072": "net-snmp (FreeBSD/Linux based: OPNsense, pfSense with net-snmp, Linux routers)", "12356": "Fortinet",
              "25461": "Palo Alto Networks", "9": "Cisco", "2636": "Juniper", "14988": "MikroTik", "12325": "FreeBSD bsnmpd (pfSense default)",
              "8741": "SonicWall", "11": "HPE", "47196": "HPE Aruba", "30065": "Arista", "6876": "VMware", "674": "Dell", "41112": "Ubiquiti"}
MANUAL_FIELDS = [("manufacturer", "Manufacturer", "text"), ("model", "Model", "text"), ("cpu_model", "CPU model", "text"),
                 ("cpu_cores", "CPU cores", "number"), ("ram_bytes", "Installed RAM (GB)", "gb"), ("cpu_pct", "Typical CPU use (%)", "number"),
                 ("mem_pct", "Typical memory use (%)", "number"), ("interfaces", "Number of interfaces", "number"),
                 ("if_speed_mbps", "Fastest interface speed (Mb/s)", "number"), ("throughput_mbps", "Approximate throughput (Mb/s)", "number"),
                 ("peak_throughput_mbps", "Peak throughput (Mb/s)", "number"), ("ids", "IDS/IPS", "select:unknown,off,ids,ips"),
                 ("logging", "Logging level", "select:unknown,blocks only,blocks + system,detailed (pass rules too)"),
                 ("flow_export", "Flow export", "select:unknown,none,NetFlow v5,NetFlow v9,IPFIX,sFlow"),
                 ("active_timeout_s", "Flow active timeout (s)", "number")]
REFRESH_S = 6 * 3600          # inventory refresh: conservative; utilization comes from the regular 1-minute poll
WALK_ROWS = 256


class SnmpError(Exception):
    pass


def classify(err: str) -> str:
    e = err.lower()
    if "timeout" in e or "no response" in e:
        return "timeout: no answer from the agent (address, UDP 161 reachability, ACL or credentials)"
    if "authentication" in e or "unknown user" in e or "usm" in e or "wrong digest" in e or "decryption" in e:
        return "authentication failed: SNMPv3 user/passphrases or protocols do not match"
    if "authorization" in e or "noaccess" in e or "no access" in e:
        return "permission denied: the SNMP view does not include this object"
    if "no such" in e:
        return "not supported: the agent does not implement this object"
    return err[:160]


def walk(host, cred, oid, timeout=3, max_rows=WALK_ROWS):
    """Small bulk walk (10 repetitions per request). Returns {index_suffix: value}."""
    r = subprocess.run(["snmpbulkwalk", *auth_args(cred), "-t", str(timeout), "-r", "1", "-Cr10", "-On", "-Oq", host, oid],
                       capture_output=True, text=True, timeout=timeout * 10)
    if r.returncode != 0 and not r.stdout:
        raise SnmpError(classify((r.stderr or r.stdout).strip()))
    out = {}
    for line in r.stdout.splitlines()[:max_rows]:
        k, _, val = line.partition(" ")
        if "No Such" in val or not k.startswith(oid):
            continue
        out[k[len(oid) + 1:]] = val.strip().strip('"')
    return out


def get(host, cred, oids):
    try:
        return snmp_get(host, cred, list(oids.values()))
    except Exception as ex:
        raise SnmpError(classify(str(ex))) from None


def cred_of(snmp):
    from . import secretbox
    if not snmp:
        return None
    if snmp.get("version", "v2c") == "v3":
        return snmp if snmp.get("v3_file") else None
    return secretbox.read_file(snmp.get("community_file")) if snmp.get("community_file") else None


def discover(dev, snmp_fn=None):
    """Read what the device exposes. Returns (fields, steps): fields {name: {value, source, ts}}, steps [(what, ok, detail)]."""
    sn = dev.get("snmp") or {}
    cred = cred_of(sn)
    steps, fields, now = [], {}, time.time()
    if not sn.get("host") or cred is None:
        steps.append(("SNMP", False, "not configured for this device: add SNMP (v3 recommended) in its settings, or enter values manually"))
        return fields, steps
    host = sn["host"]
    g = (snmp_fn or {}).get("get") or get
    w = (snmp_fn or {}).get("walk") or walk
    put = lambda k, val, src: fields.__setitem__(k, {"value": val, "source": src, "ts": now})  # noqa: E731
    if sn.get("version", "v2c") != "v3":
        steps.append(("SNMP security", True, "SNMPv2c: community sent in clear text; use SNMPv3 authPriv where the device supports it"))
    try:
        d, oid, up = g(host, cred, SYS)
        put("sys_descr", d[:300], "SNMP SNMPv2-MIB sysDescr")
        put("sys_object_id", oid, "SNMP SNMPv2-MIB sysObjectID")
        put("uptime", up, "SNMP sysUpTime")
        ent = (re.match(r"\.?1\.3\.6\.1\.4\.1\.(\d+)", oid or "") or [None, None])[1]
        if ent:
            put("agent", ENTERPRISE.get(ent, f"enterprise {ent}"), "SNMP sysObjectID enterprise number")
        steps.append(("System (SNMPv2-MIB)", True, "sysDescr, sysObjectID, sysUpTime"))
    except SnmpError as ex:
        steps.append(("System (SNMPv2-MIB)", False, str(ex)))
        return fields, steps          # nothing else will answer either
    try:
        loads = w(host, cred, HR_PROC_LOAD)
        if loads:
            vals = [int(x) for x in loads.values() if x.lstrip("-").isdigit()]
            put("cpu_cores", len(vals), "SNMP HOST-RESOURCES-MIB hrProcessorTable (entries)")
            put("cpu_pct", round(sum(vals) / len(vals), 1), "SNMP hrProcessorLoad (average of all processors, last minute)")
            descr = w(host, cred, HR_DEV_DESCR)
            names = [descr.get(i) for i in loads if descr.get(i)]
            if names:
                put("cpu_model", max(set(names), key=names.count), "SNMP HOST-RESOURCES-MIB hrDeviceDescr")
            steps.append(("CPU (HOST-RESOURCES-MIB)", True, f"{len(vals)} processors"))
        else:
            steps.append(("CPU (HOST-RESOURCES-MIB)", False, "not supported: hrProcessorTable is empty"))
    except SnmpError as ex:
        steps.append(("CPU (HOST-RESOURCES-MIB)", False, str(ex)))
    try:
        (mem,) = g(host, cred, {"m": HR_MEM})
        put("ram_bytes", int(mem) * 1024, "SNMP HOST-RESOURCES-MIB hrMemorySize")
        st = {k: w(host, cred, o, max_rows=64) for k, o in HR_STORAGE.items()}
        disks, ram_used = [], None
        for i, t in st["type"].items():
            units, size, used = (int(st[x].get(i, "0") or 0) for x in ("units", "size", "used"))
            if t.endswith(HR_RAM.lstrip(".")) or t == HR_RAM:
                ram_used = used * units
            elif (t.endswith(HR_DISK.lstrip(".")) or t == HR_DISK) and size:
                disks.append((st["descr"].get(i, i), size * units, used * units))
        if ram_used is not None and fields.get("ram_bytes"):
            put("mem_pct", round(100 * ram_used / fields["ram_bytes"]["value"], 1),
                "SNMP hrStorageRam used / hrMemorySize (includes cache on some systems)")
        if disks:
            root = next((x for x in disks if x[0] == "/"), max(disks, key=lambda x: x[1]))
            put("storage_bytes", root[1], f"SNMP hrStorageTable ({root[0]})")
            put("storage_used_pct", round(100 * root[2] / root[1], 1) if root[1] else None, f"SNMP hrStorageTable ({root[0]})")
        steps.append(("Memory and storage (HOST-RESOURCES-MIB)", True, f"{len(disks)} fixed-disk entries"))
    except SnmpError as ex:
        steps.append(("Memory and storage (HOST-RESOURCES-MIB)", False, str(ex)))
    try:
        ucd = dict(zip(UCD, g(host, cred, UCD)))
        put("cpu_pct", round(100 - float(ucd["cpu_idle"]), 1), "SNMP UCD-SNMP-MIB ssCpuIdle (system-wide)")
        if float(ucd["mem_total_kb"]):
            put("mem_pct", round(100 * (1 - float(ucd["mem_avail_kb"]) / float(ucd["mem_total_kb"])), 1),
                "SNMP UCD-SNMP-MIB memTotalReal/memAvailReal")
        steps.append(("CPU/memory (UCD-SNMP-MIB)", True, "net-snmp agent"))
    except SnmpError as ex:
        steps.append(("CPU/memory (UCD-SNMP-MIB)", False, str(ex)))
    try:
        names = w(host, cred, IF_NAME)
        speeds = w(host, cred, IF_SPEED)
        oper = w(host, cred, IF_OPER)
        ifs = [{"name": n, "speed_mbps": int(speeds.get(i, "0") or 0), "up": oper.get(i) in ("1", "up")} for i, n in names.items()]
        put("interfaces", len(ifs), "SNMP IF-MIB ifName")
        put("if_list", ifs, "SNMP IF-MIB ifName / ifHighSpeed / ifOperStatus")
        sp = [x["speed_mbps"] for x in ifs if x["up"] and x["speed_mbps"]]
        if sp:
            put("if_speed_mbps", max(sp), "SNMP IF-MIB ifHighSpeed (fastest interface that is up; port speed, not throughput)")
        steps.append(("Interfaces (IF-MIB)", True, f"{len(ifs)} interfaces"))
    except SnmpError as ex:
        steps.append(("Interfaces (IF-MIB)", False, str(ex)))
    try:
        m = w(host, cred, ENT_MODEL, max_rows=16)
        model = next((x for x in m.values() if x), None)
        if model:
            put("model", model, "SNMP ENTITY-MIB entPhysicalModelName")
        steps.append(("Model (ENTITY-MIB)", bool(model), "" if model else "not supported by this agent"))
    except SnmpError as ex:
        steps.append(("Model (ENTITY-MIB)", False, str(ex)))
    ent = (re.match(r"\.?1\.3\.6\.1\.4\.1\.(\d+)", (fields.get("sys_object_id") or {}).get("value") or "") or [None, None])[1]
    if ent in VENDOR:
        name, oids = VENDOR[ent]
        try:
            vals = dict(zip(oids, g(host, cred, oids)))
            for k, x in vals.items():
                try:
                    num = float(x)
                except ValueError:
                    continue
                if k == "mem_capacity_kb":
                    put("ram_bytes", int(num) * 1024, f"SNMP {name}")
                else:
                    put(k, num, f"SNMP {name} (implemented from the published MIB; not verified on hardware)")
            steps.append((name, True, "vendor MIB scalars"))
        except SnmpError as ex:
            steps.append((name, False, str(ex)))
    return fields, steps


def manufacturer_from(fields):
    d = (fields.get("sys_descr") or {}).get("value") or ""
    for pat, name in (("OPNsense", "OPNsense"), ("pfSense", "pfSense"), ("FortiGate", "Fortinet"), ("Palo Alto", "Palo Alto Networks"),
                      ("RouterOS|MikroTik", "MikroTik"), ("Cisco", "Cisco"), ("JUNOS|Juniper", "Juniper"), ("SonicWall|SonicOS", "SonicWall"),
                      ("Aruba|ArubaOS", "HPE Aruba"), ("FreeBSD", "FreeBSD-based"), ("Linux", "Linux-based")):
        if re.search(pat, d, re.I):
            return name
    return (fields.get("agent") or {}).get("value")


# ---------------------------------------------------------------------------------------------- storage of values
def save_discovered(conn, did, fields, steps):
    now = time.time()
    for k, f in fields.items():
        conn.execute("INSERT INTO fw_hardware(device, field, value, source, ts) VALUES (?,?,?,?,?) ON CONFLICT(device, field, source) "
                     "DO UPDATE SET value=excluded.value, ts=excluded.ts", (did, k, json.dumps(f["value"]), "auto:" + f["source"], f["ts"]))
        conn.execute("DELETE FROM fw_hardware WHERE device=? AND field=? AND source LIKE 'auto:%' AND source != ?", (did, k, "auto:" + f["source"]))
    conn.execute("INSERT INTO fw_hardware(device, field, value, source, ts) VALUES (?,?,?,?,?) ON CONFLICT(device, field, source) DO UPDATE SET "
                 "value=excluded.value, ts=excluded.ts", (did, "_discovery", json.dumps({"steps": steps}), "meta", now))
    conn.commit()


def save_manual(conn, did, values):
    now = time.time()
    for k, val in values.items():
        if val in (None, ""):
            conn.execute("DELETE FROM fw_hardware WHERE device=? AND field=? AND source='manual'", (did, k))
        else:
            conn.execute("INSERT INTO fw_hardware(device, field, value, source, ts) VALUES (?,?,?,?,?) ON CONFLICT(device, field, source) "
                         "DO UPDATE SET value=excluded.value, ts=excluded.ts", (did, k, json.dumps(val), "manual", now))
    conn.commit()


def hardware(conn, did):
    """Merged view: {field: {value, label, source, ts, auto, manual}}. Manual wins; the discovered value is kept beside it."""
    rows = conn.execute("SELECT field, value, source, ts FROM fw_hardware WHERE device=?", (did,)).fetchall()
    out, meta = {}, {}
    for r in rows:
        if r["source"] == "meta":
            meta[r["field"]] = {**json.loads(r["value"]), "ts": r["ts"]}
            continue
        f = out.setdefault(r["field"], {})
        if r["source"] == "manual":
            f["manual"] = {"value": json.loads(r["value"]), "ts": r["ts"]}
        else:
            f["auto"] = {"value": json.loads(r["value"]), "source": r["source"][5:], "ts": r["ts"]}
    for k, f in out.items():
        if "manual" in f:
            f.update(value=f["manual"]["value"], label="MANUAL", source="entered by a user", ts=f["manual"]["ts"])
        else:
            f.update(value=f["auto"]["value"], label="MEASURED", source=f["auto"]["source"], ts=f["auto"]["ts"])
    return out, meta


def record_sample(conn, did, cpu, mem, load1=None, extra=None, ts=None):
    conn.execute("INSERT INTO fw_resources(device, ts, cpu, mem, load1, extra) VALUES (?,?,?,?,?,?)",
                 (did, ts or time.time(), cpu, mem, load1, json.dumps(extra) if extra else None))


def prune(conn, keep_days=35):
    conn.execute("DELETE FROM fw_resources WHERE ts < ?", (time.time() - keep_days * 86400,))
    conn.commit()


# ---------------------------------------------------------------------------------------------- per-device capacity
# Bytes on the wire per exported record when it cannot be measured (documented in docs/firewall-resource-requirements.md).
WIRE = {"netflow_v5": (48.8, 48.8, "NetFlow v5: fixed 48-byte records plus a 24-byte header per packet of up to 30 records"),
        "netflow_v9": (40.0, 70.0, "NetFlow v9: depends on the template (IPv4 vs IPv6 fields); plus 20-byte header per packet"),
        "ipfix": (40.0, 70.0, "IPFIX: depends on the template; plus 16-byte header per message"),
        "sflow": (None, None, "sFlow: one sample per N packets plus counter samples; needs the packet rate and sampling rate")}


def device_workload(ch, dev, t0, t1):
    """Measured flow records/s from this exporter and stored log events/s from this device."""
    p = {"t0": C._dt(t0), "t1": C._dt(t1), "e": dev.get("exporter") or dev["id"], "d": dev["id"]}
    fl, ev = {}, {}
    try:
        for r in ch.query("SELECT toUInt32(toStartOfMinute(TimeReceived)) AS b, count() AS n FROM flows WHERE TimeReceived >= {t0:DateTime} "
                          "AND TimeReceived < {t1:DateTime} AND ExporterName = {e:String} GROUP BY b", p):
            fl[int(r["b"])] = r["n"] / 60
    except Exception:
        fl = None
    try:
        tabs = [r["table"] for r in ch.query("SELECT table FROM system.columns WHERE database='netmon' AND name='device' "
                                             "AND table IN (SELECT table FROM system.columns WHERE database='netmon' AND name='received')", {})]
        for t in tabs:
            for r in ch.query(f"SELECT toUInt32(toStartOfMinute(received)) AS b, count() AS n FROM netmon.{t} WHERE received >= {{t0:DateTime}} "
                              f"AND received < {{t1:DateTime}} AND if(device = '', site, device) = {{d:String}} GROUP BY b", p):
                ev[int(r["b"])] = ev.get(int(r["b"]), 0) + r["n"] / 60
    except Exception:
        ev = None
    return (C.summarize(fl, t0, t1) if fl is not None else {"label": "UNKNOWN"},
            C.summarize(ev, t0, t1) if ev is not None else {"label": "UNKNOWN"})


def export_bandwidth(flows_avg, wire_bytes=None, proto="netflow_v9"):
    """bits/s on the wire for a given record rate: measured bytes/record when available, else the protocol range."""
    if flows_avg is None:
        return None
    if wire_bytes:
        return {"low": flows_avg * wire_bytes * 8, "high": flows_avg * wire_bytes * 8, "label": "MEASURED",
                "basis": f"{wire_bytes:.0f} bytes per record measured at the collector (UDP payload incl. headers)"}
    lo, hi, why = WIRE.get(proto, WIRE["netflow_v9"])
    if lo is None:
        return {"low": None, "high": None, "label": "UNKNOWN", "basis": why}
    return {"low": flows_avg * lo * 8, "high": flows_avg * hi * 8, "label": "ESTIMATED", "basis": why}


def device_capacity(conn, ch, dev, window_s=7 * 86400, wire=None, syslog_line_bytes=None):
    """'How much monitoring can this firewall handle?' — measured state plus clearly labelled estimates."""
    now = time.time()
    hw, meta = hardware(conn, dev["id"])
    hist = C.fw_resource_history(conn, dev["id"], now - window_s, now)
    out = {"device": dev["id"], "name": dev["name"], "hardware": hw, "discovery": meta.get("_discovery"), "samples": len(hist)}
    cpu = [h["cpu"] for h in hist if h["cpu"] is not None]
    mem = [h["mem"] for h in hist if h["mem"] is not None]
    if cpu:
        out["cpu"] = {"avg": sum(cpu) / len(cpu), "p95": C.pctl(cpu, 95), "peak": max(cpu), "label": "MEASURED",
                      "source": "SNMP samples (1/min)", "hours": (hist[-1]["ts"] - hist[0]["ts"]) / 3600}
        slope = C.theil_sen([(h["ts"], h["cpu"]) for h in hist if h["cpu"] is not None])
        span_d = (hist[-1]["ts"] - hist[0]["ts"]) / 86400
        out["cpu_trend"] = {"pct_points_per_day": slope * 86400 if slope is not None else None, "days": span_d,
                            "label": "MEASURED" if span_d >= 2 else "UNKNOWN",
                            "note": "" if span_d >= 2 else "trend needs at least 2 days of samples"}
        out["cpu_headroom"] = {"value": max(0.0, 80 - out["cpu"]["p95"]), "label": "MEASURED",
                               "note": "points below 80% at P95. Host CPU from SNMP does not always reflect the forwarding/dataplane load "
                                       "(hardware offload, ASICs, dedicated cores)"}
    else:
        manual_cpu = (hw.get("cpu_pct") or {}).get("value")
        out["cpu"] = ({"avg": float(manual_cpu), "label": "MANUAL"} if manual_cpu not in (None, "") else
                      {"label": "UNKNOWN", "note": "no CPU samples: configure SNMP or enter a typical value"})
    if mem:
        out["mem"] = {"avg": sum(mem) / len(mem), "p95": C.pctl(mem, 95), "peak": max(mem), "label": "MEASURED", "source": "SNMP samples"}
    fl, ev = device_workload(ch, dev, now - window_s, now)
    out["flows"], out["events"] = fl, ev
    proto = next(iter(dev.get("flows") or []), "netflow_v9")
    out["export_flow_bw"] = export_bandwidth(fl.get("avg"), (wire or {}).get(dev.get("exporter_ip") or ""), proto)
    if ev.get("avg") is not None:
        lb = syslog_line_bytes or (150, 400)
        lb = lb if isinstance(lb, tuple) else (lb, lb)
        out["export_syslog_bw"] = {"low": ev["avg"] * lb[0] * 8, "high": ev["avg"] * lb[1] * 8,
                                   "label": "MEASURED" if lb[0] == lb[1] else "ESTIMATED",
                                   "basis": f"{lb[0]}–{lb[1]} bytes per line" if lb[0] != lb[1] else f"{lb[0]} bytes per line measured from the log files",
                                   "note": "stored events, not lines: recognized-but-not-stored lines (e.g. session starts) also cross the wire"}
    model = None
    if len(hist) >= 72 and fl.get("label") == "MEASURED":
        model = fw_cpu_model(hist, ch, dev)
    out["cpu_model"] = model or {"valid": False, "reason": f"{len(hist)} CPU samples; the export cost becomes measurable once there are "
                                                           "at least 6 hours of samples with varying load"}
    out["impacts"] = feature_impacts(out, model)
    out["profiles"] = profiles(out)
    return out


def fw_cpu_model(hist, ch, dev):
    """Firewall CPU vs its own flow and log rate (5-minute buckets). Same validity rules as the server model."""
    t0, t1 = hist[0]["ts"], hist[-1]["ts"]
    buckets = {}
    for h in hist:
        if h["cpu"] is not None:
            buckets.setdefault(int(h["ts"] // 300 * 300), []).append(h["cpu"])
    try:
        rows = ch.query("SELECT toUInt32(toStartOfFiveMinutes(TimeReceived)) AS b, count() / 300 AS f FROM flows WHERE TimeReceived >= {t0:DateTime} "
                        "AND TimeReceived < {t1:DateTime} AND ExporterName = {e:String} GROUP BY b",
                        {"t0": C._dt(t0), "t1": C._dt(t1), "e": dev.get("exporter") or dev["id"]})
    except Exception:
        return None
    fr = {int(r["b"]): r["f"] for r in rows}
    data = [(fr[b], 0.0, sum(c) / len(c) / 100) for b, c in buckets.items() if b in fr]
    return C.fit_cpu(data)


def feature_impacts(st, model):
    """Expected change from enabling or changing export features. Exact CPU overhead is never claimed without evidence."""
    f = (st.get("flows") or {}).get("avg")
    e = (st.get("events") or {}).get("avg")
    bw = st.get("export_flow_bw") or {}
    per_rec = None
    if bw.get("label") == "MEASURED" and f:
        per_rec = bw["low"] / f / 8
    cpu_per_flow = model["per_flow"] * 100 if model and model.get("valid") else None
    rows = []

    def row(name, recs, note, bw_rec=None):
        bwr = per_rec or bw_rec
        b = None if recs is None or bwr is None else (recs[0] * (bwr[0] if isinstance(bwr, tuple) else bwr) * 8,
                                                      recs[1] * (bwr[1] if isinstance(bwr, tuple) else bwr) * 8)
        cpu = None if recs is None or cpu_per_flow is None else (recs[0] * cpu_per_flow, recs[1] * cpu_per_flow)
        rows.append({"feature": name, "records": recs, "bandwidth_bps": b,
                     "cpu_pct": cpu, "cpu_label": "ESTIMATED" if cpu else "UNKNOWN",
                     "ram": "insufficient information (flow-cache and log-buffer memory are not exposed by the device)",
                     "note": note})
    row("NetFlow v9 / IPFIX on one more interface", (f * 0.5, f * 1.0) if f else None,
        "another capture point adds up to one record per flow it sees; traffic that crosses both interfaces is exported twice", (40.0, 70.0))
    row("Shorter active timeout (1800 s → 60 s)", (0, f * 1.0) if f else None,
        "only long-lived connections are exported more often; the increase depends on their share, which flow data cannot show beforehand", (40.0, 70.0))
    row("sFlow instead of NetFlow", None, "needs the packet rate and the sampling rate; not estimated")
    row("Firewall rule logging: pass rules too", (f * 0.3, f * 1.0) if f else None,
        "one log line per new connection on the logged rules (syslog, ~150–400 bytes per line)", (150.0, 400.0))
    row("IDS alert export", (0.001, 0.05), "alerts, not inspection: the IDS engine's own CPU cost exists whether or not alerts are exported", (300.0, 1500.0))
    row("DNS query logging", None, "proportional to client DNS queries; measure by enabling it on one resolver")
    row("SNMP polling (m0nitor default)", (0.5, 1.0), "about 26 objects per minute for one WAN interface; negligible on any firewall", (100.0, 200.0))
    rows[-1]["cpu_label"] = "ESTIMATED"
    rows[-1]["cpu_pct"] = None
    if e:
        rows.append({"feature": "Current syslog export", "records": (e, e), "bandwidth_bps": (st.get("export_syslog_bw") or {}).get("low") and
                     ((st["export_syslog_bw"]["low"], st["export_syslog_bw"]["high"])), "cpu_pct": None, "cpu_label": "UNKNOWN",
                     "ram": "", "note": "measured event rate"})
    return rows


def profiles(st):
    """Lightweight / Balanced / Detailed: export volume from the measured rates (or unknown), never automatic changes."""
    f = (st.get("flows") or {}).get("avg")
    e = (st.get("events") or {}).get("avg")
    cpu_model = st.get("cpu_model") or {}
    out = []
    for name, desc, fl_mult, ev_add, ev_mult in (
            ("Lightweight", "WAN flows only, block logs only, SNMP every 60 s, no DNS/IDS export", (0.5, 1.0), (0.0, 0.0), (0.2, 0.6)),
            ("Balanced", "flows on WAN (+LAN capture where needed), firewall block and system logs, IDS alerts, SNMP health", (1.0, 1.0), (0.0, 0.0), (1.0, 1.0)),
            ("Detailed", "flows on all interfaces, pass-rule logging, DNS and VPN events, optional Zeek sensor", (1.0, 2.0), (0.3, 1.0), (1.0, 1.0))):
        if f is None:
            out.append({"profile": name, "description": desc, "label": "UNKNOWN", "note": "no measured flow rate for this device"})
            continue
        fl = (f * fl_mult[0], f * fl_mult[1])
        ev = ((e or 0) * ev_mult[0] + f * ev_add[0], (e or 0) * ev_mult[1] + f * ev_add[1])
        out.append({"profile": name, "description": desc, "label": "ESTIMATED", "flows": fl, "events": ev,
                    "fw_export_bps": (fl[0] * 40 * 8 + ev[0] * 150 * 8, fl[1] * 70 * 8 + ev[1] * 400 * 8),
                    "fw_cpu": ("ESTIMATED", (fl[0] * cpu_model["per_flow"] * 100, fl[1] * cpu_model["per_flow"] * 100))
                    if cpu_model.get("valid") else ("UNKNOWN", "insufficient information: no measured relation between export volume and CPU yet"),
                    "fw_ram": ("UNKNOWN", "insufficient information"),
                    "note": "existing IDS/IPS inspection cost is part of the firewall's current load in every profile; "
                            "only exporting its alerts is counted here"})
    return out


# ---------------------------------------------------------------------------------------------- background refresh
class Refresher:
    """Conservative refresh: inventory every REFRESH_S per device (a few GETs and small walks), and a 5-minute utilization
    sample for devices the regular 1-minute poll does not cover. Never walks large tables."""

    def __init__(self, cfg, conn_factory):
        self.cfg, self.conn_factory = cfg, conn_factory
        self.lock = threading.Lock()

    def refresh(self, conn, dev):
        with self.lock:
            fields, steps = discover(dev)
            save_discovered(conn, dev["id"], fields, steps)
            if fields.get("cpu_pct") or fields.get("mem_pct"):
                record_sample(conn, dev["id"], (fields.get("cpu_pct") or {}).get("value"), (fields.get("mem_pct") or {}).get("value"),
                              extra={"source": "discovery"})
                conn.commit()
            return fields, steps

    def util_sample(self, conn, dev):
        """5-minute CPU sample for devices the 1-minute UCD poll cannot read (non net-snmp agents): vendor scalar or
        the hrProcessorLoad average. One small request; skipped when the device has no SNMP."""
        cred = cred_of(dev.get("snmp"))
        if cred is None:
            return
        host = dev["snmp"]["host"]
        hw, _ = hardware(conn, dev["id"])
        ent = (re.match(r"\.?1\.3\.6\.1\.4\.1\.(\d+)", ((hw.get("sys_object_id") or {}).get("auto") or {}).get("value") or "") or [None, None])[1]
        cpu = mem = None
        if ent == "12356":
            vals = get(host, cred, {k: VENDOR[ent][1][k] for k in ("cpu_pct", "mem_pct")})
            cpu, mem = float(vals[0]), float(vals[1])
        else:
            loads = [int(x) for x in walk(host, cred, HR_PROC_LOAD).values() if x.lstrip("-").isdigit()]
            cpu = sum(loads) / len(loads) if loads else None
        if cpu is not None:
            record_sample(conn, dev["id"], cpu, mem, extra={"source": "5-minute sample"})
            conn.commit()

    def run(self):
        from . import devices as dv
        from .core import get_state
        conn = self.conn_factory()
        C.init(conn)
        last_prune = 0
        while True:
            try:
                for dev in dv.all_devices(self.cfg):
                    if not dev.get("snmp"):
                        continue
                    _, meta = hardware(conn, dev["id"])
                    ts = (meta.get("_discovery") or {}).get("ts") or 0
                    if time.time() - ts > REFRESH_S:
                        self.refresh(conn, dev)
                    st, sts = get_state(conn, f"snmp:{dev['id']}:system", None)
                    if not (st and st.get("ok") and sts and time.time() - sts < 300):
                        try:
                            self.util_sample(conn, dev)
                        except Exception:
                            pass
                if time.time() - last_prune > 3600:
                    prune(conn)
                    last_prune = time.time()
            except Exception:
                pass
            time.sleep(300)

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
