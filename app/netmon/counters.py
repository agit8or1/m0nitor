"""Read-only WAN interface counters via SNMP (IF-MIB 64-bit HC octets).

Rates are derived from consecutive samples. A counter decrease (reset/wrap,
reboot) or a sample gap longer than 3x the poll interval produces a gap,
never a zero.
"""
import os
import subprocess
import threading
import time

from .core import db_connect, set_state

OID_IN = ".1.3.6.1.2.1.31.1.1.1.6."    # ifHCInOctets
OID_OUT = ".1.3.6.1.2.1.31.1.1.1.10."  # ifHCOutOctets
OID_NAME = ".1.3.6.1.2.1.31.1.1.1.1."  # ifName
OID_SPEED = ".1.3.6.1.2.1.31.1.1.1.15."  # ifHighSpeed (Mb/s, port speed - not capacity)
RETAIN_S = 8 * 86400
# health context (read-only, sampled once a minute): IF-MIB errors/discards, UCD-SNMP load/memory/CPU idle
OID_ERR = {"in_errors": ".1.3.6.1.2.1.2.2.1.14.", "out_errors": ".1.3.6.1.2.1.2.2.1.20.",
           "in_discards": ".1.3.6.1.2.1.2.2.1.13.", "out_discards": ".1.3.6.1.2.1.2.2.1.19."}
OID_SYS = {"load1": ".1.3.6.1.4.1.2021.10.1.3.1", "mem_total_kb": ".1.3.6.1.4.1.2021.4.5.0",
           "mem_avail_kb": ".1.3.6.1.4.1.2021.4.6.0", "cpu_idle_pct": ".1.3.6.1.4.1.2021.11.11.0"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS counters (
  site TEXT NOT NULL, iface TEXT NOT NULL, ts REAL NOT NULL, in_oct INTEGER, out_oct INTEGER, speed_mbps INTEGER);
CREATE INDEX IF NOT EXISTS counters_i ON counters(site, iface, ts);
"""


def init(conn):
    conn.executescript(SCHEMA)
    conn.commit()


def snmp_get(host, community, oids, timeout=3):
    """Return values (str) via net-snmp snmpget (community is visible to processes in this container only)."""
    r = subprocess.run(["snmpget", "-v2c", "-c", community, "-t", str(timeout), "-r", "1", "-Oqv", "-On", host, *oids],
                       capture_output=True, text=True, timeout=timeout * 3)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:200])
    vals = [v.strip().strip('"') for v in r.stdout.splitlines()]
    if len(vals) != len(oids) or any(v.startswith("No Such") for v in vals):
        raise RuntimeError(f"unexpected SNMP response: {vals}")
    return vals


def rates(samples, interval):
    """samples: [(ts, in_oct, out_oct)] sorted. Yields (t_mid, in_bps|None, out_bps|None, dt)."""
    out = []
    for (t0, i0, o0), (t1, i1, o1) in zip(samples, samples[1:]):
        dt = t1 - t0
        if dt <= 0:
            continue
        if dt > 3 * interval or i1 < i0 or o1 < o0:   # missing samples or counter reset: gap
            out.append((t1, None, None, dt))
            continue
        out.append((t1, (i1 - i0) * 8 / dt, (o1 - o0) * 8 / dt, dt))
    return out


def bucketed(conn, site, iface, start, end, bucket, interval):
    rows = conn.execute("SELECT ts, in_oct, out_oct FROM counters WHERE site=? AND iface=? AND ts>=? AND ts<=? ORDER BY ts",
                        (site, iface, start - 2 * interval, end)).fetchall()
    rs = rates([(r["ts"], r["in_oct"], r["out_oct"]) for r in rows], interval)
    acc = {}
    for t, i, o, dt in rs:
        if t < start:
            continue
        b = int(t // bucket * bucket)
        a = acc.setdefault(b, [0.0, 0.0, 0.0, 0.0])  # in_bits, out_bits, valid_dt, max_in/out packed separately
        if i is None:
            continue
        a[0] += i * dt
        a[1] += o * dt
        a[2] += dt
    peak_in = max((i for _, i, _, _ in rs if i is not None), default=None)
    peak_out = max((o for _, _, o, _ in rs if o is not None), default=None)
    pts = []
    for b in range(int(start // bucket * bucket), int(end) + 1, bucket):
        a = acc.get(b)
        # require >= 50% coverage of the bucket, else it is a gap
        if a and a[2] >= min(bucket, interval * 2) * 0.5:
            pts.append({"t": b, "in_bps": a[0] / a[2], "out_bps": a[1] / a[2]})
        else:
            pts.append({"t": b, "in_bps": None, "out_bps": None})
    last = next(((t, i, o) for t, i, o, _ in reversed(rs) if i is not None), None)
    return {"points": pts, "peak_in_bps": peak_in, "peak_out_bps": peak_out,
            "current": {"t": last[0], "in_bps": last[1], "out_bps": last[2]} if last else None,
            "first_sample": rows[0]["ts"] if rows else None}


class Poller:
    def __init__(self, cfg):
        self.cfg = cfg

    def targets(self):
        for s in self.cfg.get("sites", []):
            sn = s.get("snmp")
            if sn and os.path.exists(sn["community_file"]):
                yield s, sn

    def run(self):
        conn = db_connect()
        init(conn)
        last_prune = 0
        while True:
            for site, sn in self.targets():
                comm = open(sn["community_file"]).read().strip()
                for name, idx in sn["interfaces"].items():
                    try:
                        vin, vout, speed = snmp_get(sn["host"], comm, [OID_IN + str(idx), OID_OUT + str(idx), OID_SPEED + str(idx)])
                        conn.execute("INSERT INTO counters VALUES (?,?,?,?,?,?)",
                                     (site["id"], name, time.time(), int(vin), int(vout), int(speed)))
                        conn.commit()
                        set_state(conn, f"snmp:{site['id']}:{name}", {"ok": True, "speed_mbps": int(speed)})
                    except Exception as ex:
                        set_state(conn, f"snmp:{site['id']}:{name}", {"ok": False, "error": str(ex)[:200]})
                if time.time() - self.__dict__.setdefault("_sys", {}).get(site["id"], 0) > 60:
                    self._sys[site["id"]] = time.time()
                    try:
                        keys = list(OID_SYS)
                        vals = snmp_get(sn["host"], comm, [OID_SYS[k] for k in keys])
                        sysv = {k: float(v) for k, v in zip(keys, vals)}
                        ifs = {}
                        for name, idx in sn["interfaces"].items():
                            ev = snmp_get(sn["host"], comm, [OID_ERR[k] + str(idx) for k in OID_ERR])
                            ifs[name] = {k: int(v) for k, v in zip(OID_ERR, ev)}
                        set_state(conn, f"snmp:{site['id']}:system", {"ok": True, "ts": time.time(), **sysv, "interfaces": ifs})
                    except Exception as ex:
                        set_state(conn, f"snmp:{site['id']}:system", {"ok": False, "ts": time.time(), "error": str(ex)[:200]})
            if time.time() - last_prune > 3600:
                conn.execute("DELETE FROM counters WHERE ts < ?", (time.time() - RETAIN_S,))
                conn.commit()
                last_prune = time.time()
            time.sleep(min((sn["interval_seconds"] for _, sn in self.targets()), default=10))

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
