# Performance benchmarks

`bench/` holds the benchmark harness. It runs only when an operator starts it. It uses synthetic data only, from
documentation (RFC 5737) and private address ranges. Results are written as JSON to `/opt/netmon/data/benchmarks/`,
and the [capacity planner](capacity-planning.md) lists them there.

Only measured results are published on this page, with the hardware, versions and conditions they were measured
under.

## Modes

### `bench.py component`: storage layer and parser, isolated

```sh
sudo python3 bench/bench.py component            # defaults: --cpus 4 --memory 4g --rate 500 --hours 24
```

* Starts a throwaway ClickHouse container: the same image as the stack, `--network none`, CPU and memory capped, its
  own volume. It is removed afterwards, also on failure.
* Creates Akvorado's `flows` table (`bench/flows_schema.sql`, the upstream schema). Inserts `rate × hours × 3600`
  synthetic rows in 100,000-row batches spread over the simulated period, then runs five dashboard-style queries
  seven times each.
* Times netmon's syslog parser (`netmon.logingest.parse_line`) on synthetic OPNsense filterlog lines in the app
  image, with 1 CPU and no network.
* Checks free disk and RAM first and refuses to start if they are short.

What it does **not** measure: UDP decoding, Kafka and the Akvorado outlet. A component result therefore never sets
`sustained_flows_per_s`, and the planner keeps CPU capacity UNKNOWN on its account.

### `bench.py pipeline`: end to end, against an isolated stack

```sh
sudo docker compose -f bench/stack/docker-compose.yml up -d          # isolated stack (project m0nitor-bench)
sudo python3 bench/bench.py pipeline --clickhouse-container m0nitor-bench-clickhouse-1 --i-confirm-isolated-stack \
        [--kind netflow9] [--rates 1000,2000,4000,8000,16000,32000,64000] [--step-seconds 60] [--settle 30]
sudo docker compose -f bench/stack/docker-compose.yml down -v        # remove it and its data
```

`bench/stack/` runs the same Akvorado, Kafka and ClickHouse images as the monitoring stack, with the same inlet
settings (4 workers, 212,992-byte receive buffer), ClickHouse resolutions and TTLs. It uses its own compose project,
network and volumes, and publishes no ports. The generator sends to the inlet's address on the bench network.

This mode sends paced synthetic flows (`bench/flowgen.py`: NetFlow v5, v9 or IPFIX) at each rate in turn and counts
the rows that arrive in that stack's ClickHouse. Per step it records:

* offered and ingested flows/s and dropped records;
* the collector's UDP drops and decoder errors, and the Kafka consumer lag afterwards;
* storage growth.

After the last step it records retention (the TTL of every flow table), bytes per row, query latency (the
component-run queries, server-side and wall-clock), the image versions and the run's duration. The result is the highest
rate with under 1 % loss, no backlog still arriving after the settle time, and a generator that actually reached the
rate. Only this mode writes `sustained_flows_per_s`. The planner shows that figure as BENCHMARKED when the CPU model and
vCPU count match the server.

A trickle of 20 marker flows/s (UDP to port 9 from 10.98.0.0/16, a combination normal flowgen records never use) runs
for the whole benchmark and is excluded from every count. Akvorado's outlet sends a partial batch to ClickHouse only
when the next flow arrives, so without the trickle the tail of each step would be counted in the next step. The
trickle also delivers the NetFlow v9 / IPFIX template before the first measured record.

**Run it against a separate install, never production**: synthetic records cannot be told apart from real ones once
stored. The flag is mandatory, and the default production container name is refused. Run the generator from a second
machine for rates the stack's own host cannot generate. The result records whether the generator shared the host.

sFlow is not generated. sFlow carries sampled packet headers, not flow records, so it needs a real exporter.

### `flowgen.py`: generator on its own

```sh
python3 bench/flowgen.py selftest                                  # encode one packet of each kind
python3 bench/flowgen.py ipfix 127.0.0.1:2055 --rate 2000 --seconds 30
python3 bench/flowgen.py syslog 127.0.0.1:5514 --rate 200 --seconds 30
```

Its NetFlow v5, v9 and IPFIX packets were decoded with an independent decoder (scapy 2.6.1): templates and records
parse, and addresses, ports, protocols, TCP flags and timestamps come out as generated.

## Result format

One JSON file per run:

| Key | Content |
|---|---|
| `scope` | `component` or `pipeline` |
| `hardware` | CPU model, vCPUs, RAM, virtualization, disks, kernel; `bench_cpus` / `bench_memory` = limits given to the run |
| `versions` | ClickHouse version and image, netmon image, harness version |
| `workload` | simulated rate and period, rows, batch size; or flow format, rates and step length |
| `environment` | load average and number of other containers before and after; `shared_host` |
| `result` | ingested and dropped rows, throughput, bytes per row, compression, query latency (server-side and wall-clock), parser lines/s; for pipeline runs, per-step sent / ingested / dropped / loss and `sustained_flows_per_s` |
| `notes` | the conditions that limit what the numbers mean |

## Published results

### Component run, 2026-10-31

| | |
|---|---|
| Hardware | KVM VM, 16 vCPU Intel Xeon Gold 5120 @ 2.20 GHz, 16 GB RAM, virtual disk; run limited to **4 vCPU, 4 GB** |
| Versions | ClickHouse 26.3.62.3 (`clickhouse/clickhouse-server:26.3`), netmon 1.27, harness 1 |
| Conditions | **shared host**: the production stack (11 containers) kept running, load average ≈6.8 at the start. Figures are a lower bound |
| Workload | 24 h simulated at 500 flow records/s = 43,200,000 rows; 100,000-row inserts |
| Duration | 285 s |
| Ingested / dropped | 43,200,000 / 0 |
| Insert rate | 194,904 rows/s wall-clock over the whole insert phase; 356,818 rows/s server-side (insert batch median 267 ms server-side) |
| Storage | 760 MB on disk, 17.6 B/row, compression 8.8× (synthetic rows; real flows on the same host store at ≈10 B/row) |
| Active parts after insert | 23 |
| Syslog parser | 5,363 filterlog lines/s on one core; 100 % parsed |

Query latency, server-side, 7 runs each (wall-clock adds ≈200 ms of `docker exec` and client start-up):

| Query | Median | Max |
|---|---|---|
| traffic per minute, last hour | 26 ms | 87 ms |
| top destinations, last hour | 62 ms | 73 ms |
| top ports, 24 h | 389 ms | 978 ms |
| one host's traffic, 24 h (bloom-filter index) | 920 ms | 2,112 ms |
| country pairs, 24 h | 316 ms | 868 ms |

What it means: on this hardware the storage layer accepts several hundred times the reference installation's flow
rate, and parsing logs at the reference rate of 134 events/s would take about 2.5 % of one core if every event cost what a
filterlog line costs. Neither is an end-to-end capacity.

### Pipeline runs

#### End to end, 2026-11-10 (NetFlow v9)

| | |
|---|---|
| Hardware | KVM VM, 48 vCPU Intel Xeon Gold 5120 @ 2.20 GHz, 31 GB RAM, virtual disk (QEMU, reported rotational) |
| Versions | Akvorado 2026.10.1 (inlet, outlet, orchestrator), Kafka 4.3.2, ClickHouse 26.3.62.3; harness 2 (`bench/stack/`) |
| Conditions | **shared host**: the production stack (12 containers) kept running, load average 38.5 at the start and 22.8 at the end; the generator (one Python process) ran on the same host. Figures are a **lower bound** |
| Workload | synthetic NetFlow v9, 28 records per packet, steps of 60 s at 1,000 → 64,000 flows/s, 30 s settle; marker trickle 20 flows/s |
| Duration | 741 s |
| Retention | raw flows 30 days, 1-minute aggregates 7 days, 5-minute 90 days, 1-hour 1 year (TTL of each table, as the monitoring stack) |

| Offered flows/s | Ingested flows/s | Sent | Dropped | Collector UDP drops | Decoder errors | Queue lag after | Raw storage growth |
|---|---|---|---|---|---|---|---|
| 1,000 | 1,000 | 60,004 | 0 | 0 | 0 | 14 | 0.96 MB |
| 2,000 | 2,000 | 120,008 | 0 | 0 | 0 | 20 | 1.96 MB |
| 4,000 | 4,000 | 240,016 | 0 | 0 | 0 | 4 | 3.78 MB |
| 8,000 | 8,000 | 480,004 | 0 | 0 | 0 | 27 | 7.57 MB |
| 16,000 | 16,000 | 960,008 | 0 | 0 | 0 | 19 | 14.98 MB |
| 32,000 | 32,000 | 1,920,016 | 0 | 0 | 0 | 12 | 29.62 MB |
| 48,207 (64,000 requested) | 48,208 | 2,892,456 | 0 | 0 | 0 | 18 | 44.91 MB |

* **Sustained: 32,000 flows/s** (the highest step the generator reached at its target rate, with 0 % loss). At the
  64,000 step the single-process generator topped out at 48,207 flows/s. The stack ingested every record of that step
  too, so the ceiling of this stack on this hardware was **not reached**. A generator on a second machine is needed to
  find it.
* Storage: 6.7 million rows, 15.5 bytes per raw row right after insertion (background merges still compress further;
  synthetic rows compress differently from real flows, which store at ≈10 B/row on this host). The aggregate tables
  added nothing measurable at this point (`flows_1m0s` etc. are small). At 32,000 flows/s, 30 days of raw retention
  would need about 1.3 TB at 15.5 B/row: size the disk from your own flow rate (the planner does this).
* Query latency after the run, over the 6.7 million rows it inserted, 7 runs each:

| Query | Server p50 | Server max | Wall-clock p50 |
|---|---|---|---|
| traffic per minute, last hour | 63 ms | 375 ms | 491 ms |
| top destinations, last hour | 79 ms | 1,329 ms | 308 ms |
| top ports, 24 h | 61 ms | 78 ms | 287 ms |
| one host's traffic, 24 h | 60 ms | 1,150 ms | 307 ms |
| country pairs, 24 h | 29 ms | 60 ms | 255 ms |

  The occasional maxima above 1 s coincide with the host's production load. This dataset is smaller than a day at
  these rates: for latency over a full 24 h dataset see the component run above.

What it means: on this hardware, sharing the host with production, the collector path takes at least 48,000
NetFlow v9 records/s without loss. That is roughly 100 times the reference installation's flow rate. The figure applies
to NetFlow v9 from one exporter with synthetic records. IPFIX, NetFlow v5, sFlow, many exporters, or a real firewall's
export behaviour (bursts at active-timeout boundaries) can differ and have not been measured.

#### Real devices

No real-device throughput or attribution run exists for **pfSense** or **FortiGate**: no field hardware was available.
These paths remain fixture-only and their claims unverified. The procedure to measure them, including the onboarding
test, the export check and the guided NAT validation, is in [field validation](field-validation.md).
