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

### `bench.py pipeline`: end to end, against a stack you name

```sh
python3 bench/bench.py pipeline --inlet 127.0.0.1:2055 --clickhouse-container bench-clickhouse-1 \
        --i-confirm-isolated-stack [--kind netflow9] [--rates 500,1000,2000,4000,8000] [--step-seconds 60]
```

This mode sends paced synthetic flows (`bench/flowgen.py`: NetFlow v5, v9 or IPFIX) at each rate in turn and counts
the rows that arrive in that stack's ClickHouse. The result is the highest rate with under 1 % loss, no backlog still
arriving after the settle time, and a generator that actually reached the rate. Only this mode writes
`sustained_flows_per_s`, which the planner shows as BENCHMARKED when CPU model and vCPU count match the server.

**Run it against a separate install, never production**: synthetic records cannot be told apart from real ones once
stored. The flag is mandatory, and the default production container name is refused. Run the generator from a second
machine for rates the stack's own host cannot generate; the result records whether the generator shared the host.

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

None yet; the pipeline mode has not been run against a stack. Until a result exists, the planner and [hardware sizing](hardware-sizing.md) give no flows/s capacity for any
hardware.
