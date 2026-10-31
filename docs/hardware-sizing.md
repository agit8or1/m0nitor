# Hardware sizing

Short version: **4 vCPU, 8 GB RAM and an SSD** is the minimum; for a small site (one or two firewalls, a few hundred
flow records per second) plan 6–8 vCPU for headroom. Disk is sized by retention, and the [capacity planner](capacity-planning.md) (Settings → System →
Capacity planner) calculates it from your own data once the monitor is running.

This page separates what has been **measured** from what is **assumed**. There are no CPU throughput claims here
beyond the measured points below. Your traffic mix, query load and hardware differ, so re-measure on your own
system.

## Sizing chart

| Site | Flow records/s (avg) | vCPU | RAM | Disk (30-day flows, defaults) | Basis |
|---|---|---|---|---|---|
| Small office, 1 firewall | up to ~500 | 4 (min) – 8 | 8 – 16 GB | 128 GB SSD | measured reference point below (≈250/s avg): ≈2 vCPU avg, ≈3.7 vCPU P95, ≈5.5 GB RAM P95 |
| Several firewalls / busy site | 500 – 5,000 | 8 | 16 GB | 250 – 500 GB SSD | storage: calculated; CPU/RAM: **not measured**, run the pipeline benchmark |
| Large | > 5,000 | — | — | calculate | **unknown**: run the [pipeline benchmark](performance-benchmarks.md) on the target hardware |

The storage column uses the bytes per row measured on the reference installation (≈10 B per flow row, ≈12 B per
firewall log row) with the default retention, and includes ClickHouse's own logs, Kafka and the OS. Rows 2 and 3
give no CPU figure on purpose: the monitor has not been measured at those rates.

## Measured reference point

One production installation, measured by the capacity planner over 51 hours (confidence *medium*):

| | |
|---|---|
| Hardware | KVM VM, 16 vCPU Intel Xeon Gold 5120 @ 2.2 GHz, 16 GB RAM, virtual disk (backing storage not visible to the VM) |
| Workload | 1 OPNsense firewall; flow records 252/s avg, 385/s P95, 809/s peak 1-minute rate; log events 134/s avg (firewall ≈99/s, DNS ≈63/s) |
| Host CPU | 13 % avg, 23 % P95 of all vCPUs (whole VM: ClickHouse, Kafka, Akvorado, the app; no Zeek sensor). The period included software builds on the same VM, which raise the P95 |
| Memory | 30 % avg, 34 % P95 of 16 GB; ClickHouse resident 1.6 GB avg, 1.8 GB P95 |
| Disk | busy 3 % avg, 11 % P95; writes 3.7 MB/s avg |
| Storage per day | raw flows 230 MB (10.1 B/row), firewall/IDS/system events 105 MB, DNS 45 MB, **ClickHouse system logs ≈0.95 GB** |
| Projected steady state | ≈76 GB once every table reaches its TTL (30-day flows, 14-day events, 7-day DNS, 30-day system logs) |
| First likely limit | disk I/O at ≈7× this workload (ESTIMATED); CPU **unknown** (CPU did not track the flow rate measurably) |

What this does and does not show: a VM this size runs this workload with ample room. It does **not** show how
many flows per second 16 vCPU can take, and it does not show that 4 vCPU suffice for 500/s. The 4 vCPU / 8 GB
minimum is the install requirement; the measured footprint (≈2 vCPU on average and ≈3.7 vCPU at P95, builds included,
≈5.5 GB RAM at P95) says 4 vCPU leaves little headroom for this workload, and less with the optional Zeek sensor (not measured). Neither figure
comes from a throughput test.

## Component benchmark (storage layer)

The [benchmark harness](performance-benchmarks.md) measured ClickHouse alone on the same host (4 vCPU and 4 GB
allotted, while production kept running, so these are lower bounds):

| | |
|---|---|
| Storage-layer insert rate | ≈195,000 rows/s wall-clock (≈357,000 server-side), 100,000-row batches |
| Dashboard-style queries over 24 h at 500 flows/s (43.2 M rows) | 26 ms (per-minute traffic, 1 h) to 920 ms (one host across 24 h), server-side median |
| Syslog parsing (netmon parser, 1 core) | ≈5,400 OPNsense filterlog lines/s |

The storage layer is far from being the bottleneck at small-site rates. End-to-end flow capacity (UDP decoding,
Kafka, Akvorado outlet) has **not** been benchmarked yet.

## Disk

* **SSD or NVMe.** ClickHouse merges rewrite data continuously; spinning disks are the first limit.
* **Retention drives size.** Raw flows dominate monitoring data: flow records/s × 86,400 × bytes/row × retention
  days. At 250/s and 10 B/row: ≈220 MB/day, ≈6.5 GB for 30 days. At 5,000/s: ≈4.3 GB/day, ≈130 GB for 30 days.
  Bytes per row depend on the traffic mix; the planner uses yours once data exists (planning range 8–40 B).
* **ClickHouse's own logs** can be the largest daily share on a small installation (≈0.95 GB/day above, 30-day
  TTL ≈ 28 GB). Shorten their TTL in ClickHouse's server configuration if disk is tight.
* **Keep 15 % free** for merges (the planner's default disk reserve).
* Kafka keeps its own retention (≈2.3 GB on the reference installation).

## Memory

Memory follows queries and merges more than ingest rate. 8 GB is the minimum for the whole stack (ClickHouse, Kafka,
Akvorado, the app); the optional Zeek sensor needs more (not measured here). Give ClickHouse more for long-range queries over large datasets.

## CPU

ClickHouse ≥ 26.6 needs x86-64-v3 (AVX2); see [install.md](install.md). CPU clock speed, core count and network
link speed are **not** ingestion rates. The planner gives a CPU capacity only from a model it can verify on your
measurements, or from a pipeline benchmark on the same CPU model and vCPU count.

## Firewalls

What exporting flows and logs costs the firewall is covered in
[firewall resource requirements](firewall-resource-requirements.md).
