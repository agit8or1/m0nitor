# Capacity planning

**Settings → System → Capacity planner** answers three questions from the monitor's own measurements:

1. *Is this server big enough for what it does today?* — **Use my current setup**
2. *What does a new installation need?* — **Plan a new installation** (no flows/s or events/s required)
3. *How much more can this server take, and what runs out first?* — the reverse calculation, in both modes

**Settings → System → Resources & capacity** is the live view: host CPU, memory, disk I/O, filesystem, ClickHouse
memory, ingest rates, Kafka and ingest lag and query latency for the last hour, day, week or month, plus firewall
CPU and memory where SNMP provides them. **Printable report** gives a printable summary of the planner's current results.

Related: [hardware sizing](hardware-sizing.md) · [firewall resource requirements](firewall-resource-requirements.md) ·
[performance benchmarks](performance-benchmarks.md).

## Labels

Every figure on these pages carries one label. A figure is never shown as zero when it is unknown.

| Label | Meaning |
|---|---|
| **MEASURED** | read from this installation: ClickHouse system tables, `/proc`, SNMP, the app's own counters |
| **ESTIMATED** | calculated from measurements with a stated model (for example a regression or a retention projection); shown with a range |
| **SUGGESTED** | planning assumption for a new installation, from the questionnaire; never a measurement |
| **BENCHMARKED** | measured by the [benchmark harness](performance-benchmarks.md) on recorded hardware |
| **MANUAL** | entered by an administrator; never overwritten by discovery (the discovered value is kept beside it) |
| **UNKNOWN** | not enough information. The page says what is missing |

## Measurement rules

The planner reads per-minute series for the chosen window (1 h, 24 h, 7 d, 30 d or a custom range up to 31 days):

* **Average, P95 and peak** are computed over 1-minute buckets. *Peak* is the busiest **1-minute rate**, not an
  instantaneous burst, and the page says so. The time of the peak is shown.
* **Gaps.** A run of 10 or more minutes without any data is a *missing period*, listed with start and end, and left
  out of every statistic. A shorter quiet stretch counts as zero load (a quiet minute is real).
* **Before collection.** If the window starts before the first stored row, that part is reported as *before
  collection* and is not counted as missing or as zero.
* **Window shortened to the data.** Asking for 30 days on an installation with 2 days of data uses the 2 days and
  says so.
* **Freshness.** Each figure shows when it was measured; the overview is cached for at most 5 minutes
  (**Refresh hardware** recomputes it).
* **Confidence** is a documented rule, not a score: under 6 hours of samples → *low*, under 72 hours → *medium*,
  otherwise *high*; more than 10 % of the window missing lowers it one step.

What is measured where:

| Figure | Source |
|---|---|
| flow records/s | `count()` of stored flows per minute, by time received |
| events/s, per table | stored rows per minute in each `netmon.*_events` table |
| host CPU, memory, disk busy, I/O latency, steal, iowait | ClickHouse `system.asynchronous_metric_log` (host-wide `/proc` metrics, sampled every second) |
| filesystem use and growth | the same log's filesystem metrics; growth is a Theil–Sen slope over hourly medians |
| per-table size, rows/day, bytes/row, TTL | `system.parts`, `system.tables`; rows in the last 24 h |
| ClickHouse memory | `MemoryResident` |
| Kafka volume, disks | `host/netmon-hostinfo` (a root timer writes `data/hostinfo.json` every 5 minutes) |
| WAN throughput | SNMP IF-MIB 64-bit counters, and separately the flow-estimated rate; both are shown, labelled |
| flow export wire size | Akvorado inlet counters, bytes per record from counter deltas |

## Use my current setup

The page fills in from measurements: workload (flows, events per table, throughput), server inventory (CPU model,
vCPUs, RAM, disks, virtualization), resource use, storage per table with retention, and inventory counts (exporters,
interfaces, devices, sites). Anything the host cannot see — the physical disk behind a virtual disk, NIC models on
a hypervisor — is UNKNOWN until an administrator enters it under **Correct detected values** (stored as MANUAL;
the detected value stays visible).

### What can this server handle

The reverse calculation finds, per resource, how many times today's workload mix fits before that resource reaches
its target (default: 70 % CPU, 85 % disk, adjustable):

* **Disk space** — projected steady state: every table grows until its TTL, then stays flat. ESTIMATED.
* **Disk I/O** — P95 *busy* fraction of the ClickHouse data disk scaled with the workload. ESTIMATED.
* **CPU** — only with a defensible model. The planner fits host CPU = a + b·flows/s + c·events/s over 5-minute
  buckets (robust Huber regression). The model is used only if there are at least 72 samples (6 hours), the flow rate
  varied by at least 10 % (coefficient of variation), and the flow slope is positive and more than two standard errors from zero. Otherwise CPU capacity is
  **UNKNOWN** with the reason (typically: other activity — queries, merges, detection runs — moves CPU more than the
  flow rate does). A [pipeline benchmark](performance-benchmarks.md) on the same CPU model and vCPU count replaces
  the model and is labelled BENCHMARKED.

The smallest multiplier is the **first likely limit**. Extrapolation beyond 3× the highest load ever measured is
flagged.

### Hardware grade

A single number from 0 to 100 (100 best) at the top of the page, labelled ESTIMATED. Each resource gets a headroom
score **100 × (1 − 1/k)**, where *k* is how many times today's workload fits before that resource reaches its target:

| k (headroom) | 1× | 1.33× | 2× | 4× | 10× |
|---|---|---|---|---|---|
| score | 0 | 25 | 50 | 75 | 90 |

* CPU: the fitted CPU model when it is valid, otherwise measured P95 CPU against the 70 % target (this assumes all CPU
  use grows with the workload, which overstates the cost of ingest alone).
* Memory: measured P95 against 85 % (memory grows less than linearly with load, so this is conservative).
* Disk I/O and disk space: the multipliers above.

The grade is the **weakest** resource's score: the server is as good as what runs out first, and the page names it.
Caps: a rotational data disk limits the grade to 60, CPU steal above 5 % at P95 subtracts 10, and a disk limit
reached within 30 days limits it to 30. Bands: ≥ 75 *ample headroom*, ≥ 50 *comfortable*, ≥ 25 *tight: plan an
upgrade*, below 25 *undersized*. Fewer than two measurable resources → UNKNOWN. The grade compares this server with
**its own workload**; it is not a benchmark score and not comparable between installations with different loads.

On the reference installation in [hardware sizing](hardware-sizing.md) the grade was 60 (*comfortable*) on 2026-10-31, limited by
memory at 2.5× headroom.

### Storage and retention calculator

Per table group (raw flows, aggregated flows, firewall/IDS/system events, DNS events, ClickHouse system logs): current
size, bytes per row, rows per day, TTL, age of the oldest row, projected size at full retention. Change a retention
or the workload scale and the projection and *days until the disk limit* recalculate. Tables still younger than
their TTL are listed: their disk use keeps growing until they reach it.

ClickHouse's own diagnostic logs (`system.trace_log`, `query_log`, `part_log`, `processors_profile_log`, …) are
reported separately. On small installations they can be the largest share of daily growth; shortening their TTL in
ClickHouse's server configuration frees disk without touching monitoring data.

## Plan a new installation

The wizard asks what a person knows, not ingestion rates: number of firewalls and other exporting devices, WAN
link speed, how busy the network is, logging detail, the kind of network, which features are wanted (flows, syslog,
DNS, IDS, Zeek) and retention. It returns **ranges**, labelled SUGGESTED, with every assumption listed:

* flow records/s from link speed × utilization × flows per Mb/s (default range 2–50 records/s per Mb/s of average
  traffic at 1:1 export and a 60–120 s active timeout; highly variable with traffic mix);
* peak = 2–4 × average;
* events/s per firewall from the logging level; DNS queries/s from the network type;
* storage from bytes per row: **measured on this installation** when there is data, otherwise assumed ranges.

Link speed alone never gives an exact rate. On an installation with its own data, its own
ratios (flows per Mb/s, log lines per firewall) narrow the ranges once its measurements reach medium confidence; the
page says which ratios were used.

CPU and RAM for a new installation are given only from a benchmark result, scaled linearly and marked as such;
otherwise they are UNKNOWN. See [hardware sizing](hardware-sizing.md) for measured reference points.

**Advanced** takes explicit flows/s, events/s, retention, headroom and disk reserve, for operators who know them.

## Firewalls

Each device page has a **Hardware & capacity** card, and the planner's environment view lists every device with
its measured export rates and resource use. Discovery, manual values, the per-firewall calculator and the
Lightweight / Balanced / Detailed profiles are described in
[firewall resource requirements](firewall-resource-requirements.md).

## Calibration and forecasts

Once a day the planner stores what it measured (rates, bytes per row, disk growth) next to what it projected the day
before, in the local database only. The **Calibration** card shows how far projections were off; local ratios replace
the generic assumptions once confidence is medium or better.

Forecasts are plain statements with their basis, for example *"At current rates the data settles at about 10 % of
the disk once every table has reached its retention"* or *"Flow records changed +12% over the 9-day measurement
period"*. Trends need at least 3 days with data and are reported only above ±10 %.

## API

All endpoints need a signed-in session; changes need the CSRF token and are written to the audit log.

| Endpoint | Role | |
|---|---|---|
| `GET /netmon/api/capacity/overview?window=7d` (or `start`/`end`) | viewer | everything the planner shows |
| `POST /netmon/api/capacity/calc` | viewer | recalculate (modes `existing`, `new`, `advanced`); does not store anything |
| `POST /netmon/api/capacity/plan` | analyst | save a plan |
| `POST /netmon/settings/capacity/server` | admin | manual hardware corrections |
| `GET /netmon/api/capacity/series?range=24h` | viewer | time series for Resources & capacity |
| `GET /netmon/api/capacity/device/{id}` | viewer | per-device hardware, workload, export bandwidth, profiles |
| `POST /netmon/settings/devices/{id}/hardware/discover`, `…/manual` | admin | run SNMP discovery, save manual values |

## Limits

* Host metrics come from inside the VM: on a hypervisor, CPU steal is visible but contention on shared disks is not.
* Disk *busy* is measured; IOPS limits of the backing storage are not, so the disk-I/O multiplier is an estimate.
* Filesystem growth includes everything on the ClickHouse data filesystem (Docker images, builds, Kafka); the
  per-table projection is the better guide.
* No vendor API is used for firewall resources; SNMP and manual values only.
