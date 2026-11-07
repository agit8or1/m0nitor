# Changelog

Versions are `vMAJOR.MINOR` with two-digit minors (v1.05, v1.06, ... v1.10). Every change ships as a new version
with its own section here; the running version is in the page footer and on Changelog in the app.

## v1.52 — 2026-11-07

### Fixed
- Search: the question box now takes the full width of the row (longer questions were cut off); on a phone it sits
  above the Search button.
- Incident page: the header spaces the severity, firewall and dates apart again (they ran together).

## v1.51 — 2026-11-07

### Added
- **Dismiss** button on every open incident (Incidents list and the incident page, analyst or admin): resolves it as
  "Dismissed (no action needed)" after a confirmation, returns to the same list, and records who did it in the
  incident's history and the audit log. Its findings are left as they are. A dismissed incident shows **Reopen** on the
  Resolved tab. An incident that is already resolved keeps the reason it was given.

## v1.50 — 2026-11-07

### Added
- **Investigate → Test detections**: run a **synthetic scenario** against the real detection rules:
  - a device contacting a new country;
  - an unusually large upload;
  - the internet reaching a port with no port forward;
  - a scan of many internet addresses;
  - regular check-ins (beaconing);
  - a normal day where nothing should be raised.
  Choose the device and the scenario's numbers. The made-up records exist only inside the query (a `values()`
  table expression on the read-only session); any other table reference is refused. Production data and findings
  are never touched, and nothing is recorded, notified or blocked.
- Each test shows **expected vs actual**. When a finding is raised, the rule's own explanation says why. When it is
  not, the page gives the likely reason: thresholds, the rule being switched off, the per-firewall monitoring choice,
  still learning, a port forward, an ephemeral port. A finding the rule raised but an exception or expected device
  would hide is named. Exceptions are checked without counting a hit. "Run all scenarios" checks every scenario at
  once.
- **Preview rule changes** on Settings → Alert rules, next to Save. Nothing is saved; preview shows:
  - every changed setting, current vs proposed (relative to config.yaml, like saved changes);
  - the affected scenarios with the current and with the proposed settings;
  - **Replay on retained data**: the changed rules, current and proposed, over up to 48 sampled windows of the last
    24 hours, 3 days or 7 days, comparing how many distinct findings each would have raised, with examples of new
    and disappearing ones.
  Replay limits:
  - it runs in the background, one at a time, at most 10 minutes, and can be cancelled;
  - nothing is recorded or notified;
  - live-state rules (source silence, disk) are listed as not replayable;
  - the last result is kept per firewall and audited.
- Each rule on the Alert rules page links to its test scenario.

## v1.49 — 2026-11-07

### Added
- **Investigate → Search**: ask in plain English (for example "Which devices talked to Russia in the last 7 days?",
  "Blocked connections to 10.0.0.5 yesterday", "Devices that uploaded more than 1 GB yesterday"). netmon interprets
  the question itself, without AI, into named filters, and shows them as "Searching for …". Words it did not
  understand are listed, never guessed. Every filter can be changed in a form, and searching works without asking a
  question at all.
- Searches cover traffic records, DNS lookups, the firewall log and findings, grouped by device, remote, service,
  country, network owner, name or finding type. They are read-only, use netmon's fixed query templates with typed
  parameters (never generated SQL), and are bounded by the data's retention, a period and a row limit.
- Results name devices even behind a shared NAT address where the records allow it. Where they do not (volume sent
  behind a shared address), the page says so instead of guessing. The query behind the results is shown under
  technical details.
- Optional **AI interpretation**, when an AI key is configured. You see exactly what will be sent first: only the
  question, with internal addresses and device names replaced. Requests count against the daily AI request limit.
  The answer is only a set of filters, which netmon validates and shows for review.
- **Saved searches**: private by default; analysts can share them. A saved search can be **proposed as a
  detection** (interval 15 min – 24 h, threshold, severity). It only runs after an admin reviews it: the review shows
  how often it would have fired over the last 7 days, and an admin cannot approve their own proposal when another
  admin exists. Approved detections raise normal findings (notification rules and exceptions apply, nothing is ever
  blocked) and can be stopped at any time. All steps are audited.

## v1.48 — 2026-11-07

### Added
- **Settings → Status → WAN / VPN quality**: small active probes run from the netmon server (the vantage point)
  through each firewall:
  - ping (latency, loss, jitter);
  - TCP connect time;
  - a DNS query to a resolver (response time and result);
  - one HTTPS request (response time, status, certificate problems).
  Probes are opt-in. A recommended set covers the firewall itself, two anycast resolvers, DNS through the firewall
  and one HTTPS check, and is listed before anything is added. Each probe has a role: the firewall, the provider's
  first hop, an internet host, a VPN site, or a service. Admins set the interval (30 s to 1 h), the packets per
  round and the timeout, up to 20 probes. Results are kept 30 days. There are no bandwidth tests.
- Each probe shows its current state (normal, learning, degraded, down, no data, paused) against its usual values,
  with an accessible latency chart that marks loss.
- **Degraded periods** need two bad rounds in a row: loss, no answer, or more than twice the usual time. Each period
  lists **facts**:
  - which probes were affected and which were not;
  - WAN traffic at the time, from the traffic records, as a share of the contracted capacity when that is set;
  - firewall events logged at the same time (gateway, VPN, interface, configuration changes), each marked "not
    necessarily the cause".
  A **suspected cause** is given only where the probes support it: the local side, a busy link, beyond the
  firewall, one destination, the DNS resolver, or the VPN. The provider is suspected only when a probe to its first
  hop was affected while the firewall answered normally and the link was not busy.
- A Health row per firewall, and an Overview item while a probe is degraded or down. Both honour the per-firewall
  "WAN / VPN quality probes" choice. Configuration changes are audited.

## v1.47 — 2026-11-07

### Added
- **Internal devices → Applications**: group the devices that make up an application (with an owner and a
  "critical" mark). Each application lists **what it uses** and **what uses it** (outage impact) from the traffic
  records: internal conversations, and internet dependencies grouped by network owner (AS) and service from reply
  records, so they are tied to the device even behind a shared address. Every dependency shows its service,
  direction, records, last seen, when netmon first saw it, and a confidence based on how many days (4-hour periods
  for 24 hours) of the period it was seen.
- Dependencies are **observed** until a person **confirms** or dismisses them. A confirmed dependency that was not
  seen is listed as such, with the reminder that lack of traffic does not prove a dependency is gone.
  **New** dependencies (first seen in the last 24 hours, not counted for a just-created application) are highlighted.
- **Outage impact of one device**: which applications and devices used it, and whether it is reached from the
  internet. An optional picture shows the application and its main dependencies; the list remains the source.
- Members follow their device identity, so an address change does not drop a device from its application. Queries
  are bounded (period, row limit) and cached for five minutes. Analysts and admins edit; changes are audited.

## v1.46 — 2026-11-07

### Added
- **Internal devices → Segmentation** (monitoring only; netmon never changes firewall rules). Define **groups** of
  address ranges per firewall (e.g. Guest, IoT, Servers, Management; mark sensitive ones) and **rules** for the
  communication you expect. Rules are either "communication expected" (optionally only on listed services) or "no
  communication expected", between groups or to/from any group, optionally only during a schedule. **Templates**
  cover guest isolation, IoT apart, servers on listed services, and management only from admins.
- **Communication matrix**: for every pair of groups, what your rules expect and what the firewall saw (records,
  unexpected records, and blocks from the firewall log). Each cell opens the top conversations with links to the
  records. "Not seen" is never presented as "blocked": traffic within one switch or VLAN does not pass the firewall,
  and groups with no visible traffic are named.
- **Segmentation findings**: internal traffic your rules call unexpected becomes a finding, with high severity when
  it reaches a sensitive group. The per-firewall "Segmentation checks" choice switches it off. Precise exceptions
  (device to destination and service) work for these findings.
- The firewall's own address (proxies, NAT reflection) is not counted as device traffic.

## v1.45 — 2026-11-07

### Added
- **Investigate → Threat hunt**: search retained history for known-bad IP addresses, address ranges and domains.
  Paste indicators for one hunt, or keep **indicator lists**: manual (analyst) or an HTTPS feed fetched on a
  schedule (admin; size-limited; none by default). Plain lists and CSV (value, confidence, published, valid until)
  are accepted, including defanged forms; private addresses and very wide ranges are refused.
- A hunt searches traffic records in both directions, the DNS query log (names, and answers that point to an
  indicator address) and the firewall log. It runs in the background, one at a time, with progress and **Cancel**,
  within 31 days and fixed indicator limits.
- Results per indicator: affected devices (the device at the time) and firewalls, first and last contact, how often,
  volume, direction and a link to the records. Each result also shows the indicator's list, source and confidence,
  when netmon first knew it and when it was published, and whether it is still valid.
- Every result is qualified. It flags contact **before the indicator was published**, **CDN** addresses and
  **shared hosting** (one address, many names), **stale** indicators, and connections through the shared NAT address
  that cannot be tied to a device. It also says which history was searched, with its gaps.
- **Create a finding** from a match (analyst), so it can be triaged and grouped into an incident. It is not notified.
- Threat intel (CVE radar) links to the hunt for address and domain indicators.

## v1.44 — 2026-11-07

### Added
- **Precise exceptions.** "This is normal" on a finding now offers: only this behaviour; this device to one
  destination (IP or CIDR) and/or service; only during a schedule (days and a local time window, overnight allowed, in
  the firewall's time zone); until a date (default 90 days). Broader options (any finding of this kind, every finding
  for the device) are still there, marked as broad.
- **Preview before saving**: the sentence of what will be hidden, how many findings of the last 30 days it would have
  hidden (with examples), and how many findings for the same device would still be raised.
- An exception with a destination only hides findings that name exactly that destination. Findings about many
  destinations (scanning, external DNS, blocked outbound) are never hidden by one. For outbound volume, traffic to the
  excepted destinations is left out of the count and the rest is still checked, so a normal backup cannot hide an
  unrelated upload.
- **Security → Suppressions**: each exception as a plain sentence, how often it hid a finding and when last, its
  expiry; extend by 30 days or remove; warnings for exceptions that expire soon or never.
- **Baselines** card: learning progress per firewall and how "usual" is calculated.

### Changed
- Outbound volume is compared with the **same local hour** in the firewall's time zone (daylight saving included)
  instead of the same UTC hour, weekdays with weekdays and weekends with weekends once three of each exist.
- Hours without traffic records from the firewall are left out of the baseline instead of counted as zero, which
  removes false alarms after an outage.
- Hours covered by unresolved volume findings for the same address are not learned as normal.

## v1.43 — 2026-11-06

### Added
- **Investigate → Incidents**: related findings handled as one case. Each incident shows what happened, the affected
  devices, why it matters, confidence and missing information (monitoring problems at the time, unverified
  direction, devices known only by address, sources not monitored), the next step, a timeline (findings, people's
  actions, firewall configuration changes around the same time) and the raw evidence.
- Findings are grouped automatically when they share a **device** (its identity, so an address change does not split
  it) or a **remote address** within 6 hours, and every link says why. An incident needs two related findings, one of
  them a security finding of medium severity or higher. It covers at most a day, and never chains devices together
  through other findings. Grouping does not claim that one finding caused another.
- Assign, add notes, set status (open, investigating, resolved) with a required resolution reason, optionally close
  the findings, split a finding out (it stays out), add a finding, merge incidents. Everything is in the incident's
  history and the audit log (analyst role).
- **Evidence export** (JSON) per incident, for analysts and admins, recorded in the audit log.
- Finding pages link to their incident, or offer "Start an incident from this finding"; the Security list tags
  grouped findings.
- Overview: **Needs attention** strip (open incidents, serious findings not yet grouped, monitoring problems). It
  never says everything is fine while a monitored source has a problem.
- Open findings from the last 7 days are grouped once after the upgrade.

### Changed
- **Calmer notifications**: a channel that already received a finding of an incident in the last 6 hours is not sent
  another one of the same or lower severity; higher-severity findings are always sent. Messages link to the incident.

## v1.42 — 2026-11-06

### Added
- **Investigate → What changed?**: a short, prioritized list of plain sentences comparing two periods: today vs
  yesterday, this week vs last week, a selected period vs the one before, the same weekday and time on previous weeks,
  or two custom periods. Days and weeks follow each firewall's time zone, including daylight-saving changes.
  It highlights newly observed services answering outside clients, new destinations of fixed-function devices,
  unusual upload or download volume, configuration changes, newly observed devices, new countries and networks, and
  lost telemetry. Each line shows the actual values, the comparison, a confidence level and a **View evidence** link.
- Configuration change page: the firewall's audit lines around the change, and inbound services first observed in the
  24 hours after it, labelled as an association in time, not a cause.
- Overview: **Important changes today** (top three, computed in the background).

### Honesty rules
- "Newly observed" means not seen in the history searched, and every line says how much history that was.
- Hours without flow records are not counted as zero traffic. Incomplete periods are flagged and lower confidence;
  "nothing changed" is never shown as a clean result when data is missing.
- Expected devices are listed but labelled and never placed at the top. Novelty on the shared NAT address is marked
  as unattributable and ranked low.

## v1.41 — 2026-11-06

### Added
- **Device identity that survives address changes.** Discovery keeps time-stamped evidence per site: which MAC
  address used which IP address and when, hostnames, and DHCP leases. Every device page has an **Address history**.
  A finding shows the **device at the time** it happened, and warns when the address now belongs to another device.
  Same private address at two sites = two devices. Traffic without a MAC address, randomized MACs and two devices on
  one address are shown as probable / medium / ambiguous, never as certain.
- **Internal devices → Identity review**: questions netmon will not decide on its own (same hostname, same MAC at two
  sites, device moved), plus merge, separate, undo and rename. Every change is in the device's history and the audit
  log (admin).
- Discovery also reads the firewall's **IPv6 neighbour table** and **DHCP leases** (ISC or Kea), when the API user may.
- **What to monitor, per firewall** (Settings → Firewalls & sites): choose the sources and checks netmon analyses
  for each firewall. A source switched off shows as "not monitored (your choice)" and never fails a health check.
- **Time zone per firewall**, for schedules and local times.
- **Firewall picker on the dashboard**: all firewalls, one, or any combination (kept in the page address).

### Changed
- When the firewall refuses an API call, the message names the **exact privilege** to grant and links to
  Settings → Firewall permissions (auto-discovery, blocking, name sync). New optional privileges are listed there and
  in the permissions guide: *Diagnostics: NDP Table*, *Services: ISC DHCPv4: Leases*, *Services: DHCP: Kea(v4)*.

## v1.40 — 2026-11-06

### Security
- **Second-factor codes and login challenges are now strictly single-use under concurrent requests.** Before, recovery
  codes and the TOTP replay counter were checked and updated in separate steps, and a pending two-factor challenge was
  read and deleted separately. Two simultaneous submissions could both accept the same recovery code or the same TOTP
  timestep and each get a session. This needed the account password (a pending login) and a valid second-factor code:
  it weakened single-use and replay protection, it did not let anyone skip the second factor. Now:
  - a recovery code is removed with a compare-and-swap; only the request that actually removed it succeeds;
  - the TOTP counter only moves forward in the same statement that accepts the code, so a timestep works once;
  - a login challenge is claimed by one request at a time, deleted before the session is created, and only the
    request that deleted it gets a session. A second simultaneous submission sees "already being checked".
  Wrong codes, expiry (5 minutes), rate limiting and audit logging work as before.
- New tests reproduce the races with real concurrent database connections.
- New scheduled dependency advisory check (weekly, runtime and development lockfiles, PyPI and OSV databases).

## v1.39 — 2026-11-03

### Added
- **Device type "management controller (iDRAC / iLO / IPMI)"** in a new **Management** category, for out-of-band
  management cards. Auto-discovery sets it when the firewall's hostname for the address names one (`idrac-…`,
  `ilo-…`, `ipmi`, `bmc`, `imm`, `xcc`, `irmc`). AI analysis treats internet connections to a management controller
  as a serious exposure, while NTP, DNS, alert e-mail and vendor update traffic from it is normal.

## v1.38 — 2026-11-03

### Added
- **Settings → Firewall permissions**: every OPNsense API privilege netmon uses, what needs it (blocking, blocking
  setup, name sync, discovery, dropping states) and the endpoints behind it, plus **Check this account now**, which
  makes one read-only call per privilege and shows ✓ granted / ✗ missing for each firewall. pfSense REST API
  privileges are listed for pfSense sites. Privilege names are taken from OPNsense's own ACL definitions.
- New guide `docs/opnsense-permissions.md` with the same list, how to create the API user and how to remove access.

### Fixed
- The setup tips and the firewall connection form said a user with only "Diagnostics: PF Table IP addresses" was
  enough; that covers blocking only. They now point to the full list. The firewall setup guide named privileges that
  do not match OPNsense's; corrected.

## v1.37 — 2026-11-03

### Fixed
- **Auto-discovery read no ARP table on current OPNsense.** It called the legacy `getArp` endpoint, which current
  releases refuse even with the "Diagnostics: ARP Table" privilege. It now uses `search_arp` (all rows) and falls
  back to `getArp` on older firewalls.

## v1.36 — 2026-11-03

### Changed
- **"Servers" is now "Internal devices"** (navigation, page titles, Inventory, search results, filters, map tooltips,
  wallboard KPI). Addresses (`/netmon/servers/...`) are unchanged, so bookmarks keep working.

### Added
- **Device categories.** Every type belongs to a category: Servers, Virtual, Network, Endpoints, IoT & peripherals,
  Other, and Unclassified (no type yet). The Internal devices page has category filter chips with counts; Settings →
  Inventory groups the devices by category with jump links. AI analysis receives the category too.
- **MAC vendor lookup** from the IEEE registry (MA-L, MA-M and MA-S prefixes, longest match wins; the `ieee-data`
  package, mounted read-only). Randomized (private) MACs are recognized. Vendors that make essentially one kind of
  device (camera, printer, VoIP phone, NAS, network and firewall makers) set that type automatically; general
  vendors (Dell, HP, Cisco, Apple, Intel, …) set none. Vendors are also filled in for MACs recorded earlier, and
  passed to AI analysis.

## v1.35 — 2026-11-03

### Added
- **Inventory fills itself.** Every 15 minutes, auto-discovery adds internal addresses it has not seen before: any LAN
  address that received internet traffic in the last 24 hours, and every entry in each OPNsense firewall's ARP table
  (MAC address, vendor and hostname; needs the API privilege "Diagnostics: ARP Table"). A virtualization MAC prefix
  (Proxmox, VMware, Hyper-V, Xen, KVM, VirtualBox, …) sets the type to virtual machine; any other vendor sets no type,
  since one vendor makes servers, switches and management cards alike. New entries are tagged **auto-discovered**;
  on existing entries only empty fields (type, MAC, vendor) are filled, so nothing a person set is overwritten.
  Editing an entry makes it yours (MAC and vendor are kept).
- Settings → Inventory has an **Auto-discovery** card: on/off, **Run now**, the last run, and per-firewall ARP status
  (including the missing-privilege hint). MAC and vendor are shown under each name.
- AI analysis is told when a device type came from discovery and when an entry was not reviewed by an admin.

## v1.34 — 2026-11-03

### Added
- **Device type for every internal address.** Pick what an address *is* from a fixed list: physical server, virtual
  machine, container, hypervisor host, workstation / laptop, mobile device, printer, IoT / camera, VoIP phone, network
  device (switch / AP), firewall / router, storage / NAS, other. (Role stays what it *does*.) It is in the ✎ editor, the
  server page, Settings → Inventory (new **Type** column), and the bulk card, now **Assign type and role**, which can
  set only the type and keep each address's role.
- AI analysis receives the device type and weighs it: a workstation, printer, phone or IoT device accepting
  connections from the internet, or a printer/IoT device reaching many remotes, counts as stronger evidence than the
  same pattern on a server.

## v1.33 — 2026-11-03

### Added
- **Assign roles to servers more easily.** Settings → Inventory has an **Assign a role** card: give several internal
  IPs or CIDRs (up to 256 addresses) one role at once, for example a fleet of crawler VMs. Only the role changes on
  servers that are already named; unnamed addresses are added under their IP (or skipped with "Only servers
  already named"). Every role field (Inventory, server page, ✎ editor) now offers a picker with standard roles plus
  those already in use, and shows the role **seen in traffic** over the last 7 days (e.g. `mail+web`, with the
  services behind it) with a **Use** button.
- A server can get a role without a name; it is then listed under its IP.

## v1.32 — 2026-11-03

### Changed
- **AI analysis now knows what the server does.** The evidence sent for a finding or a server analysis includes the
  server's function: the role, software and notes set in Settings → Inventory, whether an admin marked it as an
  expected device, and the services it was actually seen serving and using over the last 7 days (for example
  "mail (SMTP), mail (IMAPS), web (HTTPS)" → observed role `mail+web`; scans without a completed handshake do not
  count). For a 1:1 NAT address this is the internal server behind it. For the shared outbound NAT address, the
  internal hosts that received replies from the same remote address around the finding's window are listed with
  their functions, marked as likely rather than proven.
- The model is told to calibrate the threat score against that function (inbound SMTP to a mail server or scanner
  noise against a web server is weaker evidence; outbound SMTP from a backup or web server, or a declared/observed
  role mismatch, is stronger) and to say in the score rationale how the function moved the score. Country and
  time-window analyses list each server's declared role.

## v1.31 — 2026-10-31

### Fixed
- **Hardware grade right after a resize was decided by a few minutes of data.** With only minutes measured on the
  new hardware, the "P95" was simply the busiest minute (boot catch-up or a one-off job), so a mostly idle, larger
  server could be graded "undersized". For the first 6 hours after a vCPU or RAM change, CPU and memory are now
  **projected** from the previous hardware's measurements, scaled by old/new vCPUs and old/new RAM (labelled
  ESTIMATED, confidence one step lower). Disk I/O keeps the whole window, since the disk did not change. After 6
  hours the new hardware's own measurements take over; the server card shows when that happens.

## v1.30 — 2026-10-31

### Fixed
- **Hardware grade ignored a VM resize.** CPU, memory and disk figures were P95s over the whole window (7 days by
  default), so after adding vCPUs or RAM the grade kept describing the old hardware for days. The planner now finds
  the last change of vCPU count or total RAM (from ClickHouse's per-CPU and memory samples) and measures resources
  only from there, skipping the first 10 minutes after the change (boot and catch-up load). The CPU model is fitted
  on the same span. The grade and the server card say when the hardware changed and what changed; workload rates
  (flows, events) still use the full window. Confidence is low until about 6 hours have been measured.
- The server card's button is now **Recalculate now** (it was "Refresh hardware"); it bypasses the 5-minute cache.

## v1.29 — 2026-10-31

### Added
- **Hardware grade 0–100** (100 best) at the top of Settings → System → Capacity planner and in the printable
  report. Each resource gets a headroom score, 100 × (1 − 1/k), where k is how many times today's workload fits
  before it reaches its target (CPU 70 %, memory 85 %, disk I/O and disk space from the capacity calculation):
  1× → 0, 2× → 50, 4× → 75, 10× → 90. The grade is the weakest resource's score, so it names what runs out first.
  Documented caps: rotational data disk ≤ 60, CPU steal above 5 % at P95 −10, disk limit within 30 days ≤ 30. Bands:
  ≥ 75 ample headroom, ≥ 50 comfortable, ≥ 25 tight, below that undersized. Labelled ESTIMATED with the measurement
  confidence; UNKNOWN when fewer than two resources can be measured.

## v1.28 — 2026-10-31

### Added
- **Capacity planner** (Settings → System → Capacity planner). *Use my current setup* fills in from this
  installation's measurements over 1 h, 24 h, 7 d, 30 d or a custom range: flow records/s, events/s per table, WAN
  throughput (SNMP and flow-estimated, both labelled), host CPU, memory, disk busy and latency, ClickHouse memory,
  storage per table with retention, and inventory counts. Each figure shows average, P95 and peak 1-minute rate,
  samples, missing periods, freshness and confidence. Every value is labelled MEASURED, ESTIMATED, SUGGESTED,
  BENCHMARKED, MANUAL or UNKNOWN; unknown values are never shown as zero.
- **What this server can handle:** how many times today's workload fits before disk space, disk I/O or CPU reaches
  its target, and which runs out first. CPU capacity is given only when a robust regression of CPU against flow and
  event rates passes documented validity checks, or from a matching benchmark; otherwise it is UNKNOWN with the reason.
- **Storage and retention calculator:** per-table steady state at TTL, days until the disk limit, changes to retention
  and workload scale. ClickHouse's own diagnostic logs are reported separately (often the largest daily share on small
  installations).
- **Plan a new installation:** a questionnaire (devices, link speed, activity, logging detail, network type,
  features, retention) gives SUGGESTED ranges with every assumption listed; no flows/s needed. Local measurements
  narrow the ranges when available. *Advanced* takes explicit rates. Plans can be saved; there is a printable report.
- **Resources & capacity** dashboard (Settings → System): live host, ClickHouse, ingest, Kafka lag, query latency and
  firewall CPU/memory charts.
- **Firewall hardware & capacity** (device page → Hardware & capacity): SNMP discovery through SNMPv2-MIB,
  HOST-RESOURCES-MIB, UCD-SNMP-MIB, IF-MIB and ENTITY-MIB (Fortinet and Palo Alto MIB values marked unverified), each
  step reporting answered / not supported / timeout / authentication / permission. Manual values are never overwritten
  by discovery. Also: measured export rates and bandwidth, a calculator for feature changes (CPU impact only when
  measured) and Lightweight / Balanced / Detailed profiles. Firewall CPU and memory are sampled every minute (UCD-SNMP) or
  every 5 minutes (other agents).
- **Calibration history** and forecasts: daily prediction vs measurement, kept locally; trends from at least 3 days.
- **Benchmark harness** (`bench/`, in the repository): synthetic NetFlow v5/v9/IPFIX and syslog generator, an
  isolated component benchmark (throwaway ClickHouse, no network) and an opt-in end-to-end pipeline benchmark for
  non-production stacks. Results with hardware, versions and conditions; the first component result is published in
  `docs/performance-benchmarks.md`.
- Optional root helper `host/netmon-hostinfo` (+ timer): read-only host facts the container cannot see (disk models,
  NICs, Kafka volume).
- Docs: hardware sizing, capacity planning, firewall resource requirements, performance benchmarks; README sizing
  chart.

## v1.27 — 2026-10-31

### Fixed
- The backup (`host/netmon-backup`) now includes `data/secrets/`, the credential files entered in the UI (per-firewall
  API keys, SNMP communities and SNMPv3 passphrases, the AI key). Before, a restore brought back the database and
  `secrets/` but not these files, so they had to be entered again. They are sealed, and `keys/` is in the same
  encrypted archive. A restore of the new archive was tested: the restored key decrypts the restored files.

## v1.26 — 2026-10-31

### Security
- Secrets at rest are encrypted (AES-256-GCM, `netmon/secretbox.py`): notification channel credentials and TOTP
  seeds in the database, and every credential file the app writes (firewall API keys, SNMP communities and SNMPv3
  passphrases, the OpenAI key). Each value is bound to where it is stored, so a sealed value copied to another field or
  file does not decrypt.
- The master key lives in its own directory, `/opt/netmon/keys` (mounted read-only at `/run/keys`), not in `data/`:
  a copy of the database or of `data/` alone no longer reveals credentials. Without a mounted key the app creates
  `data/master.key` so upgrades keep working, and Settings → Health warns until it is moved.
- Existing plaintext values are sealed at startup; operator-managed files under `secrets/` can be sealed in place with
  `python -m netmon.secretbox seal` (they are read either way). Key rotation: keep the previous key as
  `master.key.old`; everything is re-sealed with the new key at the next start.
- New Health check "Secrets at rest": key location, sealed/pending counts, plaintext operator files, values the current
  key cannot decrypt. It reports counts and paths only, never values.
- The backup script also archives `keys/` (inside the encrypted backup), so a restore can decrypt the secrets.
- New dependency: `cryptography` 50.0.2 (with `cffi`, `pycparser`), hash-pinned in `requirements.lock`.

### Docs
- docs/configuration.md: where each secret is stored (notification credentials are in the database, sealed, not in
  `secrets/` as the table said), the master key, sealing operator files, rotation, and what this does not protect
  against.

## v1.25 — 2026-10-31

### Security
- Third-party images with fixable HIGH/CRITICAL CVEs updated; none of the images below has a fixable one left:
  - Kafka 4.3.1 → 4.3.2 plus Alpine package updates (was 29 HIGH and 1 CRITICAL, brotli).
  - Traefik pinned to v3.7.17 (was one fixable HIGH).
  - IPinfo GeoIP updater: Alpine package updates (was 2 HIGH and 1 CRITICAL).
  - Caddy v2.11.7 rebuilt from source with Go 1.26.10, go-jose v4.1.6 and golang.org/x/net v0.60.0, plus Alpine
    package updates (was 9 HIGH and 1 CRITICAL). Same module set as the official image.
- Kafka, the GeoIP updater and Caddy are built locally from the upstream images (`akvorado/docker-compose-local.yml`,
  `caddy/image/Dockerfile`); refresh them with `docker compose build --pull` (see docs/install.md, Upgrade).
- Remaining, not fixable yet: Akvorado 2026.10.1 (one HIGH, golang.org/x/net, needs an Akvorado release); Debian
  and Valkey base packages; Caddy's go-jose v3 (no fixed release).

### Fixed
- `akvorado/docker-compose-local.yml` in the repository lacked the IPFIX (4739) and sFlow (6343) ports and the
  markers the host helper rewrites (multi-vendor setup, v1.14).

## v1.24 — 2026-10-31

### Security
- Countries: the "latest result" kept for serving rolling windows (v1.21) also recorded custom windows, so a signed-in
  user requesting many different custom ranges could make the app's memory grow without limit. Only rolling windows
  ending now are kept, and the store is capped.
- Test tooling: pytest 8.3.4 → 9.0.3 (PYSEC-2026-1845). Test image only; the production image does not include
  pytest. Runtime dependency pins are unchanged.

## v1.23 — 2026-10-31

### Faster
- Server filter, remote-address filter, 1:1 and shared NAT upload attribution, finding traffic and the home-country
  map placement compare and group the raw address columns instead of formatting every row's address as text first
  (the NAT upload query: 0.67 s to 0.12 s). Same results: checked against the previous queries on 24 hours of real
  traffic.
- Log ingestion inserts at most once per second per table when it has caught up, instead of one small insert per
  few lines (DNS events: about 3 inserts per second before), which reduces ClickHouse merge work. A backlog is still
  read without pausing.

## v1.22 — 2026-10-31

### Faster
- Overview, Servers, Connections and Countries: when a rolling window moves to its next step, the traffic part of
  the page is served from the previous step (with that step's own time window, so numbers and labels match) while
  the new step is computed once in the background. It is never more than two steps old (4 min for 24 h, 10 min for
  7 days). Open alerts, collection state, sources and the GeoIP policy are always current. Custom and historical
  windows are computed exactly, as before.

## v1.21 — 2026-10-31

### Faster
- Countries: when a rolling window (for example "last 24 hours") moves to its next step, the map shows the previous
  step's firewall-block counts (at most one step old: 2 min for 24 h, 5 min for 7 days) while the new ones are
  computed in the background, instead of making the viewer wait. Historical and custom windows are always exact.

## v1.20 — 2026-10-31

### Faster
- List pages (Overview recent connections, Connections, Servers, country block drill-down) no longer wait up to
  2–3 s for reverse DNS names. They wait at most 0.4 s; a name not answered yet appears on the next refresh.
  Reverse DNS lookups run on 16 workers instead of 4, because PTR lookups for Internet addresses are often slow.

## v1.19 — 2026-10-31

### Faster
- Long time ranges: the window end is rounded per range (10 s for 15 min up to 5 min for 7 days), and query results
  bound to the window are reused for as long as the window is current. Previously every viewer and every refresh
  re-scanned days of raw flows.
- The default "all sites" view for 24 h and 7 days is computed in the background once per window step, so Overview,
  Servers, Connections and Countries open from cache instead of waiting for the scans.
- Countries: logged firewall blocks per country are cached for the window's life and parsed faster.

## v1.18 — 2026-10-31

### Faster
- Traffic pages and detectors: the WAN/LAN interface filters used by every flow query were evaluated as a tuple lookup
  per row; they are now plain equalities per site, which ClickHouse evaluates on the column dictionaries. The same
  filter is about 20x faster. Results are identical: same flow counts and byte totals over 24 hours of real traffic.
  Exporter filters use `IN` instead of `has()` for the same reason.

### Fixed
- Page footer: credits now follow the GeoIP data actually loaded (IPinfo, MaxMind GeoLite2 or synthetic demo data for
  countries) and credit DB-IP when its city database places map markers. DB-IP's CC BY 4.0 license requires that
  attribution, which was missing.

## v1.17 — 2026-10-31

### Fixed
- Settings → Health, Features card: the GeoIP row named fixed products ("IPinfo (country + ASN) · DB-IP Lite") whatever
  was installed. It now names the country and city databases actually loaded, with their build dates, or says that
  one is missing. The demo therefore shows its synthetic country data instead of a product it does not use.

## v1.16 — 2026-10-31

### Fixed
- Devices page: a site firewall showed "no data" for syslog when its log rows were written before v1.14 (rows without
  a device name). Those rows are now attributed to the site firewall.
- Devices page: when the collector's own decoder counters cannot be read, flows that are arriving were shown as
  "no data". They now show as active if the device has a single flow protocol set up (with a note that the
  protocol was not confirmed), or as unknown if several are set up.

## v1.15 — 2026-10-31

### Fixed
- The device-event rules (VPN tunnel down, interface down, routing neighbor down, HA failover, configuration
  change) failed with a ClickHouse error (a result alias shadowed the `outcome` column used in the filter), which
  raised a "Detector errors" finding. Found by running the demo against a real ClickHouse.

## v1.14 — 2026-10-31

### Added — multi-vendor devices (foundation)
- Device profiles for 24 firewall/router/switch families plus Generic, each with documented flow/syslog/SNMP
  capabilities, an honest status (VERIFIED / PARTIAL / GENERIC) and device-side setup examples. Compatibility
  matrix: docs/vendors.md.
- Vendor syslog parsers with a normalized event model (traffic decision, IDS, auth, VPN, config, interface,
  routing, HA, threat): FortiGate, PAN-OS, Cisco ASA/FTD/IOS, Meraki MX, Junos/SRX, MikroTik, netfilter family
  (Linux, VyOS, EdgeOS, UniFi, OpenWrt, DD-WRT), SonicWall, Sophos, Check Point, WatchGuard, Huawei, Generic.
  Only explicit allow/deny decisions feed firewall views and blocked counts; an unknown action stays unknown.
  Unrecognized lines are kept as system events and counted per device (parser coverage).
- Settings → Devices: add routers, switches and secondary firewalls to a site; per-protocol supported /
  configured / receiving status from live evidence (collector counters, NetFlow/IPFIX versions, templates per
  observation domain, sampling rates, field coverage, last syslog line, sample events); SNMP test; insecure
  transport warnings. Additional devices keep their own flows and never add to a site's WAN totals.
- Site firewalls can use any profile (Firewalls & sites); blocking stays limited to vendors with an
  enforcement adapter (OPNsense, pfSense) and is refused for others.
- SNMPv3 authPriv (SHA/AES) for counters, credentials stored in the secrets directory.
- Collector: IPFIX on 4739 and sFlow on 6343 in addition to NetFlow/IPFIX on 2055, open to registered
  exporters only.
- Flow diagnostics (`python -m netmon.flowdiag`): NetFlow v5/v9, IPFIX and sFlow v5 decoding with template,
  sequence-gap, clock-drift and sampling-change checks.
- Alert rules from device events: VPN tunnel down, interface down, routing neighbor down, HA failover,
  configuration change, repeated failed device logins, device log feed stopped.
- Per-sender syslog rate limit for non-OPNsense devices (drops are counted).

### Changed
- ClickHouse schema v2 (additive): `device`/`vendor` columns on the event tables and a new `netmon.events`
  table, applied automatically at startup. Existing rows and the OPNsense path are unchanged (verified by
  replaying real OPNsense log lines through the old and new parser: identical output).
- Firewall-log rules only use the site firewall's own log rows.

## v1.13 — 2026-10-31

### Security
- Dependency upgrade for published advisories: Starlette 0.41.3 → 1.10.0 (several advisories, fixed in 0.47.2–1.3.1),
  python-multipart 0.0.20 → 0.0.33 (advisories fixed in 0.0.22–0.0.31), FastAPI 0.115.6 → 0.162.0 and
  uvicorn 0.34.0 → 0.54.0 to match. Lock files regenerated with hashes.
- TLS front end: Caddy 2.10.2 → 2.11.7 (fixes Caddy, smallstep and Go module advisories).

### Changed
- Startup moved from the removed `on_event("startup")` hook to a lifespan handler (Starlette 1.x).
- A missing or empty required form field still answers 400 with the readable "Not saved" page; FastAPI's newer
  versions would otherwise answer 422.

## v1.12 — 2026-10-31

### Fixed
- A reverse DNS lookup that timed out was shown as "(no rDNS)"; it is now treated as unknown (nothing shown) and
  retried after 10 minutes. "(no rDNS)" only means the resolver answered that the address has no PTR record.

## v1.11 — 2026-10-31

### Fixed
- IDS findings failed with "'NoneType' object has no attribute 'get'" (detector error) on installs that had never
  fetched the threat-radar feed, e.g. new or offline installs and the demo.

## v1.10 — 2026-10-31

### Fixed
- Country pages for busy countries took ~40 s to show anything: the 7-day "if this country were blocked" preview
  now loads separately (`/netmon/api/country/{cc}/preview`, cached 10 min) and the page's own queries run in parallel.

### Added
- Loading feedback on every page: a thin progress bar at the top while data requests are pending, shimmer
  placeholders in panels that have no data yet, and a spinner for sections that load on their own.

## v1.09 — 2026-10-31

### Changed
- Settings menu grouped into Status, Data, Detection & response and Access; admin-only pages (Users & 2FA,
  Audit log) are hidden from other roles; every settings page is titled "Settings · …".
- Settings → Health is one status view: collection health, SNMP counters and a Features summary (firewalls,
  inventory, blocking, AI, GeoIP). The duplicate sites table, the outdated "edit config.yaml" note and the links
  card are gone; GeoIP now mentions city placement.
- "Integrations" is renamed "Data sources" (telemetry status and OPNsense setup steps); its duplicate integrations
  table is gone.
- Auto-response shows the latest 25 decisions with older ones folded.

## v1.08 — 2026-10-31

### Added
- Country pages: the logged block records show reverse DNS under source and destination, and name the firewall's
  own addresses as WAN / WAN alias.
- The version is shown next to the product name in the top bar of every page (links to the changelog) and on the
  sign-in and two-factor pages.

## v1.07 — 2026-10-31

### Added
- Server pages: an Addresses line under the title with the server's LAN address and its public 1:1 NAT address
  (named as its WAN alias), each with reverse DNS; port forwards show the WAN alias and reverse DNS of their address.
- Servers list: reverse DNS under each server address, the public 1:1 NAT address with its reverse DNS, and reverse
  DNS for the top remote.

## v1.06 — 2026-10-31

### Added
- Reverse DNS under every remote address in connection tables (Connections page, Overview recent connections,
  server and country pages): "(name)", or "(no rDNS)" when the address has no PTR record.

## v1.05 — 2026-10-31

### Added
- Map tooltips list the top five source → destination address pairs per arc, region, endpoint and the site's own
  country, per direction. The firewall side is shown as the public address it is reached on — "WAN" (the outbound
  NAT address) or "WAN alias <description>" (an interface virtual IP) — followed by the internal server(s) behind it.
  LAN hosts behind one NAT address are merged into one line.
- Reverse DNS names in parentheses after addresses: PTR support in the built-in DNS client and a non-blocking,
  in-memory cache resolved through the site's firewall (new names appear on the next refresh).
- Finding pages: reverse DNS under each remote endpoint ("no rDNS" when the address has no PTR record).
- Virtual IP sync records each VIP's interface and description (setting `fwaddr:db`).
- Version number and this changelog: footer link on every page, `/netmon/changelog`, `version` in `/netmon/healthz`.

### Changed
- Map zooms to 24x; dots, site markers, labels and finding markers keep their screen size, so zooming separates
  nearby sources.
- Finding markers catch the pointer only on the diamond (the ring no longer hides neighbouring sources).
- The near-site ring around each firewall location is gone (it hid the site); its traffic stays in the site's
  tooltip and in the numbers under the site label.

## Before v1.05 (2026-10-29 – 2026-10-30, unversioned)
### Added
- Monitor identity setting (Settings → Firewalls & sites → This monitor): FQDN served by the TLS front end (root
  helper renders the Caddyfile site line, validates, restarts Caddy) and used in notification links; address firewalls
  send to; live DNS check of the FQDN (recognises a reverse proxy on one of your own addresses).
- FQDNs for remote addresses from the Unbound query log (re-resolved on the same resolver, `netmon.dns_resolved`),
  shown under remote addresses in conversation tables; per-firewall DNS card (query log mode record, resolver,
  status) and IDS / DNS query log lines on Settings → Firewalls & sites.
- Optional Zeek sensor service (`docker compose --profile zeek`, pinned zeek/zeek 9.0.0, read-only, capture caps
  only) and three documented feeds: Proxmox bridge mirror (`host/pve-mirror.sh` + timer), switch SPAN, firewall
  bridge span — docs/zeek-sensor.md.
- Threat intelligence from the ExploitHound Threat Radar (Security → Threat intel): IDS findings citing a radar CVE
  are marked (optional one-level raise for CISA KEV), servers get a *Software* list matched against the radar, firewalls
  are matched on their vendor. Enrichment only.
- Server aliases (other names per address), editable from the Servers list; "This is normal" on findings
  (suppress the finding type, the exact finding or the device, and close matching open findings).
- Demo mode (`demo/`): isolated compose project, synthetic seed and live feeder, screenshots from it.
- Expected devices: operator-declared legitimate hosts are excluded from findings, including their destinations
  behind a shared NAT address; managed on Security → Suppressions or from a finding's LAN host list.
- `brand` config option; CSV GeoIP source (`NETMON_GEOIP_DB=*.csv`) for offline tests and the demo;
  `akvorado_metrics: {}` for installs without Akvorado collector metrics.
- Return-path NAT attribution for shared outbound NAT (bandwidth per LAN host with confidence tiers; fan-out
  findings list the LAN hosts their destinations replied to).
- Source health engine with hold-down, recovery and per-source transport judgement; Coverage page.
- ClickHouse schema module (`python -m netmon.schema`) with DNS, Zeek and authentication event tables.
- Unbound query-log and sshd/sudo/su/OPNsense-audit parsing; optional Zeek JSON ingestion.
- DNS context (transport per host, DoT/DoH labels, correlation with confidence, NXDOMAIN and random-label anomalies).
- AI threat score (0-100) with rationale and history; saved analyses load on the finding page without a new request.
- Logged firewall blocks by country; per-site live GeoIP policy.
- Connections filters (direction, protocol, port, server, remote IP).

### Changed
- Several new countries/networks for one host in one window are a single finding.
- 1:1 NAT public addresses are labelled with the internal server behind them.
- Fan-out rule ignores UDP 33434-33534 traceroute probes.
- Block-target validation reports "overlaps our own network" before "private range".

### Fixed
- Security page status tabs rendered a Python function name.
- "last verified null" on the Countries page when the policy comes from the config snapshot.
- Map: French Guiana, Svalbard and Crimea no longer inherit France/Norway/Russia shading.
- Finding pages no longer overflow horizontally on phones.
