# Usability and investigation improvements — checklist

Goal: show quickly **whether anything is wrong, which device or application is affected, what changed, why it
matters and what to do next**, without needing a security analyst. Each phase ships as its own version with tests and
backward-compatible migrations. Monitoring only: nothing here changes a firewall. The existing approval workflow
stays the only way to block.

| # | Phase | Version | Status |
|---|---|---|---|
| 0 | Inspect existing code, reusable parts | — | done |
| — | Security: MFA single-use under concurrency | v1.40 | done |
| 1 | Persistent device identity (+ per-firewall monitoring choices, firewall picker, missing-permission hints) | v1.41 | done |
| 2 | "What changed?" comparisons | v1.42 | done |
| 3 | Incident correlation and timeline | v1.43 | done |
| 4 | Smarter baselines, precise exceptions | v1.44 | done |
| 5 | Historical threat hunting | v1.45 | done |
| 6 | Segmentation monitoring | v1.46 | done |
| 7 | Application dependency map | v1.47 | done |
| 8 | WAN / VPN quality probes | v1.48 | done |
| 9 | Plain-English investigation search | v1.49 | done |
| 10 | Detection testing and replay | v1.50 | done |

Navigation stays at eight entries. *Investigations* becomes **Investigate** (Incidents, What changed, Search, Threat
hunt, Test detections, AI analysis). Applications, Segmentation and Identity review are tabs under **Internal
devices**. WAN/VPN quality is under Settings → Status, with a summary on the Overview.

## Reusable parts found (phase 0)

- Findings (`alerts`), suppressions (`exceptions`), expected devices, maintenance windows, notifications with routing,
  quiet hours and rate limits, audit log (append-only).
- Detector rules over ClickHouse flows with parameterized SQL (`Detector.q`); the read-only ClickHouse user can run
  rule SQL against injected rows (`values()` + a `flows` CTE), so replay needs no writes.
- Discovery (traffic + ARP), device types/vendors, Inventory names, AI preview-first analysis with spend limits.
- Dashboard scope (sites, time range, filters) kept in the URL.
- Data on the reference deployment: ~8 days of flows, LAN↔LAN and VPN flows partly visible, OPNsense configuration
  changes in `sys_events` (`audit` "changed configuration"), DNS query log.

## Phase reports

### Phase 1 — Persistent device identity (v1.41)

- **What changed:** time-stamped identity evidence per site (`identities`, `identity_evidence`, suggestions, history);
  discovery also reads the IPv6 neighbour table and DHCP leases; findings record the device at the time; review UI
  (merge / separate / undo / rename); per-firewall monitoring choices; site time zone; multi-firewall picker; HTTP 403
  from the firewall names the missing privilege.
- **Where:** device page → Address history; Internal devices → Identity review; finding page → Device at the time;
  Settings → Firewalls & sites → What to monitor / Time zone; Settings → Inventory → Auto-discovery.
- **Data:** ARP privilege; optional NDP and DHCP-lease privileges (docs/opnsense-permissions.md).
- **Validated:**
  - unit tests for attribution across IP changes, overlapping addresses at two sites, randomized MACs, reused IPs
    without a MAC, ambiguous double use, IPv6/mapped addresses, merge/separate/undo with audit, two addresses at once;
  - web tests for roles, escaping and the monitoring choice being honoured by the detector and health checks;
  - a staging run against the real firewall and flows: 44 ARP entries became 43 devices (one server with two
    addresses) plus one traffic-only device, no false suggestions, and the two ungranted privileges named exactly.
- **Limits:** names in Inventory stay per address; devices behind other routers have no MAC evidence; existing pages
  still use the single-address label, while the new pages and finding details use the identity.

### Phase 2 — "What changed?" (v1.42)

- **What changed:** a deterministic comparison engine (`changes.py`) with five comparison modes (day, week, selected
  period, same weekday and time on previous weeks, two custom periods) in each firewall's time zone. It ranks
  telemetry gaps, newly observed inbound services, new destinations of fixed-function devices, volume changes,
  configuration changes, newly observed devices, and new countries and networks. Each item is one sentence with
  values, comparison, confidence and an evidence link. A configuration-change page shows audit lines plus services
  first observed after the change, labelled as an association.
- **Where:** Investigate → What changed; Overview → Important changes today; configuration change → View evidence.
- **Data:** flow records (raw plus Akvorado's 5-minute and 1-hour tables for coverage and history); `sys_events`
  audit lines for configuration changes; identities for newly observed devices. No AI.
- **Validated:**
  - unit tests for DST days (a 25-hour fall-back day; spring-forward on weekday comparisons) and for week and custom
    periods, including invalid ones;
  - tests that half coverage does not read as half the traffic, that "no traffic at all" is worded plainly, that the
    "newly observed" lookback is bounded by the history that exists and lowers confidence, that shared-NAT novelty is
    ranked low, that expected devices are demoted, and that the summary is capped per kind;
  - a staging run on real data: today vs yesterday in about 6 s, a week in about 9 s, the weekday comparison in
    about 3 s, with sensible results (one configuration change, a device with new countries, volume spikes).
- **Limits:** per-device outbound volume is only known for 1:1 NAT and port-forwarded devices; "contacted" is
  inferred from ports; history is what Akvorado retains (about 8 days on the reference deployment), and every line
  says so. The Overview card always compares all firewalls.

### Phase 3 — Incidents (v1.43)

- **What changed:** findings are grouped into incidents (`incidents.py`, schema v7) when they share a device identity
  or a remote address within 6 hours, with the reason stored per link. Each incident has one anchor, so devices are
  never chained together through other findings. It spans at most 24 hours and needs a medium-or-higher security
  finding to start. The incident page covers what happened, affected devices, why it matters, confidence and missing
  information, next step, timeline and raw evidence. You can assign, add notes, set status with a resolution reason,
  split, add or merge, all with history and audit. Analysts can export a JSON evidence bundle (audited).
  Notifications are deduplicated per channel and incident. The Overview has a "Needs attention" strip. Open findings
  from the last 7 days are grouped once after the upgrade.
- **Where:** Investigate → Incidents; finding page banner or "Start an incident"; Security list tags; Overview strip.
- **Data:** existing findings only. Firewall audit lines from `sys_events` go on the timeline when available.
- **Validated:**
  - tests: single findings and info-only pairs stay ungrouped; same device across an address change; same remote
    address across devices; window bounds on both sides; shared NAT, health and TEST findings excluded; a split
    finding is never re-added; merge, resolution reason required, closing findings, a resolved incident not reopened;
    per-channel dedup with higher severity still sent; roles (viewer reads only, analyst acts, export 403 for
    viewers), CSRF, escaping, the export audit record; the detector correlates before notifying;
  - staging on real data: 1,816 open findings were grouped into 6 single-device incidents in 12 s. The first version
    chained 14 devices through shared scanners; that was fixed with anchors and the medium-severity starter rule.
- **Limits:** incidents are per firewall for device anchors; a remote-address anchor can span firewalls. Evidence
  export is JSON only. Site-restricted users arrive with Phase 9 (per-user firewall access), so for now every analyst
  sees every incident.

### Phase 4 — Baselines and precise exceptions (v1.44)

- **What changed:**
  - `baselines.py`: schedules in the firewall's time zone; precise exception matching (destination, service,
    schedule, firewall, expiry); a preview of what an exception hides; telemetry-aware, local-hour, weekday/weekend
    baselines; suspicious hours left out of learning; learning progress.
  - Schema v8 adds peer, service, schedule, site, hits and last_hit to `exceptions`. Existing exceptions keep working
    unchanged.
  - The outbound-volume rule subtracts traffic to excepted destinations before the check.
  - "This is normal" has the precise options and a preview step. The Suppressions page lists exceptions in plain
    language with hit counts, extend and remove.
- **Where:** finding page → This is normal; Security → Suppressions (Baselines card, exception list).
- **Data:** flows (raw for per-destination subtraction, the hourly table for telemetry hours) and existing findings
  and incidents. No new firewall permissions.
- **Validated:**
  - tests: overnight schedules, schedules across a DST change, invalid schedules; destination exceptions hiding only
    findings that name exactly that destination; service exceptions; schedules; firewall and expiry limits; fan-out
    and volume never hidden by a destination; volume with a backup exception (the backup traffic is subtracted and an
    unrelated 900 MB upload still alerts; the backup alone is not flagged); missing telemetry days do not lower the
    baseline; hours with open findings are not learned; hit counts; preview, then save, then review/extend via the UI,
    including validation errors. Existing "This is normal" behaviour is unchanged (existing tests pass);
  - staging: subject/evidence formats of all 12 rules on real findings parse into the right peers and services. A
    destination exception on a real beaconing finding previews as "would have hidden 1, 3 others for this device
    still raised".
- **Limits:** only the outbound-volume rule has an hour-of-day baseline, so roles and schedules only shape that rule
  and the exceptions; the other rules use thresholds or novelty. Earlier volume findings are not re-evaluated when an
  exception is added. Time zones that are not whole hours are rounded to the UTC hour.

### Phase 5 — Historical threat hunting (v1.45)

- **What changed:**
  - `hunt.py` and `hunt_views.py`; schema v9 adds `indicator_lists`, `indicators`, `hunt_runs` and `hunt_matches`.
  - Indicator parsing: plain or CSV, defanged forms, URLs; private addresses and wide ranges refused.
  - Lists: manual lists, and HTTPS feeds (admin, size-limited, scheduled, none by default). The first time netmon sees
    an indicator is kept, and indicators dropped from a feed become inactive.
  - Hunts are deduplicated across lists and run in the background, one at a time, in daily chunks with progress,
    cancel, a 10-minute cap and indicator limits. Sources: flows on raw IPv6 columns in both directions, the DNS log
    (names and answers) and the firewall log.
  - Matches are merged per indicator, source, firewall and device. 1:1 NAT addresses are normalized to the internal
    device. Shared-NAT outbound rows are folded into the devices named by reply records.
  - Each match notes publication date vs contact, CDN ASN, shared hosting (names per address from `dns_resolved`),
    stale indicators and NAT, plus the coverage per source and firewall.
  - "Create a finding" turns a match into an `indicator_match` finding, which is correlated into incidents and not
    notified.
- **Where:** Investigate → Threat hunt; Security → Threat intel links to it.
- **Data:** raw flows (Akvorado's raw retention; the aggregate tables have no addresses), `dns_events`,
  `dns_resolved`, `fw_events`. No firewall permissions.
- **Validated:**
  - tests: classification (defanged, URLs, CIDR width, private refused); CSV dates; `known_since` kept across feed
    refreshes and inactive marking; dedupe across lists (highest confidence, earliest publication); merging,
    attribution and NAT folding; before-publication, CDN and shared-hosting flags; DNS-answer attribution; firewall
    log matches; coverage; every source query bounded (LIMIT, daily chunks); one hunt at a time; cancel; limits;
    feed https-only, redirect and size limits, with the last data kept on failure; roles (viewer reads, analyst hunts
    and adds manual lists, admin adds feeds); finding from a match, with low severity before publication;
  - staging on real data: a 7-day hunt over 4 indicators (2 addresses, a Cloudflare range, a domain) took 12–18 s.
    Matches were attributed to named devices, Cloudflare and shared-hosting flags were raised, and coverage was
    100% for flows and DNS.
- **Limits:** hunts reach back only as far as raw flow retention (about 9 days here) and the DNS log (about 7
  days). Outbound-only contact through the shared NAT address (no replies) cannot be tied to a device unless DNS
  answers point to it. No STIX/TAXII import; feeds are plain or CSV.

### Phase 6 — Segmentation monitoring (v1.46)

- **What changed:**
  - `segments.py` and `segments_views.py`; schema v10 adds `seg_groups` and `seg_policies`.
  - Groups of address ranges per firewall, with a sensitivity; rules (allow, optionally limited to services, or none
    expected) between groups or to/from any group, with an optional schedule; four templates.
  - Verdicts: a specific group pair beats "any group"; "allowed only on listed services" makes other services
    unexpected.
  - Observation: internal-to-internal records (address-range based, so it works across interfaces, bridge members
    and VPN), client inferred from ports, the firewall's own address excluded. Firewall-log blocks are counted
    separately.
  - The matrix shows expected vs seen vs blocked, with cell details. The `segmentation` detector rule honours the
    monitoring choice and works with precise exceptions.
- **Where:** Internal devices → Segmentation; findings on Security; per-firewall switch under What to monitor.
- **Data:** flow records with both ends internal, and the firewall log for blocks. No firewall permissions.
- **Validated:**
  - tests: group validation and the most specific range; verdicts (service-limited allow, direction, specific vs
    any, no group); schedules; templates applied once; the matrix counts unexpected records, excludes the firewall's
    address, shows blocks without traffic, notes unseen groups and a missing firewall log; the query is bounded;
    findings with severity by sensitivity; a precise exception hides exactly one; roles, validation and audit;
  - staging on real data: 3,648 internal conversations per day read in 0.8 s. VPN clients → Servers with
    "tcp/443, tcp/22 only" flagged a development port (tcp/5173) used from three VPN clients. Firewall-proxied
    traffic was correctly left out.
- **Limits:** traffic inside one switch or VLAN is invisible (said on the page). Who opened a connection is inferred
  from ports. Groups are address-based (not VLAN tags or interfaces). Blocks are only known when the firewall logs
  them.

### Phase 7 — Application dependency map (v1.47)

- **What changed:**
  - `apps.py` and `apps_views.py`; schema v11 adds `apps`, `app_members` and `app_deps`.
  - Applications per firewall, each with members, an owner and a critical mark. Members store their device
    identity and follow its current address.
  - Observed dependencies, in both directions:
    - internal conversations with a member on either side; the client is inferred from ports;
    - internet dependencies from reply records, grouped by AS and service, with a count of remote addresses.
    The other side is labelled with its application when it belongs to one.
  - Each dependency shows records, bytes, last seen, and when netmon first saw it (remembered beyond the period).
    Confidence is the share of days, or 4-hour periods for 24 hours, in which it was seen.
  - "New" means first seen in the last 24 hours; this is not applied to an application created less than a day ago.
  - Statuses: observed, confirmed or dismissed. A confirmed dependency that was not seen is listed with the reminder
    that lack of traffic does not prove it is gone.
  - Outage impact covers every application that a device belongs to.
  - An optional inline SVG picture (labelled for screen readers) supplements the list.
  - Queries are bounded by the period (24 h / 7 d) and a row limit, and cached for five minutes.
- **Where:** Internal devices → Applications (list, new application, outage impact of one device); each
  application's page (devices, what it uses, what uses it, dismissed, "Show picture").
- **Data:** flow records only (internal-to-internal and inbound/reply records). No firewall permissions.
- **Validated:**
  - Tests:
    - validation: names, internal addresses only, duplicates;
    - classification: inside the application vs uses vs used by, labelling with another application, confidence;
    - "new": first seen is remembered, and a just-created application gets no false "new";
    - confirmed but not seen, and dismissed;
    - members follow an identity's address change;
    - outage impact with a device in two applications;
    - the query is bounded and parameterised;
    - the picture is accessible and escaped;
    - roles, CSRF, audit, 404 and deletion.
  - Staging on real data, one server:
    - 15 dependencies over 24 hours in 0.3 s; 22 over 7 days in 0.6 s; outage impact in 0.6 s;
    - pages render in 0.15–0.9 s.
    - Internet dependencies were correctly tied to the server behind the shared address (AI API, code hosting,
      cloud, OS mirrors, NTP).
- **Limits:**
  - Traffic inside one switch or VLAN is invisible.
  - Direction is inferred from ports.
  - Internet dependencies are per network owner, not per host name; names from DNS are a possible extension.
  - The picture is a simple radial view of the top 12; there is no full network graph by design.

### Phase 8 — WAN / VPN quality probes (v1.48)

- **What changed:**
  - `quality.py` and `quality_views.py`; schema v12 adds `probes` and `probe_results`.
  - Probe types:
    - ping: unprivileged ICMP sockets, IPv4/IPv6; latency, loss, jitter;
    - TCP connect;
    - DNS: a hand-built query, response time and result code;
    - HTTPS: one request, no redirects, at most 64 KB read; status and certificate problems.
  - Configuration:
    - each probe has a role (firewall, provider's first hop, internet host, VPN site, service), an interval
      (30 s – 1 h), a count and a timeout;
    - limits: at most 20 probes, and count × timeout below half the interval;
    - nothing runs by default; the recommended set is listed before an admin adds it.
  - Running and storage: one runner thread with a 4-worker pool, honouring the per-firewall "probes" choice. Results
    are kept 30 days.
  - Status: compared with the probe's usual values (the 7-day median, excluding the last hour), after 60 rounds of
    learning. Reports normal, learning, degraded, down, no data or paused.
  - Degraded periods need ≥ 2 bad rounds in a row. Their facts:
    - which probes were affected and which were not;
    - WAN peak Mb/s from `flows_1m0s`, with the share of the contracted capacity;
    - firewall events at the same time (`sys_events`: gateway, VPN, interface, routing, HA, configuration changes),
      each "not necessarily the cause".
  - Suspected causes come from explicit rules; the provider is suspected only with first-hop evidence.
  - Also: a Health row per firewall, and the Overview "WAN quality" item.
- **Where:** Settings → Status → WAN / VPN quality; Settings → Health; the Overview attention strip.
- **Data:** the probes' own results, the traffic records (utilization), the device-event log (correlation). No
  firewall permissions; nothing changes on the firewall.
- **Validated:**
  - Tests:
    - validation and every limit, including the 20-probe cap;
    - round summary (loss, mean, jitter) and the DNS packet format;
    - one bad round is not a period; two or more are;
    - learning, down, no data and paused states;
    - suspected-cause rules: provider not named without first-hop evidence, named with it, a busy link wins, local
      side, one destination, DNS, VPN, no guess with one probe; events are facts only;
    - a report with utilization, bounded queries, the health row and the overview item;
    - roles, CSRF, audit and 404.
  - Staging on the real network:
    - every probe type measured (firewall 0.3 ms, anycast resolvers 7–15 ms, DNS 0.5–25 ms, HTTPS 76–309 ms);
    - NXDOMAIN and an unreachable host reported correctly.
    - An unreachable test target produced one ongoing period (13 rounds): "that destination or the path to it,
      the other probes were fine", with the real WAN utilization at 0% of capacity.
    - The report took 0.05 s and the page 0.2 s. The staging probes were removed afterwards.
- **Limits:**
  - The vantage point is the netmon server only; there are no probes from the firewall, as that would need API
    privileges or agents.
  - Firewall-side gateway monitoring (dpinger) is used only through its log events.
  - Utilization comes from flow records, which may be sampled; SNMP counters would be more exact.
  - A provider's first hop must be entered by the admin.
  - The IPv6 probes need IPv6 connectivity on the netmon host.

### Phase 9 — Plain-English search (v1.49)

- **What changed:**
  - `nlsearch.py` and `search_views.py`; schema v13 adds `saved_searches`.
  - A *search spec* with named fields:
    - what is searched: source, period or from/to, firewalls;
    - what is matched: device, remote, country, AS, owner name, port, protocol, direction, sent/received, name looked
      up, firewall action, severity, finding type, minimum volume;
    - how results come back: group, limit.
  - `validate` keeps only known fields. It types and bounds each one (retention per source, limit ≤ 200), and drops
    fields that don't apply, with a note.
  - `parse` is deterministic: periods (today, yesterday, last N hours/days/weeks), addresses and device names,
    countries, AS numbers, "owned by …", services (ssh, rdp, …), direction words, volumes ("more than 1 GB") and
    grouping words. Unknown words are reported.
  - `run` uses fixed templates for flows, `dns_events`, `fw_events` and SQLite findings, with typed parameters, on the
    client's read-only session (readonly=1, 45 s, row cap). There is a single LIMIT, and IPs and ranges go in as
    typed bounds.
  - Device attribution follows the record semantics:
    - received volume and per-device questions use the de-NATed inbound/reply records;
    - sent volume uses the outbound records, and refuses to name a device behind a shared NAT address;
    - internal traffic uses internal-to-internal records, with the client inferred from ports.
  - Optional AI:
    - the preview shows the pseudonymized question, the model and today's usage against the limit;
    - the request carries a digest check, so the question cannot change after the preview;
    - the response must match a strict JSON schema of filters only, with pseudonyms mapped back locally and
      unknown keys dropped, and then goes through the same validator;
    - requests are audited.
  - Saved searches are private, or shared by analysts and admins.
  - Detections:
    - lifecycle: proposed by an analyst → admin review, which estimates the firings per day from 24 sampled windows
      over 7 days → approved or rejected;
    - no self-approval when another admin exists; at most 20 detections;
    - each run uses its own interval window;
    - detector rule `search_detection`, with findings through the normal record/notify path.
- **Where:** Investigate → Search (the question box, examples, editable filters, results, saved searches); the
  review page, admin only. The header quick search links to it.
- **Data:** the traffic records, DNS query log, firewall log and findings that already exist. AI only if a key is
  configured. No firewall permissions.
- **Validated:**
  - Tests:
    - the parser on every example and on mixed questions, with unknown words reported;
    - validation errors and bounds, including retention per source, the limit cap and dropped fields;
    - an attack string in the owner name, plus IPs, ranges and country, never appear in the SQL (typed parameters
      only), with LIMIT and window checked;
    - shared-NAT refusal, and 1:1 NAT mapping;
    - findings search, including grouping and ranges;
    - AI: the preview pseudonymizes, model output is filters only (an injected `sql` key and unknown placeholders
      are dropped), and a question changed after the preview is refused;
    - saved-search visibility and deletion rights;
    - the detection lifecycle: nothing runs while proposed, no self-approval, findings over the interval, not due
      again, stop;
    - pages: viewers can't share or propose, analysts can't approve, saved searches are private, the review page
      estimate shows, CSRF is enforced.
  - Staging on real data:
    - "devices to Russia, 7 days": 11 devices in 0.7–1.6 s;
    - DNS by device 16–300 ms;
    - "uploaded more than 1 GB yesterday": the shared NAT address was labelled as several devices, and a 1:1 NAT
      server was shown via its address;
    - internal SSH: 66 ms.
    - The review preview took 0.8 s. A detection fired once and was not due again within its interval. Test data was
      removed.
- **Limits:**
  - The parser covers common phrasing, not arbitrary English; AI or the filter form covers the rest.
  - Sent volume per device behind a shared NAT address is not knowable from the WAN records.
  - Per-user firewall (site) restrictions are not built: as everywhere in netmon, every signed-in user can see every
    firewall. Restricting this only in Search would be a misleading control. It needs enforcement on every page and
    API, and remains open.

### Phase 10 — Detection testing and replay (v1.50)

- **What changed:**
  - `dtest.py` and `dtest_views.py`; no schema change. The last replay result is kept in `state`.
  - Isolation (`SyntheticCH`):
    - every `flows*` / `netmon.*_events` reference in a rule's SQL is rewritten to a CTE built with `values()`,
      typed and with escaped literals;
    - comments are stripped, string literals ignored, and matching is case-insensitive;
    - any other table or table function (`system.*`, `url()`, unknown tables) raises `Isolated`;
    - limits: at most 20,000 synthetic records, and the read-only session is unchanged.
  - `SandboxDetector`: the real `Detector` rules, with `record()` raising and no notifier.
  - `evaluate`:
    - follows run_site's post-filters (direction check, expected-only);
    - applies record-time checks without writing: a dry exception check (no hit counted) and expected devices;
    - honours the per-firewall monitoring choices.
  - Six scenarios (new country, large upload, exposed port, scan, beaconing, normal day). Each has parameters and
    expected findings, and builds its baseline and window records with the same record semantics as real traffic
    (de-NATed inbound, post-NAT outbound).
  - Results compare expected vs actual. "Why it triggered" is the rule's own baseline text; "why not" comes from
    the settings (thresholds, switched off, monitoring choice, learning, port forward, ephemeral floor, service port,
    active timeout), or names the exception or expected device that hid the finding.
  - Preview rule changes:
    - `admin.parse_rules_form` is shared by Save and Preview, with proposed settings relative to config.yaml;
    - `changes` / `changed_rules` (detector-wide settings affect all flow rules);
    - the affected scenarios run with current vs proposed settings.
  - Replay job:
    - current vs proposed over ≤ 48 sampled windows of 24 h / 3 d / 7 d;
    - one job at a time, ≤ 10 min, cancel button, auto-refreshing progress page;
    - distinct findings per rule with examples of added and removed ones;
    - not replayable (live state): source silence, disk;
    - audited.
  - Links: a "Test detection" link per rule on Alert rules, and a "Preview rule changes" button next to Save.
- **Where:** Investigate → Test detections; Settings → Alert rules (Preview rule changes, Test detection links).
- **Data:** none for scenarios (synthetic); for replay, the retained flow, IDS and firewall-log data. No firewall
  permissions.
- **Validated:**
  - Tests:
    - rewriting (CTE merge, lowercase, aggregated tables, empty event tables, comments, string literals) and
      refusals (system tables, unknown tables, a table function, database-qualified flows, joins to other tables);
    - an injection-style value stays one escaped literal;
    - every query the scenario rules actually send is rewritten (no `FROM flows`, no `netmon.`);
    - the sandbox never records and has no notifier;
    - scenario record shapes (window, country, interfaces, NAT address, regular intervals);
    - expected vs actual:
      - pass;
      - hidden by an exception (no hit counted);
      - a port forward;
      - an ephemeral port;
      - a monitoring choice;
      - an unexpected extra finding fails the scenario;
    - why-not thresholds;
    - settings relative to config.yaml, so a proposed default really reverts;
    - replay: counts, added findings, one at a time, a bad period refused, cancellation, no alerts written, audit;
    - pages and roles: viewers can't run tests, analysts can run but not preview, admins preview without saving.
  - Staging on real ClickHouse:
    - all six scenarios run through the real rules in about 5 s; 5 behaved as expected;
    - the large upload was raised by the rule but hidden by an existing exception for the shared NAT address, and the
      test said exactly that;
    - the escaped injection value round-tripped intact; `system.tables` was refused;
    - a replay of a fan-out threshold change (150 → 50) over 24 h finished in 114 s (24 windows), a second replay was
      refused while it ran, and no alert was written.
- **Limits:**
  - Scenarios cover the main flow rules (new country/ASN, volume, exposure, fan-out, beaconing). IDS and
    firewall-log rules can be replayed but have no synthetic scenario yet.
  - Replay samples windows, so it is an estimate, and it compares distinct findings, not notifications.
  - Rules that depend on live state can't be replayed.
  - A replay result in memory is lost on restart; the last finished result per firewall is kept.

