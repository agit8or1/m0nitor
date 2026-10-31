# Changelog

Versions are `vMAJOR.MINOR` with two-digit minors (v1.05, v1.06, ... v1.10). Every change ships as a new version
with its own section here; the running version is in the page footer and on Changelog in the app.

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
