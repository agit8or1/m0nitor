# HTTP API and storage

All endpoints need a session (cookie from `/login`); state-changing requests need the CSRF token. Responses are JSON.
Scope parameters (most GET endpoints): `site`, `range` (15m…30d) or `from`/`to`, `cc`, `host`, `asn`, `port`, `rip`.

| Method | Path | Purpose |
|---|---|---|
| GET | /netmon/healthz | liveness (no auth) |
| GET | /auth/verify | session check used by Caddy forward_auth for the Akvorado console |
| GET | /netmon/api/overview, /api/live | overview tiles, live bandwidth/freshness |
| GET | /netmon/api/servers, /api/server | per-server bandwidth (incl. NAT attribution) |
| GET | /netmon/api/connections | conversations; `dir=in|out|unknown`, `proto`, `port`, `rip` |
| GET | /netmon/api/countries, /api/country, /api/country/{cc}/blocks | traffic and logged blocks by country, policy per site |
| GET | /netmon/api/firewall, /api/ids, /api/sources | firewall events, IDS alerts, telemetry source state |
| GET | /netmon/api/onboarding?site= | onboarding test for one firewall: source states, quality rows, NAT tiers (15 min), current guided validation (404 for a firewall the user may not see) |
| GET | /netmon/api/alert/{id}/traffic | traffic behind a finding |
| GET | /netmon/api/search, /api/name | search (partial IPs/CIDRs), name lookup |
| POST | /netmon/api/geocode | site location lookup |
| GET/POST | /netmon/api/wallboards/{id} | wallboard layout |
| GET | /netmon/api/changes/top | "Important changes today" for the Overview (computed in the background, cached) |
| GET | /netmon/api/attention | open incidents, unassigned incidents, ungrouped high-severity findings, health and WAN quality problems |
| GET | /netmon/api/hunt/{id} | progress and matches of a threat hunt run |
| GET | /netmon/api/detections/test/replay/{id} | progress of a rule-change replay (admin) |
| GET | /netmon/api/ai/preview | build the exact pseudonymized payload (analyst) |
| POST | /netmon/api/ai/send | send a previewed payload (analyst, daily cap) |

## ClickHouse
- `default.flows*` — owned by Akvorado (raw + aggregated resolutions).
- `netmon.*` — owned by netmon, created by `python -m netmon.schema` (see `app/netmon/schema.py` for columns and TTLs):
  fw_events (+ fw_hourly rollup), ids_events, sys_events, dns_events, zeek_conn/tls/http/notice/stats, auth_events.

## SQLite (`/data/netmon.db`)
alerts, exceptions (suppressions), maintenance, blocks, response_log, investigations (saved AI analyses), channels and
deliveries (notifications), counters, wallboards, users, sessions, mfa_pending, login_failures, audit, settings (JSON per
key; secrets are never stored here — key files only), state.
Investigation (schema versions 7–13, added by backward-compatible migrations; `PRAGMA user_version` is the schema
version): identities, identity_events, identity_evidence, identity_suggestions; incidents, incident_alerts,
incident_events; indicator_lists, indicators, hunt_runs, hunt_matches; seg_groups, seg_policies; apps, app_members,
app_deps; probes, probe_results; saved_searches.

Most investigation pages are HTML forms rather than JSON endpoints (`/netmon/incidents`, `/netmon/changes`,
`/netmon/hunt`, `/netmon/segments`, `/netmon/apps`, `/netmon/quality`, `/netmon/search/flows`,
`/netmon/detections/test`); their POST actions need the CSRF token and the role named in
[investigation.md](investigation.md). For example, `POST /netmon/incidents/{id}/dismiss` and `/reopen` (analyst).
