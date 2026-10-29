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
| GET | /netmon/api/alert/{id}/traffic | traffic behind a finding |
| GET | /netmon/api/search, /api/name | search (partial IPs/CIDRs), name lookup |
| POST | /netmon/api/geocode | site location lookup |
| GET/POST | /netmon/api/wallboards/{id} | wallboard layout |
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
