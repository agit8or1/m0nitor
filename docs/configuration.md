# Configuration

m0nitor has three places for settings. Most day-to-day settings live in the UI.

| Where | What | Notes |
|---|---|---|
| `app/config.yaml` | Seeds a fresh install: first site, networks, detection thresholds, service ports, users | Copy from [`config.example.yaml`](../config.example.yaml). After the first start the database is authoritative for sites, names and labels. |
| UI → **Settings** (SQLite `data/netmon.db`) | Firewalls & sites, inventory names and labels, alert rules, notifications, auto-response, maintenance windows, users and 2FA, AI settings | Changes are audited (Settings → Audit log). |
| `secrets/` (mode 700, files mode 600, owner uid 10001) | API keys, SNMP community, notification credentials, AI key | Never stored in config.yaml, the database's settings JSON, logs or the UI. |

## config.yaml essentials

| Key | Meaning |
|---|---|
| `brand` | Product name in the header and page titles |
| `clickhouse_url`, `akvorado_url` | Where the app reads flows and links to the flow explorer |
| `sites` | Firewalls: exporter name and address, WAN/LAN interfaces, map location, WAN capacity. Edited later in Settings → Firewalls & sites. |
| `internal_nets`, `public_nets` | Your LAN ranges and your own public ranges (the WAN accounting boundary) |
| `outbound_nat_ips` | Shared outbound NAT (WAN) addresses; traffic behind them is attributed per [nat-attribution.md](nat-attribution.md) |
| `exporter_active_timeout` | The firewall's NetFlow active timeout in seconds (120 recommended) |
| `detector`, `rules` | Detection interval, learning period and per-rule thresholds — see [alerting.md](alerting.md) |
| `service_ports` | Ports treated as services when guessing connection direction |
| `assets`, `exposures` | Seed server names and port forwards (later edited in Settings → Inventory) |
| `opnsense` | Firewall API address, TLS server name, block alias and key file (blocking is off without a key) |
| `geoip_policy` | Fallback snapshot of the firewall's GeoIP alias, used only when the live read fails — see [geoip.md](geoip.md) |
| `ai` | Optional AI analysis: model, key file, token and daily request caps, pseudonymization |

Every key in `config.example.yaml` carries an inline comment. Example values use documentation address ranges
(RFC 5737) and private ranges only.

## Deployment variables

`.env` (from [`.env.example`](../.env.example)) holds deployment variables for the Caddy front end, such as the site
name. It holds no secrets.

## Version

The running version is shown in the top bar and footer of every page and returned by `/netmon/healthz`. Each change
is a new version (`v1.05`, `v1.06`, …) with a [changelog](../CHANGELOG.md) entry and a matching Git tag.
