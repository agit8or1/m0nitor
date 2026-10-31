# Configuration

m0nitor has three places for settings. Most day-to-day settings live in the UI.

| Where | What | Notes |
|---|---|---|
| `app/config.yaml` | Seeds a fresh install: first site, networks, detection thresholds, service ports, users | Copy from [`config.example.yaml`](../config.example.yaml). After the first start the database is authoritative for sites, names and labels. |
| UI → **Settings** (SQLite `data/netmon.db`) | Firewalls & sites, additional devices (`devices:db`), inventory names and labels, alert rules, notifications, auto-response, maintenance windows, users and 2FA, AI settings | Changes are audited (Settings → Audit log). |
| `secrets/` (mode 700, files mode 600, owner uid 10001) | Operator-placed files: bootstrap admin password, firewall API key, SNMP community | Read-only for the app. Seal them in place (below); plaintext still works and Settings → Health flags it. |
| `data/secrets/` and the database | Credentials entered in the UI: per-firewall API keys, SNMP communities and SNMPv3 passphrases, AI key (files); notification channel credentials and TOTP seeds (database) | Always sealed with the master key. Never in config.yaml, logs, exports or the UI after entry. |
| `keys/master.key` (mode 400, owner uid 10001) | The master key for secrets at rest | Mounted read-only at `/run/keys`. Not in `data/`. |

## Secrets at rest

Every credential the app stores is sealed with AES-256-GCM (`netmon/secretbox.py`). The value's location (`channel`,
`totp:<user>`, `file:<name>`) is bound as associated data, so a sealed value copied to another field or file does not
decrypt, and any change to it is detected.

- **Master key:** 32 random bytes in `/opt/netmon/keys/master.key`, mounted read-only at `/run/keys/master.key`
  (`NETMON_MASTER_KEY_FILE` overrides the path). Create it before the first start:

      sudo install -d -o 10001 -g 10001 -m 700 /opt/netmon/keys
      sudo sh -c 'umask 077; openssl rand -base64 32 > /opt/netmon/keys/master.key'
      sudo chown 10001:10001 /opt/netmon/keys/master.key && sudo chmod 400 /opt/netmon/keys/master.key

  Without it the app creates `data/master.key` so it can still start, and Settings → Health warns until you move that
  file to `/opt/netmon/keys/` and restart.
- **Upgrade from v1.25 or earlier:** at the first start, plaintext values are sealed in place (the log shows
  `secrets at rest: {...}` counts). Versions before v1.26 cannot read sealed values, so to roll back restore the
  pre-upgrade backup of `netmon.db` and `data/secrets/`.
- **Operator files** in `secrets/` are mounted read-only, so seal them with a one-off container:

      cd /opt/netmon/app && docker compose run --rm --no-deps -v /opt/netmon/secrets:/seal netmon-app \
          python -m netmon.secretbox seal /seal/opnsense_block.key /seal/snmp_community /seal/admin_password

  The app reads sealed and plaintext files alike. To replace a sealed file, write the new plaintext value and seal it
  again.
- **Rotation:** rename `master.key` to `master.key.old`, create a new `master.key` as above, restart. Everything is
  re-sealed with the new key at startup (including operator files only when you run `seal` again); Health lists the
  old key until you delete it. Keep it while you may still restore backups made before the rotation.
- **Lost key:** sealed values cannot be recovered. Health reports them as undecryptable; re-enter the credentials
  (firewall and SNMP settings, notification channels, AI key). TOTP: sign in with a recovery code (stored as hashes,
  not sealed), then enrol again.
- **Status without revealing anything:** `docker exec app-netmon-app-1 python -m netmon.secretbox status`.
- **What it protects against:** a copy of `netmon.db` or of `data/` (snapshot, disk image, support bundle) without the
  key. It does not protect against root on the host or code running in the app container, which can read the key.
  The encrypted backup includes `keys/` so a restore can decrypt; anyone with the backup key can read everything.

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
| `syslog_max_lines_per_second` | Per-sender cap for non-OPNsense devices (default 5000 per received second; drops are counted) |
| `rules` (device events) | `device_auth_failures`, `vpn_tunnel_down`, `interface_down`, `routing_neighbor_down`, `ha_failover`, `config_change`, `device_silence`: seeded with defaults when absent, so existing files need no change |

Every key in `config.example.yaml` carries an inline comment. Example values use documentation address ranges
(RFC 5737) and private ranges only.

## Deployment variables

`.env` (from [`.env.example`](../.env.example)) holds deployment variables for the Caddy front end, such as the site
name. It holds no secrets.

## Version

The running version is shown in the top bar and footer of every page and returned by `/netmon/healthz`. Each change
is a new version (`v1.05`, `v1.06`, …) with a [changelog](../CHANGELOG.md) entry and a matching Git tag.
