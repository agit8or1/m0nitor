# Privacy and hardening

## Ports
| Port | Bound to | Allowed from |
|---|---|---|
| 443/tcp (Caddy) | host | management networks only (ufw) |
| 22/tcp | host | management networks only |
| 2055/udp (NetFlow v5/v9, IPFIX), 4739/udp (IPFIX), 6343/udp (sFlow) | Akvorado inlet | registered devices only (DOCKER-USER, rendered) |
| 5514/tcp+udp (syslog) | rsyslog | registered devices only (ufw `netmon-syslog`, rsyslog AllowedSender, rendered) |
| 8090/tcp (app), 8080/8081 (Traefik) | 127.0.0.1 | local Caddy only |
ClickHouse, Kafka and Valkey are not published.

## Accounts
Local users with roles viewer / analyst / admin, optional TOTP 2FA (can be required by an admin), session cookies
HttpOnly + Secure + SameSite, CSRF tokens on every form.

## Secrets
Files only (see .env.example). Never in config.yaml, logs, URLs or the UI after entry. Rotate the firewall API key if
it is ever exposed; the app re-reads key files without a restart.

## Data and retention (defaults)
Raw flows 30 days, 1-minute 7 days, 5-minute 90 days, 1-hour 1 year (Akvorado); firewall events 14 days, IDS 90 days,
system events 30 days, DNS 7 days (configurable), Zeek 14 days, auth events 90 days. SQLite holds findings, settings,
audit log and investigations.

## AI analysis
Off until a key is configured; manual; preview of the exact payload; internal addresses and names pseudonymized
(mapping stays local); per-day request cap; the cheapest suitable model by default.
