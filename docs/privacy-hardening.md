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

**Firewall restrictions (per user).** Under Settings → Users & 2FA an admin can limit a viewer or analyst to some
firewalls. Such a user sees only those firewalls' traffic, findings, incidents, devices, applications, probes,
searches, hunts and logs, on every page and in the API; opening another firewall's record by its number gives "not
found". The restriction is read on every request, so it applies to open sessions at once. Details:

- Admins always see every firewall (they manage firewalls, users and global settings).
- Exceptions a restricted analyst adds from a finding apply to that finding's firewall only. The *expected devices*
  list applies to every firewall, so restricted users cannot change it.
- A saved search made by a restricted user stores their firewalls explicitly, so a detection approved from it never
  covers other firewalls.
- Settings shared by every firewall are not available to restricted users, and the page says so: capacity planning,
  maintenance windows, Inventory (device names and discovery), data sources, auto-response, indicator lists for threat
  hunts, and editing wallboards. Neither is the Akvorado flow explorer, which cannot be limited per user.
- Device names: a device whose address lies only in another firewall's own internal networks is not named or shown;
  addresses no single firewall claims (shared address space) keep their names.
- Incidents: an incident that groups findings from several firewalls (same remote address) is shown only to users who
  can see all of them.
- Health and detector findings are filed under the firewall they are about; monitor-wide ones (the monitor's own
  disk, ClickHouse) are shown to unrestricted users.
- Shared by every firewall and visible to everyone: alert-rule settings, notification channels and the threat-intel
  CVE feed.
- Background work (detector, probes, health checks) always covers every firewall.

## Secrets
Never in config.yaml, logs, URLs or the UI after entry. Stored credentials (UI-entered key files, notification channel
credentials, TOTP seeds) are encrypted at rest with AES-256-GCM under a master key kept outside the data directory;
see [configuration.md](configuration.md#secrets-at-rest) for the key, sealing operator files, rotation and limits.
Rotate the firewall API key if it is ever exposed; the app re-reads key files without a restart.

## Data and retention (defaults)
Raw flows 30 days, 1-minute 7 days, 5-minute 90 days, 1-hour 1 year (Akvorado); firewall events 14 days, IDS 90 days,
system events 30 days, DNS 7 days (configurable), Zeek 14 days, auth events 90 days. SQLite holds findings, settings,
audit log and investigations.

## AI analysis
Off until a key is configured; manual; preview of the exact payload; internal addresses and names pseudonymized
(mapping stays local); per-day request cap; the cheapest suitable model by default.
