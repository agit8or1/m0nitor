# Install, upgrade, uninstall, backup, restore, rollback

There is no installer script yet (see [ROADMAP.md](ROADMAP.md)). To evaluate first, run the [demo](demo.md). These are the steps the reference deployment was built with, on
Ubuntu 24.04 with Docker Engine + compose plugin, ufw and rsyslog. Paths assume `/opt/netmon`.

## Install
1. **Host:** a VM with ≥ 4 vCPU, 8 GB RAM, SSD. ClickHouse ≥ 26.6 needs x86-64-v3 (AVX2); on older CPU types pin
   ClickHouse 26.3 (`akvorado/docker-compose-local.yml` does this — remove the override when the CPU allows).
2. **Akvorado:** download the upstream quickstart bundle for `AKVORADO_VERSION` into `/opt/netmon/akvorado`
   (Akvorado's documentation, "Quick start"), then copy this repository's `akvorado/config/*` over its `config/` and
   `akvorado/docker-compose-local.yml` to `akvorado/docker/`. Add `docker/docker-compose-local.yml` as the last
   `COMPOSE_FILE` entry in `akvorado/.env` and choose the IPinfo GeoIP option there. `docker compose up -d`.
3. **App:** `cp config.example.yaml app/config.yaml` and edit (networks, NAT addresses, users). Create
   `secrets/` (mode 700) and `data/` owned by uid 10001. `cd app && docker compose up -d --build`.
4. **Schema:** `docker exec app-netmon-app-1 python -m netmon.schema | docker exec -i akvorado-clickhouse-1 clickhouse-client --multiquery`.
5. **TLS front end:** `cp .env.example .env`, set `NETMON_SITE`; `cd caddy && docker compose --env-file ../.env up -d`.
   Afterwards the monitor's FQDN can be changed in the UI (Settings → Firewalls & sites → This monitor): the root helper
   rewrites the Caddyfile site line (this monitor's IP + the FQDN, between `# BEGIN/END netmon-hosts` markers), validates
   it in a throwaway Caddy container and restarts Caddy. Notification links follow the same FQDN.
6. **Host helpers (root):** install `host/netmon-apply-sites` to `/usr/local/sbin/`, the `.path`/`.service` units to
   `/etc/systemd/system/`, `systemctl enable --now netmon-apply-sites.path`. Add firewalls in Settings → Firewalls;
   the helper renders the NetFlow/syslog ACLs, rsyslog config and Akvorado exporter metadata.
7. **ufw:** allow 22 and 443 from management networks only; the helper adds the per-firewall 2055/5514 rules.
8. **Firewall side:** [opnsense-setup.md](opnsense-setup.md). Then check the Coverage page.

## Upgrade
- App: `git pull` (or copy the new release), `cd app && docker compose up -d --build`, then re-run the schema step
  (idempotent). Read [CHANGELOG.md](../CHANGELOG.md) first; releases are tagged `vX.YY` and the running version
  is shown in the top bar and at `/netmon/healthz`.
- Akvorado: follow Akvorado's documented upgrade (download `docker-compose-upgrade.tar.gz` for the new version, review
  the `.dist` diffs, keep the local overrides, `docker compose pull`, stop the orchestrator, `docker compose up --wait`).

## Rollback
- App: check out the previous tag/commit and rebuild; the SQLite schema is additive (new tables/columns only), so an
  older app ignores newer additions. Keep the pre-upgrade backup until the new version has run for a day.
- Akvorado: restore the previous `.env`/compose files from the backup and `docker compose up -d`; flow data is kept.

## Backup
`host/netmon-backup` + `netmon-backup.timer` (daily 03:15 UTC): consistent SQLite snapshot + configs + secrets, as an
AES-256 (`openssl enc -pbkdf2`) archive in `/var/backups/netmon`, 30 days kept. Create the key first:
`install -m 600 /dev/null /root/netmon-backup.key && openssl rand -base64 48 > /root/netmon-backup.key`.
ClickHouse flow data is **not** included (it rebuilds from new flows). Copy the key and archives somewhere other than
this VM if you want to survive losing it — whether to keep off-host copies is your decision.

## Restore
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:/root/netmon-backup.key -in FILE | tar -xzf -
    tar -C /opt/netmon -xf files.tar
    install -o 10001 -g 10001 -m 600 netmon.db /opt/netmon/data/netmon.db
then start the akvorado, app and caddy compose projects and re-enable the systemd units. The archive's integrity and
contents were verified on the reference host; a full restore onto a fresh VM has **not** been performed yet.

## Uninstall
`docker compose down` in caddy, app and akvorado (add `-v` to delete flow data); disable and remove the systemd units
and `/usr/local/sbin/netmon-*`; remove `/etc/rsyslog.d/30-netmon-opnsense.conf`, the `netmon-syslog` ufw rules and the
`# BEGIN netmon-senders` block in `/etc/ufw/after.rules`; on the firewall remove the NetFlow destination, the remote
syslog target, the API user and netmon's aliases/rules (category `netmon`).
