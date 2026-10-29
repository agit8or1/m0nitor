# Demo mode

A self-contained instance with **synthetic data only** — no firewall, no OpenAI, no notification services.

    docker compose -f demo/docker-compose.yml up -d --build
    docker compose -f demo/docker-compose.yml logs seed | grep "admin password"

What it runs: its own ClickHouse and SQLite (separate volumes, project name `m0nitor-demo`), a one-shot `seed`
that creates the schema and four days of history, a `feeder` that appends one minute of traffic every minute, and
the app with `demo/config.yaml` (no API key, no SNMP, no AI key; Akvorado collector metrics marked not configured).

Isolation: every service is on an `internal: true` network, so nothing can leave the host — the app cannot even
resolve external names. To open the UI in a browser on the same machine add `demo/view.yml`
(`-f demo/docker-compose.yml -f demo/view.yml`) and browse to http://127.0.0.1:8099; that override attaches the
app to a second network to publish the port, which also gives it a route out, but the demo config holds no
credentials for anything.

Synthetic network: LAN 10.40.0.0/24, own public 203.0.113.176/28 (shared NAT .179, 1:1 NAT for crm-1 and
backup-1), and "the Internet" = the rest of the RFC 5737 documentation ranges, split into /28s and given countries
and documentation ASNs (RFC 5398) through a CSV that replaces the GeoIP database. Scenarios the real detector finds:
a workstation scanning behind the shared NAT (fan-out with LAN host attribution, NXDOMAIN/random-label burst,
many new countries), a beaconing workstation, a 3 GB upload, a blocked port scan, IDS alerts and SSH password
guessing on web-1.

Screenshots in `docs/screenshots/` were taken from this demo with `demo/screenshots.py`, running Playwright inside
the demo app's network namespace.

Reset: `docker compose -f demo/docker-compose.yml down -v`.
