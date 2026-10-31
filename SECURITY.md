# Security policy

## Supported versions
m0nitor is pre-release. Security fixes go into the latest version only (see the version in the app's top bar or
`/netmon/healthz`, and the [changelog](CHANGELOG.md)).

## Reporting
Report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository
(<https://github.com/agit8or1/m0nitor/security/advisories/new>), not in public issues. Please include the affected
version, impact and reproduction steps. Do not include real network data, credentials or captures.

## Design rules the code follows
- The monitor is passive and read-mostly: it is not in the traffic path. It changes a firewall only through objects it created itself (one block
  alias, its own auto-response alias and rules, recorded by UUID), and only when an admin has enabled that feature.
- Every automation is switchable and ships off (auto-response ships in dry-run). Notifications stay off until a test
  to the configured destination succeeded.
- Secrets live in files (mode 600, app uid 10001), never in config.yaml, the database's settings JSON, logs or the UI.
  API secrets are never displayed after entry.
- ClickHouse access from the app is read-only and parameterized; DDL is applied by an admin (`python -m netmon.schema`).
- AI analysis is manual and preview-first: you see exactly what will be sent; internal addresses and names are
  pseudonymized; daily caps apply; AI output can never trigger blocking.
- The app container runs non-root, read-only root filesystem, no capabilities, bound to loopback behind Caddy.
- No TLS interception is configured or supported.

## Hardening checklist
See docs/privacy-hardening.md (ports, firewall ACLs, retention, account security, 2FA).
