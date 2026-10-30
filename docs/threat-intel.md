# Threat intelligence

m0nitor can read the public [ExploitHound Threat Radar](https://exploithound.com/threat-radar/): CVE intelligence
built from the CISA Known Exploited Vulnerabilities catalog, FIRST EPSS and the CVE Program. It is **enrichment only**.
The radar lists vulnerabilities, not addresses, so it never marks traffic as malicious and no finding depends on it.

## What it is used for

- **IDS findings.** When a Suricata alert's rule metadata cites a CVE that is on the radar, the finding says so
  ("confirmed exploited (CISA KEV)", "predicted (high EPSS)" or "newly disclosed") and adds a next step to check
  whether the target runs the affected software. Optionally, findings citing a confirmed-exploited CVE are raised one
  severity level (off by default).
- **Software you run.** Each server can list its software (✎ on Servers → *Software*, e.g. `nextcloud`,
  `proxmox ve`). Security → Threat intel lists radar CVEs whose product name contains every word of an entry,
  marking servers that are reachable from the internet (port forward or 1:1 NAT). Firewalls are matched on their
  vendor automatically.
- **Recently confirmed exploited.** The latest KEV additions shown on the radar.

## Limits

- The radar shows a window of each list (the most recent KEV additions, the top EPSS forecasts, CVEs published in the
  last 7 days), not the whole KEV catalog.
- Product matching is by name only, with no version comparison. A match means "worth checking", not "vulnerable".
- EPSS is a 30-day forecast, not an observation.

## Operation

Fetched over HTTPS every 6 hours by default (Security → Threat intel: interval, on/off, *Fetch now*). The page is
parsed from its table rows; if a fetch fails or the layout changes, the last good copy is kept and the Coverage page
shows the error. Settings live in the database (`threatintel`); data in the state table (`threatintel:data`).
