# Blocking setup — one-time per firewall, done by an administrator in the GUI
OPNsense: sections 0–4 below. pfSense: see "pfSense" at the end. Each firewall has its own alias and API key
(Settings → Firewalls & sites → Connection settings); a block request picks which firewalls it applies to.

netmon never edits firewall rules. It only adds/removes addresses in ONE alias
(`netmon_block`) after an admin approves a previewed request in /netmon/blocks.

## 0. Backup first
System → Configuration → Backups → Download configuration.

## 1. Alias
Firewall → Aliases → +
- Name: `netmon_block`   Type: **Host(s)**   Content: (empty)
- Description: `Managed by netmon (approval-gated)` → Save → Apply

## 2. Rules (Firewall → Rules → Floating), place both at the TOP
| # | Action | Quick | Interface | Direction | Proto | Source | Destination | Log | Description |
|---|--------|-------|-----------|-----------|-------|--------|-------------|-----|-------------|
| 1 | Block | ✓ | WAN | in | any (IPv4+IPv6) | `netmon_block` | any | ✓ | netmon_block inbound |
| 2 | Block | ✓ | LAN, VPN (internal interfaces) | in | any (IPv4+IPv6) | any | `netmon_block` | ✓ | netmon_block outbound |

Apply. With the alias empty these rules match nothing (no production impact).
Rule 2 stops internal hosts and VPN clients reaching a blocked address; rule 1 stops the
address reaching any port forward. Management access is unaffected: netmon refuses to
add internal ranges, your public ranges, the WAN gateway, or the configured DNS resolvers.

Existing states: pf keeps established connections that match an existing state.
Kill them manually if needed (Firewall → Diagnostics → States, filter by address).

## 3. Enforcement API user (separate from the read-only SSH key)
System → Access → Users → +
- Username `netmon-block`, scrambled random password, no shell, not in admins group
- Effective privileges: **only** `Diagnostics: PF Table IP addresses`
  (grants api/firewall/alias_util/*; verified in Core ACL.xml on 26.7.7).
  This privilege can modify any alias via alias_util; netmon hard-codes `netmon_block`.
- API keys → + → downloads `apikey.txt`

On the monitor VM:
    sudo install -o 10001 -g 10001 -m 600 apikey.txt /opt/netmon/secrets/opnsense_block.key
    shred -u apikey.txt
    cd /opt/netmon/app && sudo docker compose restart

## 4. Test (benign, reversible)
In /netmon/blocks request a block of a documentation-safe external address you never use
(e.g. 192.0.2.x is refused as reserved, so use a real but unused IP you choose), approve it,
verify in Firewall → Diagnostics → Aliases → netmon_block, then Remove.

## Rollback
- Remove from /netmon/blocks, or edit the alias content in the GUI.
- Disable/delete the two floating rules to disable all netmon enforcement instantly.
- Delete /opt/netmon/secrets/opnsense_block.key to disable apply in the app.


## pfSense (2.7 / 24.x+) — via the pfSense REST API package
pfSense has no built-in REST API. netmon uses the community package pfSense-pkg-RESTAPI v2 (pfrest.org).
1. Backup: Diagnostics → Backup & Restore → Download configuration.
2. Install the package (pfSense shell, version-matched build from https://github.com/pfrest/pfSense-pkg-RESTAPI/releases):
   `pkg-static add https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/latest/download/pfSense-<VERSION>-pkg-RESTAPI.pkg`
3. System → REST API → Settings: Enable ✓, Authentication methods: **API Key** only; restrict allowed interfaces to the
   interface the monitor connects from.
4. System → User Manager: user `netmon-block` (random password), Effective privileges **only**
   `api-v2-firewall-aliases-get` and `api-v2-firewall-alias-patch`. System → REST API → Keys: create a key for that user.
5. Firewall → Aliases → IP: `netmon_block`, type **Host(s)**, empty.
6. Firewall → Rules → Floating, at the top: Block · Quick ✓ · WAN · in · source `netmon_block`; and Block · Quick ✓ ·
   LAN (+VPN) · in · destination `netmon_block`. Apply. With the alias empty they match nothing.
7. In netmon: Settings → Firewalls & sites → the pfSense site → Connection settings → API base URL `https://<fw>`,
   alias, paste the key. The pfSense web certificate must validate (use a real certificate, or set the TLS name to the
   certificate's hostname).
How it works: GET /api/v2/firewall/aliases?name=netmon_block, then PATCH /api/v2/firewall/alias with the full
address list (one address added or removed); the API reloads the filter. Same guardrails and approval flow as OPNsense.
