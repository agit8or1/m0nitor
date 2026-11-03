# Firewall API permissions

m0nitor reaches each firewall through **one dedicated API user**. Everything it monitors (NetFlow, syslog, SNMP,
Suricata) is pushed by the firewall and needs **no API access at all**. The API user is only for the features below.
Without it m0nitor still monitors everything; it just cannot block, sync names or discover devices.

The app shows the same list with a live check of the configured account: **Settings → Firewall permissions → Check
this account now**. The check makes one read-only call per privilege and never changes the firewall.

## OPNsense

Privilege names and the endpoints they cover are taken from OPNsense Core's `ACL.xml` files (verified on 26.7.x).

### Create the user

1. **System → Access → Users → +**
   - Username e.g. `netmon`, a long random password (it is never used to log in), login shell `/sbin/nologin`.
   - **Not** in the `admins` group. **Do not** grant *All pages*.
2. **Effective Privileges → edit**: add the privileges from the table for the features you want. Save.
3. **API keys → +**: downloads `apikey.txt` (key and secret).
4. In m0nitor: **Settings → Firewalls & sites → (firewall) → Connection settings**: API base URL (`https://<firewall>`),
   paste the key as `key:secret` (or the whole `apikey.txt` contents). The firewall's web certificate must validate
   (a real certificate, or set *TLS name* to the hostname in the certificate). Keys are stored encrypted at rest.
5. **Settings → Firewall permissions → Check this account now**: every privilege you granted shows ✓.

### Privileges

| Privilege (OPNsense name) | Needed for | Used for | Endpoints m0nitor calls |
|---|---|---|---|
| **Diagnostics: PF Table IP addresses** | blocking | Manual blocks and auto-response: add/remove addresses in the `netmon_block` and `netmon_auto` aliases | `api/firewall/alias_util/*` |
| **Firewall: Alias: Edit** | blocking setup | Create the `netmon_block` / `netmon_auto` aliases (Settings → Auto-response → Create) | `api/firewall/alias/search_item`, `add_item`, `reconfigure` |
| **Firewall: Categories** | blocking setup | Create the `netmon` category that tags m0nitor's rules and aliases | `api/firewall/category/search_item`, `add_item` |
| **Firewall: Rules [new]** | blocking setup, GeoIP policy | Create, check and repair m0nitor's 4 floating block rules (and the on/off switch); read the GeoIP block policy shown on Countries | `api/firewall/filter/search_rule`, `add_rule`, `get_rule`, `toggle_rule`, `apply` |
| **Diagnostics: Show States** | optional | Drop existing connections of an address when it is blocked; without it, established connections continue until they close | `api/diagnostics/firewall/query_states`, `del_state` |
| **Firewall: NAT: 1:1** | recommended | Attribute outbound traffic of servers that have their own public address (hourly sync) | `api/firewall/one_to_one/search_rule` |
| **Interfaces: Virtual IPs: Settings** | recommended | Name the firewall's public addresses (virtual IP labels, hourly sync) | `api/interfaces/vip_settings/search_item` |
| **Diagnostics: ARP Table** | recommended | Inventory auto-discovery: MAC address, vendor and hostname of internal devices (every 15 minutes) | `api/diagnostics/interface/search_arp` |

Notes:

- **Minimum for blocking** is *Diagnostics: PF Table IP addresses*, if you create the aliases and floating rules by
  hand ([BLOCKING.md](BLOCKING.md)). Add *Firewall: Alias: Edit*, *Firewall: Categories* and *Firewall: Rules [new]*
  to let m0nitor create them for you and repair them if they are changed.
- *Diagnostics: PF Table IP addresses* lets the user change **any** alias through `alias_util`; m0nitor only ever
  touches its own aliases, and *Firewall: Rules [new]* is only used on rules whose UUID m0nitor recorded and whose
  description starts with `netmon:`.
- *Diagnostics: ARP Table* covers `search_arp` only, not the legacy `getArp` endpoint. m0nitor uses `search_arp` and
  falls back to `getArp` only on older releases.
- Read-only alternatives exist for some features (*Firewall: Aliases* can list aliases but not create them); m0nitor
  needs the privileges above because its read and write calls share them.
- Unbound query logging, remote syslog, NetFlow and SNMP are set up in the GUI by an administrator
  ([opnsense-setup.md](opnsense-setup.md)); m0nitor never needs privileges for them.

### Network access

The API is served by the firewall's web GUI. Allow the monitor's address to reach it (System → Settings →
Administration → *Listen interfaces* / your management rules); no other inbound access to the firewall is needed.

## pfSense

pfSense has no built-in REST API; m0nitor uses the community package **pfSense-pkg-RESTAPI v2**
([BLOCKING.md](BLOCKING.md#pfsense-27--24x--via-the-pfsense-rest-api-package) has the install steps).
In **System → User Manager**, create a dedicated user with **only** these privileges, then create a key under
**System → REST API → Keys**:

| Privilege | Used for |
|---|---|
| `api-v2-firewall-aliases-get` | Find the `netmon_block` alias |
| `api-v2-firewall-alias-patch` | Replace the alias address list (one address added or removed) |

Name sync, rule creation, state dropping and ARP discovery are OPNsense-only today.

## Removing access

Delete the API key (or the user) on the firewall, and clear the key in Settings → Firewalls & sites. Monitoring
continues; blocking, syncs and discovery stop and show "no permission" / "not set up".
