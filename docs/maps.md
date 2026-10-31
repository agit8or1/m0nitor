# Maps and traffic views

## World map (Overview, Countries, wallboards)

- **Arcs** run between the site and each remote country (or, in the site's own country, each region placed by
  city-level GeoIP). Colour shows direction only: teal = inbound, purple = outbound. Line width = volume.
  Arcs show communication aggregated over the selected window, not routes or live packets.
- **Red diamonds** mark countries (or endpoints) named in an open security finding. Arcs are never red.
- **Zoom** goes to 24×. Dots, site markers, labels and finding markers keep their on-screen size, so zooming in
  separates sources that sit close together. A finding marker reacts to the pointer only on the diamond itself.
- **Shading** can show bytes, flows, findings, logged firewall blocks or the configured GeoIP policy.

## Tooltips: source → destination

Hovering an arc, a region dot or an endpoint lists the five busiest **source → destination** address pairs for that
direction, for example:

    192.0.2.154 (host.example.net) ⟶ WAN 203.0.113.179 → 10.40.0.123, 10.40.0.128 +2 · 14.2 MB
    backup-1 → WAN alias backup.example.net 203.0.113.183 ⟶ 198.51.100.20 · 3.1 MB

- The firewall side is shown as the **public address the traffic used**: `WAN` (the outbound NAT address) or
  `WAN alias <description>` (an interface virtual IP, read from the firewall's VIP list), followed by the internal
  server(s) behind it. Internal addresses are never shown in place of the public one.
- Names in parentheses are **reverse DNS** (PTR) names, resolved in the background through the site's own resolver;
  new names appear on the next refresh. Addresses with no PTR record show none.
- Several LAN hosts behind one NAT address are merged into one line, with up to three names listed.

## Reverse DNS elsewhere

Connection tables (Connections, Overview, server and country pages), finding endpoint tables, server pages and the
Servers list show the reverse DNS name under each address: `(name)`, or `(no rDNS)` when the resolver answered that
the address has none. A lookup that timed out shows nothing and is retried later.

## Accuracy

Countries come from the IPinfo country database (registration, not the operator's location). City placement uses
DB-IP City Lite and is approximate — usually the ISP's registered city. Anycast CDN addresses have no single
location; when the two databases disagree on the country, the address is not placed by city. See [geoip.md](geoip.md).
