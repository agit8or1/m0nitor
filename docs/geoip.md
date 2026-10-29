# GeoIP: policy vs. enforcement

- **Policy** is what the firewall's GeoIP aliases and the rules referencing them say. netmon reads it live
  (read-only API, cached 5 minutes): alias as source = inbound blocked, as destination = outbound blocked; a
  disabled rule means the countries are **not** blocked. If the firewall is unreachable the last good read, then
  `geoip_policy` in config.yaml, is shown and labelled as such.
- **Enforcement** is what the logs show: logged block decisions by country (Countries page, country pages). Only
  logged rules appear; an absent event is not proof that nothing happened.
- Country comes from the IPinfo country database (address registration, not who operates an address). Private and
  ambiguous ends are counted separately and never given a country. Territories that Natural Earth's 1:110m shapes
  merge into another country (e.g. French Guiana) are drawn separately.
