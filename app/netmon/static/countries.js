"use strict";
(() => {
  const { el, $, fmtBytes, fmtNum } = NM;
  const map = NMMap.create($("map"), { onSelect: (cc) => { location.href = NM.href(`/netmon/countries/${cc}`, { cc: "" }); } });
  NMMap.bindControls(map);
  const bmap = NMMap.create($("blkmap"), { policyOnly: true, onSelect: (cc) => { location.href = NM.href(`/netmon/countries/${cc}`, { cc: "" }); } });
  let filt = "all", rows = [], alerts = {};
  const fseg = $("ctfilter");
  fseg.addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (!b) return; filt = b.dataset.v;
    fseg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); table(); });
  const blkTag = (c) => el("span", {}, c.blocked_in ? el("span", { class: "tag", title: "an enabled GeoIP rule blocks traffic from this country", text: "⬇ inbound" }) : null,
    c.blocked_out ? el("span", { class: "tag", title: "an enabled GeoIP rule blocks traffic to this country", text: "⬆ outbound" }) : null,
    !c.blocked_in && !c.blocked_out ? el("span", { class: "muted", text: "—" }) : null);
  function table() {
    const keep = { all: () => true, in: (c) => c.blocked_in, out: (c) => c.blocked_out, open: (c) => !c.blocked_in && !c.blocked_out }[filt];
    const shown = rows.filter(keep);
    const tb = document.querySelector("#ct tbody");
    tb.replaceChildren(...shown.map((c) => { const a = alerts[c.cc] || {};
      return el("tr", {}, el("td", {}, c.cc === "??" ? "Unknown location" : el("a", { href: NM.href(`/netmon/countries/${c.cc}`, { cc: "" }), text: c.name })),
        el("td", { class: "num", text: fmtBytes(c.in_b) }), el("td", { class: "num", text: fmtBytes(c.out_b) }), el("td", { class: "num", text: fmtNum(c.flows) }),
        el("td", { class: "num", text: fmtNum(c.servers) }), el("td", { text: c.top_asname || (c.top_asn ? `AS${c.top_asn}` : "—") }),
        el("td", {}, a.security ? el("span", { class: "sev s-critical", text: `▲ ${a.security} security` }) : a.info ? el("span", { class: "sev s-muted", text: `○ ${a.info} info` }) : "—"),
        el("td", {}, blkTag(c))); }));
    if (!shown.length) tb.append(el("tr", {}, el("td", { colspan: 8, class: "state empty", text: "No countries with traffic in this scope match the filter" })));
  }
  function blockedLists(p, meta) {
    const nm = (cc) => (meta[cc] && meta[cc].name) || cc;
    const list = (ccs, dir) => { const s = [...ccs].sort((a, b) => nm(a).localeCompare(nm(b)));
      return el("div", {}, el("h3", { class: "grp" }, el("span", { class: `blksw ${dir}` }), ` ${dir === "in" ? "Blocked inbound" : "Blocked outbound"} · ${s.length}`),
        s.length ? el("details", {}, el("summary", { text: `Show ${s.length} countries` }),
          el("div", { class: "chiplist" }, s.map((cc) => el("a", { class: "chip static", href: NM.href(`/netmon/countries/${cc}`, { cc: "" }), title: cc, text: nm(cc) }))))
          : el("p", { class: "muted", text: dir === "in" ? "No enabled rule blocks traffic from any country." : "No enabled rule blocks traffic to any country." })); };
    $("blklists").replaceChildren(el("div", { class: "grid2 even" }, list(p.blocked_in, "in"), list(p.blocked_out, "out")),
      el("p", { class: "note", text: "Inbound = an enabled block/reject rule has a GeoIP alias as its source (traffic from that country). " +
        "Outbound = a GeoIP alias as the destination (traffic to that country). Only rules that reference the alias directly are counted." }));
    $("blknote").textContent = p.verified_at ? `${p.live ? "live" : "last verified"} ${p.verified_at}` : "configured snapshot · not verified against the firewall";
  }
  $("blkshade").addEventListener("change", (ev) => bmap.setShade(ev.target.value));
  // where the logged-block numbers come from, and how complete they are, for this exact scope
  function coverage(B) {
    const n = $("blkcov"); if (!B) return n.replaceChildren();
    if (B.state === "unavailable" || B.state === "error") return n.replaceChildren(el("p", { class: "warnline", text: B.state === "error" ? `Blocked activity unavailable: ${B.error}` : "Blocked activity unavailable — connect firewall logs." }));
    const g = B.provenance && B.provenance.geoip;
    n.replaceChildren(
      el("p", { text: `Logged block events: ${fmtNum(B.events)} firewall log records with action block/reject in this window (${B.provenance.source}). ` +
        "Each record is one packet the firewall logged as blocked — not a connection or an attack. " +
        `Inbound = from an external address to our networks (counted for the source's country); outbound = from our networks to an external address (destination's country). ` +
        `${fmtNum(B.not_attributable.events)} record(s) are not attributable to a country (both ends ours or both external, or private/link-local/multicast addresses)` +
        (B.no_country.events ? `; ${fmtNum(B.no_country.events)} have no GeoIP country` : "") + ". " +
        (B.duplicates ? `${fmtNum(B.duplicates)} identical duplicate record(s) were counted once. ` : "") +
        (B.bytes_complete ? "Logged blocked packet bytes = the sum of each logged packet's IP length; packets the firewall dropped without logging are not included." : "Some records lack a packet length: blocked volume unavailable.") }),
      el("p", { class: "muted small", text: `Countries for block events: ${g && g.database ? `${g.database}, built ${g.built}` : "GeoIP database unavailable"} — the same database as the flow (traffic) countries. ` +
        "The firewall's GeoIP alias uses its own GeoIP source, so a few addresses can be blocked by the GeoIP rule while being counted under a country outside the policy. " +
        "Observed traffic is NetFlow exported where packets leave the firewall: it mostly reflects forwarded traffic, but it is not a count of allowed connections." }),
      ...(B.coverage || []).filter((c) => c.state !== "ok").map((c) => el("p", { class: "warnline", text: `${c.state === "stale" ? "⚠ Stale: " : ""}${c.name}: ${c.note}` })));
  }
  async function load() {
    try {
      const d = await NM.get(`/netmon/api/countries?${NM.qs()}`);
      NM.scopeDesc(d.scope);
      const p = d.policy;
      const common = { countries: d.countries, sites: d.sites, span: d.scope.span, scope: d.scope, blocked: { in: p.blocked_in, out: p.blocked_out },
        policySites: d.policy_sites, blocks: d.blocks, clickHint: "Click for connections, rules, and blocked-event details" };
      map.render({ ...common, alerts: d.alert_countries, legendNode: $("maplegend"), noteNode: $("mapnote") });
      coverage(d.blocks);
      $("policy").replaceChildren(
        el("p", {}, `Blocked inbound: ${p.blocked_in.length} countries · blocked outbound: ${p.blocked_out.length}. `, el("a", { href: "#blocked", text: "See the lists" }),
          " or choose “Shade: GeoIP blocked” on the map."),
        el("p", {}, ...p.aliases.flatMap((a, i) => [i ? " · " : "", "Alias ", el("code", { text: a.name }), ` lists ${a.count} countries${a.enabled ? "" : " (alias disabled)"}`]), "."),
        el("p", { class: p.enforced ? "" : "warnline" }, el("b", { text: p.enforced ? "Enforced: " : "Not enforced: " }), p.note),
        p.aliases.some((a) => a.rules.length) ? el("ul", { class: "plain small" }, p.aliases.flatMap((a) => a.rules.map((r) => ({ ...r, alias: a.name }))).map((r) => el("li", {},
          el("span", { class: `sev s-${r.enabled ? "good" : "muted"}`, text: r.enabled ? "● enabled" : "○ disabled" }),
          ` ${r.action} ${r.direction} on ${r.interface}, ${r.negated ? "NOT " : ""}${r.side} = ${r.alias}, sequence ${r.sequence}${r.description ? ` · ${r.description}` : ""}`,
          r.blocks ? ` → blocks ${r.side === "source" ? "inbound" : "outbound"}` : ""))) : null,
        el("p", { class: "muted small", text: `${p.live ? "Checked" : "Last verified"} ${p.verified_at} · ${p.source}. This page never changes firewall rules.` }),
        el("p", { class: "muted small", text: "GeoIP describes where an address block is registered. It is one signal, not a security boundary: VPNs and cloud providers defeat it." }));
      rows = d.countries; alerts = d.alert_countries; table();
      bmap.render({ ...common, alerts: {}, legendNode: $("blklegend") });
      blockedLists(p, await NMMap.meta());
      const tot = d.countries.reduce((s, c) => s + c.in_b + c.out_b, 0);
      $("ctnote").textContent = `${d.countries.length} countries · ${fmtBytes(tot)} total = Overview transfer for the same scope (${fmtBytes(d.summary.in_b + d.summary.out_b)})`;
    } catch (e) { NM.state($("policy"), "error", e.message); }
  }
  NM.onScope(load); load(); NM.every(load, 60000);
})();
