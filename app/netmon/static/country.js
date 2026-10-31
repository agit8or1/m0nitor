"use strict";
(() => {
  const { el, $, fmtBytes, fmtBps, fmtNum } = NM;
  const cc = $("cthead").dataset.cc; document.body.dataset.fixed = "cc";
  async function load() {
    try {
      const d = await NM.get(`/netmon/api/country?${NM.qs({ cc })}`);
      NM.scopeDesc(d.scope);
      const s = d.summary;
      NM.cards($("cards"), [
        { k: "Inbound (from this country)", sw: "--in", href: "#bw", v: fmtBytes(s.in_b), s: `avg ${fmtBps(s.in_avg_bps)} · flow-estimated` },
        { k: "Outbound (to this country)", sw: "--out", href: "#bw", v: fmtBytes(s.out_b), s: `avg ${fmtBps(s.out_avg_bps)}` },
        { k: "Internal servers involved", href: "#t-servers", v: fmtNum(s.servers), s: `${fmtNum(s.peers)} remote addresses` },
        { k: "Findings", href: "#t-findings", v: String(d.findings.length), s: d.findings.length ? "linked by evidence" : "none — foreign traffic is not suspicious by itself" },
        { k: "GeoIP block", href: "#t-policy", v: d.policy.in.length && d.policy.out.length ? "In + out" : d.policy.in.length ? "Inbound" : d.policy.out.length ? "Outbound" : "Not blocked",
          s: d.policy.in.length || d.policy.out.length ? "by an enabled firewall rule" : d.policy.listed ? `listed in ${d.policy.alias}, but no enabled rule` : `not in ${d.policy.alias}`, cls: d.policy.listed && !d.policy.enforced ? "warn" : "" },
      ]);
      NM.lineChart($("bw"), d.flow_series.points, [{ key: "in_bps", cls: "in", label: "Inbound" }, { key: "out_bps", cls: "out", label: "Outbound" }], { unavailableBefore: d.collection.first });
      NM.legendInOut($("bwlegend")); $("bwnote").textContent = `Flow-estimated, ${d.flow_series.bucket} s buckets, WAN boundary filtered to remote country ${d.name}.`;
      NM.rank($("t-servers"), d.servers.map((h) => ({ ...h, in_b: h.rx, out_b: h.tx })), { label: (h) => h.name || h.ip, sub: (h) => h.ip, link: (h) => NM.href(`/netmon/servers/${h.ip}`, { cc }) });
      NM.rank($("t-orgs"), d.orgs, { label: (o) => o.asname || `AS${o.asn}`, sub: (o) => `AS${o.asn}`, link: (o) => NM.href("/netmon/connections", { asn: o.asn, cc }) });
      NM.alertList($("t-findings"), d.findings, { empty: "No findings involve this country" });
      const p = d.policy;
      $("t-policy").replaceChildren(
        el("p", {}, d.policy.listed ? `${d.name} is in alias ${p.alias}.` : `${d.name} is not in alias ${p.alias}.`),
        el("p", {}, el("b", { text: "Inbound (from this country): " }), p.in.length ? `blocked — ${p.in.join("; ")}` : "allowed"),
        el("p", {}, el("b", { text: "Outbound (to this country): " }), p.out.length ? `blocked — ${p.out.join("; ")}` : "allowed"),
        p.listed && !p.in.length && !p.out.length ? el("p", { class: "warnline", text: p.note }) : "",
        el("p", { class: "muted small", text: `${p.live ? "Checked" : "Last verified"} ${p.verified_at} · ${p.source}. This page does not change the firewall.` }));
      NM.convTable($("t-conv"), d.conversations.rows, { empty: "No conversations with this country in this scope" });
    } catch (e) { NM.state($("cards"), "error", e.message); }
  }
  // 7-day "if blocked" preview: heavy for busy countries, so it loads on its own (cached 10 min on the server)
  async function preview() {
    if (!$("t-preview").childElementCount) NM.state($("t-preview"), "loading", "Adding up the last 7 days…");
    try {
      const pv = await NM.get(`/netmon/api/country/${cc}/preview?${NM.qs({ cc: "" })}`), d = pv;
      $("t-preview").replaceChildren(
        el("p", {}, `Last 7 days: ${fmtBytes(pv.summary.in_b)} inbound and ${fmtBytes(pv.summary.out_b)} outbound with ${d.name}, involving ${fmtNum(pv.summary.servers)} servers and ${fmtNum(pv.summary.peers)} remote addresses. ` +
          "An inbound-only WAN block (like the GeoIP rule) stops new inbound connections from this country to the services below; established states continue until they close."),
        el("div", { class: "grid2 even" }, (() => { const a = el("div"); NM.rank(a, pv.servers.map((h) => ({ ...h, in_b: h.rx, out_b: h.tx })), { label: (h) => h.name || h.ip, sub: (h) => h.ip }); return a; })(),
          (() => { const b = el("div"); NM.rank(b, pv.services.exposed.map((x) => ({ ...x, in_b: x.b, out_b: 0 })), { label: (x) => `${x.name} ${x.proto}/${x.port}`, sub: (x) => `${fmtNum(x.clients)} clients from ${d.name}`, empty: "No inbound service use from this country" }); return b; })()));
    } catch (e) { NM.state($("t-preview"), "error", e.message); }
  }
  // logged firewall blocks for this country: same aggregate (and cache) as the Countries map tooltip
  async function blocks() {
    const box = $("t-blocks");
    try {
      const d = await NM.get(`/netmon/api/country/${cc}/blocks?${NM.qs({ cc: "" })}`);
      const st = d.stats, c = d.summary, g = st.provenance && st.provenance.geoip;
      $("blkstate").textContent = `${NM.fmtTime(d.scope.start, true)} → ${NM.fmtTime(d.scope.end, true)}`;
      if (st.state === "unavailable" || st.state === "error") return NM.state(box, "empty", st.state === "error" ? `Blocked activity unavailable: ${st.error}` : "Blocked activity unavailable — connect firewall logs.");
      const warn = (st.coverage || []).filter((x) => x.state !== "ok").map((x) => el("p", { class: "warnline", text: `${x.state === "stale" ? "⚠ Stale: " : ""}${x.name}: ${x.note}` }));
      if (!c) return box.replaceChildren(...warn, el("p", { text: st.state === "ok" ? "0 logged blocks in this window." : "No blocks logged for this country in this window (logging is incomplete; see above)." }));
      box.replaceChildren(...warn,
        el("p", {}, el("b", { text: "Logged block events: " }), `⬇ ${fmtNum(c.in)} inbound (from ${d.name}) · ⬆ ${fmtNum(c.out)} outbound (to ${d.name})`,
          st.geo_rules.length ? ` · by the GeoIP rule: ⬇ ${fmtNum(c.in_geo)} · ⬆ ${fmtNum(c.out_geo)}` : "",
          ` · logged blocked packet bytes ${st.bytes_complete ? fmtBytes(c.in_bytes + c.out_bytes) : "unavailable"} · last ${NM.fmtTime(c.last, true)}`),
        el("h3", { class: "grp", text: "By rule" }),
        (() => { const t = el("div"); NM.table(t, [
          { label: "Firewall", get: (r) => r.firewall }, { label: "Rule", get: (r) => el("span", {}, r.rule, r.geoip_rule ? el("span", { class: "tag", text: "GeoIP rule" }) : null,
            el("div", { class: "sub mono", text: r.rid || "—" })) },
          { label: "Interface", get: (r) => r.iface }, { label: "Direction", get: (r) => r.direction === "in" ? "⬇ inbound" : "⬆ outbound" },
          { label: "Events", cls: "num", get: (r) => fmtNum(r.events) }, { label: "Packet bytes", cls: "num", get: (r) => fmtBytes(r.bytes) },
          { label: "Last", cls: "num", get: (r) => NM.fmtTime(r.last, true) }], d.by_rule); return t; })(),
        el("h3", { class: "grp", text: `Latest ${d.rows.length} logged block records` }),
        (() => { const t = el("div", { class: "wrap" }); NM.table(t, [
          { label: "Time", cls: "num", get: (r) => NM.fmtTime(r.ts, true) }, { label: "Firewall", get: (r) => r.firewall }, { label: "Interface", get: (r) => r.iface },
          { label: "Direction", get: (r) => r.direction === "in" ? "⬇ inbound" : "⬆ outbound" },
          { label: "Source", get: (r) => el("span", {}, r.src_fw ? el("div", { class: "sub", text: r.src_fw }) : null, NM.ipCell(r.src, ""), NM.rdnsLine(r.src_rdns)) },
          { label: "Destination", get: (r) => el("span", {}, r.dst_fw ? el("div", { class: "sub", text: r.dst_fw }) : null,
            el("span", { class: "mono", text: r.dst }), NM.rdnsLine(r.dst_rdns)) },
          { label: "Service", get: (r) => `${r.proto}${r.dport ? `/${r.dport}` : ""}` },
          { label: "Rule", get: (r) => el("span", { title: r.rid }, r.rule, r.geoip_rule ? el("span", { class: "tag", text: "GeoIP" }) : null) },
          { label: "Length", cls: "num", get: (r) => `${fmtNum(r.length)} B` }], d.rows, { empty: "No records" }); return t; })(),
        el("p", { class: "muted small", text: `Source: ${st.provenance.source}. Country of each external address: ${g && g.database ? `${g.database}, built ${g.built}` : "GeoIP unavailable"} ` +
          "(same database as the traffic figures; the firewall's GeoIP alias uses its own source). Each record is one logged packet, not a connection or an attack; identical duplicate records are counted once." }));
    } catch (e) { NM.state(box, "error", e.message); }
  }
  NM.onScope(() => { load(); blocks(); preview(); }); load(); blocks(); preview(); NM.every(load, 60000); NM.every(blocks, 60000); NM.every(preview, 600000);
})();
