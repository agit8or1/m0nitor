"use strict";
(() => {
  const { el, $, fmtBytes, fmtBps, fmtNum, ago, fmtTime, sev } = NM;
  let data = null, bwSource = null;
  const map = NMMap.create($("map"), { onSelect: (cc) => NM.setScope({ cc: NM.scope.cc === cc ? "" : cc }) });
  NMMap.bindControls(map);

  const filtered = () => !!(NM.scope.cc || NM.scope.host || NM.scope.asn || NM.scope.port || NM.scope.rip);
  function counterNow(d) {
    const c = (d.counters || []).find((x) => x.ok && x.current);
    if (!c || Date.now() / 1000 - c.current.t > 60) return null;
    return c;
  }

  const src = (x) => x.state === "ok" ? "connected" : x.state === "stale" ? `stale (${ago(Date.now() / 1000 - x.last)})` : "not connected";
  const mark = (x) => x.state === "ok" ? "✓" : x.state === "stale" ? "◐" : "✕";
  // six KPIs: one dominant value, a short label, one supporting line; the detail moves into the hover title
  function renderCards(d) {
    const s = d.summary, fs = d.flow_series, c = counterNow(d), coll = d.collection, A = d.alert_summary;
    const useCounters = c && !filtered();
    const bw = (dir) => {
      const cur = useCounters ? c.current[`${dir}_bps`] : null;
      const avg = s[`${dir}_avg_bps`], peakF = fs[`peak_${dir}_bps`], peakC = c ? c[`peak_${dir}_bps`] : null;
      const peak = useCounters && peakC != null ? `${fmtBps(peakC)} (counters)` : `${fmtBps(peakF)} (flows, ${fs.bucket} s buckets)`;
      return {
        k: dir === "in" ? "Inbound bandwidth" : "Outbound bandwidth", sw: dir === "in" ? "--in" : "--out", href: "#bw",
        v: useCounters ? fmtBps(cur) : fmtBps(avg),
        s: useCounters ? `now · avg ${fmtBps(avg)} · peak ${fmtBps(peakC)}` : `window avg · flow-estimated${filtered() ? " (filtered)" : ""}`,
        tip: useCounters ? `Now: WAN interface counters (${c.interval} s sample, ${ago(Date.now() / 1000 - c.current.t)}). Average ${fmtBps(avg)} from flows. Peak ${peak}.`
          : `Average over the window, from flow records. Peak ${peak}.`,
      };
    };
    const hi = A.security.high, med = A.security.medium, lo = A.security.low;
    const age = coll.age; const fresh = age != null && age < 120;
    const snmp = (d.counters || [])[0];
    NM.cards($("cards"), [
      bw("in"), bw("out"),
      { k: "Total transferred", v: fmtBytes(s.in_b + s.out_b), href: NM.href("/netmon/connections"),
        s: el("span", {}, el("span", { class: "sw", style: "background:var(--in)" }), ` ↓ ${fmtBytes(s.in_b)}  `, el("span", { class: "sw", style: "background:var(--out)" }), ` ↑ ${fmtBytes(s.out_b)}`),
        tip: `Downloaded ${fmtBytes(s.in_b)}, uploaded ${fmtBytes(s.out_b)} at the WAN boundary · ${fmtNum(s.flows)} flow records` },
      { k: "Servers observed", href: NM.href("/netmon/servers"), v: fmtNum(s.servers), s: `${fmtNum(s.peers)} remote addresses · ${fmtNum(s.countries)} countries`,
        tip: "Internal servers that received Internet traffic in this window" },
      { k: "Security alerts", v: String(hi + med + lo), href: "/netmon/security", cls: hi ? "bad" : "",
        s: el("span", {}, sev("high"), ` ${hi}  `, sev("medium"), ` ${med}  `, sev("low"), ` ${lo}`),
        tip: `Open security alerts. Also ${A.info} informational change(s) and ${A.health} monitoring-health item(s).` },
      { k: "Collection health", cls: fresh ? "" : "bad", href: "/netmon/settings/integrations",
        v: el("span", { class: `health ${fresh ? "s-good" : "s-critical"}` }, el("span", { class: "hdot", text: fresh ? "●" : "✕" }), fresh ? "Healthy" : "Delayed"),
        s: `flows ${ago(age)} · logs ${mark(d.sources.fw)} · IDS ${mark(d.sources.ids)} · SNMP ${snmp ? (snmp.ok ? "✓" : "✕") : "–"}`,
        tip: `Newest flow ${ago(age)}; export delay ~15 s (short flows), up to ${Math.round((NM.live()?.active_timeout || 1800) / 60)} min (long). ` +
          `Firewall logs: ${src(d.sources.fw)}. IDS: ${src(d.sources.ids)}. Counters: ${snmp ? (snmp.ok ? "OK" : "error") : "n/a"}.` },
    ]);
  }

  // short prioritized list: severity, one-line explanation, affected server, age; the long metadata sits in a drawer
  const DIRS = { inbound: "⬇ Inbound", outbound: "⬆ Outbound", internal: "↔ Internal", both: "⇅ Both" };
  function renderSecurity(d) {
    const node = $("secpanel"), A = d.alert_summary, L = NM.live(), det = L ? L.detector : null;
    const pill = (lvl, n, label) => el("a", { href: "/netmon/security" }, sev(lvl), el("b", { text: String(n) }), label ? el("span", { class: "muted", text: label }) : null);
    const all = d.alerts.filter((a) => a.category === "security"), items = all.slice(0, 6);
    const ul = el("ul", { class: "slist" });
    for (const a of items) {
      const [head, tail] = a.title.split(" — ");
      const b = sev(a.severity); b.classList.add("badge");
      ul.append(el("li", {},
        el("div", { class: "row1" }, b, el("a", { href: `/netmon/alert/${a.id}`, text: head, title: a.title }), el("span", { class: "when", text: ago(Date.now() / 1000 - a.last_seen) }), NM.ackButton(a)),
        el("div", { class: "meta" }, a.asset ? (a.asset_internal ? el("a", { href: NM.href(`/netmon/servers/${a.asset}`), text: a.asset_label || a.asset })
          : el("span", { text: a.asset_label || a.asset, title: "Public/NAT address — no single internal server" })) : "site-wide",
          a.direction ? ` · ${DIRS[a.direction] || a.direction}${a.direction_verified ? " ✓" : " (unverified)"}` : "", tail ? el("span", { class: "muted mono", text: ` · ${tail}` }) : null,
          a.lan_hosts ? el("div", { class: "small", text: a.lan_hosts }) : null),
        el("details", {}, el("summary", { text: "Details" }), el("div", {},
          `${a.rule} · confidence ${a.confidence} · seen ${a.count}×${a.direction_basis ? ` · direction: ${a.direction_basis}` : ""}`,
          a.next ? el("div", { text: `Next step: ${a.next}` }) : null))));
    }
    const cov = [`flows ✓`, `firewall ${mark(d.sources.fw)}`, `IDS ${mark(d.sources.ids)}`];
    if (det) cov.push(`baseline ${Math.min(100, Math.round(100 * det.learning_days / det.baseline_days))}%`);
    node.replaceChildren(
      el("div", { class: "sevsum" }, pill("high", A.security.high), pill("medium", A.security.medium), pill("low", A.security.low),
        el("a", { href: "/netmon/security", title: "Informational changes" }, el("span", { class: "sev s-muted", text: "○ info" }), el("b", { text: String(A.info) }))),
      items.length ? ul : el("div", { class: "state empty", text: "No open security findings" }),
      el("div", { class: "sec-foot" }, el("span", { text: `Coverage: ${cov.join(" · ")}` }), el("a", { href: "/netmon/coverage", text: "What is visible →" })));
    // fixed-height panel on desktop: drop items that would be clipped instead of adding a nested scrollbar
    const more = el("li", { class: "more" }, el("a", { href: "/netmon/security" }));
    const fits = () => node.scrollHeight <= node.clientHeight + 1;
    if (!fits()) {
      ul.append(more);
      while (!fits() && ul.children.length > 2) ul.children[ul.children.length - 2].remove();
    }
    const hidden = all.length - (ul.children.length - (more.isConnected ? 1 : 0));
    if (hidden > 0) { if (!more.isConnected) ul.append(more); more.firstChild.textContent = `+ ${hidden} more security alert${hidden > 1 ? "s" : ""} →`; }
  }

  function renderBandwidth(d) {
    const c = (d.counters || []).find((x) => x.points && x.points.some((p) => p.in_bps != null));
    const seg = $("bwsrc");
    if (!bwSource) bwSource = c && !filtered() ? "counters" : "flows";
    if (filtered()) bwSource = "flows";
    seg.querySelectorAll("button").forEach((b) => { b.classList.toggle("on", b.dataset.v === bwSource); b.disabled = b.dataset.v === "counters" && (!c || filtered()); });
    const useC = bwSource === "counters" && c;
    const pts = useC ? c.points : d.flow_series.points;
    const cap = capacityFor(d, useC ? c : null);
    const refs = cap.down && cap.down === cap.up ? [{ value: cap.down * 1e6, label: "Capacity" }]
      : [cap.down ? { value: cap.down * 1e6, label: "Down cap", cls: "in" } : null, cap.up ? { value: cap.up * 1e6, label: "Up cap", cls: "out" } : null].filter(Boolean);
    NM.lineChart($("bw"), pts, [{ key: "in_bps", cls: "in", label: "Inbound" }, { key: "out_bps", cls: "out", label: "Outbound" }],
      { unavailableBefore: useC ? c.first_sample : d.collection.first, refs });
    NM.legendInOut($("bwlegend"));
    const fs = d.flow_series, s = d.summary;
    const pin = useC ? c.peak_in_bps : fs.peak_in_bps, pout = useC ? c.peak_out_bps : fs.peak_out_bps;
    const grp = (cls, label, now, avg, peak) => el("div", { class: "grp" }, el("span", { class: "k" }, el("span", { class: "sw", style: `background:var(--${cls})` }), label),
      el("span", { class: "big", text: now != null ? `${fmtBps(now)} now` : `${fmtBps(avg)} avg` }),
      el("span", { class: "sm", text: `${now != null ? `avg ${fmtBps(avg)} · ` : ""}peak ${fmtBps(peak)}` }));
    const pct = (v, cap) => { const p = 100 * v / (cap * 1e6); return p > 0 && p < 0.1 ? "<0.1%" : `${p.toFixed(p < 10 ? 1 : 0)}%`; };
    $("bwstats").replaceChildren(
      grp("in", "Inbound", useC && c.current ? c.current.in_bps : null, s.in_avg_bps, pin),
      grp("out", "Outbound", useC && c.current ? c.current.out_bps : null, s.out_avg_bps, pout),
      cap.down || cap.up ? el("div", { class: "grp" }, el("span", { class: "k", text: "Peak use of capacity" }),
        el("span", { class: "big", text: `↓ ${cap.down ? pct(pin, cap.down) : "—"}  ↑ ${cap.up ? pct(pout, cap.up) : "—"}` }),
        el("span", { class: "sm", text: `of ${cap.down ? fmtBps(cap.down * 1e6) : "?"} down / ${cap.up ? fmtBps(cap.up * 1e6) : "?"} up` })) : null);
    const note = $("bwnote");
    note.replaceChildren(el("p", { text: useC
      ? `Source: WAN interface ${c.iface} SNMP counters (IF-MIB 64-bit octets), sampled every ${c.interval} s, ${d.scope.bucket} s buckets; resets and missed polls show as gaps. ` +
        `${c.site_name} only — not affected by filters. Averages use flow records.${cap.down || cap.up ? " Dashed line = contracted WAN capacity." : ""}`
      : `Source: flow-estimated from NetFlow records at the WAN boundary, ${fs.bucket} s buckets by time received. Short flows arrive ~15 s after they end; ` +
        `long connections are exported every ${Math.round((NM.live()?.active_timeout || 1800) / 60)} min, so their bytes land in one bucket and can look like a spike. Gaps = no records.` +
        (d.collection.first && d.collection.first > d.scope.start ? ` Collection started ${fmtTime(d.collection.first, true)}; earlier time is unavailable.` : "") }));
    if (!c) note.append(el("p", {}, "Near-real-time bandwidth needs SNMP interface counters: ", el("a", { href: "/netmon/settings/integrations#tip-snmp", text: "set up in Settings →" })));
    else if (!cap.down && !cap.up) note.append(el("p", {}, `Utilization not shown: WAN capacity not configured (port speed ${c.port_speed_mbps || "?"} Mb/s is not capacity). `,
      el("a", { href: "/netmon/settings/sites", text: "Set capacity →" })));
  }

  // contracted capacity for the chart: the counter's own site, or the sum over the scoped sites (only if all have it)
  function capacityFor(d, c) {
    if (c) return { down: c.down_mbps, up: c.up_mbps };
    const cs = (NM.live()?.capacity || []).filter((x) => d.scope.sites.includes(x.id));
    const sum = (k) => cs.length && cs.every((x) => x[k]) ? cs.reduce((a, x) => a + x[k], 0) : null;
    return { down: sum("down_mbps"), up: sum("up_mbps") };
  }
  function renderMeters() {
    const L = NM.live(), node = $("capacity"); if (!L || !L.capacity) return;
    const sel = data ? data.scope.sites : L.capacity.map((x) => x.id);
    const sites = L.capacity.filter((x) => sel.includes(x.id));
    const u = (cls, arrow, bps, capM) => {
      const p = capM && bps != null ? 100 * bps / (capM * 1e6) : null;
      const st = p == null ? null : p >= 90 ? ["critical", "✕ Saturated"] : p >= 70 ? ["warning", "▲ High"] : ["good", "● Normal"];
      const tr = el("span", { class: `mtrack${capM ? "" : " nocap"}`, role: "meter", "aria-label": `${arrow === "↓" ? "Download" : "Upload"} utilization`,
        "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": p == null ? "" : p.toFixed(0) });
      if (p != null) tr.append(el("span", { class: `mfill ${cls}`, style: `width:${Math.min(100, Math.max(p, 0.5)).toFixed(1)}%` }));
      return el("span", { class: "u" }, `${arrow}`, tr, bps == null ? "no data" : capM ? `${fmtBps(bps)} of ${fmtBps(capM * 1e6)} · ${p > 0 && p < 0.1 ? "<0.1" : p.toFixed(1)}%` : `${fmtBps(bps)} · capacity not set`,
        st ? el("span", { class: `sev s-${st[0]}`, text: st[1] }) : null);
    };
    node.replaceChildren(el("b", { text: "WAN utilization" }), ...sites.flatMap((s) => [sites.length > 1 ? el("span", { class: "muted", text: s.name }) : null,
      u("in", "↓", s.in_bps, s.down_mbps), u("out", "↑", s.out_bps, s.up_mbps)]).filter(Boolean),
      el("a", { class: "small", href: "/netmon/settings/sites", style: "margin-left:auto", text: "Capacity settings →" }));
  }
  NM.onLive(renderMeters);

  function renderTables(d) {
    const srv = d.servers.map((h) => ({ ...h, in_b: h.rx, out_b: h.tx }));
    NM.rank($("t-servers"), srv.slice(0, 8), { label: (h) => h.name || h.ip, sub: (h) => `${h.ip} · ${fmtBps(h.in_bps)} in · ${h.tx ? fmtBps(h.out_bps) + " out" : "out n/a (NAT)"}`,
      link: (h) => NM.href(`/netmon/servers/${h.ip}`) });
    if (d.unattributed_nat_tx) $("t-servers").append(el("p", { class: "note", text: `+ ${fmtBytes(d.unattributed_nat_tx)} uploaded via the shared NAT address — not attributable to one server from flows.` }));
    NM.rank($("t-orgs"), d.orgs.slice(0, 8), { label: (o) => o.asname || `AS${o.asn}`, sub: (o) => `AS${o.asn}${o.cc ? " · " + o.cc : ""}`, link: (o) => NM.href("/netmon/connections", { asn: o.asn }) });
    NM.rank($("t-countries"), d.countries.filter((c) => c.cc !== "??").slice(0, 8), { label: (c) => c.name, sub: (c) => `${fmtNum(c.servers)} servers · ${fmtNum(c.flows)} flows`,
      link: (c) => NM.href(`/netmon/countries/${c.cc}`) });
    const sv = $("t-services"); sv.replaceChildren();
    const ex = el("div"), us = el("div");
    sv.append(el("h3", { class: "grp", text: "Exposed services (inventory: port forwards)" }), ex, el("h3", { class: "grp", text: "Services used by servers (port-based guess)" }), us);
    NM.rank(ex, d.services.exposed.slice(0, 4).map((s) => ({ ...s, in_b: s.b, out_b: 0 })), { label: (s) => `${s.name} · ${s.proto}/${s.port}${s.mgmt ? " ⚠ admin" : ""}`,
      sub: (s) => `${fmtNum(s.clients)} clients`, link: (s) => NM.href(`/netmon/servers/${s.ip}`), empty: "No inbound service traffic" });
    NM.rank(us, d.services.outbound.slice(0, 4).map((s) => ({ ...s, in_b: s.b, out_b: 0 })), { label: (s) => `${s.svc || "port"} ${s.proto}/${s.port}`,
      sub: (s) => `${fmtNum(s.servers)} servers · guessed from port`, link: (s) => NM.href("/netmon/connections", { port: s.port }) });
    recentPage = Math.min(recentPage, Math.max(1, Math.ceil(d.recent.rows.length / PER)));
    renderRecent();
  }

  const PER = 8; let recentPage = 1;
  function renderRecent() {
    const rows = data.recent.rows;
    NM.convTable($("t-recent"), rows.slice((recentPage - 1) * PER, recentPage * PER), { empty: "No conversations in this scope" });
    NM.pager($("recentpager"), recentPage, PER, rows.length, (p) => { recentPage = p; renderRecent(); });
  }

  function renderMapSel(d) {
    const ac = d.alert_countries || {};
    map.render({ countries: d.countries, alerts: ac, sites: d.sites, home: d.home, span: d.scope.span, window: `${d.scope.range === "custom" ? "custom range" : "last " + d.scope.range}`, selected: NM.scope.cc,
      legendNode: $("maplegend"), noteNode: $("mapnote"), blocked: d.blocked });
    const h = document.querySelector(".map-card .card-h h2");
    h.replaceChildren("Where traffic goes", NM.scope.cc ? el("a", { class: "small sel-link", href: NM.href(`/netmon/countries/${NM.scope.cc}`), text: ` · open ${d.scope.cc_name} details →` }) : "");
  }

  async function load() {
    try {
      data = await NM.get("/netmon/api/overview?" + NM.qs());
      NM.scopeDesc(data.scope);
      renderCards(data); renderMapSel(data); renderSecurity(data);
      renderBandwidth(data); renderTables(data); renderMeters();
    } catch (e) { NM.state($("cards"), "error", `Could not load dashboard: ${e.message}`); }
  }
  $("bwsrc").addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (!b || b.disabled) return; bwSource = b.dataset.v; if (data) renderBandwidth(data); });
  NM.onScope(load);
  load();
  NM.every(load, 30000);
  window.addEventListener("nm-theme", () => { if (data) { renderMapSel(data); renderBandwidth(data); } });
  let rs; window.addEventListener("resize", () => { clearTimeout(rs); rs = setTimeout(() => data && renderBandwidth(data), 200); });
})();
