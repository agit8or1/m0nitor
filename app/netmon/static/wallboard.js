// Wallboard renderer: one data fetch per refresh, tiles laid out on a 12-column grid. Every tile is a link.
"use strict";
const WB = (() => {
  const { el, fmtBytes, fmtBps, fmtNum, ago, fmtTime, sev } = NM;
  let def = null, layout = null, node = null, timer = null, maps = {};
  const H = (path, extra = {}) => { const p = new URLSearchParams(); if (layout.site && layout.site !== "all") p.set("site", layout.site);
    p.set("range", layout.range); for (const [k, v] of Object.entries(extra)) p.set(k, v); return `${path}?${p}`; };
  const needs = (t) => layout.widgets.some((w) => w.type === t);
  const LINK = { kpi_in: "/netmon/#bw", kpi_out: "/netmon/#bw", kpi_volume: "/netmon/connections", kpi_servers: "/netmon/servers", kpi_alerts: "/netmon/security", capacity: "/netmon/settings/sites",
    kpi_health: "/netmon/settings", kpi_fw: "/netmon/firewall", kpi_ids: "/netmon/ids", clock: "/netmon/settings/sites", map: "/netmon/countries",
    security: "/netmon/security", bandwidth: "/netmon/", top_servers: "/netmon/servers", top_orgs: "/netmon/connections", top_countries: "/netmon/countries",
    top_services: "/netmon/connections", recent: "/netmon/connections", fw_sources: "/netmon/firewall", ids_sigs: "/netmon/ids" };

  function kpi(body, v, s, cls) { body.replaceChildren(el("div", { class: `wbv ${cls || ""}` }, v), s ? el("div", { class: "wbs" }, s) : null); }
  const cnow = (d) => { const c = (d.counters || []).find((x) => x.ok && x.current); return c && Date.now() / 1000 - c.current.t < 60 ? c : null; };

  const R = {
    kpi_in: (b, d) => { const c = cnow(d); kpi(b, fmtBps(c ? c.current.in_bps : d.summary.in_avg_bps), c ? `now (counters) · avg ${fmtBps(d.summary.in_avg_bps)}` : "window avg · flow-estimated"); },
    kpi_out: (b, d) => { const c = cnow(d); kpi(b, fmtBps(c ? c.current.out_bps : d.summary.out_avg_bps), c ? `now (counters) · avg ${fmtBps(d.summary.out_avg_bps)}` : "window avg · flow-estimated"); },
    kpi_volume: (b, d) => kpi(b, el("span", {}, `↓ ${fmtBytes(d.summary.in_b)}`, el("br"), `↑ ${fmtBytes(d.summary.out_b)}`), `${fmtNum(d.summary.flows)} flow records`),
    kpi_servers: (b, d) => kpi(b, fmtNum(d.summary.servers), `${fmtNum(d.summary.peers)} remote addresses · ${fmtNum(d.summary.countries)} countries`),
    kpi_alerts: (b, d) => { const A = d.alert_summary.security; kpi(b, String(A.high + A.medium + A.low), el("span", {}, sev("high"), ` ${A.high} `, sev("medium"), ` ${A.medium} `, sev("low"), ` ${A.low}`), A.high ? "bad" : ""); },
    kpi_health: (b, d) => { const a = d.collection.age, ok = a != null && a < 120;
      kpi(b, el("span", { class: `sev s-${ok ? "good" : "critical"}`, text: ok ? "● Healthy" : "✕ Delayed" }), `flows ${ago(a)} · logs ${d.sources.fw.last ? "on" : "off"} · IDS ${d.sources.ids.last ? "on" : "off"}`); },
    kpi_fw: (b, d) => d.sources.fw.last ? kpi(b, fmtNum(d.sources.fw.blocks24), "blocked in 24 h (firewall logs)") : kpi(b, "Not connected", "firewall logs — counts unavailable", "na"),
    kpi_ids: (b, d) => d.sources.ids.last ? kpi(b, fmtNum(d.sources.ids.alerts24), "Suricata alerts in 24 h") : kpi(b, "Not connected", "Suricata IDS", "na"),
    clock: (b, d) => { const s = d.sites[0]; kpi(b, new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), `${new Date().toLocaleDateString()} · ${NM.tz} · ${s ? s.name : ""}`); },
    map: (b, d, w) => { let m = maps[w._k]; if (!m || !b.contains(m.node)) { b.replaceChildren(); const n = el("div", { class: "map" }); b.append(n); m = maps[w._k] = { node: n, map: NMMap.create(n, { onSelect: (cc) => { location.href = H(`/netmon/countries/${cc}`); } }) }; }
      m.map.render({ countries: d.countries, alerts: d.alert_countries, sites: d.sites, span: d.scope.span }); },
    security: (b, d) => NM.alertList(b, d.alerts, { limit: 8, empty: "No open findings" }),
    capacity: (b) => { const L = NM.live(); NM.meters(b, ((L && L.capacity) || []).filter((x) => layout.site === "all" || !layout.site || x.id === layout.site)); },
    bandwidth: (b, d) => { const c = (d.counters || []).find((x) => x.points && x.points.some((p) => p.in_bps != null));
      const n = el("div", { class: "chart fill" }); b.replaceChildren(n);
      NM.lineChart(n, c ? c.points : d.flow_series.points, [{ key: "in_bps", cls: "in", label: "Inbound" }, { key: "out_bps", cls: "out", label: "Outbound" }],
        { unavailableBefore: c ? c.first_sample : d.collection.first, height: b.clientHeight - 4 });
      b.append(el("div", { class: "wbs", text: c ? "WAN interface counters" : "flow-estimated" })); },
    top_servers: (b, d) => NM.rank(b, d.servers.map((h) => ({ ...h, in_b: h.rx, out_b: h.tx })), { label: (h) => h.name || h.ip, link: (h) => H(`/netmon/servers/${h.ip}`) }),
    top_orgs: (b, d) => NM.rank(b, d.orgs, { label: (o) => o.asname || `AS${o.asn}`, link: (o) => H("/netmon/connections", { asn: o.asn }) }),
    top_countries: (b, d) => NM.rank(b, d.countries.slice(0, 10), { label: (c) => c.name, link: (c) => H(`/netmon/countries/${c.cc}`) }),
    top_services: (b, d) => NM.rank(b, d.services.exposed.map((s) => ({ ...s, in_b: s.b, out_b: 0 })), { label: (s) => `${s.name} ${s.proto}/${s.port}`, value: (s) => `${fmtNum(s.clients)} clients`, link: (s) => H(`/netmon/servers/${s.ip}`) }),
    recent: (b, d) => NM.convTable(b, d.recent.rows.slice(0, 8)),
    fw_sources: (b, d, w, x) => x.fw ? NM.rank(b, x.fw.top_sources.map((r) => ({ ...r, in_b: +r.n, out_b: 0 })), { label: (r) => r.ip, value: (r) => fmtNum(r.n), link: (r) => H("/netmon/connections", { rip: r.ip }), empty: d.sources.fw.last ? "No blocks" : "Firewall logs not connected" }) : null,
    ids_sigs: (b, d, w, x) => x.ids ? NM.table(b, [{ label: "Sev", get: (r) => sev({ 1: "high", 2: "medium" }[r.severity] || "low") }, { label: "Signature", get: (r) => r.signature },
      { label: "Hits", cls: "num", get: (r) => fmtNum(r.hits) }], x.ids.signatures.slice(0, 8), { empty: d.sources.ids.last ? "No IDS alerts" : "Suricata not connected" }) : null,
  };

  function build() {
    node.replaceChildren(); maps = {};
    layout.widgets.forEach((w, i) => {
      w._k = `${i}-${w.type}`;
      const cat = def.catalog[w.type] || { label: w.type };
      const kpiLike = w.type.startsWith("kpi_") || w.type === "clock";
      const head = el("a", { class: "tile-h", href: H(LINK[w.type] || "/netmon/") }, w.title || cat.label, el("span", { class: "go", text: "→" }));
      const body = el("div", { class: "tile-b" });
      const tile = el(kpiLike ? "a" : "div", { class: `tile ${kpiLike ? "kpi-tile link" : ""}`, href: kpiLike ? H(LINK[w.type]) : null,
        style: `grid-column: span ${w.w}; grid-row: span ${w.h}`, "data-k": w._k }, kpiLike ? el("div", { class: "tile-h", text: w.title || cat.label }) : head, body);
      w._body = body; node.append(tile);
    });
  }
  // size rows so the whole layout fits the visible height (kiosk, page or fullscreen); stacked phone layout scrolls.
  // Rows holding only KPI tiles keep the height a KPI needs; the remaining height is shared by the other rows.
  function fit() {
    if (!node || node.dataset.preview) return;
    node.style.gridAutoRows = ""; node.style.gridTemplateRows = "";
    if (window.matchMedia("(max-width: 1100px)").matches) return;
    const kiosk = document.body.classList.contains("kiosk"), fs = document.fullscreenElement === node;
    const KPI = kiosk || fs ? 118 : 104, MIN = 72, PROBE = 100;
    const gap = parseFloat(getComputedStyle(node).rowGap) || 12;
    node.style.gridAutoRows = `${PROBE}px`;
    const rows = getComputedStyle(node).gridTemplateRows.split(" ").filter(Boolean).length || 1;
    const kpiOnly = Array(rows).fill(true), y0 = node.getBoundingClientRect().top;
    for (const t of node.children) {
      const r = t.getBoundingClientRect(), a = Math.round((r.top - y0) / (PROBE + gap)), n = Math.round((r.height + gap) / (PROBE + gap));
      if (!t.classList.contains("kpi-tile")) for (let k = a; k < a + n && k < rows; k++) kpiOnly[k] = false;
    }
    const top = fs ? 0 : y0 + window.scrollY, pad = fs ? 32 : 18;
    const nk = kpiOnly.filter(Boolean).length, nr = rows - nk;
    const free = window.innerHeight - top - pad - gap * (rows - 1) - nk * KPI;
    const h = nr ? Math.max(MIN, Math.floor(free / nr)) : KPI;
    const tpl = (hh) => kpiOnly.map((k) => `${k ? KPI : hh}px`).join(" ");
    node.style.gridTemplateRows = tpl(h);
    // absorb page padding/margins we did not measure, so a layout that fits leaves no stray scrollbar
    const over = fs ? node.scrollHeight - node.clientHeight : document.documentElement.scrollHeight - window.innerHeight;
    if (over > 0 && nr && h > MIN) node.style.gridTemplateRows = tpl(Math.max(MIN, h - Math.ceil(over / nr)));
  }
  let fitT;
  const refit = () => { clearTimeout(fitT); fitT = setTimeout(() => { fit(); refresh(); }, 150); };
  window.addEventListener("resize", refit);
  document.addEventListener("fullscreenchange", refit);
  window.addEventListener("nm-theme", () => refresh());

  async function refresh() {
    try {
      const qs = new URLSearchParams({ range: layout.range }); if (layout.site && layout.site !== "all") qs.set("site", layout.site);
      const [d, fw, ids] = await Promise.all([NM.get(`/netmon/api/overview?${qs}`),
        needs("fw_sources") ? NM.get(`/netmon/api/firewall?${qs}`).catch(() => null) : null, needs("ids_sigs") ? NM.get(`/netmon/api/ids?${qs}`).catch(() => null) : null]);
      for (const w of layout.widgets) { try { R[w.type] && R[w.type](w._body, d, w, { fw, ids }); } catch (e) { NM.state(w._body, "error", e.message); } }
      const info = document.getElementById("wbinfo"); if (info) info.textContent = `${layout.range} · refresh ${layout.refresh} s · updated ${fmtTime(Date.now() / 1000)}`;
    } catch (e) { node.prepend(el("div", { class: "banner bad", text: `Could not load data: ${e.message}` })); }
  }
  function render(lay) { layout = lay; build(); fit(); refresh(); clearInterval(timer); timer = setInterval(() => { if (!document.hidden) refresh(); }, layout.refresh * 1000); }
  async function init() {
    node = document.getElementById("wb"); if (!node) return;
    def = await NM.get(`/netmon/api/wallboards/${node.dataset.id}`);
    const sel = document.getElementById("wbsel");
    if (sel) { sel.replaceChildren(...def.boards.map((b) => el("option", { value: b.id, selected: b.id === def.id || null, text: b.name })));
      sel.addEventListener("change", () => { location.href = `/netmon/wallboards/${sel.value}`; }); }
    const fs = document.getElementById("wbfull"); if (fs) fs.addEventListener("click", () => node.requestFullscreen && node.requestFullscreen());
    const ck = document.getElementById("wbclock"); if (ck) { const t = () => { ck.textContent = `${new Date().toLocaleString()} (${NM.tz})`; }; t(); setInterval(t, 1000); }
    if (!node.dataset.preview) render(def.layout);
    return def;
  }
  const ready = new Promise((res) => document.addEventListener("DOMContentLoaded", () => init().then(res)));
  return { ready, render, def: () => def };
})();
